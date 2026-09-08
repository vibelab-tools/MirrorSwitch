use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const IVY_UPSTREAM: &str = "sbt-plugins--language-registry";
const MAVEN_ENDPOINT: &str = "https://repo.huaweicloud.com/repository/maven/";
const IVY_ENDPOINT: &str = "https://repo.huaweicloud.com/repository/ivy/";
const MAVEN_ID: &str = "mirrorswitch-maven";
const IVY_ID: &str = "mirrorswitch-ivy";
const IVY_PATTERN: &str = "[organization]/[module]/(scala_[scalaVersion]/)(sbt_[sbtVersion]/)[revision]/[type]s/[artifact](-[classifier]).[ext]";
const VERIFY_SBT_VERSION: &str = "1.13.0";
const VERIFY_SCALA_VERSION: &str = "2.13.16";

#[derive(Clone, Copy, Debug, Default)]
pub struct SbtAdapter;

impl Adapter for SbtAdapter {
    fn key(&self) -> &'static str {
        "sbt"
    }

    fn tool_id(&self) -> &'static str {
        "sbt"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::User
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        require_supported_context(context)?;
        if !runtime.command_exists("sbt") {
            return Ok(None);
        }
        if !runtime.command_exists("java") {
            return Err(AdapterError::Unsupported(
                "sbt was found but Java is unavailable on PATH".into(),
            ));
        }
        let layout = config_layout(runtime)?;
        let project = inspect_project(runtime, &layout)?;
        let version = sbt_version(runtime, project.sbt_version.as_deref())?;
        reviewed_version(&version)?;
        let java = run_command(runtime, "java", &["-version"], "java -version")?;
        let mut evidence = vec![
            format!("sbt {version}"),
            format!(
                "JDK {}",
                java.lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("unknown")
            ),
            format!(
                "launcher repository file is {}",
                layout.user_repositories.display()
            ),
            format!("project resolver declaration(s): {}", project.resolvers),
            format!("project/plugin declaration(s): {}", project.plugins),
            format!("credential declaration(s): {}", project.credentials),
        ];
        evidence.push(match project.scala_version {
            Some(version) => format!("project Scala {version}"),
            None => "project Scala version is not a simple literal or no project was found".into(),
        });
        evidence.push(match project.sbt_version {
            Some(version) => format!("project build.properties requests sbt {version}"),
            None => "project build.properties does not declare sbt.version".into(),
        });
        if runtime
            .environment_variable("SBT_CREDENTIALS")
            .is_some_and(|value| !value.trim().is_empty())
        {
            evidence.push("SBT_CREDENTIALS is configured (contents not read)".into());
        }
        Ok(Some(DetectedTool {
            tool_id: "sbt".into(),
            executable: Some(PathBuf::from("sbt")),
            version: Some(version),
            evidence,
        }))
    }

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        require_supported_context(context)?;
        require_scope(scope)?;
        if detected.tool_id != "sbt" {
            return Err(AdapterError::InvalidConfiguration(
                "sbt read received another tool's detection result".into(),
            ));
        }
        let layout = config_layout(runtime)?;
        let project = inspect_project(runtime, &layout)?;
        let version = sbt_version(runtime, project.sbt_version.as_deref())?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "sbt version changed after detection".into(),
            ));
        }
        reviewed_version(&version)?;
        let mut sources = environment_sources(runtime);
        sources.push(snapshot_source("sbt-version", &version));
        let mut files = Vec::new();
        let mut documents = Vec::new();

        let repositories = read_document(runtime, &layout.user_repositories)?;
        if repositories.exists {
            files.push(repositories.path.clone());
            let text = utf8(&repositories.path, &repositories.contents)?;
            if text.trim().is_empty() {
                sources.push(policy_source("empty-repositories", &repositories.path));
            } else {
                sources.extend(repository_sources(text, &repositories.path)?);
            }
        }
        documents.push(ConfigurationDocument {
            path: repositories.path,
            format: "sbt-user-repositories".into(),
            contents: repositories.contents,
        });

        for path in read_only_paths(runtime, &layout)? {
            let document = read_document(runtime, &path)?;
            if !document.exists {
                continue;
            }
            files.push(path.clone());
            let text = utf8(&path, &document.contents)?;
            sources.extend(read_only_sources(text, &path));
            documents.push(ConfigurationDocument {
                path,
                format: "sbt-read-only-configuration".into(),
                contents: document.contents,
            });
        }

        for (path, format, canonical) in verification_documents(&layout) {
            let document = read_document(runtime, &path)?;
            if document.exists {
                files.push(path.clone());
                if document.contents != canonical.as_bytes() {
                    sources.push(policy_source("verification-conflict", &path));
                }
            }
            documents.push(ConfigurationDocument {
                path,
                format: format.into(),
                contents: document.contents,
            });
        }

        Ok(CurrentConfiguration {
            tool_id: "sbt".into(),
            scope,
            files,
            sources,
            documents,
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context)?;
        require_current(current)?;
        let version = detected
            .version
            .as_deref()
            .ok_or_else(|| AdapterError::InvalidConfiguration("sbt version is missing".into()))?;
        let repository_version = sbt_repository_version(version)?;
        Ok(SelectionRequest {
            tool_id: "sbt".into(),
            adapter_key: "sbt".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![MAVEN_UPSTREAM.into(), IVY_UPSTREAM.into()],
            repository_versions: BTreeMap::from([
                (MAVEN_UPSTREAM.into(), repository_version.into()),
                (IVY_UPSTREAM.into(), repository_version.into()),
            ]),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![
                EndpointRole::Index,
                EndpointRole::Metadata,
                EndpointRole::Artifacts,
            ],
            allowed_delivery_modes: vec![DeliveryMode::Proxy],
            composition_policy: CompositionPolicy::Single,
            overrides: BTreeMap::new(),
        })
    }

    fn plan(
        &self,
        context: &SystemContext,
        current: &CurrentConfiguration,
        selections: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_supported_context(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let selected = selected_endpoints(selections)?;
        let repositories = find_document(current, "sbt-user-repositories")?;
        let repositories_text = utf8(&repositories.path, &repositories.contents)?;
        let mut rendered = rewrite_repositories(
            repositories_text,
            current.files.contains(&repositories.path),
            &selected.maven,
            &selected.ivy,
        )?
        .into_bytes();
        if repositories.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let mut changes = Vec::new();
        add_change_if_needed(
            context,
            current,
            repositories,
            rendered,
            "add or retarget separate credential-free Maven and Ivy resolvers after local while preserving private resolvers, comments and order",
            &mut changes,
        );
        for (_, format, canonical) in verification_documents_from_current(current)? {
            let document = find_document(current, format)?;
            add_change_if_needed(
                context,
                current,
                document,
                canonical.as_bytes().to_vec(),
                "create an isolated sbt dependency and plugin resolution fixture",
                &mut changes,
            );
        }
        Ok(ChangePlan {
            adapter_key: "sbt".into(),
            tool_id: "sbt".into(),
            scope: ConfigurationScope::User,
            changes,
            requires_elevation: false,
            service_impact: ServiceImpact::None,
        })
    }

    fn apply(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        runtime.apply_plan(plan)
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let layout = config_layout(runtime)?;
            let known_targets = verification_documents(&layout)
                .into_iter()
                .map(|(path, _, _)| rooted(&context.root, &path))
                .chain(std::iter::once(rooted(
                    &context.root,
                    &layout.user_repositories,
                )))
                .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known_targets.contains(target))
            {
                return Err(AdapterError::Verification(
                    "sbt transaction receipt contains no known target".into(),
                ));
            }
            let repositories = runtime.read(&layout.user_repositories)?.ok_or_else(|| {
                AdapterError::Verification("sbt user repositories disappeared".into())
            })?;
            let effective = managed_endpoints(utf8(&layout.user_repositories, &repositories)?)?;
            if effective.maven != MAVEN_ENDPOINT || effective.ivy != IVY_ENDPOINT {
                return Err(AdapterError::Verification(
                    "sbt user repositories do not contain the reviewed Maven/Ivy pair".into(),
                ));
            }
            for (path, _, canonical) in verification_documents(&layout) {
                let contents = runtime.read(&path)?.ok_or_else(|| {
                    AdapterError::Verification(format!(
                        "sbt verification file {} disappeared",
                        path.display()
                    ))
                })?;
                if contents != canonical.as_bytes() {
                    return Err(AdapterError::Verification(format!(
                        "sbt verification file {} is not canonical",
                        path.display()
                    )));
                }
            }
            let arguments = verification_arguments(&layout)?;
            let output = run_sbt_in(runtime, &layout.verification_root, &arguments)?;
            for expected in [
                MAVEN_ENDPOINT.trim_end_matches('/'),
                IVY_ENDPOINT.trim_end_matches('/'),
                VERIFY_SCALA_VERSION,
                "mirrorswitch-sbt-verification",
            ] {
                if !output.contains(expected) {
                    return Err(AdapterError::Verification(format!(
                        "sbt verification output did not contain {expected}"
                    )));
                }
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "sbt resolved a Maven dependency and an Ivy-layout plugin through {} and {}",
                    effective.maven, effective.ivy
                ),
            })
        })();
        match result {
            Ok(result) => Ok(result),
            Err(error) => verification_failure(runtime, receipt, error.to_string()),
        }
    }

    fn restore(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: format!(
                "restored {} sbt configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct ConfigLayout {
    user_repositories: PathBuf,
    verification_root: PathBuf,
    verification_repositories: PathBuf,
    verification_build: PathBuf,
    verification_properties: PathBuf,
    verification_plugins: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct ProjectInspection {
    resolvers: usize,
    plugins: usize,
    credentials: usize,
    scala_version: Option<String>,
    sbt_version: Option<String>,
}

#[derive(Clone, Debug)]
struct ObservedDocument {
    path: PathBuf,
    exists: bool,
    contents: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedEndpoints {
    maven: String,
    ivy: String,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "sbt on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "sbt adapter requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "sbt adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "sbt" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "sbt operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(runtime: &dyn Runtime) -> Result<ConfigLayout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("sbt user configuration requires a home directory".into())
    })?;
    validate_path(&home)?;
    let verification_root = home.join(".mirrorswitch/verification/sbt");
    Ok(ConfigLayout {
        user_repositories: home.join(".sbt/repositories"),
        verification_repositories: verification_root.join("repositories"),
        verification_build: verification_root.join("build.sbt"),
        verification_properties: verification_root.join("project/build.properties"),
        verification_plugins: verification_root.join("project/plugins.sbt"),
        verification_root,
    })
}

fn read_only_paths(
    runtime: &dyn Runtime,
    layout: &ConfigLayout,
) -> Result<Vec<PathBuf>, AdapterError> {
    let home = layout
        .user_repositories
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| AdapterError::InvalidConfiguration("sbt home path is invalid".into()))?;
    let mut paths = vec![
        home.join(".sbt/1.0/global.sbt"),
        home.join(".sbt/2.0/global.sbt"),
    ];
    if let Some(project) = runtime.project_dir() {
        validate_path(&project)?;
        paths.extend([
            project.join("build.sbt"),
            project.join("project/build.properties"),
            project.join(".sbtopts"),
            project.join(".jvmopts"),
        ]);
        paths.extend(
            runtime
                .list_files(&project.join("project"))?
                .into_iter()
                .filter(|path| path.extension().is_some_and(|extension| extension == "sbt")),
        );
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn inspect_project(
    runtime: &dyn Runtime,
    layout: &ConfigLayout,
) -> Result<ProjectInspection, AdapterError> {
    let mut inspection = ProjectInspection::default();
    for path in read_only_paths(runtime, layout)? {
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        let text = utf8(&path, &contents)?;
        inspection.resolvers +=
            text.matches("resolvers").count() + text.matches("externalResolvers").count();
        inspection.plugins += text.matches("addSbtPlugin").count();
        inspection.credentials += text.matches("credentials").count();
        if path.file_name().is_some_and(|name| name == "build.sbt")
            && inspection.scala_version.is_none()
        {
            inspection.scala_version = assigned_string(text, "scalaVersion");
        }
        if path
            .file_name()
            .is_some_and(|name| name == "build.properties")
        {
            inspection.sbt_version = property_value(text, "sbt.version");
        }
    }
    Ok(inspection)
}

fn read_document(runtime: &dyn Runtime, path: &Path) -> Result<ObservedDocument, AdapterError> {
    validate_path(path)?;
    let observed = runtime.read(path)?;
    Ok(ObservedDocument {
        path: path.to_path_buf(),
        exists: observed.is_some(),
        contents: observed.unwrap_or_default(),
    })
}

fn verification_documents(layout: &ConfigLayout) -> Vec<(PathBuf, &'static str, String)> {
    vec![
        (
            layout.verification_repositories.clone(),
            "sbt-verification-repositories",
            render_repositories(MAVEN_ENDPOINT, IVY_ENDPOINT),
        ),
        (
            layout.verification_build.clone(),
            "sbt-verification-build",
            render_verification_build(),
        ),
        (
            layout.verification_properties.clone(),
            "sbt-verification-properties",
            render_verification_properties(),
        ),
        (
            layout.verification_plugins.clone(),
            "sbt-verification-plugins",
            render_verification_plugins(),
        ),
    ]
}

fn verification_documents_from_current(
    current: &CurrentConfiguration,
) -> Result<Vec<(PathBuf, &'static str, String)>, AdapterError> {
    let repositories = find_document(current, "sbt-verification-repositories")?;
    let build = find_document(current, "sbt-verification-build")?;
    let properties = find_document(current, "sbt-verification-properties")?;
    let plugins = find_document(current, "sbt-verification-plugins")?;
    Ok(vec![
        (
            repositories.path.clone(),
            "sbt-verification-repositories",
            render_repositories(MAVEN_ENDPOINT, IVY_ENDPOINT),
        ),
        (
            build.path.clone(),
            "sbt-verification-build",
            render_verification_build(),
        ),
        (
            properties.path.clone(),
            "sbt-verification-properties",
            render_verification_properties(),
        ),
        (
            plugins.path.clone(),
            "sbt-verification-plugins",
            render_verification_plugins(),
        ),
    ])
}

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<&'a ConfigurationDocument, AdapterError> {
    let matches = current
        .documents
        .iter()
        .filter(|document| document.format == format)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "sbt current configuration must contain exactly one {format} document"
        )));
    }
    Ok(matches[0])
}

fn add_change_if_needed(
    context: &SystemContext,
    current: &CurrentConfiguration,
    document: &ConfigurationDocument,
    new_contents: Vec<u8>,
    summary: &str,
    changes: &mut Vec<PlannedFileChange>,
) {
    if document.contents == new_contents {
        return;
    }
    changes.push(PlannedFileChange {
        target: rooted(&context.root, &document.path),
        old_contents: current
            .files
            .contains(&document.path)
            .then(|| document.contents.clone()),
        old_mode: None,
        new_contents,
        new_mode: None,
        summary: summary.into(),
    });
}

fn environment_sources(runtime: &dyn Runtime) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    for variable in ["SBT_OPTS", "JAVA_OPTS", "JVM_OPTS"] {
        if let Some(value) = runtime.environment_variable(variable) {
            if has_precedence_override(&value) {
                sources.push(policy_source("precedence-override", Path::new(":env:")));
            }
            if has_boot_credentials(&value) {
                sources.push(policy_source("credentials-detected", Path::new(":env:")));
            }
        }
    }
    if runtime
        .environment_variable("SBT_CREDENTIALS")
        .is_some_and(|value| !value.trim().is_empty())
    {
        sources.push(policy_source("credentials-detected", Path::new(":env:")));
    }
    sources
}

fn read_only_sources(text: &str, path: &Path) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if has_precedence_override(text) {
        sources.push(policy_source("precedence-override", path));
    }
    if has_boot_credentials(text) || text.contains("credentials") {
        sources.push(policy_source("credentials-detected", path));
    }
    if text.contains("resolvers") || text.contains("externalResolvers") {
        sources.push(policy_source("project-resolvers-preserved", path));
    }
    if text.contains("addSbtPlugin") {
        sources.push(policy_source("project-plugins-preserved", path));
    }
    sources
}

fn repository_sources(text: &str, path: &Path) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let parsed = parse_repositories(text)?;
    let mut sources = Vec::new();
    for entry in parsed.entries {
        let (kind, upstream, url) = match entry.name.as_deref() {
            None => ("local", None, "local".into()),
            Some(MAVEN_ID) if is_reviewed_base(&entry.value, MAVEN_ENDPOINT) => (
                "managed-maven",
                Some(MAVEN_UPSTREAM.into()),
                MAVEN_ENDPOINT.into(),
            ),
            Some(IVY_ID) if is_reviewed_ivy(&entry.value) => (
                "managed-ivy",
                Some(IVY_UPSTREAM.into()),
                IVY_ENDPOINT.into(),
            ),
            Some(MAVEN_ID | IVY_ID) => ("managed-id-conflict", None, "<preserved>".into()),
            Some(_) => ("resolver-preserved", None, displayable_url(&entry.value)),
        };
        sources.push(ConfiguredSource {
            upstream_id: upstream,
            url,
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec![kind.into()]),
                ("config_path".into(), vec![path.display().to_string()]),
            ]),
        });
    }
    Ok(sources)
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        match kind {
            "precedence-override" => {
                return Err(AdapterError::Unsupported(
                    "sbt repository precedence is overridden by environment, .sbtopts or .jvmopts"
                        .into(),
                ));
            }
            "managed-id-conflict" => {
                return Err(AdapterError::Unsupported(
                    "a MirrorSwitch sbt resolver id is already bound to an unreviewed or credential-bearing entry"
                        .into(),
                ));
            }
            "empty-repositories" => {
                return Err(AdapterError::InvalidConfiguration(
                    "existing sbt repositories file is empty".into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "sbt verification target contains data not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ParsedRepositories {
    lines: Vec<String>,
    section: usize,
    section_end: usize,
    entries: Vec<RepositoryEntry>,
}

#[derive(Clone, Debug)]
struct RepositoryEntry {
    line: usize,
    name: Option<String>,
    value: String,
}

fn parse_repositories(text: &str) -> Result<ParsedRepositories, AdapterError> {
    let lines = split_lines(text);
    let sections = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            (trimmed.starts_with('[') && trimmed.ends_with(']')).then_some((index, trimmed))
        })
        .collect::<Vec<_>>();
    let repository_sections = sections
        .iter()
        .filter(|(_, name)| name.eq_ignore_ascii_case("[repositories]"))
        .collect::<Vec<_>>();
    if repository_sections.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "sbt repositories file must contain exactly one [repositories] section".into(),
        ));
    }
    let section = repository_sections[0].0;
    let section_end = sections
        .iter()
        .find(|(index, _)| *index > section)
        .map_or(lines.len(), |(index, _)| *index);
    let mut entries = Vec::new();
    for (index, line) in lines.iter().enumerate().take(section_end).skip(section + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed == "local" {
            entries.push(RepositoryEntry {
                line: index,
                name: None,
                value: "local".into(),
            });
            continue;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            if trimmed.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            }) {
                entries.push(RepositoryEntry {
                    line: index,
                    name: Some(trimmed.into()),
                    value: trimmed.into(),
                });
                continue;
            }
            return Err(AdapterError::InvalidConfiguration(format!(
                "unrecognized sbt repository entry on line {}",
                index + 1
            )));
        };
        if name.trim().is_empty() || value.trim().is_empty() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "incomplete sbt repository entry on line {}",
                index + 1
            )));
        }
        entries.push(RepositoryEntry {
            line: index,
            name: Some(name.trim().into()),
            value: value.trim().into(),
        });
    }
    let local = entries
        .iter()
        .filter(|entry| entry.name.is_none())
        .collect::<Vec<_>>();
    if local.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "sbt repositories file contains local more than once".into(),
        ));
    }
    if local
        .first()
        .is_some_and(|entry| entry.line != entries[0].line)
    {
        return Err(AdapterError::Unsupported(
            "sbt local repository exists but is not the first resolver".into(),
        ));
    }
    let mut names = BTreeSet::new();
    for entry in &entries {
        if let Some(name) = &entry.name
            && !names.insert(name.to_ascii_lowercase())
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "sbt repository id {name} is defined more than once"
            )));
        }
    }
    Ok(ParsedRepositories {
        lines,
        section,
        section_end,
        entries,
    })
}

fn rewrite_repositories(
    text: &str,
    existed: bool,
    maven: &str,
    ivy: &str,
) -> Result<String, AdapterError> {
    if !existed {
        return Ok(render_repositories(maven, ivy));
    }
    let parsed = parse_repositories(text)?;
    for entry in &parsed.entries {
        match entry.name.as_deref() {
            Some(MAVEN_ID) if !is_reviewed_base(&entry.value, MAVEN_ENDPOINT) => {
                return Err(AdapterError::Unsupported(
                    "the MirrorSwitch Maven resolver id is bound to another endpoint".into(),
                ));
            }
            Some(IVY_ID) if !is_reviewed_ivy(&entry.value) => {
                return Err(AdapterError::Unsupported(
                    "the MirrorSwitch Ivy resolver id is bound to another endpoint or layout"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    let managed_lines = parsed
        .entries
        .iter()
        .filter(|entry| matches!(entry.name.as_deref(), Some(MAVEN_ID | IVY_ID)))
        .map(|entry| entry.line)
        .collect::<BTreeSet<_>>();
    let local_line = parsed
        .entries
        .iter()
        .find(|entry| entry.name.is_none())
        .map(|entry| entry.line);
    let newline = newline(text);
    let indent = local_line
        .and_then(|line| parsed.lines.get(line))
        .map(|line| &line[..line.len() - line.trim_start().len()])
        .unwrap_or("  ");
    let managed = [
        format!(
            "{indent}{MAVEN_ID}: {}/{newline}",
            maven.trim_end_matches('/')
        ),
        format!(
            "{indent}{IVY_ID}: {}/, {IVY_PATTERN}{newline}",
            ivy.trim_end_matches('/')
        ),
    ];
    let mut output = String::new();
    for (index, line) in parsed.lines.iter().enumerate() {
        if managed_lines.contains(&index) {
            continue;
        }
        output.push_str(line);
        let insert_after = local_line.map_or(index == parsed.section, |local| index == local);
        if insert_after {
            if !output.ends_with(['\n', '\r']) {
                output.push_str(newline);
            }
            if local_line.is_none() {
                output.push_str(&format!("{indent}local{newline}"));
            }
            output.push_str(&managed.concat());
        }
    }
    if parsed.section_end == parsed.lines.len() && !output.ends_with(['\n', '\r']) {
        output.push_str(newline);
    }
    Ok(output)
}

fn managed_endpoints(text: &str) -> Result<SelectedEndpoints, AdapterError> {
    let parsed = parse_repositories(text)?;
    let maven = parsed
        .entries
        .iter()
        .find(|entry| entry.name.as_deref() == Some(MAVEN_ID))
        .filter(|entry| is_reviewed_base(&entry.value, MAVEN_ENDPOINT))
        .map(|_| MAVEN_ENDPOINT.to_owned())
        .ok_or_else(|| {
            AdapterError::Verification("managed sbt Maven resolver is missing".into())
        })?;
    let ivy = parsed
        .entries
        .iter()
        .find(|entry| entry.name.as_deref() == Some(IVY_ID))
        .filter(|entry| is_reviewed_ivy(&entry.value))
        .map(|_| IVY_ENDPOINT.to_owned())
        .ok_or_else(|| AdapterError::Verification("managed sbt Ivy resolver is missing".into()))?;
    Ok(SelectedEndpoints { maven, ivy })
}

fn split_lines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines = text
        .split_inclusive('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !text.ends_with('\n') && lines.is_empty() {
        lines.push(text.into());
    }
    lines
}

fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

fn render_repositories(maven: &str, ivy: &str) -> String {
    format!(
        "# Managed by MirrorSwitch: sbt repositories v1\n[repositories]\n  local\n  {MAVEN_ID}: {}/\n  {IVY_ID}: {}/, {IVY_PATTERN}\n",
        maven.trim_end_matches('/'),
        ivy.trim_end_matches('/')
    )
}

fn render_verification_build() -> String {
    format!(
        "// Managed by MirrorSwitch: sbt verification build v1\nThisBuild / scalaVersion := \"{VERIFY_SCALA_VERSION}\"\nThisBuild / organization := \"org.mirrorswitch\"\nname := \"mirrorswitch-sbt-verification\"\nlibraryDependencies += \"org.apache.commons\" % \"commons-lang3\" % \"3.14.0\"\nenablePlugins(JavaAppPackaging)\n"
    )
}

fn render_verification_properties() -> String {
    format!(
        "# Managed by MirrorSwitch: sbt verification properties v1\nsbt.version={VERIFY_SBT_VERSION}\n"
    )
}

fn render_verification_plugins() -> String {
    "// Managed by MirrorSwitch: sbt verification plugins v1\naddSbtPlugin(\"com.typesafe.sbt\" % \"sbt-native-packager\" % \"1.7.6\")\n".into()
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<SelectedEndpoints, AdapterError> {
    if selections.len() != 2 {
        return Err(AdapterError::InvalidConfiguration(
            "sbt plan requires one Maven and one Ivy selection".into(),
        ));
    }
    let maven = selection_base(selections, MAVEN_UPSTREAM, MAVEN_ENDPOINT)?;
    let ivy = selection_base(selections, IVY_UPSTREAM, IVY_ENDPOINT)?;
    let providers = selections
        .iter()
        .map(|selection| selection.provider_id.as_str())
        .collect::<BTreeSet<_>>();
    if providers != BTreeSet::from(["huaweicloud"]) {
        return Err(AdapterError::InvalidConfiguration(
            "sbt Maven and Ivy selections must be the reviewed Huawei Cloud pair".into(),
        ));
    }
    Ok(SelectedEndpoints { maven, ivy })
}

fn selection_base(
    selections: &[MirrorSelection],
    upstream: &str,
    expected: &str,
) -> Result<String, AdapterError> {
    let selection = selections
        .iter()
        .find(|selection| selection.tool_id == "sbt" && selection.upstream_id == upstream)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("sbt selection is missing {upstream}"))
        })?;
    let mut bases = BTreeSet::new();
    for role in [
        EndpointRole::Index,
        EndpointRole::Metadata,
        EndpointRole::Artifacts,
    ] {
        let matches = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "sbt {upstream} selection must contain exactly one HTTPS {role:?} endpoint"
            )));
        }
        bases.insert(normalized_base(&matches[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("sbt {upstream} endpoint is unsafe"))
        })?);
    }
    if bases != BTreeSet::from([expected.trim_end_matches('/').to_ascii_lowercase()]) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "sbt {upstream} endpoints are not the reviewed repository"
        )));
    }
    Ok(expected.into())
}

fn normalized_base(value: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(value).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(value.trim_end_matches('/').to_ascii_lowercase())
}

fn is_reviewed_base(value: &str, expected: &str) -> bool {
    normalized_base(value.split(',').next().unwrap_or_default().trim()).as_deref()
        == Some(expected.trim_end_matches('/'))
}

fn is_reviewed_ivy(value: &str) -> bool {
    let Some((base, pattern)) = value.split_once(',') else {
        return false;
    };
    is_reviewed_base(base.trim(), IVY_ENDPOINT) && pattern.trim() == IVY_PATTERN
}

fn displayable_url(value: &str) -> String {
    let base = value.split(',').next().unwrap_or_default().trim();
    let Ok(url) = reqwest::Url::parse(base) else {
        return "<preserved>".into();
    };
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
        "<preserved>".into()
    } else {
        base.into()
    }
}

fn verification_arguments(layout: &ConfigLayout) -> Result<Vec<String>, AdapterError> {
    let string = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| AdapterError::Verification("sbt verification path is not UTF-8".into()))
    };
    let repositories = string(&layout.verification_repositories)?;
    let cache = layout.verification_root.join("cache");
    Ok(vec![
        "-batch".into(),
        "-Dsbt.color=false".into(),
        "-Dsbt.supershell=false".into(),
        "-Dsbt.server.autostart=false".into(),
        "-Dsbt.override.build.repos=true".into(),
        format!("-Dsbt.repository.config={repositories}"),
        format!("-Dsbt.boot.directory={}", string(&cache.join("boot"))?),
        format!("-Dsbt.global.base={}", string(&cache.join("global"))?),
        format!("-Dsbt.ivy.home={}", string(&cache.join("ivy"))?),
        format!("-Dsbt.coursier.home={}", string(&cache.join("coursier"))?),
        ";show fullResolvers;update;show scalaVersion;show Universal / packageName".into(),
    ])
}

fn sbt_version(
    runtime: &dyn Runtime,
    configured_version: Option<&str>,
) -> Result<String, AdapterError> {
    if let Some(version) = configured_version.filter(|version| valid_version_token(version)) {
        let output = runtime.run("sbt", &["--script-version".into()])?;
        if output.status.success()
            && parse_sbt_version(&command_output(output, "sbt --script-version")?).is_some()
        {
            return Ok(version.into());
        }
    }
    for argument in ["--numeric-version", "--version"] {
        let output = runtime.run("sbt", &[argument.into()])?;
        if !output.status.success() {
            continue;
        }
        let output = command_output(output, &format!("sbt {argument}"))?;
        if let Some(version) = parse_sbt_version(&output) {
            return Ok(version);
        }
    }
    Err(AdapterError::Unsupported(
        "sbt version output is unrecognized".into(),
    ))
}

fn parse_sbt_version(output: &str) -> Option<String> {
    let lines = output.lines().map(strip_ansi).collect::<Vec<_>>();
    for prefix in ["sbt version in this project:", "sbt version:"] {
        if let Some(version) = lines
            .iter()
            .map(|line| line.trim())
            .find_map(|line| line.strip_prefix(prefix).map(str::trim))
            && valid_version_token(version)
        {
            return Some(version.into());
        }
    }
    lines
        .iter()
        .map(|line| line.trim())
        .find(|line| valid_version_token(line))
        .map(|line| (*line).to_owned())
}

fn strip_ansi(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{001b}' && characters.peek() == Some(&'[') {
            characters.next();
            for code in characters.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else {
            result.push(character);
        }
    }
    result
}

fn valid_version_token(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
        && value.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    sbt_repository_version(version).map(|_| ())
}

fn sbt_repository_version(version: &str) -> Result<&'static str, AdapterError> {
    let mut parts = version.split(['.', '-']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    match (major, minor) {
        (Some(1), Some(_)) => Ok("sbt-1.x"),
        (Some(2), Some(_)) => Ok("sbt-2.x"),
        _ => Err(AdapterError::Unsupported(format!(
            "sbt {version} is outside the reviewed 1.x and 2.x repositories model"
        ))),
    }
}

fn run_command(
    runtime: &dyn Runtime,
    program: &str,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|value| (*value).into())
        .collect::<Vec<_>>();
    let output = runtime.run(program, &arguments)?;
    command_output(output, label)
}

fn run_sbt_in(
    runtime: &dyn Runtime,
    directory: &Path,
    arguments: &[String],
) -> Result<String, AdapterError> {
    let output = runtime.run_in(directory, "sbt", arguments)?;
    command_output(output, "sbt dependency/plugin verification")
}

fn command_output(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{label} failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stdout")))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stderr")))?;
    Ok(format!("{stdout}\n{stderr}").trim().into())
}

fn has_precedence_override(value: &str) -> bool {
    value.contains("sbt.repository.config") || value.contains("sbt.override.build.repos")
}

fn has_boot_credentials(value: &str) -> bool {
    value.contains("sbt.boot.credentials")
}

fn assigned_string(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.split("//").next()?.trim();
        let (left, right) = line.split_once(":=")?;
        left.trim_end()
            .ends_with(key)
            .then(|| quoted_value(right.trim_start()))
            .flatten()
    })
}

fn quoted_value(value: &str) -> Option<String> {
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].into())
}

fn property_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('!') {
            return None;
        }
        let (name, value) = line.split_once('=')?;
        (name.trim() == key && !value.trim().is_empty()).then(|| value.trim().into())
    })
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("sbt-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn policy_source(kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("sbt source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "sbt source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "sbt reported unsafe path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "sbt configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{reason}; configuration restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
