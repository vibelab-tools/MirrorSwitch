use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
};

use roxmltree::{Document, Node};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const MANAGED_ID: &str = "mirrorswitch-central";
const OFFICIAL_CENTRAL: &str = "https://repo.maven.apache.org/maven2";
const MIRROR_BASES: &[&str] = &[
    "https://maven.aliyun.com/repository/public",
    "https://repo.huaweicloud.com/repository/maven",
    "https://repo.nju.edu.cn/maven",
];
const VERIFY_POM_MARKER: &str = "<!-- Managed by MirrorSwitch: Maven verification project v1 -->";
const VERIFY_ARTIFACT: &str = "org.apache.commons:commons-lang3:3.14.0";
const HELP_GOAL: &str = "org.apache.maven.plugins:maven-help-plugin:3.5.2:effective-settings";
const DEPENDENCY_GOAL: &str = "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:get";

#[derive(Clone, Copy, Debug, Default)]
pub struct MavenAdapter;

impl Adapter for MavenAdapter {
    fn key(&self) -> &'static str {
        "maven"
    }

    fn tool_id(&self) -> &'static str {
        "maven"
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
        require_linux(context)?;
        if !runtime.command_exists("mvn") {
            return Ok(None);
        }
        let output = run_maven(runtime, None, ["--version"])?;
        let version = maven_version(&output)?;
        reviewed_version(&version)?;
        let maven_home = maven_home(&output)?;
        validate_path(&maven_home)?;
        let mut evidence = vec![format!("Maven home is {}", maven_home.display())];
        evidence.extend(
            output
                .lines()
                .map(strip_ansi)
                .map(str::trim)
                .filter(|line| line.starts_with("Java version:") || line.starts_with("OS name:"))
                .map(str::to_owned),
        );
        let layout = config_layout(runtime, &maven_home)?;
        evidence.push(format!(
            "user settings {}",
            if runtime.read(&layout.user_settings)?.is_some() {
                "found"
            } else {
                "not found"
            }
        ));
        evidence.push(format!(
            "global settings {}",
            if runtime.read(&layout.global_settings)?.is_some() {
                "found"
            } else {
                "not found"
            }
        ));
        evidence.push(format!(
            "project POM {}",
            if layout.project_pom.is_some() {
                "found"
            } else {
                "not found"
            }
        ));
        Ok(Some(DetectedTool {
            tool_id: "maven".into(),
            executable: Some(PathBuf::from("mvn")),
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
        require_linux(context)?;
        require_scope(scope)?;
        reviewed_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Maven version is missing".into())
        })?)?;
        let version_output = run_maven(runtime, None, ["--version"])?;
        let home = maven_home(&version_output)?;
        let layout = config_layout(runtime, &home)?;
        let mut paths = vec![
            (layout.user_settings.clone(), DocumentKind::UserSettings),
            (layout.global_settings.clone(), DocumentKind::GlobalSettings),
            (
                layout.verification_pom.clone(),
                DocumentKind::VerificationPom,
            ),
        ];
        if let Some(path) = layout.project_pom.clone() {
            paths.push((path, DocumentKind::ProjectPom));
        }
        if let Some(path) = layout.maven_config.clone() {
            paths.push((path, DocumentKind::MavenConfig));
        }

        let mut sources = environment_sources(runtime);
        let mut files = Vec::new();
        let mut documents = Vec::new();
        for (path, kind) in paths {
            validate_path(&path)?;
            let observed = runtime.read(&path)?;
            let exists = observed.is_some();
            let contents = observed.unwrap_or_default();
            if exists {
                files.push(path.clone());
                let text = utf8(&path, &contents)?;
                match kind {
                    DocumentKind::UserSettings => {
                        sources.extend(settings_sources(text, &path, SettingsScope::User)?);
                    }
                    DocumentKind::GlobalSettings => {
                        sources.extend(settings_sources(text, &path, SettingsScope::Global)?);
                    }
                    DocumentKind::ProjectPom => {
                        sources.extend(pom_sources(text, &path)?);
                    }
                    DocumentKind::MavenConfig => {
                        if has_settings_override(text) {
                            sources.push(policy_source("settings-override", &path));
                        }
                    }
                    DocumentKind::VerificationPom => {
                        if text != render_verification_pom() {
                            sources.push(policy_source("verification-project-conflict", &path));
                        }
                    }
                }
            }
            documents.push(ConfigurationDocument {
                path,
                format: match kind {
                    DocumentKind::UserSettings => "maven-selected-user-settings",
                    DocumentKind::GlobalSettings => "maven-global-settings-read-only",
                    DocumentKind::ProjectPom => "maven-project-pom-read-only",
                    DocumentKind::MavenConfig => "maven-project-config-read-only",
                    DocumentKind::VerificationPom => "maven-verification-project",
                }
                .into(),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "maven".into(),
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
        require_linux(context)?;
        require_current(current)?;
        Ok(SelectionRequest {
            tool_id: "maven".into(),
            adapter_key: "maven".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![MAVEN_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Index, EndpointRole::Artifacts],
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let settings = current
            .documents
            .iter()
            .find(|document| document.format == "maven-selected-user-settings")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected Maven settings are missing".into())
            })?;
        let settings_text = utf8(&settings.path, &settings.contents)?;
        let settings_contents = rewrite_settings(settings_text, endpoint)?.into_bytes();
        let verification = current
            .documents
            .iter()
            .find(|document| document.format == "maven-verification-project")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Maven verification project document is missing".into(),
                )
            })?;
        let mut changes = Vec::new();
        if settings_contents != settings.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &settings.path),
                old_contents: current
                    .files
                    .contains(&settings.path)
                    .then(|| settings.contents.clone()),
                old_mode: None,
                new_contents: settings_contents,
                new_mode: None,
                summary: "add or retarget one credential-free mirrorOf=central entry in user settings while preserving servers, proxies, profiles, plugin repositories, private repositories, comments and ordering".into(),
            });
        }
        let verification_contents = render_verification_pom().into_bytes();
        if verification_contents != verification.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &verification.path),
                old_contents: current
                    .files
                    .contains(&verification.path)
                    .then(|| verification.contents.clone()),
                old_mode: None,
                new_contents: verification_contents,
                new_mode: None,
                summary: "create an isolated user-owned Maven project used only for effective-settings, plugin and dependency resolution checks".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "maven".into(),
            tool_id: "maven".into(),
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
            let version_output = run_maven(runtime, None, ["--version"])?;
            let home = maven_home(&version_output)?;
            let layout = config_layout(runtime, &home)?;
            let settings_target = rooted(&context.root, &layout.user_settings);
            let verification_target = rooted(&context.root, &layout.verification_pom);
            if !receipt.changed_targets.contains(&settings_target)
                && !receipt.changed_targets.contains(&verification_target)
            {
                return Err(AdapterError::Verification(
                    "Maven transaction receipt does not contain a known target".into(),
                ));
            }
            let settings = runtime.read(&layout.user_settings)?.ok_or_else(|| {
                AdapterError::Verification("Maven user settings disappeared".into())
            })?;
            let central = effective_central_mirror(utf8(&layout.user_settings, &settings)?)?;
            if !is_maven_mirror(&central.url) {
                return Err(AdapterError::Verification(
                    "Maven user settings have no reviewed Central mirror".into(),
                ));
            }
            let pom = runtime.read(&layout.verification_pom)?.ok_or_else(|| {
                AdapterError::Verification("Maven verification project disappeared".into())
            })?;
            if utf8(&layout.verification_pom, &pom)? != render_verification_pom() {
                return Err(AdapterError::Verification(
                    "Maven verification project is not canonical".into(),
                ));
            }
            let verification_dir = layout.verification_pom.parent().ok_or_else(|| {
                AdapterError::Verification("Maven verification project has no directory".into())
            })?;
            let repository = verification_dir
                .join("repository")
                .join(endpoint_cache_key(&central.url)?);
            let settings_arg = layout.user_settings.to_str().ok_or_else(|| {
                AdapterError::Verification("Maven settings path is not valid UTF-8".into())
            })?;
            let repository_arg = repository.to_str().ok_or_else(|| {
                AdapterError::Verification("Maven repository path is not valid UTF-8".into())
            })?;
            let effective = run_maven(
                runtime,
                Some(verification_dir),
                [
                    "--batch-mode",
                    "--no-transfer-progress",
                    "--strict-checksums",
                    "--settings",
                    settings_arg,
                    &format!("-Dmaven.repo.local={repository_arg}"),
                    HELP_GOAL,
                    "-DshowPasswords=false",
                ],
            )?;
            if !effective.contains(&format!("<id>{}</id>", central.id))
                || !effective.contains(&format!("<url>{}</url>", central.url))
                || !effective.contains("<mirrorOf>central</mirrorOf>")
            {
                return Err(AdapterError::Verification(
                    "Maven effective settings did not select the expected Central mirror".into(),
                ));
            }
            run_maven(
                runtime,
                Some(verification_dir),
                [
                    "--batch-mode",
                    "--no-transfer-progress",
                    "--strict-checksums",
                    "--update-snapshots",
                    "--settings",
                    settings_arg,
                    &format!("-Dmaven.repo.local={repository_arg}"),
                    DEPENDENCY_GOAL,
                    &format!("-Dartifact={VERIFY_ARTIFACT}"),
                    "-Dtransitive=false",
                ],
            )?;
            let artifact_dir = repository.join("org/apache/commons/commons-lang3/3.14.0");
            let artifact = runtime
                .read(&artifact_dir.join("commons-lang3-3.14.0.jar"))?
                .filter(|contents| !contents.is_empty())
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "Maven did not resolve the verification artifact".into(),
                    )
                })?;
            let tracking = runtime
                .read(&artifact_dir.join("_remote.repositories"))?
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "Maven did not record the verification repository identity".into(),
                    )
                })?;
            let tracking = utf8(&artifact_dir.join("_remote.repositories"), &tracking)?;
            if !tracking.contains(&format!(">{}=", central.id)) {
                return Err(AdapterError::Verification(
                    "Maven artifact tracking did not record the effective Central mirror".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "effective settings, plugin resolution and {}-byte dependency resolution used {}",
                    artifact.len(),
                    central.url
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
                "restored {} Maven configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DocumentKind {
    UserSettings,
    GlobalSettings,
    ProjectPom,
    MavenConfig,
    VerificationPom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingsScope {
    User,
    Global,
}

#[derive(Clone, Debug)]
struct ConfigLayout {
    user_settings: PathBuf,
    global_settings: PathBuf,
    project_pom: Option<PathBuf>,
    maven_config: Option<PathBuf>,
    verification_pom: PathBuf,
}

#[derive(Clone, Debug)]
struct MirrorRecord {
    url_range: Range<usize>,
    id: String,
    url: String,
    mirror_of: String,
    mirror_of_layouts: Option<String>,
    blocked: bool,
}

#[derive(Clone, Debug)]
struct CentralMirror {
    id: String,
    url: String,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Maven adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Maven adapter supports user settings only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "maven" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Maven operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(runtime: &dyn Runtime, maven_home: &Path) -> Result<ConfigLayout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("Maven user settings require a home directory".into())
    })?;
    validate_path(&home)?;
    validate_path(maven_home)?;
    let project = runtime.project_dir();
    if let Some(project) = &project {
        validate_path(project)?;
    }
    let project_pom = if let Some(project) = &project {
        let path = project.join("pom.xml");
        runtime.read(&path)?.is_some().then_some(path)
    } else {
        None
    };
    let maven_config = if let Some(project) = &project {
        let path = project.join(".mvn").join("maven.config");
        runtime.read(&path)?.is_some().then_some(path)
    } else {
        None
    };
    Ok(ConfigLayout {
        user_settings: home.join(".m2").join("settings.xml"),
        global_settings: maven_home.join("conf").join("settings.xml"),
        project_pom,
        maven_config,
        verification_pom: home
            .join(".m2")
            .join("mirrorswitch")
            .join("verification")
            .join("pom.xml"),
    })
}

fn run_maven<'a>(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Result<String, AdapterError> {
    let arguments = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
    let output = if let Some(directory) = directory {
        runtime.run_in(directory, "mvn", &arguments)?
    } else {
        runtime.run("mvn", &arguments)?
    };
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "Maven command failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("Maven returned non-UTF-8 stdout".into()))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| AdapterError::Runtime("Maven returned non-UTF-8 stderr".into()))?;
    Ok(format!("{stdout}\n{stderr}").trim().to_owned())
}

fn maven_version(output: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .map(strip_ansi)
        .map(str::trim)
        .find(|line| line.starts_with("Apache Maven "))
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("Maven version output is unrecognized".into()))
}

fn maven_home(output: &str) -> Result<PathBuf, AdapterError> {
    output
        .lines()
        .map(strip_ansi)
        .map(str::trim)
        .find_map(|line| line.strip_prefix("Maven home: "))
        .map(PathBuf::from)
        .ok_or_else(|| AdapterError::Unsupported("Maven home is missing from --version".into()))
}

fn strip_ansi(value: &str) -> &str {
    let value = if value.starts_with('\u{001b}') {
        value.find('m').map_or(value, |index| &value[index + 1..])
    } else {
        value
    };
    value
        .find('\u{001b}')
        .map_or(value, |index| &value[..index])
}

fn reviewed_version(value: &str) -> Result<(), AdapterError> {
    let version = value
        .split_whitespace()
        .find(|token| token.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .ok_or_else(|| AdapterError::Unsupported(format!("unrecognized Maven version {value}")))?;
    let mut parts = version.split(['.', '-']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    let patch = parts.next().and_then(|part| part.parse::<u64>().ok());
    if major != Some(3) || (minor, patch) < (Some(6), Some(3)) {
        return Err(AdapterError::Unsupported(format!(
            "Maven {version} is outside the reviewed 3.6.3 through 3.x settings model"
        )));
    }
    Ok(())
}

fn settings_sources(
    text: &str,
    path: &Path,
    scope: SettingsScope,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    if text.trim().is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven settings {} are empty",
            path.display()
        )));
    }
    let document = parse_settings(text, path)?;
    let root = document.root_element();
    let server_ids = server_ids(root)?;
    let mirrors = mirror_records(root)?;
    let mut sources = Vec::new();
    let mut exact_central = 0;
    for mirror in mirrors {
        if mirror.mirror_of == "central" {
            exact_central += 1;
            let kind = if scope == SettingsScope::Global {
                "global-central-mirror"
            } else if server_ids.contains(&mirror.id) {
                "central-mirror-credentials"
            } else if mirror.blocked
                || !mirror
                    .mirror_of_layouts
                    .as_deref()
                    .is_none_or(layout_matches_default)
            {
                "central-mirror-policy-conflict"
            } else if mirror.id == MANAGED_ID
                || is_maven_mirror(&mirror.url)
                || is_official_central(&mirror.url)
            {
                "central-mirror-adoptable"
            } else {
                "central-mirror-conflict"
            };
            sources.push(ConfiguredSource {
                upstream_id: (kind == "central-mirror-adoptable").then(|| MAVEN_UPSTREAM.into()),
                url: if is_maven_mirror(&mirror.url) || is_official_central(&mirror.url) {
                    format!("{}/", mirror.url.trim_end_matches('/'))
                } else {
                    "<preserved>".into()
                },
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec![kind.into()]),
                    ("config_path".into(), vec![path.display().to_string()]),
                ]),
            });
        } else if mirror.id == MANAGED_ID {
            sources.push(policy_source("managed-id-conflict", path));
        } else {
            sources.push(policy_source("preserved-mirror", path));
        }
    }
    if exact_central > 1 {
        sources.push(policy_source("duplicate-central-mirror", path));
    }
    if direct_child_text(root, "offline")?
        .is_some_and(|(value, _)| value.eq_ignore_ascii_case("true"))
    {
        sources.push(policy_source("offline", path));
    }
    sources.extend(repository_identity_sources(root, path)?);
    Ok(sources)
}

fn pom_sources(text: &str, path: &Path) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let document = Document::parse(text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Maven project POM {} is invalid XML: {error}",
            path.display()
        ))
    })?;
    if !document.root_element().has_tag_name("project") {
        return Err(AdapterError::InvalidConfiguration(
            "Maven project POM root is not project".into(),
        ));
    }
    let mut sources = repository_identity_sources(document.root_element(), path)?;
    if document
        .descendants()
        .any(|node| node.is_element() && node.has_tag_name("repositories"))
    {
        sources.push(policy_source("project-repositories", path));
    }
    if document
        .descendants()
        .any(|node| node.is_element() && node.has_tag_name("pluginRepositories"))
    {
        sources.push(policy_source("project-plugin-repositories", path));
    }
    Ok(sources)
}

fn repository_identity_sources(
    root: Node<'_, '_>,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    for repository in root.descendants().filter(|node| {
        node.is_element()
            && ((node.has_tag_name("repository")
                && node
                    .parent_element()
                    .is_some_and(|parent| parent.has_tag_name("repositories")))
                || (node.has_tag_name("pluginRepository")
                    && node
                        .parent_element()
                        .is_some_and(|parent| parent.has_tag_name("pluginRepositories"))))
    }) {
        let id = direct_child_text(repository, "id")?;
        let url = direct_child_text(repository, "url")?;
        if id.as_ref().is_some_and(|(id, _)| id == "central")
            && url
                .as_ref()
                .is_some_and(|(url, _)| !is_official_central(url))
        {
            sources.push(policy_source("central-id-conflict", path));
        }
    }
    Ok(sources)
}

fn environment_sources(runtime: &dyn Runtime) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if runtime
        .environment_variable("MAVEN_ARGS")
        .is_some_and(|value| !value.trim().is_empty())
    {
        sources.push(policy_source("maven-args", Path::new(":env:")));
    }
    if runtime
        .environment_variable("MAVEN_OPTS")
        .is_some_and(|value| has_settings_override(&value))
    {
        sources.push(policy_source("settings-override", Path::new(":env:")));
    }
    sources
}

fn has_settings_override(value: &str) -> bool {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    tokens.iter().any(|token| {
        matches!(*token, "-s" | "--settings" | "-gs" | "--global-settings")
            || token.starts_with("--settings=")
            || token.starts_with("--global-settings=")
            || token.starts_with("-Dmaven.user.conf=")
            || token.starts_with("-Dmaven.user.settings=")
            || token.starts_with("-Dmaven.installation.settings=")
    })
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "global-central-mirror" => {
                return Err(AdapterError::Unsupported(
                    "global Maven settings already define an exact Central mirror".into(),
                ));
            }
            "central-mirror-credentials" => {
                return Err(AdapterError::Unsupported(
                    "the exact Central mirror has a matching server entry and cannot be retargeted"
                        .into(),
                ));
            }
            "central-mirror-conflict" | "central-id-conflict" => {
                return Err(AdapterError::Unsupported(
                    "repository id central is mapped to a private or unreviewed endpoint".into(),
                ));
            }
            "central-mirror-policy-conflict" => {
                return Err(AdapterError::Unsupported(
                    "the exact Central mirror is blocked or excludes Maven's default layout".into(),
                ));
            }
            "managed-id-conflict" => {
                return Err(AdapterError::Unsupported(
                    "the MirrorSwitch Maven mirror id is already used for another repository"
                        .into(),
                ));
            }
            "duplicate-central-mirror" => {
                return Err(AdapterError::Unsupported(
                    "Maven settings define more than one exact Central mirror".into(),
                ));
            }
            "offline" => {
                return Err(AdapterError::Unsupported(
                    "Maven offline mode prevents post-apply repository verification".into(),
                ));
            }
            "maven-args" => {
                return Err(AdapterError::Unsupported(
                    "MAVEN_ARGS can inject goals or settings ahead of MirrorSwitch verification"
                        .into(),
                ));
            }
            "settings-override" => {
                return Err(AdapterError::Unsupported(
                    "Maven settings precedence is overridden by environment or project options"
                        .into(),
                ));
            }
            "verification-project-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Maven verification project target is not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_settings(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    if text.is_empty() {
        return Ok(render_new_settings(endpoint));
    }
    if text.trim().is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "Maven user settings are empty".into(),
        ));
    }
    let document = parse_settings(text, Path::new("settings.xml"))?;
    let root = document.root_element();
    let servers = server_ids(root)?;
    let mirrors = mirror_records(root)?;
    let exact = mirrors
        .iter()
        .filter(|mirror| mirror.mirror_of == "central")
        .collect::<Vec<_>>();
    if exact.len() > 1 {
        return Err(AdapterError::Unsupported(
            "Maven settings define more than one exact Central mirror".into(),
        ));
    }
    if let Some(mirror) = exact.first() {
        if servers.contains(&mirror.id) {
            return Err(AdapterError::Unsupported(
                "the exact Central mirror has a matching server entry".into(),
            ));
        }
        if mirror.id != MANAGED_ID
            && !is_maven_mirror(&mirror.url)
            && !is_official_central(&mirror.url)
        {
            return Err(AdapterError::Unsupported(
                "the exact Central mirror is private or unreviewed".into(),
            ));
        }
        if mirror.blocked
            || !mirror
                .mirror_of_layouts
                .as_deref()
                .is_none_or(layout_matches_default)
        {
            return Err(AdapterError::Unsupported(
                "the exact Central mirror is blocked or excludes Maven's default layout".into(),
            ));
        }
        return Ok(replace_range(
            text,
            mirror.url_range.clone(),
            &format!("<url>{}/</url>", endpoint.trim_end_matches('/')),
        ));
    }
    if mirrors.iter().any(|mirror| mirror.id == MANAGED_ID) {
        return Err(AdapterError::Unsupported(
            "the MirrorSwitch Maven mirror id is already used".into(),
        ));
    }
    let mirror_xml = render_mirror(endpoint, "    ", newline(text));
    if let Some(mirrors_node) = direct_children(root, "mirrors")?.into_iter().next() {
        insert_child(text, mirrors_node.range(), "mirrors", &mirror_xml)
    } else {
        let block = format!(
            "  <mirrors>{nl}{mirror}{nl}  </mirrors>",
            nl = newline(text),
            mirror = mirror_xml
        );
        insert_child(text, root.range(), "settings", &block)
    }
}

fn effective_central_mirror(text: &str) -> Result<CentralMirror, AdapterError> {
    let document = parse_settings(text, Path::new("settings.xml"))?;
    let mirrors = mirror_records(document.root_element())?;
    let exact = mirrors
        .into_iter()
        .filter(|mirror| mirror.mirror_of == "central")
        .collect::<Vec<_>>();
    if exact.len() != 1 {
        return Err(AdapterError::Verification(
            "Maven user settings do not contain exactly one Central mirror".into(),
        ));
    }
    if exact[0].blocked
        || !exact[0]
            .mirror_of_layouts
            .as_deref()
            .is_none_or(layout_matches_default)
    {
        return Err(AdapterError::Verification(
            "Maven Central mirror is blocked or excludes the default layout".into(),
        ));
    }
    Ok(CentralMirror {
        id: exact[0].id.clone(),
        url: format!("{}/", exact[0].url.trim_end_matches('/')),
    })
}

fn parse_settings<'a>(text: &'a str, path: &Path) -> Result<Document<'a>, AdapterError> {
    let document = Document::parse(text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Maven settings {} are invalid XML: {error}",
            path.display()
        ))
    })?;
    if !document.root_element().has_tag_name("settings") {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven settings {} root is not settings",
            path.display()
        )));
    }
    let root_range = document.root_element().range();
    let root_opening = &text[root_range.start..root_range.end];
    let root_name = root_opening
        .strip_prefix('<')
        .and_then(|value| value.split([' ', '\t', '\r', '\n', '/', '>']).next())
        .unwrap_or_default();
    if root_name.contains(':') {
        return Err(AdapterError::Unsupported(
            "prefixed Maven settings XML is outside the reviewed formatting-preserving model"
                .into(),
        ));
    }
    let mirror_containers = direct_children(document.root_element(), "mirrors")?;
    if let Some(mirrors) = mirror_containers.first() {
        let range = mirrors.range();
        let opening = &text[range.start..range.end];
        let name = opening
            .strip_prefix('<')
            .and_then(|value| value.split([' ', '\t', '\r', '\n', '/', '>']).next())
            .unwrap_or_default();
        if name.contains(':') {
            return Err(AdapterError::Unsupported(
                "prefixed Maven mirrors XML is outside the reviewed formatting-preserving model"
                    .into(),
            ));
        }
    }
    if mirror_containers.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Maven settings contain more than one top-level mirrors element".into(),
        ));
    }
    Ok(document)
}

fn mirror_records(root: Node<'_, '_>) -> Result<Vec<MirrorRecord>, AdapterError> {
    let Some(mirrors) = direct_children(root, "mirrors")?.into_iter().next() else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for mirror in direct_children(mirrors, "mirror")? {
        let (id, _) = required_child_text(mirror, "id")?;
        let (url, url_range) = required_child_text(mirror, "url")?;
        let (mirror_of, _) = required_child_text(mirror, "mirrorOf")?;
        let mirror_of_layouts =
            direct_child_text(mirror, "mirrorOfLayouts")?.map(|(value, _)| value);
        let blocked = direct_child_text(mirror, "blocked")?
            .is_some_and(|(value, _)| value.eq_ignore_ascii_case("true"));
        records.push(MirrorRecord {
            url_range,
            id,
            url,
            mirror_of,
            mirror_of_layouts,
            blocked,
        });
    }
    Ok(records)
}

fn server_ids(root: Node<'_, '_>) -> Result<BTreeSet<String>, AdapterError> {
    let mut ids = BTreeSet::new();
    let Some(servers) = direct_children(root, "servers")?.into_iter().next() else {
        return Ok(ids);
    };
    for server in direct_children(servers, "server")? {
        if let Some((id, _)) = direct_child_text(server, "id")? {
            ids.insert(id);
        }
    }
    Ok(ids)
}

fn layout_matches_default(value: &str) -> bool {
    let tokens = value.split(',').collect::<Vec<_>>();
    if tokens.iter().any(|token| token.trim() != *token) {
        return false;
    }
    if tokens.contains(&"!default") {
        return false;
    }
    tokens.iter().any(|token| matches!(*token, "default" | "*"))
}

fn direct_children<'a, 'input>(
    parent: Node<'a, 'input>,
    name: &str,
) -> Result<Vec<Node<'a, 'input>>, AdapterError> {
    let children = parent
        .children()
        .filter(|child| child.is_element() && child.has_tag_name(name))
        .collect::<Vec<_>>();
    if name != "mirror" && name != "server" && children.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven XML defines {name} more than once in one parent"
        )));
    }
    Ok(children)
}

fn required_child_text(
    parent: Node<'_, '_>,
    name: &str,
) -> Result<(String, Range<usize>), AdapterError> {
    direct_child_text(parent, name)?.ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Maven XML element is missing {name}"))
    })
}

fn direct_child_text(
    parent: Node<'_, '_>,
    name: &str,
) -> Result<Option<(String, Range<usize>)>, AdapterError> {
    let children = parent
        .children()
        .filter(|child| child.is_element() && child.has_tag_name(name))
        .collect::<Vec<_>>();
    if children.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven XML defines {name} more than once"
        )));
    }
    let Some(child) = children.first() else {
        return Ok(None);
    };
    if child.children().any(|node| node.is_element()) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven XML {name} contains nested elements"
        )));
    }
    let value = child.text().unwrap_or_default().trim().to_owned();
    if value.is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven XML {name} is empty"
        )));
    }
    Ok(Some((value, child.range())))
}

fn insert_child(
    text: &str,
    parent: Range<usize>,
    parent_name: &str,
    child: &str,
) -> Result<String, AdapterError> {
    let slice = &text[parent.clone()];
    let nl = newline(text);
    let trimmed = slice.trim_end();
    if trimmed.ends_with("/>") {
        let relative = slice.rfind("/>").ok_or_else(|| {
            AdapterError::InvalidConfiguration("Maven XML self-closing tag is malformed".into())
        })?;
        let position = parent.start + relative;
        let indent = line_indent(text, parent.start);
        return Ok(format!(
            "{}>{nl}{child}{nl}{indent}</{parent_name}>{}",
            &text[..position],
            &text[position + 2..]
        ));
    }
    let relative_close = slice.rfind("</").ok_or_else(|| {
        AdapterError::InvalidConfiguration("Maven XML parent has no closing tag".into())
    })?;
    let close = parent.start + relative_close;
    let line_start = text[..close].rfind('\n').map_or(close, |index| index + 1);
    let insertion = if text[line_start..close].trim().is_empty() {
        line_start
    } else {
        close
    };
    let indent = line_indent(text, parent.start);
    let prefix = if insertion == close { nl } else { "" };
    Ok(format!(
        "{}{prefix}{child}{nl}{indent}{}",
        &text[..insertion],
        &text[insertion..]
    ))
}

fn replace_range(text: &str, range: Range<usize>, replacement: &str) -> String {
    format!(
        "{}{}{}",
        &text[..range.start],
        replacement,
        &text[range.end..]
    )
}

fn line_indent(text: &str, position: usize) -> &str {
    let start = text[..position].rfind('\n').map_or(0, |index| index + 1);
    let prefix = &text[start..position];
    if prefix.trim().is_empty() { prefix } else { "" }
}

fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

fn render_new_settings(endpoint: &str) -> String {
    let mirror = render_mirror(endpoint, "    ", "\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 https://maven.apache.org/xsd/settings-1.2.0.xsd">
  <mirrors>
{mirror}
  </mirrors>
</settings>
"#
    )
}

fn render_mirror(endpoint: &str, indent: &str, nl: &str) -> String {
    let field = format!("{indent}  ");
    format!(
        "{indent}<mirror>{nl}{field}<id>{MANAGED_ID}</id>{nl}{field}<name>MirrorSwitch Maven Central</name>{nl}{field}<url>{}/</url>{nl}{field}<mirrorOf>central</mirrorOf>{nl}{indent}</mirror>",
        endpoint.trim_end_matches('/')
    )
}

fn render_verification_pom() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
{VERIFY_POM_MARKER}
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.mirrorswitch</groupId>
  <artifactId>repository-verification</artifactId>
  <version>1</version>
</project>
"#
    )
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "maven"
        || selections[0].upstream_id != MAVEN_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Maven plan requires exactly one Maven Central selection".into(),
        ));
    }
    let index = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Maven selection has no metadata endpoint".into())
        })?;
    let artifact = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Maven selection has no artifact endpoint".into())
        })?;
    let index_base = normalized_base(&index.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Maven metadata endpoint is unsafe".into())
    })?;
    let artifact_base = normalized_base(&artifact.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Maven artifact endpoint is unsafe".into())
    })?;
    if index_base != artifact_base || !MIRROR_BASES.contains(&index_base.as_str()) {
        return Err(AdapterError::InvalidConfiguration(
            "Maven metadata and artifact endpoints are not one reviewed repository".into(),
        ));
    }
    Ok(index.url.trim_end_matches('/'))
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

fn is_maven_mirror(value: &str) -> bool {
    normalized_base(value).is_some_and(|base| MIRROR_BASES.contains(&base.as_str()))
}

fn is_official_central(value: &str) -> bool {
    normalized_base(value).as_deref() == Some(OFFICIAL_CENTRAL)
}

fn endpoint_cache_key(value: &str) -> Result<&'static str, AdapterError> {
    match normalized_base(value).as_deref() {
        Some("https://maven.aliyun.com/repository/public") => Ok("aliyun"),
        Some("https://repo.huaweicloud.com/repository/maven") => Ok("huaweicloud"),
        Some("https://repo.nju.edu.cn/maven") => Ok("nju"),
        _ => Err(AdapterError::Verification(
            "Maven Central mirror has no isolated verification cache".into(),
        )),
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
        AdapterError::InvalidConfiguration(format!("Maven source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Maven source has ambiguous {key} metadata"
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
            "Maven reported unsafe path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Maven configuration {} is not UTF-8",
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
