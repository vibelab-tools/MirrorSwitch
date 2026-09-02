use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
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

const NPM_UPSTREAM: &str = "npm--language-registry";
const HUAWEI_REGISTRY: &str = "https://repo.huaweicloud.com/repository/npm";
const OFFICIAL_REGISTRIES: &[&str] =
    &["https://registry.yarnpkg.com", "https://registry.npmjs.org"];
const NPM_AUTH_KEYS: &[&str] = &["_auth", "_authtoken", "username", "_password"];

#[derive(Clone, Copy, Debug, Default)]
pub struct YarnAdapter;

impl Adapter for YarnAdapter {
    fn key(&self) -> &'static str {
        "yarn"
    }

    fn tool_id(&self) -> &'static str {
        "yarn"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::User, ConfigurationScope::Project]
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
        if !runtime.command_exists("yarn") {
            return Ok(None);
        }
        let project = runtime.project_dir();
        let version = run_yarn(
            runtime,
            project.as_deref(),
            &["--version"],
            "yarn --version",
        )?;
        let generation = generation(&version)?;
        let setting = registry_setting(generation);
        let registry = run_yarn(
            runtime,
            project.as_deref(),
            &["config", "get", setting],
            "yarn config get registry",
        )?;
        let registry_class = if is_official_registry(&registry) {
            "official Yarn/npm registry"
        } else if is_known_mirror(&registry) {
            "reviewed mirror"
        } else {
            "custom or private registry"
        };
        Ok(Some(DetectedTool {
            tool_id: "yarn".into(),
            executable: Some(PathBuf::from("yarn")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Yarn {version} ({})", generation.name()),
                format!("effective default registry is a {registry_class}"),
            ],
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
        let generation = generation(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Yarn version is missing".into())
        })?)?;
        let project = runtime.project_dir();
        let project_root = project_root(runtime, project.as_deref())?;
        let paths = config_paths(
            runtime,
            generation,
            project.as_deref(),
            project_root.as_deref(),
        )?;
        let selected = paths
            .iter()
            .find(|item| item.scope == origin_scope(scope))
            .map(|item| item.path.clone());
        let effective = run_yarn(
            runtime,
            project.as_deref(),
            &["config", "get", registry_setting(generation)],
            "yarn config get registry",
        )?;
        let mut sources = vec![configured_source(
            &effective,
            "effective-registry",
            OriginScope::Effective,
            Path::new(":effective:"),
        )];
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut seen = BTreeSet::new();
        for item in paths {
            if !seen.insert(item.path.clone()) {
                continue;
            }
            let observed = runtime.read(&item.path)?;
            let exists = observed.is_some();
            let contents = observed.unwrap_or_default();
            if exists {
                files.push(item.path.clone());
            }
            let text = utf8(&item.path, &contents)?;
            sources.extend(match item.kind {
                ConfigKind::Classic => classic_sources(text, item.scope, &item.path)?,
                ConfigKind::Berry => berry_sources(text, item.scope, &item.path)?,
                ConfigKind::Npm => npmrc_sources(text, item.scope, &item.path)?,
            });
            documents.push(ConfigurationDocument {
                path: item.path.clone(),
                format: document_format(
                    generation,
                    item.kind,
                    selected.as_ref() == Some(&item.path),
                ),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "yarn".into(),
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
        Ok(SelectionRequest {
            tool_id: "yarn".into(),
            adapter_key: "yarn".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![NPM_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Index],
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
        let endpoint = selected_endpoint(selections)?;
        let (generation, document) = selected_document(current)?;
        if generation == YarnGeneration::Berry
            && !current
                .documents
                .iter()
                .any(|document| document.format.starts_with("yarn-berry-project"))
        {
            return Err(AdapterError::Unsupported(
                "Yarn Berry user changes require a project context for effective-config and registry verification"
                    .into(),
            ));
        }
        validate_precedence(current, generation)?;
        require_transport_policy(current, endpoint)?;
        let text = utf8(&document.path, &document.contents)?;
        let mut new_contents = match generation {
            YarnGeneration::Classic => rewrite_classic(text, endpoint)?,
            YarnGeneration::Berry => rewrite_berry(text, endpoint)?,
        }
        .into_bytes();
        if document.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            new_contents.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "set only {} in explicit {} scope using {} syntax; preserve scopes, authentication, plugins, and unrelated project settings",
                    registry_setting(generation),
                    scope_name(current.scope),
                    generation.name()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "yarn".into(),
            tool_id: "yarn".into(),
            scope: current.scope,
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
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let project = runtime.project_dir();
            let version = run_yarn(
                runtime,
                project.as_deref(),
                &["--version"],
                "yarn --version",
            )?;
            let generation = generation(&version)?;
            let registry = run_yarn(
                runtime,
                project.as_deref(),
                &["config", "get", registry_setting(generation)],
                "yarn config get registry",
            )?;
            if !is_known_mirror(&registry) {
                return Err(AdapterError::Verification(
                    "Yarn effective registry is not the reviewed mirror".into(),
                ));
            }
            let metadata = match generation {
                YarnGeneration::Classic => run_yarn(
                    runtime,
                    project.as_deref(),
                    &["info", "is-number@7.0.0", "--json"],
                    "yarn info package metadata",
                )?,
                YarnGeneration::Berry => {
                    if project.is_none() {
                        return Err(AdapterError::Verification(
                            "Yarn Berry metadata verification requires a project context".into(),
                        ));
                    }
                    run_yarn(
                        runtime,
                        project.as_deref(),
                        &[
                            "npm",
                            "info",
                            "is-number@7.0.0",
                            "--fields",
                            "name,version,dist",
                            "--json",
                        ],
                        "yarn npm info package metadata",
                    )?
                }
            };
            let package = package_metadata(generation, &metadata)?;
            validate_package_metadata(&registry, package)?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} effective config and real package metadata validated the registry",
                    generation.name()
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
                "restored {} Yarn configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YarnGeneration {
    Classic,
    Berry,
}

impl YarnGeneration {
    fn name(self) -> &'static str {
        match self {
            Self::Classic => "Classic",
            Self::Berry => "Berry",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginScope {
    System,
    User,
    Project,
    Effective,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigKind {
    Classic,
    Berry,
    Npm,
}

#[derive(Clone, Debug)]
struct ConfigPath {
    scope: OriginScope,
    kind: ConfigKind,
    path: PathBuf,
}

#[derive(Clone, Debug)]
struct ScalarEntry {
    key: String,
    value: String,
    value_range: Range<usize>,
    quote: Option<char>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Yarn on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Yarn adapter requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if !matches!(
        scope,
        ConfigurationScope::User | ConfigurationScope::Project
    ) {
        return Err(AdapterError::Unsupported(
            "Yarn supports user and explicit project scopes".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "yarn" {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn generation(version: &str) -> Result<YarnGeneration, AdapterError> {
    let major = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| AdapterError::Unsupported(format!("unrecognized Yarn version {version}")))?;
    match major {
        1 => Ok(YarnGeneration::Classic),
        2.. => Ok(YarnGeneration::Berry),
        _ => Err(AdapterError::Unsupported(format!(
            "Yarn {version} predates the Classic configuration contract"
        ))),
    }
}

fn registry_setting(generation: YarnGeneration) -> &'static str {
    match generation {
        YarnGeneration::Classic => "registry",
        YarnGeneration::Berry => "npmRegistryServer",
    }
}

fn run_yarn(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = match directory {
        Some(directory) => runtime.run_in(directory, "yarn", &arguments)?,
        None => runtime.run("yarn", &arguments)?,
    };
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 output")))
}

fn project_root(
    runtime: &dyn Runtime,
    project: Option<&Path>,
) -> Result<Option<PathBuf>, AdapterError> {
    let Some(project) = project else {
        return Ok(None);
    };
    validate_path(project)?;
    let mut cursor = project.to_path_buf();
    let mut package_root = None;
    loop {
        if runtime.read(&cursor.join("yarn.lock"))?.is_some() {
            return Ok(Some(cursor));
        }
        if package_root.is_none() && runtime.read(&cursor.join("package.json"))?.is_some() {
            package_root = Some(cursor.clone());
        }
        let Some(parent) = cursor.parent() else {
            break;
        };
        if parent == cursor {
            break;
        }
        cursor = parent.to_path_buf();
    }
    Ok(Some(package_root.unwrap_or_else(|| project.to_path_buf())))
}

fn config_paths(
    runtime: &dyn Runtime,
    generation: YarnGeneration,
    project: Option<&Path>,
    project_root: Option<&Path>,
) -> Result<Vec<ConfigPath>, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("Yarn user scope requires a home directory".into())
    })?;
    validate_path(&home)?;
    let mut paths = Vec::new();
    match generation {
        YarnGeneration::Classic => {
            if runtime.command_exists("yarn") {
                let list = run_yarn(
                    runtime,
                    project,
                    &["config", "list", "--verbose", "--json"],
                    "yarn config list",
                )?;
                for path in classic_discovered_paths(&list)? {
                    let scope = if path == home.join(".yarnrc") {
                        OriginScope::User
                    } else if project_root.is_some_and(|root| path.starts_with(root)) {
                        OriginScope::Project
                    } else {
                        OriginScope::System
                    };
                    paths.push(ConfigPath {
                        scope,
                        kind: ConfigKind::Classic,
                        path,
                    });
                }
            }
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::Classic,
                path: home.join(".yarnrc"),
            });
            if let Some(root) = project_root {
                paths.push(ConfigPath {
                    scope: OriginScope::Project,
                    kind: ConfigKind::Classic,
                    path: root.join(".yarnrc"),
                });
                paths.push(ConfigPath {
                    scope: OriginScope::Project,
                    kind: ConfigKind::Npm,
                    path: root.join(".npmrc"),
                });
            }
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::Npm,
                path: home.join(".npmrc"),
            });
        }
        YarnGeneration::Berry => {
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::Berry,
                path: home.join(".yarnrc.yml"),
            });
            if let Some(root) = project_root {
                paths.push(ConfigPath {
                    scope: OriginScope::Project,
                    kind: ConfigKind::Berry,
                    path: root.join(".yarnrc.yml"),
                });
            }
        }
    }
    for path in &paths {
        validate_path(&path.path)?;
    }
    for (index, left) in paths.iter().enumerate() {
        if paths[index + 1..]
            .iter()
            .any(|right| left.path == right.path && left.scope != right.scope)
        {
            return Err(AdapterError::InvalidConfiguration(
                "Yarn user and project scopes resolve to the same configuration file".into(),
            ));
        }
    }
    Ok(paths)
}

fn classic_discovered_paths(text: &str) -> Result<Vec<PathBuf>, AdapterError> {
    let mut paths = Vec::new();
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("type").and_then(|value| value.as_str()) != Some("verbose") {
            continue;
        }
        let Some(data) = value.get("data").and_then(|value| value.as_str()) else {
            continue;
        };
        let Some(path) = data
            .strip_prefix("Found configuration file \"")
            .and_then(|value| value.strip_suffix("\"."))
        else {
            continue;
        };
        let path = PathBuf::from(path);
        if path.file_name().and_then(|value| value.to_str()) == Some(".yarnrc") {
            validate_path(&path)?;
            paths.push(path);
        }
    }
    Ok(paths)
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Yarn reported unsafe configuration path {}",
            path.display()
        )));
    }
    Ok(())
}

fn document_format(generation: YarnGeneration, kind: ConfigKind, selected: bool) -> String {
    match (generation, kind, selected) {
        (YarnGeneration::Classic, ConfigKind::Classic, true) => "yarn-classic-selected",
        (YarnGeneration::Classic, ConfigKind::Classic, false) => "yarn-classic-read-only",
        (YarnGeneration::Classic, ConfigKind::Npm, _) => "yarn-classic-npm-read-only",
        (YarnGeneration::Berry, ConfigKind::Berry, true) => "yarn-berry-selected",
        (YarnGeneration::Berry, ConfigKind::Berry, false) => "yarn-berry-project-read-only",
        _ => "yarn-config-read-only",
    }
    .into()
}

fn selected_document(
    current: &CurrentConfiguration,
) -> Result<(YarnGeneration, &ConfigurationDocument), AdapterError> {
    for document in &current.documents {
        let generation = match document.format.as_str() {
            "yarn-classic-selected" => Some(YarnGeneration::Classic),
            "yarn-berry-selected" => Some(YarnGeneration::Berry),
            _ => None,
        };
        if let Some(generation) = generation {
            return Ok((generation, document));
        }
    }
    Err(AdapterError::Unsupported(format!(
        "Yarn {} scope has no addressable configuration file",
        scope_name(current.scope)
    )))
}

fn classic_entries(text: &str) -> Result<Vec<ScalarEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += inclusive.len();
            continue;
        }
        let key_end = line.find(char::is_whitespace).unwrap_or(line.len());
        let key = line[..key_end]
            .trim()
            .trim_matches(['\'', '"'])
            .to_ascii_lowercase();
        if key.is_empty() || key_end == line.len() {
            offset += inclusive.len();
            continue;
        }
        let raw = &line[key_end..];
        let leading = raw.len() - raw.trim_start().len();
        let value_text = scalar_token(raw.trim())?;
        let (value, quote) = scalar_value(value_text)?;
        entries.push(ScalarEntry {
            key,
            value,
            value_range: offset + key_end + leading..offset + key_end + leading + value_text.len(),
            quote,
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn classic_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    Ok(classic_entries(text)?
        .into_iter()
        .filter_map(|entry| match entry.key.as_str() {
            "registry" => Some(configured_source(
                &entry.value,
                "default-registry",
                scope,
                path,
            )),
            "strict-ssl" => Some(configured_source(
                &entry.value.to_ascii_lowercase(),
                "strict-ssl",
                scope,
                path,
            )),
            "_auth" | "_authtoken" | "_password" => Some(configured_source(
                "<redacted>",
                "unscoped-auth",
                scope,
                path,
            )),
            _ => None,
        })
        .collect())
}

fn npmrc_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let (value, _) = scalar_value(raw_value.trim())?;
        if key.starts_with('@') && key.ends_with(":registry") {
            sources.push(configured_source(&value, "scoped-registry", scope, path));
        } else if key == "strict-ssl" {
            sources.push(configured_source(
                &value.to_ascii_lowercase(),
                "strict-ssl",
                scope,
                path,
            ));
        } else if NPM_AUTH_KEYS.contains(&key.as_str()) {
            sources.push(configured_source(
                "<redacted>",
                "unscoped-auth",
                scope,
                path,
            ));
        } else if let Some(registry) = npm_auth_registry(&key) {
            sources.push(configured_source(&registry, "scoped-auth", scope, path));
        }
    }
    Ok(sources)
}

fn npm_auth_registry(key: &str) -> Option<String> {
    let (registry, auth_key) = key.rsplit_once(':')?;
    if !registry.starts_with("//") || !NPM_AUTH_KEYS.contains(&auth_key) {
        return None;
    }
    Some(format!("https:{registry}"))
}

fn berry_top_entries(text: &str) -> Result<Vec<ScalarEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        if line.starts_with('\t') {
            return Err(AdapterError::InvalidConfiguration(
                "Yarn Berry config uses a tab indentation".into(),
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with(' ') {
            offset += inclusive.len();
            continue;
        }
        let Some(delimiter) = line.find(':') else {
            offset += inclusive.len();
            continue;
        };
        let key = yaml_key(line[..delimiter].trim())?;
        let raw = &line[delimiter + 1..];
        let leading = raw.len() - raw.trim_start().len();
        let value_text = scalar_token(raw.trim())?;
        let (value, quote) = scalar_value(value_text)?;
        entries.push(ScalarEntry {
            key,
            value,
            value_range: offset + delimiter + 1 + leading
                ..offset + delimiter + 1 + leading + value_text.len(),
            quote,
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn berry_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    for entry in berry_top_entries(text)? {
        match entry.key.as_str() {
            "npmRegistryServer" => sources.push(configured_source(
                &entry.value,
                "default-registry",
                scope,
                path,
            )),
            "enableStrictSsl" => sources.push(configured_source(
                &entry.value.to_ascii_lowercase(),
                "strict-ssl",
                scope,
                path,
            )),
            "npmAuthToken" | "npmAuthIdent" => sources.push(configured_source(
                "<redacted>",
                "unscoped-auth",
                scope,
                path,
            )),
            "npmScopes" | "npmRegistries" if !matches!(entry.value.as_str(), "" | "{}") => {
                sources.push(configured_source(
                    "<redacted>",
                    "complex-registry-map",
                    scope,
                    path,
                ));
            }
            _ => {}
        }
    }
    sources.extend(berry_nested_sources(text, scope, path)?);
    Ok(sources)
}

fn berry_nested_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut section = String::new();
    let mut block = String::new();
    let mut blocks: BTreeMap<(String, String), (Option<String>, bool)> = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with('\t') {
            return Err(AdapterError::InvalidConfiguration(
                "Yarn Berry config uses a tab indentation".into(),
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        let Some((raw_key, raw_value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = yaml_key(raw_key.trim())?;
        let (value, _) = scalar_value(raw_value.trim())?;
        if indent == 0 {
            section = key;
            block.clear();
        } else if indent == 2 && matches!(section.as_str(), "npmScopes" | "npmRegistries") {
            block = key;
            blocks.entry((section.clone(), block.clone())).or_default();
        } else if indent >= 4 && !block.is_empty() {
            let state = blocks.entry((section.clone(), block.clone())).or_default();
            if key == "npmRegistryServer" {
                state.0 = Some(value);
            } else if matches!(key.as_str(), "npmAuthToken" | "npmAuthIdent") {
                state.1 = true;
            }
        }
    }
    let mut sources = Vec::new();
    for ((section, block), (registry, auth)) in blocks {
        let registry = if section == "npmRegistries" {
            Some(normalize_registry_key(&block))
        } else {
            registry
        };
        if let Some(registry) = &registry {
            sources.push(configured_source(registry, "scoped-registry", scope, path));
        }
        if auth {
            sources.push(configured_source(
                registry.as_deref().unwrap_or("<default>"),
                "scoped-auth",
                scope,
                path,
            ));
        }
    }
    Ok(sources)
}

fn normalize_registry_key(value: &str) -> String {
    if value.starts_with("//") {
        format!("https:{value}")
    } else {
        value.into()
    }
}

fn yaml_key(value: &str) -> Result<String, AdapterError> {
    let (value, _) = scalar_value(value)?;
    if value.is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn Berry config has an empty key".into(),
        ));
    }
    Ok(value)
}

fn scalar_value(value: &str) -> Result<(String, Option<char>), AdapterError> {
    let value = scalar_token(value.trim())?;
    for quote in ['\'', '"'] {
        if value.starts_with(quote) {
            let inner = value
                .strip_prefix(quote)
                .and_then(|value| value.strip_suffix(quote))
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Yarn config contains an unterminated quoted scalar".into(),
                    )
                })?;
            return Ok((inner.into(), Some(quote)));
        }
    }
    Ok((value.into(), None))
}

fn scalar_token(value: &str) -> Result<&str, AdapterError> {
    let value = value.trim();
    let Some(quote) = value
        .chars()
        .next()
        .filter(|value| matches!(value, '\'' | '"'))
    else {
        return Ok(value
            .split_once(" #")
            .map_or(value, |(value, _)| value.trim_end()));
    };
    let mut escaped = false;
    for (index, character) in value.char_indices().skip(1) {
        if quote == '"' && character == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if character == quote && !escaped {
            let end = index + character.len_utf8();
            let trailing = value[end..].trim();
            if trailing.is_empty() || trailing.starts_with('#') {
                return Ok(&value[..end]);
            }
            return Err(AdapterError::InvalidConfiguration(
                "Yarn config has content after a quoted scalar".into(),
            ));
        }
        escaped = false;
    }
    Err(AdapterError::InvalidConfiguration(
        "Yarn config contains an unterminated quoted scalar".into(),
    ))
}

fn configured_source(url: &str, kind: &str, scope: OriginScope, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: (matches!(kind, "default-registry" | "scoped-registry")
            && is_yarn_registry(url))
        .then(|| NPM_UPSTREAM.into()),
        url: url.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin_scope".into(), vec![origin_name(scope).into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn validate_precedence(
    current: &CurrentConfiguration,
    generation: YarnGeneration,
) -> Result<(), AdapterError> {
    let selected_rank = scope_rank(scope_name(current.scope))?;
    let mut expected: Option<(u8, &str)> = None;
    let mut effective = None;
    for source in &current.sources {
        match metadata(source, "kind")? {
            "effective-registry" => effective = Some(source.url.as_str()),
            "default-registry" => {
                let origin = metadata(source, "origin_scope")?;
                let rank = scope_rank(origin)?;
                if rank > selected_rank {
                    return Err(AdapterError::Unsupported(format!(
                        "Yarn {origin} registry has higher precedence than selected {} scope",
                        scope_name(current.scope)
                    )));
                }
                if expected.is_none_or(|(current_rank, _)| rank >= current_rank) {
                    expected = Some((rank, source.url.as_str()));
                }
            }
            "complex-registry-map" => {
                return Err(AdapterError::Unsupported(
                    "Yarn Berry registry maps use an unsupported inline or aliased YAML shape"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    let default = match generation {
        YarnGeneration::Classic | YarnGeneration::Berry => "https://registry.yarnpkg.com",
    };
    let expected = expected.map_or(default, |(_, value)| value);
    let effective = effective.ok_or_else(|| {
        AdapterError::InvalidConfiguration("Yarn effective registry observation is missing".into())
    })?;
    if !is_yarn_registry(expected) || !is_yarn_registry(effective) {
        return Err(AdapterError::Unsupported(
            "Yarn effective default registry is private or unmapped and will not be overridden"
                .into(),
        ));
    }
    if normalize_registry(effective) != normalize_registry(expected) {
        return Err(AdapterError::Unsupported(
            "Yarn effective registry comes from an environment or unaddressed configuration source"
                .into(),
        ));
    }
    Ok(())
}

fn require_transport_policy(
    current: &CurrentConfiguration,
    endpoint: &str,
) -> Result<(), AdapterError> {
    let selected = reqwest::Url::parse(endpoint).expect("reviewed Yarn registry URL");
    let mut effective_tls: Option<(u8, &str)> = None;
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        let origin = metadata(source, "origin_scope")?;
        if kind == "strict-ssl" {
            let rank = scope_rank(origin)?;
            if effective_tls.is_none_or(|(current_rank, _)| rank >= current_rank) {
                effective_tls = Some((rank, source.url.as_str()));
            }
        } else if kind == "unscoped-auth" {
            return Err(AdapterError::InvalidConfiguration(
                "Yarn contains unscoped authentication that could follow the changed registry"
                    .into(),
            ));
        } else if kind == "scoped-auth" {
            let auth = reqwest::Url::parse(&source.url).ok();
            if auth.is_none()
                || auth.as_ref().and_then(reqwest::Url::host_str) == selected.host_str()
            {
                return Err(AdapterError::InvalidConfiguration(
                    "selected public Yarn registry has matching scoped authentication".into(),
                ));
            }
        }
    }
    if effective_tls.is_some_and(|(_, value)| value.eq_ignore_ascii_case("false")) {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn TLS certificate verification is disabled".into(),
        ));
    }
    Ok(())
}

fn rewrite_classic(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let entries = classic_entries(text)?;
    let matching = entries
        .iter()
        .filter(|entry| entry.key == "registry")
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn Classic config contains multiple registry options".into(),
        ));
    }
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    if let Some(entry) = matching.first() {
        if !is_yarn_registry(&entry.value) {
            return Err(AdapterError::Unsupported(
                "Yarn Classic selected scope has a private or unmapped registry".into(),
            ));
        }
        let replacement = match entry.quote {
            Some(quote) => format!("{quote}{endpoint}{quote}"),
            None => endpoint,
        };
        let mut rewritten = text.to_owned();
        rewritten.replace_range(entry.value_range.clone(), &replacement);
        return Ok(rewritten);
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut rewritten = text.to_owned();
    if !rewritten.is_empty() && !rewritten.ends_with(['\n', '\r']) {
        rewritten.push_str(newline);
    }
    rewritten.push_str(&format!("registry \"{endpoint}\"{newline}"));
    Ok(rewritten)
}

fn rewrite_berry(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let entries = berry_top_entries(text)?;
    let matching = entries
        .iter()
        .filter(|entry| entry.key == "npmRegistryServer")
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn Berry config contains multiple npmRegistryServer keys".into(),
        ));
    }
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    if let Some(entry) = matching.first() {
        if !is_yarn_registry(&entry.value) {
            return Err(AdapterError::Unsupported(
                "Yarn Berry selected scope has a private or unmapped registry".into(),
            ));
        }
        let replacement = match entry.quote {
            Some(quote) => format!("{quote}{endpoint}{quote}"),
            None => format!("\"{endpoint}\""),
        };
        let mut rewritten = text.to_owned();
        rewritten.replace_range(entry.value_range.clone(), &replacement);
        return Ok(rewritten);
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut rewritten = text.to_owned();
    if !rewritten.is_empty() && !rewritten.ends_with(['\n', '\r']) {
        rewritten.push_str(newline);
    }
    rewritten.push_str(&format!("npmRegistryServer: \"{endpoint}\"{newline}"));
    Ok(rewritten)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "yarn"
        || selections[0].upstream_id != NPM_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn plan requires exactly one npm registry selection".into(),
        ));
    }
    let endpoint = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Yarn selection has no HTTPS registry endpoint".into(),
            )
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "Yarn selection is not the reviewed metadata-and-tarball registry".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn package_metadata(
    generation: YarnGeneration,
    output: &str,
) -> Result<serde_json::Value, AdapterError> {
    match generation {
        YarnGeneration::Berry => serde_json::from_str(output).map_err(|error| {
            AdapterError::Verification(format!("Yarn Berry metadata is invalid JSON: {error}"))
        }),
        YarnGeneration::Classic => {
            for line in output.lines() {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if value.get("type").and_then(|value| value.as_str()) == Some("inspect")
                    && value.get("data").is_some_and(serde_json::Value::is_object)
                {
                    return Ok(value["data"].clone());
                }
            }
            Err(AdapterError::Verification(
                "Yarn Classic metadata has no inspect object".into(),
            ))
        }
    }
}

fn validate_package_metadata(
    registry: &str,
    package: serde_json::Value,
) -> Result<(), AdapterError> {
    if package.get("name").and_then(|value| value.as_str()) != Some("is-number")
        || package.get("version").and_then(|value| value.as_str()) != Some("7.0.0")
    {
        return Err(AdapterError::Verification(
            "Yarn returned unexpected package metadata".into(),
        ));
    }
    let tarball = package
        .pointer("/dist/tarball")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AdapterError::Verification("Yarn metadata lacks a tarball URL".into()))?;
    let registry = reqwest::Url::parse(registry).expect("reviewed Yarn registry URL");
    let tarball = reqwest::Url::parse(tarball)
        .map_err(|_| AdapterError::Verification("Yarn tarball URL is invalid".into()))?;
    if tarball.scheme() != "https"
        || !tarball.username().is_empty()
        || tarball.password().is_some()
        || tarball.host_str() != registry.host_str()
    {
        return Err(AdapterError::Verification(
            "Yarn tarball URL is not HTTPS on the selected registry host".into(),
        ));
    }
    Ok(())
}

fn normalize_registry(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(['\'', '"']);
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

fn is_official_registry(value: &str) -> bool {
    normalize_registry(value)
        .as_deref()
        .is_some_and(|value| OFFICIAL_REGISTRIES.contains(&value))
}

fn is_known_mirror(value: &str) -> bool {
    normalize_registry(value).as_deref() == Some(HUAWEI_REGISTRY)
}

fn is_yarn_registry(value: &str) -> bool {
    is_official_registry(value) || is_known_mirror(value)
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Yarn source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Yarn source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn origin_scope(scope: ConfigurationScope) -> OriginScope {
    match scope {
        ConfigurationScope::User => OriginScope::User,
        ConfigurationScope::Project => OriginScope::Project,
        _ => unreachable!("validated Yarn scope"),
    }
}

fn scope_name(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::User => "user",
        ConfigurationScope::Project => "project",
        _ => unreachable!("validated Yarn scope"),
    }
}

fn origin_name(scope: OriginScope) -> &'static str {
    match scope {
        OriginScope::System => "system",
        OriginScope::User => "user",
        OriginScope::Project => "project",
        OriginScope::Effective => "effective",
    }
}

fn scope_rank(scope: &str) -> Result<u8, AdapterError> {
    match scope {
        "system" => Ok(0),
        "user" => Ok(1),
        "project" => Ok(2),
        "effective" => Ok(3),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "unknown Yarn scope {scope}"
        ))),
    }
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

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Yarn configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
