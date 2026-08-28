use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
};

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

const NPM_UPSTREAM: &str = "npm--language-registry";
const OFFICIAL_REGISTRY: &str = "https://registry.npmjs.org";
const HUAWEI_REGISTRY: &str = "https://repo.huaweicloud.com/repository/npm";
const AUTH_KEYS: &[&str] = &[
    "_auth",
    "_authtoken",
    "username",
    "_password",
    "certfile",
    "keyfile",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct PnpmAdapter;

impl Adapter for PnpmAdapter {
    fn key(&self) -> &'static str {
        "pnpm"
    }

    fn tool_id(&self) -> &'static str {
        "pnpm"
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
        if !runtime.command_exists("pnpm") {
            return Ok(None);
        }
        let project = runtime.project_dir();
        let version = run_pnpm(
            runtime,
            project.as_deref(),
            &["--version"],
            "pnpm --version",
        )?;
        let model = version_model(&version)?;
        let registry = run_pnpm(
            runtime,
            project.as_deref(),
            &["config", "get", "registry"],
            "pnpm config get registry",
        )?;
        let registry_class = if is_official_registry(&registry) {
            "official npm registry"
        } else if is_known_mirror(&registry) {
            "reviewed mirror"
        } else {
            "custom or private registry"
        };
        Ok(Some(DetectedTool {
            tool_id: "pnpm".into(),
            executable: Some(PathBuf::from("pnpm")),
            version: Some(version.clone()),
            evidence: vec![
                format!("pnpm {version}; {}", model.name()),
                format!("effective default registry is a {registry_class}"),
                format!(
                    "persistent user registry file is {}",
                    model.user_file_name()
                ),
                format!(
                    "registry environment prefix is {}",
                    model.environment_prefix()
                ),
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
        require_linux(context)?;
        require_scope(scope)?;
        let version = detected
            .version
            .as_deref()
            .ok_or_else(|| AdapterError::InvalidConfiguration("pnpm version is missing".into()))?;
        let model = version_model(version)?;
        let project = runtime.project_dir();
        if let Some(project) = &project {
            validate_path(project)?;
        }
        let paths = config_paths(runtime, model, project.as_deref())?;
        let effective = run_pnpm(
            runtime,
            project.as_deref(),
            &["config", "get", "registry"],
            "pnpm config get registry",
        )?;
        let mut sources = vec![configured_source(
            &effective,
            "effective-registry",
            OriginScope::Effective,
            Path::new(":effective:"),
        )];
        if let Some(registry) = registry_environment(runtime, model) {
            sources.push(configured_source(
                &registry,
                "default-registry",
                OriginScope::Environment,
                Path::new(":environment:"),
            ));
        }

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
                ConfigKind::Ini => ini_sources(text, item.scope, &item.path)?,
                ConfigKind::ProjectYaml => yaml_sources(text, item.scope, &item.path)?,
                ConfigKind::SettingsYaml => settings_sources(text, item.scope, &item.path)?,
            });
            let format = document_format(model, &item);
            documents.push(ConfigurationDocument {
                path: item.path,
                format,
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "pnpm".into(),
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
            tool_id: "pnpm".into(),
            adapter_key: "pnpm".into(),
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
        require_linux(context)?;
        require_current(current)?;
        let endpoint = selected_endpoint(selections)?;
        let document = selected_document(current)?;
        validate_precedence(current, document)?;
        require_transport_policy(current, endpoint)?;
        if !mutable_config_path(&document.path) {
            return Err(AdapterError::Unsupported(
                "pnpm user config resolves to a non-file target".into(),
            ));
        }
        let new_contents =
            rewrite_default_registry(utf8(&document.path, &document.contents)?, endpoint)?
                .into_bytes();
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "set only the pnpm user registry in {}; preserve private scopes, authentication, store settings, and project configuration",
                    document.path.display()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "pnpm".into(),
            tool_id: "pnpm".into(),
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
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let project = runtime.project_dir();
            let registry = run_pnpm(
                runtime,
                project.as_deref(),
                &["config", "get", "registry"],
                "pnpm config get registry",
            )?;
            if !is_known_mirror(&registry) {
                return Err(AdapterError::Verification(
                    "pnpm effective registry is not the reviewed mirror".into(),
                ));
            }
            let metadata = run_pnpm(
                runtime,
                project.as_deref(),
                &["view", "is-number@7.0.0", "--json"],
                "pnpm view package metadata",
            )?;
            let metadata: serde_json::Value = serde_json::from_str(&metadata).map_err(|error| {
                AdapterError::Verification(format!(
                    "pnpm package metadata is not valid JSON: {error}"
                ))
            })?;
            let tarball = metadata
                .get("dist")
                .and_then(|value| value.get("tarball"))
                .and_then(|value| value.as_str());
            if metadata.get("name").and_then(|value| value.as_str()) != Some("is-number")
                || metadata.get("version").and_then(|value| value.as_str()) != Some("7.0.0")
                || tarball.is_none_or(str::is_empty)
            {
                return Err(AdapterError::Verification(
                    "pnpm metadata lacks the expected package, version, or tarball URL".into(),
                ));
            }
            let registry_url = reqwest::Url::parse(&registry).expect("reviewed pnpm registry URL");
            let tarball_url = reqwest::Url::parse(tarball.unwrap()).map_err(|_| {
                AdapterError::Verification("pnpm returned an invalid tarball URL".into())
            })?;
            if tarball_url.scheme() != "https"
                || !tarball_url.username().is_empty()
                || tarball_url.password().is_some()
                || tarball_url.host_str() != registry_url.host_str()
            {
                return Err(AdapterError::Verification(
                    "pnpm tarball URL is not HTTPS on the selected registry host".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: "pnpm effective config and real package metadata validated the registry"
                    .into(),
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
                "restored {} pnpm configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VersionModel {
    Legacy10,
    Split11,
}

impl VersionModel {
    fn name(self) -> &'static str {
        match self {
            Self::Legacy10 => "npm-compatible INI configuration model",
            Self::Split11 => "split auth.ini/config.yaml configuration model",
        }
    }

    fn user_file_name(self) -> &'static str {
        match self {
            Self::Legacy10 => ".npmrc",
            Self::Split11 => "auth.ini",
        }
    }

    fn environment_prefix(self) -> &'static str {
        match self {
            Self::Legacy10 => "npm_config_",
            Self::Split11 => "pnpm_config_",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginScope {
    User,
    Project,
    Environment,
    Effective,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigKind {
    Ini,
    ProjectYaml,
    SettingsYaml,
}

#[derive(Clone, Debug)]
struct ConfigPath {
    scope: OriginScope,
    kind: ConfigKind,
    path: PathBuf,
    selected: bool,
}

#[derive(Clone, Debug)]
struct IniEntry {
    key: String,
    value: String,
    value_range: Range<usize>,
    quote: Option<char>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "pnpm adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "pnpm v0.1 supports only the user scope; project configuration is read-only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "pnpm" {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn version_model(version: &str) -> Result<VersionModel, AdapterError> {
    let numeric = version.trim().trim_start_matches('v');
    let mut parts = numeric.split(['.', '-']);
    let parse = |value: Option<&str>| value.and_then(|value| value.parse::<u64>().ok());
    let major = parse(parts.next());
    let minor = parse(parts.next());
    let patch = parse(parts.next());
    let (major, minor, patch) = match (major, minor, patch) {
        (Some(major), Some(minor), Some(patch)) => (major, minor, patch),
        _ => {
            return Err(AdapterError::Unsupported(format!(
                "unrecognized pnpm version {version}"
            )));
        }
    };
    match major {
        10 if (minor, patch) >= (34, 2) => Ok(VersionModel::Legacy10),
        11 if (minor, patch) >= (22, 0) => Ok(VersionModel::Split11),
        10 => Err(AdapterError::Unsupported(
            "pnpm 10 support starts at 10.34.2".into(),
        )),
        11 => Err(AdapterError::Unsupported(
            "pnpm 11 support starts at 11.22.0".into(),
        )),
        _ => Err(AdapterError::Unsupported(format!(
            "pnpm {version} is outside the reviewed 10.x and 11.x compatibility range"
        ))),
    }
}

fn run_pnpm(
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
        Some(directory) => runtime.run_in(directory, "pnpm", &arguments)?,
        None => runtime.run("pnpm", &arguments)?,
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

fn config_paths(
    runtime: &dyn Runtime,
    model: VersionModel,
    project: Option<&Path>,
) -> Result<Vec<ConfigPath>, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("pnpm user scope requires a home directory".into())
    })?;
    validate_path(&home)?;
    let mut paths = Vec::new();
    match model {
        VersionModel::Legacy10 => {
            let user =
                environment_path(runtime, &["npm_config_userconfig", "NPM_CONFIG_USERCONFIG"])
                    .unwrap_or_else(|| home.join(".npmrc"));
            validate_path(&user)?;
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::Ini,
                path: user,
                selected: true,
            });
        }
        VersionModel::Split11 => {
            let config_directory = environment_path(
                runtime,
                &["pnpm_config_config_dir", "PNPM_CONFIG_CONFIG_DIR"],
            )
            .or_else(|| {
                environment_path(runtime, &["XDG_CONFIG_HOME"]).map(|path| path.join("pnpm"))
            })
            .unwrap_or_else(|| home.join(".config/pnpm"));
            validate_path(&config_directory)?;
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::Ini,
                path: config_directory.join("auth.ini"),
                selected: true,
            });
            let fallback = environment_path(
                runtime,
                &["pnpm_config_userconfig", "PNPM_CONFIG_USERCONFIG"],
            )
            .unwrap_or_else(|| home.join(".npmrc"));
            validate_path(&fallback)?;
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::Ini,
                path: fallback,
                selected: false,
            });
            paths.push(ConfigPath {
                scope: OriginScope::User,
                kind: ConfigKind::SettingsYaml,
                path: config_directory.join("config.yaml"),
                selected: false,
            });
        }
    }
    if let Some(project) = project {
        paths.push(ConfigPath {
            scope: OriginScope::Project,
            kind: ConfigKind::Ini,
            path: project.join(".npmrc"),
            selected: false,
        });
        paths.push(ConfigPath {
            scope: OriginScope::Project,
            kind: ConfigKind::ProjectYaml,
            path: project.join("pnpm-workspace.yaml"),
            selected: false,
        });
    }
    if paths.iter().any(|item| {
        !item.path.is_absolute()
            || item
                .path
                .components()
                .any(|component| component == Component::ParentDir)
    }) {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm reported an unsafe configuration path".into(),
        ));
    }
    Ok(paths)
}

fn environment_path(runtime: &dyn Runtime, names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|name| {
        runtime
            .environment_variable(name)
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
    })
}

fn registry_environment(runtime: &dyn Runtime, model: VersionModel) -> Option<String> {
    let names: &[&str] = match model {
        VersionModel::Legacy10 => &["npm_config_registry", "NPM_CONFIG_REGISTRY"],
        VersionModel::Split11 => &["pnpm_config_registry", "PNPM_CONFIG_REGISTRY"],
    };
    names.iter().find_map(|name| {
        runtime
            .environment_variable(name)
            .filter(|value| !value.trim().is_empty())
    })
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "pnpm reported unsafe configuration path {}",
            path.display()
        )));
    }
    Ok(())
}

fn document_format(model: VersionModel, path: &ConfigPath) -> String {
    if path.selected {
        return match model {
            VersionModel::Legacy10 => "pnpm10-selected-npmrc",
            VersionModel::Split11 => "pnpm11-selected-auth-ini",
        }
        .into();
    }
    match (path.scope, path.kind) {
        (OriginScope::User, ConfigKind::Ini) => "pnpm-user-ini-read-only",
        (OriginScope::User, ConfigKind::SettingsYaml) => "pnpm-user-settings-read-only",
        (OriginScope::Project, ConfigKind::Ini) => "pnpm-project-ini-read-only",
        (OriginScope::Project, ConfigKind::ProjectYaml) => "pnpm-project-yaml-read-only",
        _ => "pnpm-config-read-only",
    }
    .into()
}

fn parse_ini(text: &str) -> Result<Vec<IniEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            offset += inclusive.len();
            continue;
        }
        let Some(delimiter) = line.find('=') else {
            offset += inclusive.len();
            continue;
        };
        let key = line[..delimiter].trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "pnpm config contains an empty option name".into(),
            ));
        }
        let raw = &line[delimiter + 1..];
        let leading = raw.len() - raw.trim_start().len();
        let trimmed_value = raw.trim();
        let (value, quote) = unquote(trimmed_value)?;
        entries.push(IniEntry {
            key,
            value,
            value_range: offset + delimiter + 1 + leading
                ..offset + delimiter + 1 + leading + trimmed_value.len(),
            quote,
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn unquote(value: &str) -> Result<(String, Option<char>), AdapterError> {
    for quote in ['\'', '"'] {
        if value.starts_with(quote) {
            let inner = value
                .strip_prefix(quote)
                .and_then(|value| value.strip_suffix(quote))
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "pnpm config contains an unterminated quoted value".into(),
                    )
                })?;
            return Ok((inner.into(), Some(quote)));
        }
    }
    Ok((value.into(), None))
}

fn ini_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    Ok(parse_ini(text)?
        .into_iter()
        .filter_map(|entry| {
            let (kind, value) = if entry.key == "registry" {
                ("default-registry", entry.value)
            } else if is_scoped_registry_key(&entry.key) {
                ("scoped-registry", entry.value)
            } else if entry.key == "strict-ssl" {
                ("strict-ssl", entry.value.to_ascii_lowercase())
            } else if AUTH_KEYS.contains(&entry.key.as_str()) {
                ("unscoped-auth", "<redacted>".into())
            } else if let Some(registry) = scoped_auth_registry(&entry.key) {
                ("scoped-auth", registry)
            } else if matches!(entry.key.as_str(), "store-dir" | "store_dir" | "storedir") {
                ("store-setting", "<preserved>".into())
            } else {
                return None;
            };
            Some(configured_source(&value, kind, scope, path))
        })
        .collect())
}

fn settings_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    for line in text.lines() {
        let trimmed = strip_yaml_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(['\'', '"']).to_ascii_lowercase();
        if key == "registry" || key == "registries" {
            return Err(AdapterError::InvalidConfiguration(
                "pnpm 11 config.yaml contains registry data that belongs in auth.ini".into(),
            ));
        }
        if matches!(key.as_str(), "storedir" | "store-dir" | "store_dir") {
            let _ = value;
            sources.push(configured_source(
                "<preserved>",
                "store-setting",
                scope,
                path,
            ));
        }
    }
    Ok(sources)
}

fn yaml_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    let mut registries_indent = None;
    for line in text.lines() {
        let line = strip_yaml_comment(line);
        if line.trim().is_empty() {
            continue;
        }
        let leading = &line[..line.len() - line.trim_start().len()];
        if leading.contains('\t') {
            if line.to_ascii_lowercase().contains("registr") {
                return Err(AdapterError::InvalidConfiguration(
                    "pnpm workspace registry YAML uses unsupported tab indentation".into(),
                ));
            }
            continue;
        }
        let indent = leading.len();
        if registries_indent.is_some_and(|base| indent <= base) {
            registries_indent = None;
        }
        let trimmed = line.trim();
        let Some((raw_key, raw_value)) = trimmed.split_once(':') else {
            if trimmed.to_ascii_lowercase().contains("registr") {
                return Err(AdapterError::InvalidConfiguration(
                    "pnpm workspace contains an unsupported registry YAML shape".into(),
                ));
            }
            continue;
        };
        let key = raw_key
            .trim()
            .trim_matches(['\'', '"'])
            .to_ascii_lowercase();
        let value = raw_value.trim();
        if indent == 0 && key == "registry" {
            sources.push(configured_source(
                &yaml_scalar(value)?,
                "default-registry",
                scope,
                path,
            ));
        } else if indent == 0 && key == "registries" {
            if !value.is_empty() && value != "{}" {
                return Err(AdapterError::InvalidConfiguration(
                    "pnpm workspace contains an unsupported inline registries map".into(),
                ));
            }
            registries_indent = Some(indent);
        } else if registries_indent.is_some_and(|base| indent > base) {
            if key == "default" {
                sources.push(configured_source(
                    &yaml_scalar(value)?,
                    "default-registry",
                    scope,
                    path,
                ));
            } else if key.starts_with('@') {
                sources.push(configured_source(
                    &yaml_scalar(value)?,
                    "scoped-registry",
                    scope,
                    path,
                ));
            }
        }
    }
    Ok(sources)
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote == Some('"') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if character == '#' && quote.is_none() {
            return &line[..index];
        }
    }
    line
}

fn yaml_scalar(value: &str) -> Result<String, AdapterError> {
    if value.is_empty()
        || value.starts_with(['{', '[', '&', '*', '!', '|', '>'])
        || value.contains("${")
    {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm workspace registry must be a literal scalar URL".into(),
        ));
    }
    unquote(value).map(|(value, _)| value)
}

fn configured_source(value: &str, kind: &str, scope: OriginScope, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: (matches!(
            kind,
            "default-registry" | "scoped-registry" | "effective-registry"
        ) && is_npm_registry(value))
        .then(|| NPM_UPSTREAM.into()),
        url: value.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin_scope".into(), vec![origin_name(scope).into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn is_scoped_registry_key(key: &str) -> bool {
    key.starts_with('@') && key.ends_with(":registry")
}

fn scoped_auth_registry(key: &str) -> Option<String> {
    let (registry, auth_key) = key.rsplit_once(':')?;
    if !registry.starts_with("//") || !AUTH_KEYS.contains(&auth_key) {
        return None;
    }
    Some(format!("https:{registry}"))
}

fn selected_document(
    current: &CurrentConfiguration,
) -> Result<&ConfigurationDocument, AdapterError> {
    current
        .documents
        .iter()
        .find(|document| {
            document.format.starts_with("pnpm10-selected-")
                || document.format.starts_with("pnpm11-selected-")
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("pnpm selected user configuration is missing".into())
        })
}

fn validate_precedence(
    current: &CurrentConfiguration,
    selected: &ConfigurationDocument,
) -> Result<(), AdapterError> {
    let selected_has_registry = parse_ini(utf8(&selected.path, &selected.contents)?)?
        .iter()
        .any(|entry| entry.key == "registry");
    for source in &current.sources {
        if metadata(source, "kind")? != "default-registry" {
            continue;
        }
        let origin = metadata(source, "origin_scope")?;
        if origin == "environment" {
            return Err(AdapterError::Unsupported(
                "pnpm registry environment override must be changed outside MirrorSwitch".into(),
            ));
        }
        if origin == "project" {
            return Err(AdapterError::Unsupported(
                "pnpm project default registry has higher precedence than user scope".into(),
            ));
        }
        if origin == "user"
            && metadata(source, "config_path")? != selected.path.to_string_lossy()
            && !selected_has_registry
            && !is_npm_registry(&source.url)
        {
            return Err(AdapterError::Unsupported(
                "pnpm fallback user config has a private or unmapped default registry".into(),
            ));
        }
    }
    Ok(())
}

fn require_transport_policy(
    current: &CurrentConfiguration,
    endpoint: &str,
) -> Result<(), AdapterError> {
    let mut effective_tls: Option<(u8, &str)> = None;
    let selected = reqwest::Url::parse(endpoint).expect("reviewed pnpm endpoint is a URL");
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
                "pnpm contains unscoped authentication that could follow a changed registry".into(),
            ));
        } else if kind == "scoped-auth" {
            let auth = reqwest::Url::parse(&source.url).ok();
            if auth.is_none()
                || auth.as_ref().and_then(reqwest::Url::host_str) == selected.host_str()
            {
                return Err(AdapterError::InvalidConfiguration(
                    "selected public pnpm mirror has registry-scoped authentication".into(),
                ));
            }
        }
    }
    if effective_tls.is_some_and(|(_, value)| value.eq_ignore_ascii_case("false")) {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm strict-ssl is disabled in the effective configuration".into(),
        ));
    }
    Ok(())
}

fn rewrite_default_registry(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let entries = parse_ini(text)?;
    let matching = entries
        .iter()
        .filter(|entry| entry.key == "registry")
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm user config contains multiple default registry options".into(),
        ));
    }
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    if let Some(entry) = matching.first() {
        if !is_npm_registry(&entry.value) {
            return Err(AdapterError::Unsupported(
                "pnpm selected user config has a private or unmapped default registry".into(),
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
    rewritten.push_str(&format!("registry={endpoint}{newline}"));
    Ok(rewritten)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "pnpm"
        || selections[0].upstream_id != NPM_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm plan requires exactly one registry selection".into(),
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
                "pnpm selection has no HTTPS registry endpoint".into(),
            )
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "pnpm selection is not a reviewed metadata-and-tarball registry".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn normalize_registry(value: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(value.trim()).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(value.trim().trim_end_matches('/').to_ascii_lowercase())
}

fn is_official_registry(value: &str) -> bool {
    normalize_registry(value).as_deref() == Some(OFFICIAL_REGISTRY)
}

fn is_known_mirror(value: &str) -> bool {
    normalize_registry(value).as_deref() == Some(HUAWEI_REGISTRY)
}

fn is_npm_registry(value: &str) -> bool {
    is_official_registry(value) || is_known_mirror(value)
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("pnpm source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "pnpm source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn origin_name(scope: OriginScope) -> &'static str {
    match scope {
        OriginScope::User => "user",
        OriginScope::Project => "project",
        OriginScope::Environment => "environment",
        OriginScope::Effective => "effective",
    }
}

fn scope_rank(scope: &str) -> Result<u8, AdapterError> {
    match scope {
        "user" => Ok(1),
        "project" => Ok(2),
        "environment" => Ok(3),
        "effective" => Ok(4),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "unknown pnpm scope {scope}"
        ))),
    }
}

fn mutable_config_path(path: &Path) -> bool {
    path != Path::new("/")
        && path != Path::new("/dev/null")
        && !path.starts_with("/dev")
        && !path.starts_with("/proc")
        && !path.starts_with("/sys")
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
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "pnpm configuration {} is not UTF-8",
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
