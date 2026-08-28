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
const MIRROR_REGISTRIES: &[&str] = &["https://repo.huaweicloud.com/repository/npm"];
const AUTH_KEYS: &[&str] = &[
    "_auth",
    "_authtoken",
    "username",
    "_password",
    "certfile",
    "keyfile",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct NpmAdapter;

impl Adapter for NpmAdapter {
    fn key(&self) -> &'static str {
        "npm"
    }

    fn tool_id(&self) -> &'static str {
        "npm"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[
            ConfigurationScope::System,
            ConfigurationScope::User,
            ConfigurationScope::Project,
        ]
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
        if !runtime.command_exists("npm") {
            return Ok(None);
        }
        let project = runtime.project_dir();
        let npm_version = run_text(runtime, project.as_deref(), &["--version"], "npm --version")?;
        let node_version = if runtime.command_exists("node") {
            run_program_text(
                runtime,
                project.as_deref(),
                "node",
                &["--version"],
                "node --version",
            )?
        } else {
            "unavailable".into()
        };
        let registry = run_text(
            runtime,
            project.as_deref(),
            &["config", "get", "registry"],
            "npm config get registry",
        )?;
        let registry_class = if is_official_registry(&registry) {
            "official npm registry"
        } else if is_known_mirror(&registry) {
            "reviewed mirror"
        } else {
            "custom or private registry"
        };
        let list = run_text(
            runtime,
            project.as_deref(),
            &["config", "list"],
            "npm config list",
        )?;
        let environment = parse_environment_config(&list)?;
        let mut evidence = vec![
            format!("npm {npm_version}; Node.js {node_version}"),
            format!("effective default registry is a {registry_class}"),
        ];
        let scoped = environment
            .iter()
            .filter(|entry| is_scoped_registry_key(&entry.key))
            .count();
        if scoped > 0 {
            evidence.push(format!("environment defines {scoped} scoped registries"));
        }
        if environment.iter().any(|entry| entry.key == "registry") {
            evidence.push("environment overrides the default registry".into());
        }
        Ok(Some(DetectedTool {
            tool_id: "npm".into(),
            executable: Some(PathBuf::from("npm")),
            version: Some(format!("npm {npm_version}; node {node_version}")),
            evidence,
        }))
    }

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        require_linux(context)?;
        require_scope(scope)?;
        let project = runtime.project_dir();
        let paths = config_paths(runtime, project.as_deref())?;
        let selected = paths
            .iter()
            .find(|item| item.scope == origin_scope(scope))
            .map(|item| item.path.clone());
        let environment_text = run_text(
            runtime,
            project.as_deref(),
            &["config", "list"],
            "npm config list",
        )?;
        let mut sources = sources_from_entries(
            &parse_environment_config(&environment_text)?,
            OriginScope::Environment,
            Path::new(":env:"),
        );
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
            sources.extend(sources_from_entries(
                &parse_npmrc(utf8(&item.path, &contents)?)?,
                item.scope,
                &item.path,
            ));
            documents.push(ConfigurationDocument {
                path: item.path.clone(),
                format: if selected.as_ref() == Some(&item.path) {
                    "npm-selected-config".into()
                } else {
                    "npm-config-read-only".into()
                },
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "npm".into(),
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
            tool_id: "npm".into(),
            adapter_key: "npm".into(),
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
        validate_precedence(current)?;
        require_transport_policy(current, endpoint)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "npm-selected-config")
            .ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "npm {} scope has no addressable configuration file",
                    scope_name(current.scope)
                ))
            })?;
        if !mutable_config_path(&document.path) {
            return Err(AdapterError::Unsupported(format!(
                "npm {} scope resolves to a non-file configuration target",
                scope_name(current.scope)
            )));
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
                    "set only the npm default registry in explicit {} scope; preserve scoped registries and authentication",
                    scope_name(current.scope)
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "npm".into(),
            tool_id: "npm".into(),
            scope: current.scope,
            changes,
            requires_elevation: current.scope == ConfigurationScope::System,
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
            let registry = run_text(
                runtime,
                project.as_deref(),
                &["config", "get", "registry"],
                "npm config get registry",
            )?;
            if !is_known_mirror(&registry) {
                return Err(AdapterError::Verification(
                    "npm effective default registry is not a reviewed mirror".into(),
                ));
            }
            let metadata = run_text(
                runtime,
                project.as_deref(),
                &[
                    "view",
                    "is-number@7.0.0",
                    "name",
                    "version",
                    "dist.tarball",
                    "--json",
                ],
                "npm view package metadata",
            )?;
            let metadata: serde_json::Value = serde_json::from_str(&metadata).map_err(|error| {
                AdapterError::Verification(format!(
                    "npm package metadata is not valid JSON: {error}"
                ))
            })?;
            let tarball = metadata
                .get("dist.tarball")
                .and_then(|value| value.as_str());
            if metadata.get("name").and_then(|value| value.as_str()) != Some("is-number")
                || metadata.get("version").and_then(|value| value.as_str()) != Some("7.0.0")
                || tarball.is_none_or(str::is_empty)
            {
                return Err(AdapterError::Verification(
                    "npm package metadata lacks the expected package, version, or tarball URL"
                        .into(),
                ));
            }
            let registry_url = reqwest::Url::parse(&registry).expect("reviewed npm registry URL");
            let tarball_url = reqwest::Url::parse(tarball.unwrap()).map_err(|_| {
                AdapterError::Verification("npm returned an invalid tarball URL".into())
            })?;
            if tarball_url.scheme() != "https"
                || !tarball_url.username().is_empty()
                || tarball_url.password().is_some()
                || tarball_url.host_str() != registry_url.host_str()
            {
                return Err(AdapterError::Verification(
                    "npm tarball URL is not HTTPS on the selected registry host".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary:
                    "npm effective config and real package metadata query validated the registry"
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
                "restored {} npm configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginScope {
    System,
    User,
    Project,
    Environment,
}

#[derive(Clone, Debug)]
struct ConfigPath {
    scope: OriginScope,
    path: PathBuf,
}

#[derive(Clone, Debug)]
struct NpmEntry {
    key: String,
    value: String,
    value_range: Option<Range<usize>>,
    quote: Option<char>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "npm adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if !matches!(
        scope,
        ConfigurationScope::System | ConfigurationScope::User | ConfigurationScope::Project
    ) {
        return Err(AdapterError::Unsupported(
            "npm supports global, user, and explicit project config scopes".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "npm" {
        return Err(AdapterError::InvalidConfiguration(
            "npm operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn run_text(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    run_program_text(runtime, directory, "npm", arguments, operation)
}

fn run_program_text(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = match directory {
        Some(directory) => runtime.run_in(directory, program, &arguments)?,
        None => runtime.run(program, &arguments)?,
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
    project: Option<&Path>,
) -> Result<Vec<ConfigPath>, AdapterError> {
    let global = run_text(
        runtime,
        project,
        &["config", "get", "globalconfig"],
        "npm config get globalconfig",
    )?;
    let user = run_text(
        runtime,
        project,
        &["config", "get", "userconfig"],
        "npm config get userconfig",
    )?;
    let mut paths = vec![
        ConfigPath {
            scope: OriginScope::System,
            path: PathBuf::from(global),
        },
        ConfigPath {
            scope: OriginScope::User,
            path: PathBuf::from(user),
        },
    ];
    if let Some(project) = project {
        let prefix = run_text(runtime, Some(project), &["prefix"], "npm prefix")?;
        paths.push(ConfigPath {
            scope: OriginScope::Project,
            path: PathBuf::from(prefix).join(".npmrc"),
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
            "npm reported an unsafe configuration path".into(),
        ));
    }
    if paths
        .iter()
        .map(|item| &item.path)
        .collect::<BTreeSet<_>>()
        .len()
        != paths.len()
    {
        return Err(AdapterError::InvalidConfiguration(
            "npm scopes resolve to the same configuration file".into(),
        ));
    }
    Ok(paths)
}

fn parse_npmrc(text: &str) -> Result<Vec<NpmEntry>, AdapterError> {
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
                "npm config contains an empty option name".into(),
            ));
        }
        let raw = &line[delimiter + 1..];
        let leading = raw.len() - raw.trim_start().len();
        let trimmed_value = raw.trim();
        let (value, quote) = unquote_value(trimmed_value)?;
        entries.push(NpmEntry {
            key,
            value,
            value_range: Some(
                offset + delimiter + 1 + leading
                    ..offset + delimiter + 1 + leading + trimmed_value.len(),
            ),
            quote,
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn parse_environment_config(text: &str) -> Result<Vec<NpmEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut environment = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("; \"") && trimmed.contains("\" config ") {
            environment = trimmed.starts_with("; \"env\" config ");
            continue;
        }
        if !environment || trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        let Some((key, raw)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let raw = raw.trim();
        let raw = raw
            .split_once(" ; overridden by ")
            .map_or(raw, |(value, _)| value.trim());
        let (value, quote) = unquote_value(raw)?;
        entries.push(NpmEntry {
            key,
            value,
            value_range: None,
            quote,
        });
    }
    Ok(entries)
}

fn unquote_value(value: &str) -> Result<(String, Option<char>), AdapterError> {
    for quote in ['\'', '"'] {
        if value.starts_with(quote) {
            let inner = value
                .strip_prefix(quote)
                .and_then(|value| value.strip_suffix(quote))
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "npm config contains an unterminated quoted value".into(),
                    )
                })?;
            return Ok((inner.into(), Some(quote)));
        }
    }
    Ok((value.into(), None))
}

fn sources_from_entries(
    entries: &[NpmEntry],
    scope: OriginScope,
    path: &Path,
) -> Vec<ConfiguredSource> {
    entries
        .iter()
        .filter_map(|entry| {
            let (kind, url) = if entry.key == "registry" {
                ("default-registry", entry.value.clone())
            } else if is_scoped_registry_key(&entry.key) {
                ("scoped-registry", entry.value.clone())
            } else if entry.key == "strict-ssl" {
                ("strict-ssl", entry.value.to_ascii_lowercase())
            } else if AUTH_KEYS.contains(&entry.key.as_str()) {
                ("unscoped-auth", "<redacted>".into())
            } else if let Some(registry) = scoped_auth_registry(&entry.key) {
                ("scoped-auth", registry)
            } else {
                return None;
            };
            Some(ConfiguredSource {
                upstream_id: (matches!(kind, "default-registry" | "scoped-registry")
                    && is_npm_registry(&url))
                .then(|| NPM_UPSTREAM.into()),
                url,
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec![kind.into()]),
                    ("origin_scope".into(), vec![origin_name(scope).into()]),
                    ("config_path".into(), vec![path.display().to_string()]),
                ]),
            })
        })
        .collect()
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

fn validate_precedence(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    let selected_rank = scope_rank(scope_name(current.scope))?;
    for source in &current.sources {
        if metadata(source, "kind")? != "default-registry" {
            continue;
        }
        let origin = metadata(source, "origin_scope")?;
        if origin == "environment" {
            return Err(AdapterError::Unsupported(
                "npm environment registry override must be changed outside MirrorSwitch".into(),
            ));
        }
        if scope_rank(origin)? > selected_rank {
            return Err(AdapterError::Unsupported(format!(
                "npm {origin} default registry has higher precedence than selected {} scope",
                scope_name(current.scope)
            )));
        }
    }
    Ok(())
}

fn require_transport_policy(
    current: &CurrentConfiguration,
    endpoint: &str,
) -> Result<(), AdapterError> {
    let mut effective_tls: Option<(u8, &str)> = None;
    let selected = reqwest::Url::parse(endpoint).expect("reviewed npm endpoint is a URL");
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
                "npm contains unscoped authentication that could follow a changed default registry"
                    .into(),
            ));
        } else if kind == "scoped-auth" {
            let auth = reqwest::Url::parse(&source.url).ok();
            if auth.is_none()
                || auth.as_ref().and_then(reqwest::Url::host_str) == selected.host_str()
            {
                return Err(AdapterError::InvalidConfiguration(
                    "selected public npm mirror has registry-scoped authentication".into(),
                ));
            }
        }
    }
    if effective_tls.is_some_and(|(_, value)| value.eq_ignore_ascii_case("false")) {
        return Err(AdapterError::InvalidConfiguration(
            "npm strict-ssl is disabled in the effective configuration".into(),
        ));
    }
    Ok(())
}

fn rewrite_default_registry(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let entries = parse_npmrc(text)?;
    let matching = entries
        .iter()
        .filter(|entry| entry.key == "registry")
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "npm config contains multiple default registry options".into(),
        ));
    }
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    if let Some(entry) = matching.first() {
        if !is_npm_registry(&entry.value) {
            return Err(AdapterError::Unsupported(
                "npm selected scope has a private or unmapped default registry".into(),
            ));
        }
        let replacement = match entry.quote {
            Some(quote) => format!("{quote}{endpoint}{quote}"),
            None => endpoint,
        };
        let mut rewritten = text.to_owned();
        rewritten.replace_range(entry.value_range.clone().unwrap(), &replacement);
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
        || selections[0].tool_id != "npm"
        || selections[0].upstream_id != NPM_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "npm plan requires exactly one registry selection".into(),
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
                "npm selection has no HTTPS registry endpoint".into(),
            )
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "npm selection is not a reviewed metadata-and-tarball registry".into(),
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
    normalize_registry(value)
        .as_deref()
        .is_some_and(|value| MIRROR_REGISTRIES.contains(&value))
}

fn is_npm_registry(value: &str) -> bool {
    is_official_registry(value) || is_known_mirror(value)
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("npm source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "npm source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn origin_scope(scope: ConfigurationScope) -> OriginScope {
    match scope {
        ConfigurationScope::System => OriginScope::System,
        ConfigurationScope::User => OriginScope::User,
        ConfigurationScope::Project => OriginScope::Project,
        _ => unreachable!("validated npm scope"),
    }
}

fn scope_name(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::System => "system",
        ConfigurationScope::User => "user",
        ConfigurationScope::Project => "project",
        _ => unreachable!("validated npm scope"),
    }
}

fn origin_name(scope: OriginScope) -> &'static str {
    match scope {
        OriginScope::System => "system",
        OriginScope::User => "user",
        OriginScope::Project => "project",
        OriginScope::Environment => "environment",
    }
}

fn scope_rank(scope: &str) -> Result<u8, AdapterError> {
    match scope {
        "system" => Ok(0),
        "user" => Ok(1),
        "project" => Ok(2),
        "environment" => Ok(3),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "unknown npm scope {scope}"
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
            "npm configuration {} is not UTF-8",
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
