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

const PYPI_UPSTREAM: &str = "pypi--language-registry";
const OFFICIAL_INDEXES: &[&str] = &["https://pypi.org/simple", "https://pypi.python.org/simple"];
const MIRROR_INDEXES: &[&str] = &[
    "https://mirrors.aliyun.com/pypi/simple",
    "https://repo.huaweicloud.com/repository/pypi/simple",
    "https://mirrors.nju.edu.cn/pypi/web/simple",
    "https://mirror.sjtu.edu.cn/pypi/web/simple",
    "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple",
    "https://mirrors.ustc.edu.cn/pypi/simple",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct PipAdapter;

impl Adapter for PipAdapter {
    fn key(&self) -> &'static str {
        "pip"
    }

    fn tool_id(&self) -> &'static str {
        "pip"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[
            ConfigurationScope::System,
            ConfigurationScope::User,
            ConfigurationScope::Site,
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
        let Some(command) = pip_command(runtime) else {
            return Ok(None);
        };
        let version = run_text(runtime, command, &["--version"], "pip --version")?;
        let debug_text = run_text(runtime, command, &["config", "debug"], "pip config debug")?;
        let debug = parse_debug(&debug_text)?;
        let existing = debug.paths.iter().filter(|path| path.exists).count();
        let mut evidence = vec![format!("pip command {version}")];
        evidence.push(format!(
            "pip reported {} configuration paths ({existing} existing)",
            debug.paths.len()
        ));
        if debug.environment.contains_key("PIP_INDEX_URL") {
            evidence.push("PIP_INDEX_URL is present and overrides configuration files".into());
        }
        if debug.environment.contains_key("PIP_CONFIG_FILE") {
            evidence.push("PIP_CONFIG_FILE is present and loads after site configuration".into());
        }
        Ok(Some(DetectedTool {
            tool_id: "pip".into(),
            executable: Some(PathBuf::from(format!("/usr/bin/{command}"))),
            version: (!version.is_empty()).then_some(version),
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
        let command = pip_command(runtime).ok_or_else(|| {
            AdapterError::Runtime("pip command disappeared after detection".into())
        })?;
        let debug_text = run_text(runtime, command, &["config", "debug"], "pip config debug")?;
        let debug = parse_debug(&debug_text)?;
        let selected_path = selected_path(&debug, runtime, scope)?;
        let mut paths = debug.paths.clone();
        if !paths.iter().any(|path| path.path == selected_path) {
            paths.push(DebugPath {
                scope: origin_scope(scope),
                path: selected_path.clone(),
                exists: false,
            });
        }
        validate_paths(&paths)?;

        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = environment_sources(&debug);
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
            sources.extend(configured_sources(
                utf8(&item.path, &contents)?,
                item.scope,
                &item.path,
            )?);
            documents.push(ConfigurationDocument {
                path: item.path.clone(),
                format: if item.path == selected_path {
                    "pip-selected-config".into()
                } else {
                    "pip-config-read-only".into()
                },
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "pip".into(),
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
            tool_id: "pip".into(),
            adapter_key: "pip".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![PYPI_UPSTREAM.into()],
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
            allowed_delivery_modes: vec![DeliveryMode::Mirror, DeliveryMode::Proxy],
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
        validate_precedence(current, endpoint)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "pip-selected-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected pip config document is missing".into())
            })?;
        let text = utf8(&document.path, &document.contents)?;
        require_tls_policy(current, endpoint)?;
        let new_contents = rewrite_primary_index(text, endpoint)?.into_bytes();
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "set one complete PyPI primary index in {} scope; preserve every extra index and never add trusted-host",
                    scope_name(current.scope)
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "pip".into(),
            tool_id: "pip".into(),
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
            let command = pip_command(runtime).ok_or_else(|| {
                AdapterError::Runtime("pip command disappeared before verification".into())
            })?;
            run_text(runtime, command, &["config", "debug"], "pip config debug")?;
            let list = run_text(runtime, command, &["config", "list"], "pip config list")?;
            let effective = parse_config_list(&list)?;
            if effective.contains_key(":env:.index-url") {
                return Err(AdapterError::Verification(
                    "PIP_INDEX_URL overrides the applied pip config".into(),
                ));
            }
            let index = effective.get("global.index-url").ok_or_else(|| {
                AdapterError::Verification("pip has no effective global.index-url".into())
            })?;
            if !is_known_mirror(index) {
                return Err(AdapterError::Verification(
                    "pip effective primary index is not a reviewed mirror".into(),
                ));
            }
            let query = runtime.run(
                command,
                &[
                    "index".into(),
                    "versions".into(),
                    "sampleproject".into(),
                    "--disable-pip-version-check".into(),
                    "--no-cache-dir".into(),
                ],
            )?;
            if !query.status.success()
                || !String::from_utf8_lossy(&query.stdout)
                    .to_ascii_lowercase()
                    .contains("sampleproject")
            {
                return Err(AdapterError::Verification(format!(
                    "pip index query failed with status {}",
                    query.status
                )));
            }
            Ok(VerificationResult {
                valid: true,
                summary:
                    "pip config debug/list and a real Simple API query validated the primary index"
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
                "restored {} pip configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginScope {
    System,
    User,
    Site,
    Environment,
}

#[derive(Clone, Debug)]
struct DebugPath {
    scope: OriginScope,
    path: PathBuf,
    exists: bool,
}

#[derive(Clone, Debug, Default)]
struct DebugInfo {
    paths: Vec<DebugPath>,
    environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct IniEntry {
    section: String,
    key: String,
    value: String,
    value_range: Range<usize>,
    multiline: bool,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "pip adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn pip_command(runtime: &dyn Runtime) -> Option<&'static str> {
    ["pip", "pip3"]
        .into_iter()
        .find(|command| runtime.command_exists(command))
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if !matches!(
        scope,
        ConfigurationScope::System | ConfigurationScope::User | ConfigurationScope::Site
    ) {
        return Err(AdapterError::Unsupported(
            "pip supports global, user, and site config scopes; environment sources are read-only"
                .into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "pip" {
        return Err(AdapterError::InvalidConfiguration(
            "pip operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn run_text(
    runtime: &dyn Runtime,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = runtime.run(program, &arguments)?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 output")))
}

fn parse_debug(text: &str) -> Result<DebugInfo, AdapterError> {
    let mut debug = DebugInfo::default();
    let mut section = None;
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if !raw_line.starts_with(char::is_whitespace) && trimmed.ends_with(':') {
            section = match trimmed.trim_end_matches(':') {
                "env_var" => Some(OriginScope::Environment),
                "env" => Some(OriginScope::Environment),
                "global" => Some(OriginScope::System),
                "user" => Some(OriginScope::User),
                "site" => Some(OriginScope::Site),
                _ => None,
            };
            continue;
        }
        let Some(scope) = section else {
            continue;
        };
        if scope == OriginScope::Environment && trimmed.starts_with("PIP_") {
            if let Some((key, value)) = trimmed.split_once('=') {
                debug.environment.insert(key.into(), unquote_debug(value)?);
            }
            continue;
        }
        let Some((path, exists)) = trimmed.rsplit_once(", exists: ") else {
            continue;
        };
        let exists = match exists {
            "True" => true,
            "False" => false,
            _ => {
                return Err(AdapterError::InvalidConfiguration(
                    "pip config debug returned an invalid exists flag".into(),
                ));
            }
        };
        debug.paths.push(DebugPath {
            scope,
            path: PathBuf::from(path),
            exists,
        });
    }
    Ok(debug)
}

fn unquote_debug(value: &str) -> Result<String, AdapterError> {
    let value = value.trim();
    if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .or_else(|| {
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
        })
    {
        return Ok(inner.into());
    }
    if value.starts_with(['\'', '"']) || value.ends_with(['\'', '"']) {
        return Err(AdapterError::InvalidConfiguration(
            "pip config debug returned an unterminated environment value".into(),
        ));
    }
    Ok(value.into())
}

fn validate_paths(paths: &[DebugPath]) -> Result<(), AdapterError> {
    if paths.iter().any(|item| {
        !item.path.is_absolute()
            || item
                .path
                .components()
                .any(|component| component == Component::ParentDir)
    }) {
        return Err(AdapterError::InvalidConfiguration(
            "pip config debug returned an unsafe configuration path".into(),
        ));
    }
    Ok(())
}

fn selected_path(
    debug: &DebugInfo,
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<PathBuf, AdapterError> {
    let origin = origin_scope(scope);
    if let Some(path) = debug
        .paths
        .iter()
        .rev()
        .find(|path| path.scope == origin)
        .map(|path| path.path.clone())
    {
        return Ok(path);
    }
    match scope {
        ConfigurationScope::System => Ok(PathBuf::from("/etc/pip.conf")),
        ConfigurationScope::User => runtime
            .home_dir()
            .map(|home| home.join(".config/pip/pip.conf"))
            .ok_or_else(|| {
                AdapterError::Unsupported("pip user scope requires a home directory".into())
            }),
        ConfigurationScope::Site => Err(AdapterError::Unsupported(
            "pip did not report a site configuration path".into(),
        )),
        _ => unreachable!("validated pip scope"),
    }
}

fn origin_scope(scope: ConfigurationScope) -> OriginScope {
    match scope {
        ConfigurationScope::System => OriginScope::System,
        ConfigurationScope::User => OriginScope::User,
        ConfigurationScope::Site => OriginScope::Site,
        _ => unreachable!("validated pip scope"),
    }
}

fn environment_sources(debug: &DebugInfo) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(url) = debug.environment.get("PIP_INDEX_URL") {
        sources.push(source(url, "index-url", OriginScope::Environment, ":env:"));
    }
    if let Some(urls) = debug.environment.get("PIP_EXTRA_INDEX_URL") {
        sources.extend(
            urls.split_whitespace()
                .map(|url| source(url, "extra-index-url", OriginScope::Environment, ":env:")),
        );
    }
    if let Some(hosts) = debug.environment.get("PIP_TRUSTED_HOST") {
        sources.extend(hosts.split_whitespace().map(|host| {
            source(
                &format!("https://{host}/"),
                "trusted-host",
                OriginScope::Environment,
                ":env:",
            )
        }));
    }
    if debug.environment.contains_key("PIP_CONFIG_FILE") {
        sources.push(source(
            "<redacted>",
            "config-file",
            OriginScope::Environment,
            ":env:",
        ));
    }
    sources
}

fn configured_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    for entry in parse_ini(text)? {
        match entry.key.as_str() {
            "index-url" => sources.push(source(&entry.value, "index-url", scope, &entry.section)),
            "extra-index-url" => sources.extend(
                entry
                    .value
                    .split_whitespace()
                    .map(|url| source(url, "extra-index-url", scope, &entry.section)),
            ),
            "trusted-host" => sources.extend(entry.value.split_whitespace().map(|host| {
                source(
                    &format!("https://{host}/"),
                    "trusted-host",
                    scope,
                    &entry.section,
                )
            })),
            _ => {}
        }
    }
    for source in &mut sources {
        source
            .metadata
            .insert("config_path".into(), vec![path.display().to_string()]);
    }
    Ok(sources)
}

fn source(url: &str, kind: &str, scope: OriginScope, section: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: is_pypi_index(url).then(|| PYPI_UPSTREAM.into()),
        url: url.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin_scope".into(), vec![origin_name(scope).into()]),
            ("section".into(), vec![section.into()]),
        ]),
    }
}

fn parse_ini(text: &str) -> Result<Vec<IniEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut pending: Option<IniEntry> = None;
    let mut section = None;
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        let continuation = line.starts_with(char::is_whitespace)
            && pending.is_some()
            && !trimmed.starts_with(['#', ';', '[']);
        if continuation {
            if !trimmed.is_empty() {
                let entry = pending.as_mut().unwrap();
                entry.value.push(' ');
                entry.value.push_str(trimmed);
                entry.multiline = true;
            }
            offset += inclusive.len();
            continue;
        }
        if let Some(entry) = pending.take() {
            entries.push(entry);
        }
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            offset += inclusive.len();
            continue;
        }
        if trimmed.starts_with('[') {
            let name = trimmed
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "pip config contains a malformed section header".into(),
                    )
                })?;
            section = Some(name.to_ascii_lowercase());
            offset += inclusive.len();
            continue;
        }
        let current = section.as_ref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("pip config option appears before a section".into())
        })?;
        let delimiter = line.find('=').or_else(|| line.find(':')).ok_or_else(|| {
            AdapterError::InvalidConfiguration("pip config option has no delimiter".into())
        })?;
        let key = line[..delimiter]
            .trim()
            .to_ascii_lowercase()
            .replace('_', "-");
        if key.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "pip config contains an empty option name".into(),
            ));
        }
        let raw_value = &line[delimiter + 1..];
        let leading = raw_value.len() - raw_value.trim_start().len();
        let value = raw_value.trim().to_owned();
        let start = offset + delimiter + 1 + leading;
        pending = Some(IniEntry {
            section: current.clone(),
            key,
            value,
            value_range: start..start + raw_value.trim().len(),
            multiline: false,
        });
        offset += inclusive.len();
    }
    if let Some(entry) = pending {
        entries.push(entry);
    }
    Ok(entries)
}

fn validate_precedence(
    current: &CurrentConfiguration,
    _endpoint: &str,
) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        let origin = metadata(source, "origin_scope")?;
        let section = metadata(source, "section")?;
        if kind == "config-file" || (kind == "index-url" && origin == "environment") {
            return Err(AdapterError::Unsupported(
                "pip environment overrides must be removed or changed outside MirrorSwitch before editing a config scope"
                    .into(),
            ));
        }
        if kind == "index-url" && section != "global" {
            return Err(AdapterError::Unsupported(format!(
                "pip command-specific [{section}] index-url would override the global primary index"
            )));
        }
        if kind == "index-url" && scope_rank(origin)? > scope_rank(scope_name(current.scope))? {
            return Err(AdapterError::Unsupported(format!(
                "pip {origin} index-url has higher precedence than selected {} scope",
                scope_name(current.scope)
            )));
        }
    }
    Ok(())
}

fn require_tls_policy(current: &CurrentConfiguration, endpoint: &str) -> Result<(), AdapterError> {
    let selected_host = reqwest::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .expect("reviewed pip endpoint has a host");
    for source in &current.sources {
        if metadata(source, "kind")? != "trusted-host" {
            continue;
        }
        if reqwest::Url::parse(&source.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
            .as_deref()
            == Some(selected_host.as_str())
        {
            return Err(AdapterError::InvalidConfiguration(
                "selected pip mirror is present in trusted-host; TLS verification must stay enabled"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn rewrite_primary_index(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let entries = parse_ini(text)?;
    let matching = entries
        .iter()
        .filter(|entry| entry.section == "global" && entry.key == "index-url")
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "pip [global] contains multiple index-url options".into(),
        ));
    }
    if let Some(entry) = matching.first() {
        if entry.multiline || entry.value.split_whitespace().count() != 1 {
            return Err(AdapterError::InvalidConfiguration(
                "pip primary index-url must contain exactly one URL".into(),
            ));
        }
        if !is_pypi_index(&entry.value) {
            return Err(AdapterError::Unsupported(
                "pip selected scope has a private or unmapped primary index".into(),
            ));
        }
        let mut rewritten = text.to_owned();
        rewritten.replace_range(entry.value_range.clone(), endpoint);
        return Ok(rewritten);
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    if let Some(offset) = global_header_end(text) {
        let prefix = if !text[..offset].ends_with(['\n', '\r']) {
            newline
        } else {
            ""
        };
        let mut rewritten = text.to_owned();
        rewritten.insert_str(offset, &format!("{prefix}index-url = {endpoint}{newline}"));
        return Ok(rewritten);
    }
    let mut rewritten = text.to_owned();
    if !rewritten.is_empty() && !rewritten.ends_with(['\n', '\r']) {
        rewritten.push_str(newline);
    }
    if !rewritten.is_empty() && !rewritten.ends_with(&format!("{newline}{newline}")) {
        rewritten.push_str(newline);
    }
    rewritten.push_str(&format!("[global]{newline}index-url = {endpoint}{newline}"));
    Ok(rewritten)
}

fn global_header_end(text: &str) -> Option<usize> {
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        offset += inclusive.len();
        if inclusive.trim() == "[global]" {
            return Some(offset);
        }
    }
    None
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "pip"
        || selections[0].upstream_id != PYPI_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "pip plan requires exactly one PyPI selection".into(),
        ));
    }
    let endpoint = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("pip selection has no HTTPS index endpoint".into())
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "pip selection is not a reviewed complete Simple API endpoint".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn is_pypi_index(value: &str) -> bool {
    let normalized = normalize_index(value).unwrap_or_default();
    OFFICIAL_INDEXES.contains(&normalized) || MIRROR_INDEXES.contains(&normalized)
}

fn is_known_mirror(value: &str) -> bool {
    let normalized = normalize_index(value).unwrap_or_default();
    MIRROR_INDEXES.contains(&normalized)
}

fn normalize_index(value: &str) -> Option<&str> {
    let value = value.trim().trim_end_matches('/');
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
    Some(value)
}

fn parse_config_list(text: &str) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut values = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            AdapterError::Verification("pip config list returned a malformed entry".into())
        })?;
        values.insert(key.trim().into(), unquote_debug(raw_value)?);
    }
    Ok(values)
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("pip source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "pip source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn scope_rank(scope: &str) -> Result<u8, AdapterError> {
    match scope {
        "system" => Ok(0),
        "user" => Ok(1),
        "site" => Ok(2),
        "environment" => Ok(3),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "unknown pip scope {scope}"
        ))),
    }
}

fn scope_name(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::System => "system",
        ConfigurationScope::User => "user",
        ConfigurationScope::Site => "site",
        _ => unreachable!("validated pip scope"),
    }
}

fn origin_name(scope: OriginScope) -> &'static str {
    match scope {
        OriginScope::System => "system",
        OriginScope::User => "user",
        OriginScope::Site => "site",
        OriginScope::Environment => "environment",
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
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "pip configuration {} is not UTF-8",
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
