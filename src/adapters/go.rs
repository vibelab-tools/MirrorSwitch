use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use serde_json::Value;

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

const GO_PROXY_UPSTREAM: &str = "goproxy--language-registry";
const REVIEWED_MODULE: &str = "github.com/pkg/errors";
const REVIEWED_VERSION: &str = "v0.9.1";
const MIRROR_PROXIES: &[&str] = &["https://mirrors.aliyun.com/goproxy"];
const REPLACEABLE_PUBLIC_PROXIES: &[&str] = &[
    "https://proxy.golang.org",
    "https://proxy.golang.com.cn",
    "https://goproxy.cn",
    "https://mirrors.aliyun.com/goproxy",
    "https://repo.huaweicloud.com/repository/goproxy",
    "https://repo.nju.edu.cn/go",
];
const ENV_KEYS: &[&str] = &[
    "GOENV",
    "GO111MODULE",
    "GOPROXY",
    "GOSUMDB",
    "GOPRIVATE",
    "GONOPROXY",
    "GONOSUMDB",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct GoAdapter;

impl Adapter for GoAdapter {
    fn key(&self) -> &'static str {
        "go"
    }

    fn tool_id(&self) -> &'static str {
        "go"
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
        if !runtime.command_exists("go") {
            return Ok(None);
        }
        let version_output = run_go(runtime, &["version"], "go version")?;
        let version = go_version(&version_output)?;
        reviewed_version(&version)?;
        let snapshot = go_env(runtime)?;
        let path = goenv_path(runtime, &snapshot)?;
        let chain = ProxyChain::parse(snapshot.required("GOPROXY")?)?;
        let separators = chain.separator_summary();
        let mut evidence = vec![
            format!("go {version}"),
            format!("persistent go environment is {}", path.display()),
            format!(
                "effective GOPROXY has {} entries with {separators} fallback semantics",
                chain.entries.len()
            ),
            format!(
                "GOSUMDB is {}",
                if snapshot.required("GOSUMDB")? == "off" {
                    "disabled"
                } else {
                    "enabled"
                }
            ),
        ];
        for key in ["GOPRIVATE", "GONOPROXY", "GONOSUMDB"] {
            evidence.push(format!(
                "{key} is {}",
                if snapshot.required(key)?.is_empty() {
                    "unset"
                } else {
                    "set"
                }
            ));
        }
        evidence.push(format!(
            "GOPROXY process override is {}",
            if environment_override(runtime, "GOPROXY") {
                "set"
            } else {
                "unset"
            }
        ));
        Ok(Some(DetectedTool {
            tool_id: "go".into(),
            executable: Some(PathBuf::from("go")),
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
        if scope != ConfigurationScope::User {
            return Err(AdapterError::Unsupported(
                "Go Modules only supports the persistent user GOENV file".into(),
            ));
        }
        reviewed_version(
            detected.version.as_deref().ok_or_else(|| {
                AdapterError::InvalidConfiguration("Go version is missing".into())
            })?,
        )?;
        let snapshot = go_env(runtime)?;
        let path = goenv_path(runtime, &snapshot)?;
        let observed = runtime.read(&path)?;
        let exists = observed.is_some();
        let contents = observed.unwrap_or_default();
        let text = utf8(&path, &contents)?;
        let persisted = persisted_proxy(text, &path)?;
        let effective = snapshot.required("GOPROXY")?;
        if !environment_override(runtime, "GOPROXY")
            && persisted.is_some_and(|value| value != effective)
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} GOPROXY does not match the value reported by go env",
                path.display()
            )));
        }
        let chain = ProxyChain::parse(effective)?;
        let mut sources = chain.sources(&path);
        if environment_override(runtime, "GOPROXY") {
            sources.push(policy_source("environment-goproxy-override", &path));
        }
        add_policy_sources(&mut sources, &snapshot, &path)?;
        Ok(CurrentConfiguration {
            tool_id: "go".into(),
            scope,
            sources,
            files: exists.then_some(path.clone()).into_iter().collect(),
            documents: vec![ConfigurationDocument {
                path,
                format: "go-selected-env".into(),
                contents,
            }],
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
        reviewed_version(
            detected.version.as_deref().ok_or_else(|| {
                AdapterError::InvalidConfiguration("Go version is missing".into())
            })?,
        )?;
        validate_policy(current)?;
        replaceable_public_index(&effective_chain(current)?)?;
        Ok(SelectionRequest {
            tool_id: "go".into(),
            adapter_key: "go".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![GO_PROXY_UPSTREAM.into()],
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
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let chain = effective_chain(current)?;
        let replaced = chain.replace_public(endpoint)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "go-selected-env")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected GOENV document is missing".into())
            })?;
        let old = utf8(&document.path, &document.contents)?;
        let new_contents = rewrite_goenv(old, &replaced.render(), &document.path)?.into_bytes();
        let preserved = chain.entries.len().saturating_sub(1);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current
                    .files
                    .contains(&document.path)
                    .then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "replace exactly one public GOPROXY entry in {}; preserve {preserved} enterprise/direct/off entries, every comma/pipe separator, GOPRIVATE, GONOPROXY, GONOSUMDB and GOSUMDB",
                    document.path.display()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "go".into(),
            tool_id: "go".into(),
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
            let snapshot = go_env(runtime)?;
            validate_snapshot_policy(runtime, &snapshot)?;
            let path = goenv_path(runtime, &snapshot)?;
            let target = rooted(&context.root, &path);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "Go transaction receipt does not contain the selected GOENV file".into(),
                ));
            }
            let contents = runtime.read(&path)?.ok_or_else(|| {
                AdapterError::Verification("selected GOENV file disappeared".into())
            })?;
            let persisted = persisted_proxy(utf8(&path, &contents)?, &path)?.ok_or_else(|| {
                AdapterError::Verification("selected GOENV file has no GOPROXY entry".into())
            })?;
            if persisted != snapshot.required("GOPROXY")? {
                return Err(AdapterError::Verification(
                    "go env did not load the persisted GOPROXY value".into(),
                ));
            }
            let chain = ProxyChain::parse(persisted)?;
            let public = replaceable_public_index(&chain)?;
            let endpoint = normalized_url(&chain.entries[public].value)
                .filter(|value| MIRROR_PROXIES.contains(&value.as_str()))
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "effective GOPROXY public entry is not a reviewed mirror".into(),
                    )
                })?;
            let output = run_go(
                runtime,
                &[
                    "mod",
                    "download",
                    "-json",
                    &format!("{REVIEWED_MODULE}@{REVIEWED_VERSION}"),
                ],
                "go mod download checksum verification",
            )?;
            verify_download(&output)?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "go env loaded {endpoint}; {REVIEWED_MODULE}@{REVIEWED_VERSION} passed module and checksum verification"
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
                "restored {} Go environment file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GoEnvSnapshot {
    values: BTreeMap<String, String>,
}

impl GoEnvSnapshot {
    fn required(&self, key: &str) -> Result<&str, AdapterError> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| AdapterError::Runtime(format!("go env JSON is missing {key}")))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyChain {
    entries: Vec<ProxyEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyEntry {
    value: String,
    separator_after: Option<char>,
}

impl ProxyChain {
    fn parse(value: &str) -> Result<Self, AdapterError> {
        if value.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "GOPROXY is empty".into(),
            ));
        }
        let mut entries = Vec::new();
        let mut start = 0;
        for (index, character) in value.char_indices() {
            if !matches!(character, ',' | '|') {
                continue;
            }
            entries.push(proxy_entry(&value[start..index], Some(character))?);
            start = index + character.len_utf8();
        }
        entries.push(proxy_entry(&value[start..], None)?);
        Ok(Self { entries })
    }

    fn render(&self) -> String {
        let mut rendered = String::new();
        for entry in &self.entries {
            rendered.push_str(&entry.value);
            if let Some(separator) = entry.separator_after {
                rendered.push(separator);
            }
        }
        rendered
    }

    fn replace_public(&self, endpoint: &str) -> Result<Self, AdapterError> {
        let index = replaceable_public_index(self)?;
        let mut replaced = self.clone();
        replaced.entries[index].value = endpoint.trim_end_matches('/').into();
        Ok(replaced)
    }

    fn separator_summary(&self) -> &'static str {
        let comma = self
            .entries
            .iter()
            .any(|entry| entry.separator_after == Some(','));
        let pipe = self
            .entries
            .iter()
            .any(|entry| entry.separator_after == Some('|'));
        match (comma, pipe) {
            (true, true) => "comma and pipe",
            (true, false) => "comma",
            (false, true) => "pipe",
            (false, false) => "single-source",
        }
    }

    fn sources(&self, path: &Path) -> Vec<ConfiguredSource> {
        self.entries
            .iter()
            .enumerate()
            .map(|(position, entry)| {
                let kind = match entry.value.as_str() {
                    "direct" => "proxy-direct",
                    "off" => "proxy-off",
                    _ => "proxy-url",
                };
                ConfiguredSource {
                    upstream_id: (kind == "proxy-url" && is_replaceable_public(&entry.value))
                        .then(|| GO_PROXY_UPSTREAM.into()),
                    url: entry.value.clone(),
                    enabled: true,
                    metadata: BTreeMap::from([
                        ("kind".into(), vec![kind.into()]),
                        ("position".into(), vec![position.to_string()]),
                        (
                            "separator_after".into(),
                            vec![
                                entry
                                    .separator_after
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "none".into()),
                            ],
                        ),
                        ("config_path".into(), vec![path.display().to_string()]),
                    ]),
                }
            })
            .collect()
    }
}

fn proxy_entry(value: &str, separator_after: Option<char>) -> Result<ProxyEntry, AdapterError> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(AdapterError::InvalidConfiguration(
            "GOPROXY contains an empty or whitespace-bearing entry".into(),
        ));
    }
    if !matches!(value, "direct" | "off") {
        validate_proxy_url(value)?;
    }
    Ok(ProxyEntry {
        value: value.into(),
        separator_after,
    })
}

fn validate_proxy_url(value: &str) -> Result<(), AdapterError> {
    let with_scheme = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let parsed = reqwest::Url::parse(&with_scheme).map_err(|_| {
        AdapterError::InvalidConfiguration("GOPROXY contains an invalid URL".into())
    })?;
    if !matches!(parsed.scheme(), "https" | "http" | "file")
        || parsed.host_str().is_none() && parsed.scheme() != "file"
        || parsed.fragment().is_some()
    {
        return Err(AdapterError::InvalidConfiguration(
            "GOPROXY contains an unsupported URL".into(),
        ));
    }
    Ok(())
}

fn go_env(runtime: &dyn Runtime) -> Result<GoEnvSnapshot, AdapterError> {
    let mut arguments = vec!["env", "-json"];
    arguments.extend(ENV_KEYS.iter().copied());
    let output = run_go(runtime, &arguments, "go env -json")?;
    let values: BTreeMap<String, String> = serde_json::from_str(&output)
        .map_err(|error| AdapterError::Runtime(format!("go env returned invalid JSON: {error}")))?;
    for key in ENV_KEYS {
        if !values.contains_key(*key) {
            return Err(AdapterError::Runtime(format!(
                "go env JSON is missing {key}"
            )));
        }
    }
    Ok(GoEnvSnapshot { values })
}

fn run_go(
    runtime: &dyn Runtime,
    arguments: &[&str],
    description: &str,
) -> Result<String, AdapterError> {
    let output = runtime.run(
        "go",
        &arguments
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{description} failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{description} returned non-UTF-8 stdout")))
}

fn go_version(output: &str) -> Result<String, AdapterError> {
    output
        .split_whitespace()
        .find_map(|token| {
            token
                .strip_prefix("go")
                .filter(|value| value.starts_with('1'))
        })
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("go version output is unrecognized".into()))
}

fn reviewed_version(value: &str) -> Result<(), AdapterError> {
    let parts = value.split('.').collect::<Vec<_>>();
    let valid = matches!(parts.len(), 2 | 3)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    let major = parts.first().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.get(1).and_then(|part| part.parse::<u64>().ok());
    if !valid || major != Some(1) || minor.is_none_or(|minor| minor < 13) {
        return Err(AdapterError::Unsupported(format!(
            "Go {value} is outside the reviewed stable 1.13+ module environment model"
        )));
    }
    Ok(())
}

fn goenv_path(runtime: &dyn Runtime, snapshot: &GoEnvSnapshot) -> Result<PathBuf, AdapterError> {
    let value = snapshot.required("GOENV")?;
    if value.is_empty() || value == "off" {
        return Err(AdapterError::Unsupported(
            "Go persistent environment is disabled or unavailable".into(),
        ));
    }
    let path = PathBuf::from(value);
    validate_path(&path, "GOENV")?;
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Go requires a detected user home".into()))?;
    validate_path(&home, "home")?;
    if !path.starts_with(&home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "GOENV {} is outside the selected user home",
            path.display()
        )));
    }
    Ok(path)
}

fn persisted_proxy<'a>(text: &'a str, path: &Path) -> Result<Option<&'a str>, AdapterError> {
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix("GOPROXY="))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => {
            ProxyChain::parse(value)?;
            Ok(Some(value))
        }
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "{} contains duplicate GOPROXY entries",
            path.display()
        ))),
    }
}

fn rewrite_goenv(text: &str, value: &str, path: &Path) -> Result<String, AdapterError> {
    persisted_proxy(text, path)?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut replaced = false;
    let mut result = String::new();
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.starts_with("GOPROXY=") {
            result.push_str("GOPROXY=");
            result.push_str(value);
            result.push_str(if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            });
            replaced = true;
        } else {
            result.push_str(line);
        }
    }
    if !replaced {
        if !result.is_empty() && !result.ends_with('\n') {
            result.push_str(newline);
        }
        result.push_str("GOPROXY=");
        result.push_str(value);
        result.push_str(newline);
    }
    Ok(result)
}

fn effective_chain(current: &CurrentConfiguration) -> Result<ProxyChain, AdapterError> {
    let mut positioned = current
        .sources
        .iter()
        .filter_map(|source| {
            let kind = metadata(source, "kind")?;
            matches!(kind, "proxy-url" | "proxy-direct" | "proxy-off").then_some(source)
        })
        .map(|source| {
            let position = metadata(source, "position")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "GOPROXY source position metadata is invalid".into(),
                    )
                })?;
            let separator_after = match metadata(source, "separator_after") {
                Some(",") => Some(','),
                Some("|") => Some('|'),
                Some("none") => None,
                _ => {
                    return Err(AdapterError::InvalidConfiguration(
                        "GOPROXY separator metadata is invalid".into(),
                    ));
                }
            };
            Ok((
                position,
                ProxyEntry {
                    value: source.url.clone(),
                    separator_after,
                },
            ))
        })
        .collect::<Result<Vec<_>, AdapterError>>()?;
    positioned.sort_by_key(|(position, _)| *position);
    if positioned.is_empty()
        || positioned
            .iter()
            .enumerate()
            .any(|(expected, (actual, _))| expected != *actual)
    {
        return Err(AdapterError::InvalidConfiguration(
            "GOPROXY source ordering metadata is incomplete".into(),
        ));
    }
    let chain = ProxyChain {
        entries: positioned.into_iter().map(|(_, entry)| entry).collect(),
    };
    ProxyChain::parse(&chain.render())
}

fn replaceable_public_index(chain: &ProxyChain) -> Result<usize, AdapterError> {
    let matches = chain
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| is_replaceable_public(&entry.value))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(AdapterError::InvalidConfiguration(
            "GOPROXY has no recognized public proxy entry to replace without changing enterprise fallback policy"
                .into(),
        )),
        _ => Err(AdapterError::InvalidConfiguration(
            "GOPROXY has multiple public proxy entries; replacing one would leave ambiguous public fallback policy"
                .into(),
        )),
    }
}

fn is_replaceable_public(value: &str) -> bool {
    normalized_url(value).is_some_and(|url| REPLACEABLE_PUBLIC_PROXIES.contains(&url.as_str()))
}

fn normalized_url(value: &str) -> Option<String> {
    let with_scheme = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let parsed = reqwest::Url::parse(&with_scheme).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(with_scheme.trim_end_matches('/').to_ascii_lowercase())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let selected = selections
        .iter()
        .filter(|selection| selection.tool_id == "go" && selection.upstream_id == GO_PROXY_UPSTREAM)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Go Modules requires exactly one GOPROXY selection".into(),
        ));
    }
    let endpoints = selected[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    if endpoints.len() != 1
        || !normalized_url(&endpoints[0].url)
            .is_some_and(|url| MIRROR_PROXIES.contains(&url.as_str()))
    {
        return Err(AdapterError::InvalidConfiguration(
            "Go Modules selection has no single reviewed HTTPS GOPROXY endpoint".into(),
        ));
    }
    Ok(endpoints[0].url.trim_end_matches('/'))
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind") {
            Some("environment-goproxy-override") => {
                return Err(AdapterError::InvalidConfiguration(
                    "the GOPROXY process environment overrides persistent GOENV configuration"
                        .into(),
                ));
            }
            Some("module-mode-off") => {
                return Err(AdapterError::InvalidConfiguration(
                    "GO111MODULE=off disables the Go Modules proxy model".into(),
                ));
            }
            Some("checksum-disabled") => {
                return Err(AdapterError::InvalidConfiguration(
                    "public module checksum verification is disabled".into(),
                ));
            }
            Some("public-proxy-bypassed") => {
                return Err(AdapterError::InvalidConfiguration(
                    "GONOPROXY/GOPRIVATE bypasses GOPROXY for all public modules".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_snapshot_policy(
    runtime: &dyn Runtime,
    snapshot: &GoEnvSnapshot,
) -> Result<(), AdapterError> {
    let mut sources = Vec::new();
    if environment_override(runtime, "GOPROXY") {
        sources.push(policy_source(
            "environment-goproxy-override",
            Path::new(":env:"),
        ));
    }
    add_policy_sources(&mut sources, snapshot, Path::new(":env:"))?;
    validate_policy(&CurrentConfiguration {
        tool_id: "go".into(),
        scope: ConfigurationScope::User,
        files: Vec::new(),
        sources,
        documents: Vec::new(),
    })
}

fn add_policy_sources(
    sources: &mut Vec<ConfiguredSource>,
    snapshot: &GoEnvSnapshot,
    path: &Path,
) -> Result<(), AdapterError> {
    if snapshot.required("GO111MODULE")? == "off" {
        sources.push(policy_source("module-mode-off", path));
    }
    let private_covers_all = patterns_cover_all(snapshot.required("GOPRIVATE")?);
    let no_sumdb = snapshot.required("GONOSUMDB")?;
    let sumdb = snapshot.required("GOSUMDB")?;
    if sumdb.is_empty()
        || sumdb == "off"
        || patterns_cover_all(no_sumdb)
        || (no_sumdb.is_empty() && private_covers_all)
    {
        sources.push(policy_source("checksum-disabled", path));
    } else {
        sources.push(policy_source("checksum-enabled", path));
    }
    let no_proxy = snapshot.required("GONOPROXY")?;
    if patterns_cover_all(no_proxy) || (no_proxy.is_empty() && private_covers_all) {
        sources.push(policy_source("public-proxy-bypassed", path));
    }
    for key in ["GOPRIVATE", "GONOPROXY", "GONOSUMDB"] {
        if !snapshot.required(key)?.is_empty() {
            sources.push(policy_source(
                &format!("{}-preserved", key.to_ascii_lowercase()),
                path,
            ));
        }
    }
    Ok(())
}

fn patterns_cover_all(value: &str) -> bool {
    value.split(',').any(|pattern| pattern.trim() == "*")
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

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn environment_override(runtime: &dyn Runtime, key: &str) -> bool {
    runtime
        .environment_variable(key)
        .is_some_and(|value| !value.is_empty())
}

fn verify_download(output: &str) -> Result<(), AdapterError> {
    let value: Value = serde_json::from_str(output).map_err(|error| {
        AdapterError::Verification(format!("go mod download returned invalid JSON: {error}"))
    })?;
    if value.get("Error").is_some() {
        return Err(AdapterError::Verification(
            "go mod download reported a module error".into(),
        ));
    }
    let matches = value.get("Path").and_then(Value::as_str) == Some(REVIEWED_MODULE)
        && value.get("Version").and_then(Value::as_str) == Some(REVIEWED_VERSION)
        && value
            .get("Sum")
            .and_then(Value::as_str)
            .is_some_and(|sum| sum.starts_with("h1:") && sum.len() > 3)
        && value
            .get("GoModSum")
            .and_then(Value::as_str)
            .is_some_and(|sum| sum.starts_with("h1:") && sum.len() > 3);
    if !matches {
        return Err(AdapterError::Verification(
            "go mod download did not return the reviewed module version and checksum fields".into(),
        ));
    }
    Ok(())
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Go Modules on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Go Modules requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "go" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Go Modules plan requires the persistent user GOENV scope".into(),
        ));
    }
    Ok(())
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Go reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Go environment file {} is not UTF-8",
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
