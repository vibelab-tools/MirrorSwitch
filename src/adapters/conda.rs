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

const CONDA_UPSTREAM: &str = "anaconda--language-registry";
const MIRROR_BASES: &[&str] = &[
    "https://mirrors.nju.edu.cn/anaconda",
    "https://mirrors.tuna.tsinghua.edu.cn/anaconda",
    "https://mirrors.ustc.edu.cn/anaconda",
];
const CLIENTS: &[&str] = &["conda", "mamba", "micromamba"];

#[derive(Clone, Copy, Debug, Default)]
pub struct CondaAdapter;

impl Adapter for CondaAdapter {
    fn key(&self) -> &'static str {
        "conda"
    }

    fn tool_id(&self) -> &'static str {
        "conda"
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
        let mut evidence = Vec::new();
        let mut versions = Vec::new();
        let mut executable = None;
        for client in installed_clients(runtime) {
            let version = run_text(
                runtime,
                client,
                &["--version"],
                &format!("{client} --version"),
            )?;
            if executable.is_none() {
                executable = Some(PathBuf::from(client));
            }
            evidence.push(format!("detected {client}: {version}"));
            versions.push(format!("{client}={version}"));
        }
        if versions.is_empty() {
            return Ok(None);
        }
        Ok(Some(DetectedTool {
            tool_id: "conda".into(),
            executable,
            version: Some(versions.join("; ")),
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
        require_supported_context(context)?;
        require_scope(scope)?;
        let home = runtime.home_dir().ok_or_else(|| {
            AdapterError::Unsupported("Conda user scope requires a home directory".into())
        })?;
        validate_path(&home)?;
        let selected = home.join(".condarc");
        let mut paths = BTreeSet::from([selected.clone()]);
        for client in installed_clients(runtime) {
            for path in client_sources(runtime, client)? {
                validate_path(&path)?;
                paths.insert(path);
            }
        }
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = Vec::new();
        for path in paths {
            let observed = runtime.read(&path)?;
            let exists = observed.is_some();
            let contents = observed.unwrap_or_default();
            if exists {
                files.push(path.clone());
            }
            let origin = if path == selected {
                OriginScope::User
            } else if is_system_source(context, runtime, &path) {
                OriginScope::System
            } else {
                OriginScope::Environment
            };
            sources.extend(condarc_sources(utf8(&path, &contents)?, origin, &path)?);
            documents.push(ConfigurationDocument {
                path: path.clone(),
                format: if path == selected {
                    "conda-selected-config".into()
                } else {
                    "conda-config-read-only".into()
                },
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "conda".into(),
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
        let (subdir, package) = match (context.os, context.architecture) {
            (OperatingSystem::Linux, Architecture::X86_64) => {
                ("linux-64", "python-3.12.9-h5148396_0.conda")
            }
            (OperatingSystem::Linux, Architecture::Arm64) => {
                ("linux-aarch64", "python-3.12.9-h8edadfe_0.conda")
            }
            (OperatingSystem::Macos, Architecture::X86_64) => {
                ("osx-64", "python-3.12.9-hcd54a6c_0.conda")
            }
            (OperatingSystem::Macos, Architecture::Arm64) => {
                ("osx-arm64", "python-3.12.13-hd7e0f33_1.conda")
            }
            (OperatingSystem::Windows, Architecture::X86_64) => {
                ("win-64", "python-3.12.13-h63b1a2d_1.conda")
            }
            (OperatingSystem::Windows, Architecture::Arm64) => unreachable!("rejected context"),
        };
        Ok(SelectionRequest {
            tool_id: "conda".into(),
            adapter_key: "conda".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![CONDA_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                CONDA_UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("subdir".into(), subdir.into()),
                    ("representative_package".into(), package.into()),
                ])],
            )]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Index],
            allowed_delivery_modes: vec![DeliveryMode::Mirror],
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
        validate_precedence(current)?;
        validate_policy(current)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "conda-selected-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected .condarc document is missing".into())
            })?;
        let mut new_contents =
            rewrite_condarc(utf8(&document.path, &document.contents)?, endpoint)?.into_bytes();
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
                summary: "redirect Anaconda defaults and conda-forge to one compatible provider; preserve channel order, private channels, aliases, tokens, and channel priority".into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "conda".into(),
            tool_id: "conda".into(),
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
            let clients = installed_clients(runtime);
            if clients.is_empty() {
                return Err(AdapterError::Verification(
                    "all detected Conda-family clients disappeared".into(),
                ));
            }
            let mut verified = Vec::new();
            for client in clients {
                let config = if client == "conda" {
                    run_text(
                        runtime,
                        client,
                        &[
                            "config",
                            "--show",
                            "default_channels",
                            "custom_channels",
                            "--json",
                        ],
                        "conda effective config",
                    )?
                } else {
                    run_text(
                        runtime,
                        client,
                        &["config", "list", "--json"],
                        &format!("{client} effective config"),
                    )?
                };
                if !effective_config_has_reviewed_mirror(&config) {
                    return Err(AdapterError::Verification(format!(
                        "{client} effective config does not contain a reviewed mirror"
                    )));
                }
                let query = if client == "conda" {
                    run_text(
                        runtime,
                        client,
                        &["search", "python=3.12", "--json"],
                        "conda repodata query",
                    )?
                } else {
                    run_text(
                        runtime,
                        client,
                        &["repoquery", "search", "python=3.12", "--json"],
                        &format!("{client} repodata query"),
                    )?
                };
                let query = query.to_ascii_lowercase();
                if !query.contains("python") || !query.contains("3.12") {
                    return Err(AdapterError::Verification(format!(
                        "{client} repodata query returned no Python 3.12 package"
                    )));
                }
                verified.push(client);
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "effective sources and real repodata queries passed for {}",
                    verified.join(", ")
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
                "restored {} Conda configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

fn effective_config_has_reviewed_mirror(config: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(config)
        .is_ok_and(|value| json_contains_reviewed_mirror(&value))
}

fn json_contains_reviewed_mirror(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => MIRROR_BASES.iter().any(|base| {
            [*base, base.trim_start_matches("https://")]
                .iter()
                .any(|candidate| {
                    value == candidate
                        || value
                            .strip_prefix(candidate)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
        }),
        serde_json::Value::Array(values) => values.iter().any(json_contains_reviewed_mirror),
        serde_json::Value::Object(values) => values.values().any(json_contains_reviewed_mirror),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::effective_config_has_reviewed_mirror;

    #[test]
    fn effective_config_accepts_full_urls_and_conda_26_location_objects() {
        assert!(effective_config_has_reviewed_mirror(
            r#"{"default_channels":["https://mirrors.ustc.edu.cn/anaconda/pkgs/main"]}"#
        ));
        assert!(effective_config_has_reviewed_mirror(
            r#"{"custom_channels":{"conda-forge":{"location":"mirrors.ustc.edu.cn/anaconda/cloud"}}}"#
        ));
        assert!(!effective_config_has_reviewed_mirror(
            r#"{"location":"https://private.example/?next=mirrors.ustc.edu.cn/anaconda"}"#
        ));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginScope {
    System,
    User,
    Environment,
}

#[derive(Clone, Debug)]
struct Section {
    key: String,
    value: String,
    start: usize,
    body_start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct ValueEntry {
    key: Option<String>,
    value: String,
    range: Range<usize>,
    quote: Option<char>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Conda on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Conda adapter requires x86_64 or arm64".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "Conda has no native win-arm64 repository subdir; x64 emulation is not native support"
                .into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Conda shared .condarc supports user scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "conda" {
        return Err(AdapterError::InvalidConfiguration(
            "Conda operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn installed_clients(runtime: &dyn Runtime) -> Vec<&'static str> {
    CLIENTS
        .iter()
        .copied()
        .filter(|client| runtime.command_exists(client))
        .collect()
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
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 output")))
}

fn client_sources(runtime: &dyn Runtime, client: &str) -> Result<Vec<PathBuf>, AdapterError> {
    if client == "conda" {
        let output = run_text(
            runtime,
            client,
            &["config", "--show-sources", "--json"],
            "conda config sources",
        )?;
        let value: serde_json::Value = serde_json::from_str(&output).map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "conda config sources returned invalid JSON: {error}"
            ))
        })?;
        return Ok(value
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .collect());
    }
    let output = run_text(
        runtime,
        client,
        &["config", "sources"],
        &format!("{client} config sources"),
    )?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let path = PathBuf::from(line);
            if path.is_absolute() {
                Some(path)
            } else {
                line.strip_prefix("~/")
                    .and_then(|relative| runtime.home_dir().map(|home| home.join(relative)))
            }
        })
        .collect())
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Conda reported unsafe configuration path {}",
            path.display()
        )));
    }
    Ok(())
}

fn is_system_source(context: &SystemContext, runtime: &dyn Runtime, path: &Path) -> bool {
    match context.os {
        OperatingSystem::Linux => {
            path.starts_with("/etc") || path.starts_with("/opt") || path.starts_with("/usr")
        }
        OperatingSystem::Macos => path.starts_with("/Library") || path.starts_with("/etc"),
        OperatingSystem::Windows => ["ProgramData", "ProgramFiles", "ProgramFiles(x86)"]
            .into_iter()
            .filter_map(|name| runtime.environment_variable(name))
            .map(PathBuf::from)
            .any(|root| path.starts_with(root)),
    }
}

fn sections(text: &str) -> Result<Vec<Section>, AdapterError> {
    let mut found = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with(' ') {
            offset += inclusive.len();
            continue;
        }
        if line.starts_with('\t') {
            return Err(AdapterError::InvalidConfiguration(
                ".condarc uses a tab indentation".into(),
            ));
        }
        let Some(delimiter) = line.find(':') else {
            offset += inclusive.len();
            continue;
        };
        let key = yaml_scalar(line[..delimiter].trim())?.0;
        let value = yaml_scalar(line[delimiter + 1..].trim())?.0;
        found.push(Section {
            key,
            value,
            start: offset,
            body_start: offset + inclusive.len(),
            end: text.len(),
        });
        offset += inclusive.len();
    }
    for index in 0..found.len().saturating_sub(1) {
        found[index].end = found[index + 1].start;
    }
    let mut keys = BTreeSet::new();
    if found.iter().any(|section| !keys.insert(&section.key)) {
        return Err(AdapterError::InvalidConfiguration(
            ".condarc contains duplicate top-level keys".into(),
        ));
    }
    Ok(found)
}

fn list_entries(text: &str, section: &Section) -> Result<Vec<ValueEntry>, AdapterError> {
    if !section.value.is_empty() && section.value != "[]" {
        return Err(AdapterError::Unsupported(format!(
            ".condarc {} uses an inline or aliased list",
            section.key
        )));
    }
    let mut entries = Vec::new();
    let mut offset = section.body_start;
    for inclusive in text[section.body_start..section.end].split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.starts_with('-') {
            let raw = trimmed.trim_start_matches('-').trim_start();
            let value_start = line.find(raw).unwrap_or(line.len());
            let token = yaml_token(raw)?;
            let (value, quote) = yaml_scalar(token)?;
            entries.push(ValueEntry {
                key: None,
                value,
                range: offset + value_start..offset + value_start + token.len(),
                quote,
            });
        }
        offset += inclusive.len();
    }
    Ok(entries)
}

fn map_entries(text: &str, section: &Section) -> Result<Vec<ValueEntry>, AdapterError> {
    if !section.value.is_empty() && section.value != "{}" {
        return Err(AdapterError::Unsupported(format!(
            ".condarc {} uses an inline or aliased map",
            section.key
        )));
    }
    let mut entries = Vec::new();
    let mut offset = section.body_start;
    for inclusive in text[section.body_start..section.end].split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() || line.trim().starts_with('#') {
            offset += inclusive.len();
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if indent == 0 {
            break;
        }
        let trimmed = line.trim();
        let Some(delimiter) = trimmed.find(':') else {
            offset += inclusive.len();
            continue;
        };
        let key = yaml_scalar(trimmed[..delimiter].trim())?.0;
        let raw = trimmed[delimiter + 1..].trim_start();
        let token = yaml_token(raw)?;
        let (value, quote) = yaml_scalar(token)?;
        let value_start = line.find(raw).unwrap_or(line.len());
        entries.push(ValueEntry {
            key: Some(key),
            value,
            range: offset + value_start..offset + value_start + token.len(),
            quote,
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn yaml_scalar(value: &str) -> Result<(String, Option<char>), AdapterError> {
    let token = yaml_token(value.trim())?;
    for quote in ['\'', '"'] {
        if token.starts_with(quote) {
            let inner = token
                .strip_prefix(quote)
                .and_then(|value| value.strip_suffix(quote))
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        ".condarc contains an unterminated quoted scalar".into(),
                    )
                })?;
            return Ok((inner.into(), Some(quote)));
        }
    }
    Ok((token.into(), None))
}

fn yaml_token(value: &str) -> Result<&str, AdapterError> {
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
    for (index, character) in value.char_indices().skip(1) {
        if character == quote {
            let end = index + character.len_utf8();
            let trailing = value[end..].trim();
            if trailing.is_empty() || trailing.starts_with('#') {
                return Ok(&value[..end]);
            }
        }
    }
    Err(AdapterError::InvalidConfiguration(
        ".condarc contains an unterminated quoted scalar".into(),
    ))
}

fn condarc_sources(
    text: &str,
    scope: OriginScope,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    for section in sections(text)? {
        match section.key.as_str() {
            "channels" | "default_channels" => {
                let kind = if section.key == "channels" {
                    "channel"
                } else {
                    "default-channel"
                };
                for entry in list_entries(text, &section)? {
                    sources.push(configured_source(&entry.value, kind, scope, path, None));
                }
            }
            "custom_channels" => {
                for entry in map_entries(text, &section)? {
                    sources.push(configured_source(
                        &entry.value,
                        "custom-channel",
                        scope,
                        path,
                        entry.key.as_deref(),
                    ));
                }
            }
            "channel_alias" => sources.push(configured_source(
                &section.value,
                "channel-alias",
                scope,
                path,
                None,
            )),
            "channel_priority" => sources.push(configured_source(
                &section.value,
                "channel-priority",
                scope,
                path,
                None,
            )),
            "ssl_verify" => sources.push(configured_source(
                &section.value.to_ascii_lowercase(),
                "ssl-verify",
                scope,
                path,
                None,
            )),
            _ => {}
        }
    }
    Ok(sources)
}

fn configured_source(
    value: &str,
    kind: &str,
    scope: OriginScope,
    path: &Path,
    channel_name: Option<&str>,
) -> ConfiguredSource {
    let mut metadata = BTreeMap::from([
        ("kind".into(), vec![kind.into()]),
        ("origin_scope".into(), vec![origin_name(scope).into()]),
        ("config_path".into(), vec![path.display().to_string()]),
    ]);
    if let Some(channel_name) = channel_name {
        metadata.insert("channel_name".into(), vec![channel_name.into()]);
    }
    let public = is_public_conda_value(value);
    let observed = if matches!(
        kind,
        "channel" | "default-channel" | "custom-channel" | "channel-alias"
    ) && reqwest::Url::parse(value).is_ok()
        && !public
    {
        "<redacted>"
    } else {
        value
    };
    ConfiguredSource {
        upstream_id: public.then(|| CONDA_UPSTREAM.into()),
        url: observed.into(),
        enabled: true,
        metadata,
    }
}

fn validate_precedence(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        if metadata(source, "origin_scope")? != "environment" {
            continue;
        }
        let kind = metadata(source, "kind")?;
        let conda_forge = kind == "custom-channel"
            && source
                .metadata
                .get("channel_name")
                .is_some_and(|names| names == &["conda-forge"]);
        if kind == "default-channel" || conda_forge {
            return Err(AdapterError::Unsupported(
                "an environment-level Conda source overrides the user mirror plan".into(),
            ));
        }
    }
    Ok(())
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    let channels = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some("channel"))
        .map(|source| source.url.as_str())
        .collect::<Vec<_>>();
    if !channels.is_empty()
        && !channels
            .iter()
            .any(|channel| matches!(*channel, "defaults" | "conda-forge"))
    {
        return Err(AdapterError::Unsupported(
            "Conda configuration contains only private or unmapped channels".into(),
        ));
    }
    for source in &current.sources {
        match metadata(source, "kind")? {
            "ssl-verify" if source.url.eq_ignore_ascii_case("false") => {
                return Err(AdapterError::InvalidConfiguration(
                    "Conda TLS certificate verification is disabled".into(),
                ));
            }
            "channel-priority"
                if !matches!(
                    source.url.to_ascii_lowercase().as_str(),
                    "strict" | "flexible" | "disabled" | "true" | "false" | ""
                ) =>
            {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "unsupported Conda channel_priority value {}",
                    source.url
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_condarc(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let sections = sections(text)?;
    let mut replacements: Vec<(Range<usize>, String)> = Vec::new();
    let mut insertions: Vec<(usize, String)> = Vec::new();
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let main = format!("{endpoint}/pkgs/main");
    let r = format!("{endpoint}/pkgs/r");
    let cloud = format!("{endpoint}/cloud");

    if let Some(section) = sections
        .iter()
        .find(|section| section.key == "default_channels")
    {
        let entries = list_entries(text, section)?;
        let mut has_main = false;
        let mut has_r = false;
        for entry in entries {
            let replacement = if conda_channel_kind(&entry.value) == Some("main") {
                has_main = true;
                Some(main.as_str())
            } else if conda_channel_kind(&entry.value) == Some("r") {
                has_r = true;
                Some(r.as_str())
            } else {
                None
            };
            if let Some(replacement) = replacement {
                replacements.push((entry.range, quote_value(replacement, entry.quote)));
            }
        }
        let mut addition = String::new();
        if !has_main {
            addition.push_str(&format!("  - {main}{newline}"));
        }
        if !has_r {
            addition.push_str(&format!("  - {r}{newline}"));
        }
        if !addition.is_empty() {
            insertions.push((section.end, addition));
        }
    } else {
        insertions.push((
            text.len(),
            format!(
                "{}default_channels:{newline}  - {main}{newline}  - {r}{newline}",
                append_prefix(text, newline)
            ),
        ));
    }

    if let Some(section) = sections
        .iter()
        .find(|section| section.key == "custom_channels")
    {
        let entries = map_entries(text, section)?;
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.key.as_deref() == Some("conda-forge"))
        {
            if is_public_custom_channel(&entry.value) {
                replacements.push((entry.range.clone(), quote_value(&cloud, entry.quote)));
            }
        } else {
            insertions.push((section.end, format!("  conda-forge: {cloud}{newline}")));
        }
    } else {
        insertions.push((
            text.len(),
            format!(
                "{}custom_channels:{newline}  conda-forge: {cloud}{newline}",
                append_prefix(text, newline)
            ),
        ));
    }

    let mut edits = replacements;
    edits.extend(
        insertions
            .into_iter()
            .map(|(offset, value)| (offset..offset, value)),
    );
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0.start));
    let mut rewritten = text.to_owned();
    for (range, value) in edits {
        rewritten.replace_range(range, &value);
    }
    Ok(rewritten)
}

fn append_prefix(text: &str, newline: &str) -> &'static str {
    if text.is_empty() || text.ends_with(['\n', '\r']) {
        ""
    } else if newline == "\r\n" {
        "\r\n"
    } else {
        "\n"
    }
}

fn quote_value(value: &str, quote: Option<char>) -> String {
    match quote {
        Some(quote) => format!("{quote}{value}{quote}"),
        None => value.into(),
    }
}

fn conda_channel_kind(value: &str) -> Option<&'static str> {
    let normalized = normalized_url(value)?;
    if !normalized.starts_with("https://repo.anaconda.com/")
        && !MIRROR_BASES.iter().any(|base| normalized.starts_with(base))
    {
        return None;
    }
    if normalized.ends_with("/pkgs/main") {
        Some("main")
    } else if normalized.ends_with("/pkgs/r") {
        Some("r")
    } else {
        None
    }
}

fn is_public_custom_channel(value: &str) -> bool {
    normalized_url(value).is_some_and(|value| {
        value == "https://conda.anaconda.org"
            || MIRROR_BASES
                .iter()
                .any(|base| value == format!("{base}/cloud"))
    })
}

fn is_public_conda_value(value: &str) -> bool {
    matches!(value, "defaults" | "conda-forge")
        || normalized_url(value).is_some_and(|value| {
            value.starts_with("https://repo.anaconda.com/")
                || value.starts_with("https://conda.anaconda.org/")
                || MIRROR_BASES.iter().any(|base| value.starts_with(base))
        })
}

fn normalized_url(value: &str) -> Option<String> {
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

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "conda"
        || selections[0].upstream_id != CONDA_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Conda plan requires exactly one Anaconda mirror selection".into(),
        ));
    }
    let endpoint = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Conda selection has no HTTPS index endpoint".into())
        })?;
    let normalized = normalized_url(&endpoint.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Conda selection URL is unsafe".into())
    })?;
    if !MIRROR_BASES.contains(&normalized.as_str()) {
        return Err(AdapterError::InvalidConfiguration(
            "Conda selection is not a reviewed multi-subdir mirror".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Conda source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Conda source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn origin_name(scope: OriginScope) -> &'static str {
    match scope {
        OriginScope::System => "system",
        OriginScope::User => "user",
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
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Conda configuration {} is not UTF-8",
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
