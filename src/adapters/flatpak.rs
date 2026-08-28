use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const SYSTEM_CONFIG: &str = "/var/lib/flatpak/repo/config";
const FLATHUB_UPSTREAM: &str = "flathub--static-files";
const FLATHUB_URLS: &[&str] = &["https://dl.flathub.org/repo", "https://flathub.org/repo"];
const FLATHUB_MIRRORS: &[&str] = &[
    "https://mirror.sjtu.edu.cn/flathub",
    "https://mirrors.ustc.edu.cn/flathub",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct FlatpakAdapter;

impl Adapter for FlatpakAdapter {
    fn key(&self) -> &'static str {
        "flatpak"
    }

    fn tool_id(&self) -> &'static str {
        "flatpak"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System, ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
    }

    fn default_scope_for(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
    ) -> Result<ConfigurationScope, AdapterError> {
        require_supported_context(context)?;
        for scope in [ConfigurationScope::System, ConfigurationScope::User] {
            let configuration = read_scope_configuration(runtime, scope)?;
            if configuration
                .remotes
                .iter()
                .any(|remote| is_flathub_url(&remote.url))
            {
                return Ok(scope);
            }
        }
        Err(AdapterError::Unsupported(
            "Flatpak has no existing mapped Flathub remote in system or user scope".into(),
        ))
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
        if !runtime.command_exists("flatpak") {
            return Ok(None);
        }
        let output = runtime.run("flatpak", &["--version".into()])?;
        if !output.status.success() {
            return Err(AdapterError::Runtime(format!(
                "flatpak --version failed with status {}",
                output.status
            )));
        }
        let observed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let mut evidence = vec![format!("Flatpak command {observed}")];
        for scope in [ConfigurationScope::System, ConfigurationScope::User] {
            let path = config_path(runtime, scope)?;
            if runtime.read(&path)?.is_some() {
                evidence.push(format!(
                    "Flatpak {} remote configuration {}",
                    scope_name(scope),
                    path.display()
                ));
            }
        }
        Ok(Some(DetectedTool {
            tool_id: "flatpak".into(),
            executable: Some(PathBuf::from("/usr/bin/flatpak")),
            version: (!observed.is_empty()).then_some(observed),
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
        let configuration = read_scope_configuration(runtime, scope)?;
        let mut sources = Vec::new();
        for remote in &configuration.remotes {
            let upstream = is_flathub_url(&remote.url).then(|| FLATHUB_UPSTREAM.into());
            if upstream.is_some() && (!remote.gpg_verify || !remote.gpg_verify_summary) {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Flatpak remote {} must retain GPG verification for commits and summary metadata",
                    remote.name
                )));
            }
            sources.push(ConfiguredSource {
                upstream_id: upstream,
                url: remote.url.clone(),
                enabled: remote.enabled,
                metadata: BTreeMap::from([
                    ("remote_name".into(), vec![remote.name.clone()]),
                    ("scope".into(), vec![scope_name(scope).into()]),
                    ("gpg_verify".into(), vec![remote.gpg_verify.to_string()]),
                    (
                        "gpg_verify_summary".into(),
                        vec![remote.gpg_verify_summary.to_string()],
                    ),
                    ("priority".into(), vec![remote.priority.to_string()]),
                    (
                        "flatpak_arch".into(),
                        vec![flatpak_arch(context.architecture).into()],
                    ),
                ]),
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "flatpak".into(),
            scope,
            files: configuration
                .existing
                .then(|| configuration.path.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path: configuration.path,
                format: format!("flatpak-{}-ostree-config", scope_name(scope)),
                contents: configuration.contents,
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
        if current.tool_id != "flatpak"
            || !matches!(
                current.scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
        {
            return Err(AdapterError::InvalidConfiguration(
                "Flatpak selection requires a system or user remote configuration".into(),
            ));
        }
        let mapped = current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(FLATHUB_UPSTREAM))
            .collect::<Vec<_>>();
        if mapped.is_empty() {
            return Err(AdapterError::Unsupported(
                "selected Flatpak scope has no existing mapped Flathub remote".into(),
            ));
        }
        let arches = mapped
            .iter()
            .map(|source| single_metadata(source, "flatpak_arch"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if arches.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(
                "Flatpak remotes disagree on the target architecture".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "flatpak".into(),
            adapter_key: "flatpak".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![FLATHUB_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                FLATHUB_UPSTREAM.into(),
                vec![BTreeMap::from([(
                    "flatpak_arch".into(),
                    (*arches.first().unwrap()).to_owned(),
                )])],
            )]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Artifacts],
            allowed_delivery_modes: vec![DeliveryMode::Proxy],
            composition_policy: CompositionPolicy::Single,
            overrides: BTreeMap::new(),
        })
    }

    fn plan(
        &self,
        context: &SystemContext,
        current: &CurrentConfiguration,
        selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "flatpak"
            || !matches!(
                current.scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
            || current.documents.len() != 1
        {
            return Err(AdapterError::InvalidConfiguration(
                "Flatpak plan requires exactly one system or user OSTree config".into(),
            ));
        }
        let endpoint = selected_endpoint(selection)?;
        let document = &current.documents[0];
        let text = utf8(&document.path, &document.contents)?;
        let remotes = parse_config(text)?;
        let mut replacements = Vec::new();
        for remote in remotes.iter().filter(|remote| is_flathub_url(&remote.url)) {
            if !remote.gpg_verify || !remote.gpg_verify_summary {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Flatpak remote {} does not enforce GPG verification",
                    remote.name
                )));
            }
            replacements.push((remote.url_range.clone(), endpoint.to_owned()));
        }
        if replacements.is_empty() {
            return Err(AdapterError::Unsupported(
                "Flatpak plan has no mapped remote to replace".into(),
            ));
        }
        replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0.start));
        let mut rewritten = text.to_owned();
        for (range, value) in replacements {
            rewritten.replace_range(range, &value);
        }
        let new_contents = rewritten.into_bytes();
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "replace mapped Flathub URLs in {} scope without changing remote identity, GPG policy, or priority",
                    scope_name(current.scope)
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "flatpak".into(),
            tool_id: "flatpak".into(),
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
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let mut configurations = Vec::new();
            for candidate in [ConfigurationScope::System, ConfigurationScope::User] {
                let configuration = read_scope_configuration(runtime, candidate)?;
                if configuration
                    .remotes
                    .iter()
                    .any(|remote| is_known_mirror(&remote.url))
                {
                    configurations.push((candidate, configuration));
                }
            }
            if configurations.is_empty() {
                return Err(AdapterError::Verification(
                    "effective Flatpak configuration has no reviewed mirror".into(),
                ));
            }
            let arch = flatpak_arch(context.architecture);
            let mut queried = 0;
            let mut scopes = Vec::new();
            for (scope, configuration) in configurations {
                scopes.push(scope_name(scope));
                let mapped = configuration
                    .remotes
                    .iter()
                    .filter(|remote| is_flathub_url(&remote.url))
                    .collect::<Vec<_>>();
                if mapped.iter().any(|remote| {
                    !is_known_mirror(&remote.url)
                        || !remote.gpg_verify
                        || !remote.gpg_verify_summary
                }) {
                    return Err(AdapterError::Verification(format!(
                        "Flatpak {} scope did not retain complete GPG verification",
                        scope_name(scope)
                    )));
                }
                for remote in mapped.into_iter().filter(|remote| remote.enabled) {
                    let arguments = vec![
                        scope_flag(scope).into(),
                        "remote-ls".into(),
                        format!("--arch={arch}"),
                        "--columns=ref".into(),
                        remote.name.clone(),
                    ];
                    let output = runtime.run("flatpak", &arguments)?;
                    if !output.status.success() {
                        return Err(AdapterError::Verification(format!(
                            "Flatpak remote query for {} failed with status {}",
                            remote.name, output.status
                        )));
                    }
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if !stdout.contains(&format!("/{arch}/")) {
                        return Err(AdapterError::Verification(format!(
                            "Flatpak remote {} returned no {arch} refs",
                            remote.name
                        )));
                    }
                    queried += 1;
                }
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Flatpak re-read {} scope(s) with GPG verification and queried {queried} enabled {arch} remotes",
                    scopes.join(", ")
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
                "restored {} Flatpak remote configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

struct ScopeConfiguration {
    path: PathBuf,
    contents: Vec<u8>,
    existing: bool,
    remotes: Vec<Remote>,
}

#[derive(Clone, Debug)]
struct Remote {
    name: String,
    url: String,
    url_range: Range<usize>,
    gpg_verify: bool,
    gpg_verify_summary: bool,
    priority: u32,
    enabled: bool,
}

#[derive(Clone, Debug)]
struct Field {
    key: String,
    value: String,
    value_range: Range<usize>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Flatpak adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn config_path(runtime: &dyn Runtime, scope: ConfigurationScope) -> Result<PathBuf, AdapterError> {
    match scope {
        ConfigurationScope::System => Ok(PathBuf::from(SYSTEM_CONFIG)),
        ConfigurationScope::User => runtime
            .home_dir()
            .map(|home| home.join(".local/share/flatpak/repo/config"))
            .ok_or_else(|| {
                AdapterError::Unsupported(
                    "Flatpak user scope requires a detected home directory".into(),
                )
            }),
        _ => Err(AdapterError::Unsupported(
            "Flatpak supports only system and user scopes".into(),
        )),
    }
}

fn read_scope_configuration(
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<ScopeConfiguration, AdapterError> {
    let path = config_path(runtime, scope)?;
    let existing = runtime.read(&path)?;
    let contents = existing.clone().unwrap_or_default();
    let text = utf8(&path, &contents)?;
    let remotes = parse_config(text)?;
    Ok(ScopeConfiguration {
        path,
        contents,
        existing: existing.is_some(),
        remotes,
    })
}

fn parse_config(text: &str) -> Result<Vec<Remote>, AdapterError> {
    let mut remotes = Vec::new();
    let mut current_name = None;
    let mut fields = Vec::new();
    let mut offset = 0;
    for raw_line in text.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') {
                return Err(AdapterError::InvalidConfiguration(
                    "Flatpak OSTree section header is malformed".into(),
                ));
            }
            if let Some(name) = current_name.take() {
                remotes.push(build_remote(name, &fields)?);
            }
            fields.clear();
            current_name = parse_remote_name(trimmed)?;
        } else if !trimmed.is_empty() && !trimmed.starts_with(['#', ';']) {
            let equals = line.find('=').ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Flatpak OSTree configuration field has no '='".into(),
                )
            })?;
            if current_name.is_some() {
                let key = line[..equals].trim().to_ascii_lowercase();
                let raw_value = &line[equals + 1..];
                let leading = raw_value.len() - raw_value.trim_start().len();
                let value = raw_value.trim().to_owned();
                let start = offset + equals + 1 + leading;
                fields.push(Field {
                    key,
                    value,
                    value_range: start..start + raw_value.trim().len(),
                });
            }
        }
        offset += raw_line.len();
    }
    if let Some(name) = current_name {
        remotes.push(build_remote(name, &fields)?);
    }
    Ok(remotes)
}

fn parse_remote_name(header: &str) -> Result<Option<String>, AdapterError> {
    if !header.starts_with("[remote ") {
        return Ok(None);
    }
    let name = header
        .strip_prefix("[remote \"")
        .and_then(|value| value.strip_suffix("\"]"))
        .filter(|value| !value.is_empty() && !value.contains('"'))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Flatpak remote section name is malformed".into())
        })?;
    Ok(Some(name.into()))
}

fn build_remote(name: String, fields: &[Field]) -> Result<Remote, AdapterError> {
    let urls = fields
        .iter()
        .filter(|field| field.key == "url")
        .collect::<Vec<_>>();
    if urls.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flatpak remote {name} must have exactly one URL"
        )));
    }
    let gpg_verify = boolean_field(fields, "gpg-verify")?.unwrap_or(false);
    let gpg_verify_summary = boolean_field(fields, "gpg-verify-summary")?.unwrap_or(false);
    let enabled = !boolean_field(fields, "xa.disable")?.unwrap_or(false);
    let priority = fields
        .iter()
        .rev()
        .find(|field| field.key == "xa.prio")
        .map(|field| {
            field.value.parse::<u32>().map_err(|_| {
                AdapterError::InvalidConfiguration(format!(
                    "Flatpak remote {name} has invalid priority {}",
                    field.value
                ))
            })
        })
        .transpose()?
        .unwrap_or(1);
    Ok(Remote {
        name,
        url: normalize_url(&urls[0].value),
        url_range: urls[0].value_range.clone(),
        gpg_verify,
        gpg_verify_summary,
        priority,
        enabled,
    })
}

fn boolean_field(fields: &[Field], key: &str) -> Result<Option<bool>, AdapterError> {
    let values = fields
        .iter()
        .filter(|field| field.key == key)
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flatpak remote has multiple {key} fields"
        )));
    }
    values
        .first()
        .map(|field| match field.value.to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Ok(true),
            "false" | "no" | "0" => Ok(false),
            _ => Err(AdapterError::InvalidConfiguration(format!(
                "Flatpak field {key} is not boolean"
            ))),
        })
        .transpose()
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "flatpak"
        || selections[0].upstream_id != FLATHUB_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Flatpak plan requires exactly one Flathub selection".into(),
        ));
    }
    let endpoint = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Flatpak selection has no HTTPS artifacts endpoint".into(),
            )
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "Flatpak selection is not a reviewed Flathub endpoint".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn is_flathub_url(url: &str) -> bool {
    let normalized = normalize_url(url);
    FLATHUB_URLS.contains(&normalized.as_str()) || FLATHUB_MIRRORS.contains(&normalized.as_str())
}

fn is_known_mirror(url: &str) -> bool {
    FLATHUB_MIRRORS.contains(&normalize_url(url).as_str())
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_owned()
}

fn flatpak_arch(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "aarch64",
    }
}

fn scope_name(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::System => "system",
        ConfigurationScope::User => "user",
        _ => unreachable!("Flatpak accepts only system and user scopes"),
    }
}

fn scope_flag(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::System => "--system",
        ConfigurationScope::User => "--user",
        _ => unreachable!("Flatpak accepts only system and user scopes"),
    }
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Flatpak source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flatpak source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
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
            "Flatpak configuration {} is not UTF-8",
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
