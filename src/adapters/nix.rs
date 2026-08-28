use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
};

use serde_json::Value;

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

const SYSTEM_CONFIG: &str = "/etc/nix/nix.conf";
const CACHE_UPSTREAM: &str = "nix-channels--binary-cache";
const OFFICIAL_CACHE: &str = "https://cache.nixos.org";
const OFFICIAL_CACHE_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
const CACHE_MIRRORS: &[&str] = &[
    "https://mirrors.nju.edu.cn/nix-channels/store",
    "https://mirror.sjtu.edu.cn/nix-channels/store",
    "https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store",
    "https://mirrors.ustc.edu.cn/nix-channels/store",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct NixAdapter;

impl Adapter for NixAdapter {
    fn key(&self) -> &'static str {
        "nix"
    }

    fn tool_id(&self) -> &'static str {
        "nix"
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
        Ok(if is_multi_user(runtime)? {
            ConfigurationScope::System
        } else {
            ConfigurationScope::User
        })
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
        let has_nix = runtime.command_exists("nix");
        let system_config = runtime.read(Path::new(SYSTEM_CONFIG))?.is_some();
        let user_config = user_config_path(runtime)
            .map(|path| runtime.read(&path))
            .transpose()?
            .flatten()
            .is_some();
        if !has_nix && !system_config && !user_config {
            return Ok(None);
        }

        let mut evidence = Vec::new();
        let mut version = None;
        if has_nix {
            let output = runtime.run("nix", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "nix --version failed with status {}",
                    output.status
                )));
            }
            let observed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            version = (!observed.is_empty()).then_some(observed.clone());
            evidence.push(format!("Nix command {observed}"));
        }
        evidence.push(if is_multi_user(runtime)? {
            "Nix multi-user daemon installation".into()
        } else {
            "Nix single-user local-store installation".into()
        });
        if system_config {
            evidence.push(format!("Nix system configuration {SYSTEM_CONFIG}"));
        }
        if user_config {
            evidence.push("Nix user configuration under the detected home directory".into());
        }
        Ok(Some(DetectedTool {
            tool_id: "nix".into(),
            executable: has_nix.then(|| PathBuf::from("/usr/bin/nix")),
            version,
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
        let path = configuration_path(runtime, scope)?;
        if scope == ConfigurationScope::System
            && context
                .distribution
                .as_ref()
                .is_some_and(|distribution| distribution.id == "nixos")
        {
            return Err(AdapterError::Unsupported(
                "NixOS generates nix.conf declaratively; configure nix.settings instead".into(),
            ));
        }

        let existing = runtime.read(&path)?;
        let contents = existing.clone().unwrap_or_default();
        let text = utf8(&path, &contents)?;
        parse_configuration(text)?;

        let effective = read_effective_config(runtime)?;
        validate_effective_config(context, &effective)?;
        let store_path = discover_store_path(runtime)?;
        let narinfo_hash = store_path_hash(&store_path)?;
        let mut sources = effective
            .substituters
            .iter()
            .map(|url| ConfiguredSource {
                upstream_id: is_official_or_mirror(url).then(|| CACHE_UPSTREAM.into()),
                url: url.clone(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("configuration_surface".into(), vec!["binary-cache".into()]),
                    ("nix_system".into(), vec![effective.system.clone()]),
                    ("narinfo_hash".into(), vec![narinfo_hash.clone()]),
                    ("store_path".into(), vec![store_path.clone()]),
                    ("signature_key".into(), vec![OFFICIAL_CACHE_KEY.into()]),
                ]),
            })
            .collect::<Vec<_>>();
        sources.extend(channel_sources(runtime)?);
        if let Some(registry) = effective.flake_registry {
            if !registry.trim().is_empty() {
                sources.push(ConfiguredSource {
                    upstream_id: None,
                    url: registry,
                    enabled: true,
                    metadata: BTreeMap::from([(
                        "configuration_surface".into(),
                        vec!["flake-registry".into()],
                    )]),
                });
            }
        }

        Ok(CurrentConfiguration {
            tool_id: "nix".into(),
            scope,
            files: existing
                .is_some()
                .then(|| path.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path,
                format: match scope {
                    ConfigurationScope::System => "nix-system",
                    ConfigurationScope::User => "nix-user",
                    _ => unreachable!("configuration_path accepts only system and user"),
                }
                .into(),
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
        if current.tool_id != "nix"
            || !matches!(
                current.scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
        {
            return Err(AdapterError::InvalidConfiguration(
                "Nix selection requires a system or user configuration".into(),
            ));
        }
        let mut contexts = current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(CACHE_UPSTREAM))
            .map(|source| {
                Ok(BTreeMap::from([(
                    "narinfo_hash".into(),
                    single_metadata(source, "narinfo_hash")?.to_owned(),
                )]))
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        contexts.sort();
        contexts.dedup();
        if contexts.len() != 1 {
            return Err(AdapterError::Unsupported(
                "no unambiguous signed nixpkgs binary cache is configured".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "nix".into(),
            adapter_key: "nix".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![CACHE_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(CACHE_UPSTREAM.into(), contexts)]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Artifacts],
            allowed_delivery_modes: vec![DeliveryMode::Mirror],
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
        if current.tool_id != "nix"
            || !matches!(
                current.scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
            || current.documents.len() != 1
        {
            return Err(AdapterError::InvalidConfiguration(
                "Nix plan requires exactly one system or user nix.conf document".into(),
            ));
        }
        let endpoint = selected_endpoint(selection)?;
        let document = &current.documents[0];
        let text = utf8(&document.path, &document.contents)?;
        let new_contents = rewrite_configuration(text, endpoint)?.into_bytes();
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "prefer the selected signed nixpkgs cache without changing keys or custom caches"
                    .into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "nix".into(),
            tool_id: "nix".into(),
            scope: current.scope,
            changes,
            requires_elevation: current.scope == ConfigurationScope::System,
            service_impact: if current.scope == ConfigurationScope::System {
                ServiceImpact::RestartRequired
            } else {
                ServiceImpact::None
            },
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
        let effective = match read_effective_config(runtime) {
            Ok(effective) => effective,
            Err(error) => {
                return verification_failure(
                    runtime,
                    receipt,
                    format!("Nix could not read applied config: {error}"),
                );
            }
        };
        if let Err(error) = validate_effective_config(context, &effective) {
            return verification_failure(runtime, receipt, error.to_string());
        }
        let mirrors = effective
            .substituters
            .iter()
            .filter(|url| is_known_mirror(url))
            .collect::<BTreeSet<_>>();
        if mirrors.len() != 1 {
            return verification_failure(
                runtime,
                receipt,
                "effective Nix configuration does not contain exactly one selected mirror".into(),
            );
        }
        let endpoint = mirrors.into_iter().next().unwrap();
        let store_path = match discover_store_path(runtime) {
            Ok(path) => path,
            Err(error) => {
                return verification_failure(
                    runtime,
                    receipt,
                    format!("Nix store path discovery failed: {error}"),
                );
            }
        };
        for arguments in [
            vec![
                "--extra-experimental-features".into(),
                "nix-command".into(),
                "store".into(),
                "ping".into(),
                "--store".into(),
                endpoint.clone(),
            ],
            vec![
                "--extra-experimental-features".into(),
                "nix-command".into(),
                "path-info".into(),
                "--store".into(),
                endpoint.clone(),
                store_path.clone(),
            ],
        ] {
            let output = match runtime.run("nix", &arguments) {
                Ok(output) => output,
                Err(error) => {
                    return verification_failure(
                        runtime,
                        receipt,
                        format!("nix remote cache query could not run: {error}"),
                    );
                }
            };
            if !output.status.success() {
                return verification_failure(
                    runtime,
                    receipt,
                    format!(
                        "nix remote cache query failed with status {}",
                        output.status
                    ),
                );
            }
        }
        Ok(VerificationResult {
            valid: true,
            summary:
                "Nix read the signed cache configuration and queried a current-system store path"
                    .into(),
        })
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
                "restored {} Nix configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct EffectiveConfig {
    substituters: Vec<String>,
    trusted_public_keys: Vec<String>,
    require_sigs: bool,
    system: String,
    flake_registry: Option<String>,
}

#[derive(Clone, Debug)]
struct SettingLine {
    value_range: Range<usize>,
    values: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ParsedConfiguration {
    base: Option<SettingLine>,
    extra: Option<SettingLine>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Nix adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn configuration_path(
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<PathBuf, AdapterError> {
    match scope {
        ConfigurationScope::System => Ok(PathBuf::from(SYSTEM_CONFIG)),
        ConfigurationScope::User => user_config_path(runtime).ok_or_else(|| {
            AdapterError::Unsupported("Nix user scope requires a detected home directory".into())
        }),
        _ => Err(AdapterError::Unsupported(
            "Nix supports only system and user nix.conf scopes".into(),
        )),
    }
}

fn user_config_path(runtime: &dyn Runtime) -> Option<PathBuf> {
    runtime
        .home_dir()
        .map(|home| home.join(".config/nix/nix.conf"))
}

fn is_multi_user(runtime: &dyn Runtime) -> Result<bool, AdapterError> {
    let daemon_socket = runtime
        .list_files(Path::new("/nix/var/nix/daemon-socket"))?
        .into_iter()
        .any(|path| path.file_name().is_some_and(|name| name == "socket"));
    let daemon_profile = runtime
        .read(Path::new(
            "/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh",
        ))?
        .is_some();
    Ok(daemon_socket || daemon_profile)
}

fn read_effective_config(runtime: &dyn Runtime) -> Result<EffectiveConfig, AdapterError> {
    if !runtime.command_exists("nix") {
        return Err(AdapterError::Unsupported(
            "Nix command is required to read effective settings".into(),
        ));
    }
    let mut failures = Vec::new();
    for arguments in [
        vec![
            "--extra-experimental-features".into(),
            "nix-command".into(),
            "config".into(),
            "show".into(),
            "--json".into(),
        ],
        vec!["show-config".into(), "--json".into()],
    ] {
        let output = runtime.run("nix", &arguments)?;
        if !output.status.success() {
            failures.push(output.status.to_string());
            continue;
        }
        let root: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "nix config show returned invalid JSON: {error}"
            ))
        })?;
        return Ok(EffectiveConfig {
            substituters: setting_strings(&root, "substituters")?,
            trusted_public_keys: setting_strings(&root, "trusted-public-keys")?,
            require_sigs: setting_bool(&root, "require-sigs")?,
            system: setting_string(&root, "system")?,
            flake_registry: optional_setting_string(&root, "flake-registry")?,
        });
    }
    Err(AdapterError::Runtime(format!(
        "both Nix config commands failed with statuses {}",
        failures.join(", ")
    )))
}

fn setting_value<'a>(root: &'a Value, name: &str) -> Result<&'a Value, AdapterError> {
    let value = root.get(name).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix effective config is missing {name}"))
    })?;
    Ok(value.get("value").unwrap_or(value))
}

fn setting_strings(root: &Value, name: &str) -> Result<Vec<String>, AdapterError> {
    match setting_value(root, name)? {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Nix setting {name} contains a non-string value"
                    ))
                })
            })
            .collect(),
        Value::String(value) => Ok(value.split_whitespace().map(str::to_owned).collect()),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "Nix setting {name} is not a string list"
        ))),
    }
}

fn setting_string(root: &Value, name: &str) -> Result<String, AdapterError> {
    setting_value(root, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Nix setting {name} is not a string"))
        })
}

fn optional_setting_string(root: &Value, name: &str) -> Result<Option<String>, AdapterError> {
    let Some(value) = root.get(name) else {
        return Ok(None);
    };
    value
        .get("value")
        .unwrap_or(value)
        .as_str()
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Nix setting {name} is not a string"))
        })
}

fn setting_bool(root: &Value, name: &str) -> Result<bool, AdapterError> {
    setting_value(root, name)?.as_bool().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix setting {name} is not boolean"))
    })
}

fn validate_effective_config(
    context: &SystemContext,
    effective: &EffectiveConfig,
) -> Result<(), AdapterError> {
    let expected = match context.architecture {
        Architecture::X86_64 => "x86_64-linux",
        Architecture::Arm64 => "aarch64-linux",
    };
    if effective.system != expected {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Nix system {} conflicts with detected architecture {expected}",
            effective.system
        )));
    }
    if !effective.require_sigs {
        return Err(AdapterError::InvalidConfiguration(
            "Nix require-sigs is disabled".into(),
        ));
    }
    if !effective
        .trusted_public_keys
        .iter()
        .any(|key| key == OFFICIAL_CACHE_KEY)
    {
        return Err(AdapterError::InvalidConfiguration(
            "Nix does not trust the canonical cache.nixos.org signing key".into(),
        ));
    }
    Ok(())
}

fn discover_store_path(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    if !runtime.command_exists("nix-store") {
        return Err(AdapterError::Unsupported(
            "nix-store is required to discover an architecture-specific narinfo".into(),
        ));
    }
    let mut roots = vec![
        "/proc/self/exe".to_owned(),
        "/nix/var/nix/profiles/default".into(),
    ];
    if let Some(home) = runtime.home_dir() {
        roots.push(home.join(".nix-profile").display().to_string());
    }
    for root in roots {
        let output = runtime.run(
            "nix-store",
            &["--query".into(), "--requisites".into(), root],
        )?;
        if !output.status.success() {
            continue;
        }
        if let Some(path) = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .find(|value| store_path_hash(value).is_ok())
        {
            return Ok(path.to_owned());
        }
    }
    Err(AdapterError::Unsupported(
        "no current-system Nix store path was available for narinfo probing".into(),
    ))
}

fn store_path_hash(path: &str) -> Result<String, AdapterError> {
    let name = path.strip_prefix("/nix/store/").ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix store path is outside /nix/store: {path}"))
    })?;
    let (hash, package) = name.split_once('-').ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix store path has no package name: {path}"))
    })?;
    const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    if hash.len() != 32
        || package.is_empty()
        || !hash.chars().all(|character| NIX_BASE32.contains(character))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Nix store path has an invalid hash: {path}"
        )));
    }
    Ok(hash.into())
}

fn channel_sources(runtime: &dyn Runtime) -> Result<Vec<ConfiguredSource>, AdapterError> {
    if !runtime.command_exists("nix-channel") {
        return Ok(Vec::new());
    }
    let output = runtime.run("nix-channel", &["--list".into()])?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let url = fields.next()?;
            Some(ConfiguredSource {
                upstream_id: None,
                url: url.into(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("configuration_surface".into(), vec!["channel".into()]),
                    ("channel_name".into(), vec![name.into()]),
                ]),
            })
        })
        .collect())
}

fn parse_configuration(text: &str) -> Result<ParsedConfiguration, AdapterError> {
    let mut parsed = ParsedConfiguration::default();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let content_end = line.find('#').unwrap_or(line.len());
        let active = &line[..content_end];
        let trimmed = active.trim();
        if trimmed.is_empty() {
            offset += inclusive.len();
            continue;
        }
        if trimmed.starts_with("include ") || trimmed.starts_with("!include ") {
            return Err(AdapterError::Unsupported(
                "Nix include directives require declarative owner-aware editing".into(),
            ));
        }
        let Some(equals) = active.find('=') else {
            offset += inclusive.len();
            continue;
        };
        let key = active[..equals].trim();
        let value_part = &active[equals + 1..];
        let leading = value_part.len() - value_part.trim_start().len();
        let trailing = value_part.len() - value_part.trim_end().len();
        let start = offset + equals + 1 + leading;
        let end = offset + active.len() - trailing;
        let setting = SettingLine {
            value_range: start..end,
            values: value_part.split_whitespace().map(str::to_owned).collect(),
        };
        let target = match key {
            "substituters" | "binary-caches" => Some(&mut parsed.base),
            "extra-substituters" | "extra-binary-caches" => Some(&mut parsed.extra),
            _ => None,
        };
        if let Some(target) = target {
            if target.replace(setting).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Nix configuration has multiple active {key} assignments"
                )));
            }
        }
        offset += inclusive.len();
    }
    Ok(parsed)
}

fn rewrite_configuration(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let parsed = parse_configuration(text)?;
    let mut replacements = Vec::new();
    let extra_has_mirror = parsed
        .extra
        .as_ref()
        .is_some_and(|line| line.values.iter().any(|value| is_known_mirror(value)));

    if let Some(base) = &parsed.base {
        let values = rewrite_cache_values(&base.values, endpoint, true);
        replacements.push((base.value_range.clone(), values.join(" ")));
        if let Some(extra) = &parsed.extra {
            let values = extra
                .values
                .iter()
                .filter(|value| !is_known_mirror(value))
                .cloned()
                .collect::<Vec<_>>();
            replacements.push((extra.value_range.clone(), values.join(" ")));
        }
    } else if !extra_has_mirror {
        let mut output = text.to_owned();
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&format!("substituters = {endpoint} {OFFICIAL_CACHE}/\n"));
        return Ok(output);
    } else if let Some(extra) = &parsed.extra {
        let values = rewrite_cache_values(&extra.values, endpoint, false);
        replacements.push((extra.value_range.clone(), values.join(" ")));
    }
    replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0.start));
    let mut output = text.to_owned();
    for (range, value) in replacements {
        output.replace_range(range, &value);
    }
    Ok(output)
}

fn rewrite_cache_values(values: &[String], endpoint: &str, ensure_mirror: bool) -> Vec<String> {
    let mut output = Vec::new();
    let mut inserted = false;
    for value in values {
        if is_known_mirror(value) {
            if !inserted {
                output.push(endpoint.into());
                inserted = true;
            }
            continue;
        }
        if ensure_mirror && is_official_cache(value) && !inserted {
            output.push(endpoint.into());
            inserted = true;
        }
        output.push(value.clone());
    }
    if ensure_mirror && !inserted {
        output.push(endpoint.into());
    }
    output
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "nix" && selection.upstream_id == CACHE_UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Nix plan requires exactly one binary cache selection".into(),
        ));
    }
    let endpoint = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Nix selection has no HTTPS artifacts endpoint".into(),
            )
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "Nix selection is not a reviewed signed nixpkgs cache endpoint".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn is_official_or_mirror(url: &str) -> bool {
    is_official_cache(url) || is_known_mirror(url)
}

fn is_official_cache(url: &str) -> bool {
    url.trim_end_matches('/') == OFFICIAL_CACHE
}

fn is_known_mirror(url: &str) -> bool {
    let normalized = url.trim_end_matches('/');
    CACHE_MIRRORS.contains(&normalized)
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Nix source has ambiguous {key} metadata"
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
            "Nix configuration {} is not UTF-8",
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
