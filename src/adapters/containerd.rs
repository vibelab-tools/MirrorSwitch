use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use toml_edit::{Array, DocumentMut, Item, Table, value};

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

const UPSTREAM: &str = "registry.k8s.io--container-registry";
const SOURCE: &str = "https://registry.k8s.io";
const MIRROR: &str = "https://k8s.nju.edu.cn";
const CONFIG_PATH: &str = "/etc/containerd/certs.d";
const HOSTS_MARKER: &str = "# Managed by MirrorSwitch: containerd registry host v1";

#[derive(Clone, Copy, Debug, Default)]
pub struct ContainerdAdapter;

impl Adapter for ContainerdAdapter {
    fn key(&self) -> &'static str {
        "containerd"
    }

    fn tool_id(&self) -> &'static str {
        "containerd"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
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
        if !runtime.command_exists("containerd") {
            return Ok(None);
        }
        if !runtime.command_exists("ctr") {
            return Err(AdapterError::Unsupported(
                "containerd mirror verification requires ctr".into(),
            ));
        }
        let version = containerd_version(runtime)?;
        review_version(&version)?;
        let layout = layout();
        let config = read_config(runtime, &layout.config, &version)?;
        let hosts = read_hosts(runtime, &layout.hosts)?;
        let cri = cri_plugin_state(runtime);
        Ok(Some(DetectedTool {
            tool_id: "containerd".into(),
            executable: Some(PathBuf::from("containerd")),
            version: Some(version.clone()),
            evidence: vec![
                format!("containerd {version}"),
                format!("containerd config version is {}", config.version),
                format!("CRI plugin state is {cri}"),
                format!(
                    "registry config_path is {}",
                    config.config_path.as_deref().unwrap_or("unset")
                ),
                format!("registry hosts path is {}", layout.hosts.display()),
                format!("existing registry hosts: {}", hosts.host_count),
                format!(
                    "service manager is {}",
                    if runtime.command_exists("systemctl") {
                        "systemd"
                    } else if runtime.command_exists("service") {
                        "service"
                    } else {
                        "not detected"
                    }
                ),
                "MirrorSwitch never restarts containerd automatically".into(),
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
        if detected.tool_id != "containerd" {
            return Err(AdapterError::InvalidConfiguration(
                "containerd read received another tool's detection result".into(),
            ));
        }
        let version = containerd_version(runtime)?;
        review_version(&version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "containerd version changed after detection".into(),
            ));
        }
        let layout = layout();
        let config_contents = runtime.read(&layout.config)?;
        let config_exists = config_contents.is_some();
        let config_contents = config_contents.unwrap_or_default();
        let config = parse_config(&layout.config, &config_contents, &version)?;
        let hosts_contents = runtime.read(&layout.hosts)?;
        let hosts_exists = hosts_contents.is_some();
        let hosts_contents = hosts_contents.unwrap_or_default();
        let hosts = parse_hosts(&layout.hosts, &hosts_contents)?;
        let mut files = Vec::new();
        if config_exists {
            files.push(layout.config.clone());
        }
        if hosts_exists {
            files.push(layout.hosts.clone());
        }
        let mut sources = vec![snapshot_source("containerd-version", &version)];
        sources.push(snapshot_source(
            "config-version",
            &config.version.to_string(),
        ));
        if config.cri_disabled {
            sources.push(policy_source("cri-disabled", &layout.config));
        }
        if config.legacy_registry {
            sources.push(policy_source("legacy-registry-config", &layout.config));
        }
        if let Some(path) = &config.config_path {
            sources.push(snapshot_source("config-path", path));
        }
        if hosts_exists
            && !hosts.managed
            && hosts
                .server
                .as_deref()
                .is_some_and(|server| server != SOURCE)
        {
            sources.push(policy_source("custom-server", &layout.hosts));
        }
        if hosts.existing_mirror_unsafe {
            sources.push(policy_source("unsafe-existing-mirror", &layout.hosts));
        }
        if hosts.existing_mirror && !hosts.managed {
            sources.push(policy_source("existing-nju-host", &layout.hosts));
        }
        if hosts.custom_tls_or_auth {
            sources.push(policy_source("custom-tls-auth-preserved", &layout.hosts));
        }
        if hosts.host_count > usize::from(hosts.existing_mirror) {
            sources.push(policy_source("custom-host-order-preserved", &layout.hosts));
        }
        Ok(CurrentConfiguration {
            tool_id: "containerd".into(),
            scope,
            files,
            sources,
            documents: vec![
                ConfigurationDocument {
                    path: layout.config,
                    format: "containerd-config".into(),
                    contents: config_contents,
                },
                ConfigurationDocument {
                    path: layout.hosts,
                    format: "containerd-registry-hosts".into(),
                    contents: hosts_contents,
                },
            ],
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
        review_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("containerd version is missing".into())
        })?)?;
        let architecture = match context.architecture {
            Architecture::X86_64 => "amd64",
            Architecture::Arm64 => "arm64",
        };
        Ok(SelectionRequest {
            tool_id: "containerd".into(),
            adapter_key: "containerd".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("repository_path".into(), "pause".into()),
                    ("tag".into(), "3.10.1".into()),
                    ("oci_arch".into(), architecture.into()),
                ])],
            )]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Registry],
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
        validate_selection(selections)?;
        let version = current_value(current, "containerd-version")?;
        let config = find_document(current, "containerd-config")?;
        let hosts = find_document(current, "containerd-registry-hosts")?;
        let rendered_config = rewrite_config(&config.path, &config.contents, &version)?;
        let rendered_hosts = rewrite_hosts(&hosts.path, &hosts.contents)?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            config,
            rendered_config.into_bytes(),
            "set the version-correct CRI registry config_path while preserving runtime, auth, TLS, and plugin configuration",
            &mut changes,
        );
        add_change(
            context,
            current,
            hosts,
            rendered_hosts.into_bytes(),
            "add a secure registry.k8s.io pull mirror before preserved custom hosts",
            &mut changes,
        );
        let config_changed = changes
            .iter()
            .any(|change| change.target.ends_with("config.toml"));
        Ok(ChangePlan {
            adapter_key: "containerd".into(),
            tool_id: "containerd".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
            service_impact: if config_changed {
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
        let result = (|| {
            let layout = layout();
            let known = [
                rooted(&context.root, &layout.config),
                rooted(&context.root, &layout.hosts),
            ];
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "containerd transaction contains no known target".into(),
                ));
            }
            let version = containerd_version(runtime)?;
            let config = runtime.read(&layout.config)?.ok_or_else(|| {
                AdapterError::Verification("containerd config.toml disappeared".into())
            })?;
            let parsed_config = parse_config(&layout.config, &config, &version)?;
            if !config_path_contains(parsed_config.config_path.as_deref(), CONFIG_PATH) {
                return Err(AdapterError::Verification(
                    "containerd CRI config_path does not include certs.d".into(),
                ));
            }
            let hosts = runtime.read(&layout.hosts)?.ok_or_else(|| {
                AdapterError::Verification("containerd hosts.toml disappeared".into())
            })?;
            let parsed_hosts = parse_hosts(&layout.hosts, &hosts)?;
            if !parsed_hosts.existing_mirror || parsed_hosts.existing_mirror_unsafe {
                return Err(AdapterError::Verification(
                    "containerd NJU mirror host is missing or unsafe".into(),
                ));
            }
            let dump = run_containerd(
                runtime,
                &["--config", path_string(&layout.config)?, "config", "dump"],
                "containerd config dump",
            )?;
            if !dump.contains(CONFIG_PATH) || !dump.contains(plugin_id(parsed_config.version)?) {
                return Err(AdapterError::Verification(
                    "containerd config dump does not expose the expected CRI registry config_path"
                        .into(),
                ));
            }
            let platform = match context.architecture {
                Architecture::X86_64 => "linux/amd64",
                Architecture::Arm64 => "linux/arm64",
            };
            let output = run_ctr(
                runtime,
                &[
                    "--debug",
                    "images",
                    "pull",
                    "--hosts-dir",
                    CONFIG_PATH,
                    "--platform",
                    platform,
                    "registry.k8s.io/pause:3.10.1",
                ],
                "containerd registry pull",
            )?;
            if !output.contains("k8s.nju.edu.cn") {
                return Err(AdapterError::Verification(
                    "ctr did not report pulling blobs through the NJU mirror".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "containerd config version {} parsed and ctr pulled registry.k8s.io/pause:3.10.1 for {platform} through NJU; daemon restart was not performed",
                    parsed_config.version
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
                "restored {} containerd configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

struct Layout {
    config: PathBuf,
    hosts: PathBuf,
}

struct ParsedConfig {
    version: i64,
    config_path: Option<String>,
    legacy_registry: bool,
    cri_disabled: bool,
}

#[derive(Default)]
struct ParsedHosts {
    managed: bool,
    server: Option<String>,
    host_count: usize,
    existing_mirror: bool,
    existing_mirror_unsafe: bool,
    custom_tls_or_auth: bool,
}

fn layout() -> Layout {
    Layout {
        config: PathBuf::from("/etc/containerd/config.toml"),
        hosts: PathBuf::from("/etc/containerd/certs.d/registry.k8s.io/hosts.toml"),
    }
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "containerd adapter supports Linux only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "containerd registry mirrors require system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "containerd" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "containerd operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn read_config(
    runtime: &dyn Runtime,
    path: &Path,
    containerd_version: &str,
) -> Result<ParsedConfig, AdapterError> {
    parse_config(
        path,
        &runtime.read(path)?.unwrap_or_default(),
        containerd_version,
    )
}

fn parse_config(
    path: &Path,
    contents: &[u8],
    containerd_version: &str,
) -> Result<ParsedConfig, AdapterError> {
    if contents.is_empty() {
        let version = if version_major(containerd_version) == Some(2) {
            3
        } else {
            2
        };
        return Ok(ParsedConfig {
            version,
            config_path: None,
            legacy_registry: false,
            cri_disabled: false,
        });
    }
    let document = parse_document(path, utf8(path, contents)?)?;
    let version = document
        .get("version")
        .and_then(Item::as_integer)
        .unwrap_or(1);
    if !matches!(version, 2 | 3) {
        return Err(AdapterError::Unsupported(format!(
            "containerd config version {version} is not reviewed"
        )));
    }
    if version == 3 && version_major(containerd_version) != Some(2) {
        return Err(AdapterError::Unsupported(
            "containerd 1.x cannot use config version 3".into(),
        ));
    }
    let plugin = plugin_id(version)?;
    let registry = table_at(&document, &["plugins", plugin, "registry"]);
    let config_path = registry
        .and_then(|table| table.get("config_path"))
        .and_then(Item::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let legacy_registry = registry.is_some_and(|table| {
        ["mirrors", "configs", "auths"]
            .iter()
            .any(|key| table.get(key).is_some())
    });
    let cri_disabled = document
        .get("disabled_plugins")
        .and_then(Item::as_array)
        .is_some_and(|array| array.iter().any(|value| value.as_str() == Some("cri")));
    Ok(ParsedConfig {
        version,
        config_path,
        legacy_registry,
        cri_disabled,
    })
}

fn read_hosts(runtime: &dyn Runtime, path: &Path) -> Result<ParsedHosts, AdapterError> {
    parse_hosts(path, &runtime.read(path)?.unwrap_or_default())
}

fn parse_hosts(path: &Path, contents: &[u8]) -> Result<ParsedHosts, AdapterError> {
    if contents.is_empty() {
        return Ok(ParsedHosts::default());
    }
    let text = utf8(path, contents)?;
    let document = parse_document(path, text)?;
    let managed = text.lines().next() == Some(HOSTS_MARKER);
    let server = document
        .get("server")
        .and_then(Item::as_str)
        .map(str::to_owned);
    let Some(hosts) = document.get("host").and_then(Item::as_table) else {
        return Ok(ParsedHosts {
            managed,
            server,
            ..ParsedHosts::default()
        });
    };
    let mut parsed = ParsedHosts {
        managed,
        server,
        host_count: hosts.len(),
        ..ParsedHosts::default()
    };
    for (location, item) in hosts.iter() {
        let table = item.as_table().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "containerd host {location} in {} is not a table",
                path.display()
            ))
        })?;
        if location == MIRROR {
            parsed.existing_mirror = true;
            let capabilities = table
                .get("capabilities")
                .and_then(Item::as_array)
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            parsed.existing_mirror_unsafe = table
                .get("skip_verify")
                .and_then(Item::as_bool)
                .unwrap_or(false)
                || !capabilities.contains(&"pull")
                || !capabilities.contains(&"resolve")
                || capabilities.contains(&"push");
        }
        if ["ca", "client", "header"]
            .iter()
            .any(|key| table.get(key).is_some())
        {
            parsed.custom_tls_or_auth = true;
        }
    }
    Ok(parsed)
}

fn parse_document(path: &Path, text: &str) -> Result<DocumentMut, AdapterError> {
    text.parse::<DocumentMut>().map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "containerd configuration {} is invalid TOML",
            path.display()
        ))
    })
}

fn table_at<'a>(document: &'a DocumentMut, path: &[&str]) -> Option<&'a Table> {
    let mut item = document.as_item();
    for key in path {
        item = item.get(key)?;
    }
    item.as_table()
}

fn plugin_id(version: i64) -> Result<&'static str, AdapterError> {
    match version {
        2 => Ok("io.containerd.grpc.v1.cri"),
        3 => Ok("io.containerd.cri.v1.images"),
        _ => Err(AdapterError::Unsupported(format!(
            "containerd config version {version} has no reviewed CRI image plugin"
        ))),
    }
}

fn rewrite_config(
    path: &Path,
    contents: &[u8],
    containerd_version: &str,
) -> Result<String, AdapterError> {
    let parsed = parse_config(path, contents, containerd_version)?;
    let mut document = if contents.is_empty() {
        let mut document = DocumentMut::new();
        document["version"] = value(parsed.version);
        document
    } else {
        parse_document(path, utf8(path, contents)?)?
    };
    let plugin = plugin_id(parsed.version)?;
    let root = document.as_table_mut();
    let plugins = ensure_table(root, "plugins")?;
    let cri = ensure_table(plugins, plugin)?;
    let registry = ensure_table(cri, "registry")?;
    let new_path = match parsed.config_path {
        Some(existing) if config_path_contains(Some(&existing), CONFIG_PATH) => existing,
        Some(existing) => format!("{existing}:{CONFIG_PATH}"),
        None => CONFIG_PATH.into(),
    };
    registry["config_path"] = value(new_path);
    Ok(document.to_string())
}

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table, AdapterError> {
    if parent.get(key).is_none() {
        parent[key] = Item::Table(Table::new());
    }
    parent[key].as_table_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "containerd configuration key {key} is not a table"
        ))
    })
}

fn rewrite_hosts(path: &Path, contents: &[u8]) -> Result<String, AdapterError> {
    if contents.is_empty() {
        return Ok(render_hosts());
    }
    let parsed = parse_hosts(path, contents)?;
    if parsed.managed
        && parsed.existing_mirror
        && !parsed.existing_mirror_unsafe
        && parsed.server.as_deref() == Some(SOURCE)
    {
        return Ok(utf8(path, contents)?.to_owned());
    }
    let mut document = parse_document(path, utf8(path, contents)?)?;
    if document.get("server").is_none() {
        document["server"] = value(SOURCE);
    }
    let existing = document
        .get("host")
        .and_then(Item::as_table)
        .cloned()
        .unwrap_or_else(Table::new);
    let mut hosts = Table::new();
    hosts.set_implicit(true);
    let mut mirror = Table::new();
    let mut capabilities = Array::new();
    capabilities.push("pull");
    capabilities.push("resolve");
    mirror["capabilities"] = value(capabilities);
    mirror["skip_verify"] = value(false);
    hosts.insert(MIRROR, Item::Table(mirror));
    for (key, item) in existing.iter() {
        if key != MIRROR {
            hosts.insert(key, item.clone());
        }
    }
    document["host"] = Item::Table(hosts);
    let rendered = document.to_string();
    Ok(format!("{HOSTS_MARKER}\n{rendered}"))
}

fn render_hosts() -> String {
    format!(
        "{HOSTS_MARKER}\nserver = \"{SOURCE}\"\n\n[host.\"{MIRROR}\"]\n  capabilities = [\"pull\", \"resolve\"]\n  skip_verify = false\n"
    )
}

fn config_path_contains(value: Option<&str>, expected: &str) -> bool {
    value.is_some_and(|value| value.split(':').any(|path| path == expected))
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "cri-disabled" => {
                return Err(AdapterError::Unsupported(
                    "containerd CRI plugin is explicitly disabled".into(),
                ));
            }
            "legacy-registry-config" => {
                return Err(AdapterError::Unsupported(
                    "deprecated registry.mirrors/configs must be migrated before config_path can be enabled"
                        .into(),
                ));
            }
            "custom-server" => {
                return Err(AdapterError::Unsupported(
                    "registry.k8s.io hosts.toml uses a custom primary server".into(),
                ));
            }
            "unsafe-existing-mirror" => {
                return Err(AdapterError::Unsupported(
                    "existing NJU containerd host disables TLS verification or has unsafe capabilities"
                        .into(),
                ));
            }
            "existing-nju-host" => {
                return Err(AdapterError::Unsupported(
                    "existing NJU host policy is not owned by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_selection(selections: &[MirrorSelection]) -> Result<(), AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "containerd"
        || selections[0].upstream_id != UPSTREAM
        || selections[0].provider_id != "nju"
    {
        return Err(AdapterError::InvalidConfiguration(
            "containerd requires exactly one reviewed registry.k8s.io selection".into(),
        ));
    }
    let endpoints = selections[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Registry && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    if endpoints.len() != 1 || normalized_endpoint(&endpoints[0].url).as_deref() != Some(MIRROR) {
        return Err(AdapterError::InvalidConfiguration(
            "containerd registry endpoint is not the reviewed NJU mirror".into(),
        ));
    }
    Ok(())
}

fn normalized_endpoint(value: &str) -> Option<String> {
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

fn containerd_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = run_containerd(runtime, &["--version"], "containerd --version")?;
    output
        .split_whitespace()
        .find_map(|token| {
            let version = token.strip_prefix('v').unwrap_or(token);
            (version
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
                && version.matches('.').count() >= 1)
                .then(|| version.to_owned())
        })
        .ok_or_else(|| AdapterError::Unsupported("containerd version output is invalid".into()))
}

fn version_major(version: &str) -> Option<u64> {
    version.split('.').next()?.parse().ok()
}

fn review_version(version: &str) -> Result<(), AdapterError> {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|value| value.parse::<u64>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u64>().ok());
    if !matches!((major, minor), (Some(1), Some(7..)) | (Some(2), Some(_))) {
        return Err(AdapterError::Unsupported(format!(
            "containerd {version} is outside reviewed 1.7+ and 2.x hosts.toml support"
        )));
    }
    Ok(())
}

fn cri_plugin_state(runtime: &dyn Runtime) -> String {
    let output = run_ctr(runtime, &["plugins", "ls"], "ctr plugins list");
    match output {
        Ok(output)
            if output
                .lines()
                .any(|line| line.contains("cri") && line.contains("ok")) =>
        {
            "ok".into()
        }
        Ok(_) => "not confirmed".into(),
        Err(_) => "daemon unavailable".into(),
    }
}

fn run_containerd(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    run_command(runtime, "containerd", arguments, label)
}

fn run_ctr(runtime: &dyn Runtime, arguments: &[&str], label: &str) -> Result<String, AdapterError> {
    run_command(runtime, "ctr", arguments, label)
}

fn run_command(
    runtime: &dyn Runtime,
    program: &str,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = runtime.run(program, &arguments)?;
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

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<&'a ConfigurationDocument, AdapterError> {
    current
        .documents
        .iter()
        .find(|document| document.format == format)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "containerd current state is missing {format}"
            ))
        })
}

fn add_change(
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

fn current_value(current: &CurrentConfiguration, kind: &str) -> Result<String, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some(kind))
        .map(|source| metadata(source, "value").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "containerd state has ambiguous {kind}"
        )));
    }
    Ok(values[0].clone())
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("containerd-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
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
        AdapterError::InvalidConfiguration(format!("containerd source lacks {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "containerd source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn path_string(path: &Path) -> Result<&str, AdapterError> {
    path.to_str().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("path {} is not UTF-8", path.display()))
    })
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "containerd configuration {} is not UTF-8",
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
        "{reason}; containerd configuration restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
