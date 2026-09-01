use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use toml_edit::{DocumentMut, Item};

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

const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: Podman registry mirrors v1";

#[derive(Clone, Copy)]
struct RegistrySpec {
    upstream: &'static str,
    source: &'static str,
    mirror: &'static str,
    repository: &'static str,
    tag: &'static str,
}

const REGISTRIES: &[RegistrySpec] = &[
    RegistrySpec {
        upstream: "gcr.io--container-registry",
        source: "gcr.io",
        mirror: "gcr.nju.edu.cn",
        repository: "distroless/static-debian12",
        tag: "nonroot",
    },
    RegistrySpec {
        upstream: "ghcr.io--container-registry",
        source: "ghcr.io",
        mirror: "ghcr.nju.edu.cn",
        repository: "oras-project/oras",
        tag: "v1.2.0",
    },
    RegistrySpec {
        upstream: "quay.io--container-registry",
        source: "quay.io",
        mirror: "quay.nju.edu.cn",
        repository: "prometheus/node-exporter",
        tag: "v1.9.1",
    },
];

#[derive(Clone, Copy, Debug, Default)]
pub struct PodmanRegistryAdapter;

impl Adapter for PodmanRegistryAdapter {
    fn key(&self) -> &'static str {
        "podman-registry"
    }

    fn tool_id(&self) -> &'static str {
        "podman-registry"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System, ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::User
    }

    fn default_scope_for(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
    ) -> Result<ConfigurationScope, AdapterError> {
        require_linux(context)?;
        Ok(if podman_rootless(runtime)? {
            ConfigurationScope::User
        } else {
            ConfigurationScope::System
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
        require_linux(context)?;
        if !runtime.command_exists("podman") {
            return Ok(None);
        }
        let version = podman_version(runtime)?;
        review_version(&version)?;
        let rootless = podman_rootless(runtime)?;
        require_info(runtime)?;
        let layout = layout(runtime)?;
        let documents = read_documents(runtime, &layout, ConfigurationScope::User)?;
        let legacy = documents
            .iter()
            .filter(|document| document.exists && document.kind == ConfigKind::V1)
            .count();
        let v2 = documents
            .iter()
            .filter(|document| document.exists && document.kind == ConfigKind::V2)
            .count();
        Ok(Some(DetectedTool {
            tool_id: "podman-registry".into(),
            executable: Some(PathBuf::from("podman")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Podman {version}"),
                format!("Podman backend is rootless: {rootless}"),
                format!("registries.conf v1 documents: {legacy}"),
                format!("registries.conf v2 documents: {v2}"),
                format!(
                    "system drop-in target is {}",
                    layout.system_target.display()
                ),
                format!("user drop-in target is {}", layout.user_target.display()),
                format!(
                    "REGISTRY_AUTH_FILE is {}",
                    if runtime
                        .environment_variable("REGISTRY_AUTH_FILE")
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        "set and preserved"
                    } else {
                        "unset"
                    }
                ),
                "Docker daemon.json is not a Podman configuration surface".into(),
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
        if detected.tool_id != "podman-registry" {
            return Err(AdapterError::InvalidConfiguration(
                "Podman registry read received another tool's detection result".into(),
            ));
        }
        let version = podman_version(runtime)?;
        review_version(&version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Podman version changed after detection".into(),
            ));
        }
        let layout = layout(runtime)?;
        let documents = read_documents(runtime, &layout, scope)?;
        let target = target_path(&layout, scope);
        let mut files = Vec::new();
        let mut configs = Vec::new();
        let mut sources = vec![snapshot_source("podman-version", &version)];
        sources.push(snapshot_source(
            "podman-rootless",
            if podman_rootless(runtime)? {
                "true"
            } else {
                "false"
            },
        ));
        for document in documents {
            if document.exists {
                files.push(document.path.clone());
            }
            if document.path == target
                && document.exists
                && utf8(&document.path, &document.contents)?
                    .lines()
                    .next()
                    .is_none_or(|line| line != MANAGED_MARKER)
            {
                sources.push(policy_source("managed-target-conflict", &document.path));
            }
            if document.kind == ConfigKind::V1 {
                sources.push(policy_source("legacy-v1-config", &document.path));
            }
            inspect_registry_policy(&document, &target, &mut sources)?;
            configs.push(ConfigurationDocument {
                path: document.path.clone(),
                format: if document.path == target {
                    "podman-managed-registry-drop-in".into()
                } else {
                    "podman-registry-config-read-only".into()
                },
                contents: document.contents,
            });
        }
        if runtime
            .environment_variable("REGISTRY_AUTH_FILE")
            .is_some_and(|value| !value.trim().is_empty())
        {
            sources.push(policy_source(
                "authentication-override-preserved",
                Path::new(":env:"),
            ));
        }
        sources.push(policy_source(
            "containers-auth-preserved",
            Path::new(":containers-auth:"),
        ));
        Ok(CurrentConfiguration {
            tool_id: "podman-registry".into(),
            scope,
            files,
            sources,
            documents: configs,
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
            AdapterError::InvalidConfiguration("Podman version is missing".into())
        })?)?;
        let architecture = match context.architecture {
            Architecture::X86_64 => "amd64",
            Architecture::Arm64 => "arm64",
        };
        let required_upstreams = REGISTRIES
            .iter()
            .map(|registry| registry.upstream.into())
            .collect::<Vec<_>>();
        let probe_contexts = REGISTRIES
            .iter()
            .map(|registry| {
                (
                    registry.upstream.into(),
                    vec![BTreeMap::from([
                        ("repository_path".into(), registry.repository.into()),
                        ("tag".into(), registry.tag.into()),
                        ("oci_arch".into(), architecture.into()),
                    ])],
                )
            })
            .collect();
        Ok(SelectionRequest {
            tool_id: "podman-registry".into(),
            adapter_key: "podman-registry".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams,
            repository_versions: BTreeMap::new(),
            probe_contexts,
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
        validate_selections(selections)?;
        let target = find_document(current, "podman-managed-registry-drop-in")?;
        let rendered = render_config().into_bytes();
        let changes = if target.contents == rendered {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &target.path),
                old_contents: current
                    .files
                    .contains(&target.path)
                    .then(|| target.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: "add three secure containers/image registry mirror mappings without changing short-name, blocked, insecure, private registry, or authentication policy".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "podman-registry".into(),
            tool_id: "podman-registry".into(),
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
            let layout = layout(runtime)?;
            let system_target = rooted(&context.root, &layout.system_target);
            let user_target = rooted(&context.root, &layout.user_target);
            let logical_target = if receipt.changed_targets.contains(&system_target) {
                layout.system_target
            } else if receipt.changed_targets.contains(&user_target) {
                layout.user_target
            } else {
                return Err(AdapterError::Verification(
                    "Podman registry transaction contains no known target".into(),
                ));
            };
            let target = rooted(&context.root, &logical_target);
            if receipt.changed_targets.len() != 1 || !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "Podman registry transaction changed an unexpected target".into(),
                ));
            }
            let contents = runtime.read(&logical_target)?.ok_or_else(|| {
                AdapterError::Verification("Podman registry drop-in disappeared".into())
            })?;
            let text = utf8(&logical_target, &contents)?;
            if text != render_config() {
                return Err(AdapterError::Verification(
                    "Podman registry drop-in is not canonical".into(),
                ));
            }
            parse_document(&logical_target, text)?;
            require_info(runtime)?;
            let home = runtime.home_dir().ok_or_else(|| {
                AdapterError::Verification("Podman verification requires a user home".into())
            })?;
            let root = home.join(".mirrorswitch/verification/podman/root");
            let runroot = home.join(".mirrorswitch/verification/podman/runroot");
            let mut verified = 0;
            for registry in REGISTRIES {
                let image = format!(
                    "{}/{}:{}",
                    registry.source, registry.repository, registry.tag
                );
                let output = run_podman(
                    runtime,
                    &[
                        "--log-level=debug",
                        "--root",
                        path_string(&root)?,
                        "--runroot",
                        path_string(&runroot)?,
                        "--storage-driver=vfs",
                        "--events-backend=file",
                        "pull",
                        &image,
                    ],
                    "Podman mirror pull verification",
                )?;
                if !output.contains(registry.mirror) {
                    return Err(AdapterError::Verification(format!(
                        "Podman did not report pulling {image} through {}",
                        registry.mirror
                    )));
                }
                verified += 1;
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Podman parsed the selected scope and pulled {verified} representative images through their secure NJU mirrors using an isolated image store"
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
                "restored {} Podman registry configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug)]
struct Layout {
    system_main: PathBuf,
    system_dir: PathBuf,
    system_target: PathBuf,
    user_main: PathBuf,
    user_dir: PathBuf,
    user_target: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigKind {
    Empty,
    Neutral,
    V1,
    V2,
}

#[derive(Debug)]
struct ObservedDocument {
    path: PathBuf,
    contents: Vec<u8>,
    exists: bool,
    kind: ConfigKind,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Podman registry v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if !matches!(scope, ConfigurationScope::System | ConfigurationScope::User) {
        return Err(AdapterError::Unsupported(
            "Podman registry adapter supports explicit system or user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "podman-registry"
        || !matches!(
            current.scope,
            ConfigurationScope::System | ConfigurationScope::User
        )
    {
        return Err(AdapterError::InvalidConfiguration(
            "Podman registry operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Podman registry requires a user home".into()))?;
    validate_path(&home, "home")?;
    let config_home = match runtime
        .environment_variable("XDG_CONFIG_HOME")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => {
            let path = PathBuf::from(value);
            validate_user_path(&path, &home, "XDG_CONFIG_HOME")?;
            path
        }
        None => home.join(".config"),
    };
    let user_dir = config_home.join("containers/registries.conf.d");
    let system_dir = PathBuf::from("/etc/containers/registries.conf.d");
    Ok(Layout {
        system_main: PathBuf::from("/etc/containers/registries.conf"),
        system_target: system_dir.join("99-mirrorswitch.conf"),
        system_dir,
        user_main: config_home.join("containers/registries.conf"),
        user_target: user_dir.join("99-mirrorswitch.conf"),
        user_dir,
    })
}

fn target_path(layout: &Layout, scope: ConfigurationScope) -> PathBuf {
    if scope == ConfigurationScope::System {
        layout.system_target.clone()
    } else {
        layout.user_target.clone()
    }
}

fn read_documents(
    runtime: &dyn Runtime,
    layout: &Layout,
    scope: ConfigurationScope,
) -> Result<Vec<ObservedDocument>, AdapterError> {
    let target = target_path(layout, scope);
    let mut paths = BTreeSet::from([layout.system_main.clone(), target]);
    for path in runtime.list_files(&layout.system_dir)? {
        if path
            .extension()
            .is_some_and(|extension| extension == "conf")
        {
            paths.insert(path);
        }
    }
    if scope == ConfigurationScope::User {
        paths.insert(layout.user_main.clone());
        for path in runtime.list_files(&layout.user_dir)? {
            if path
                .extension()
                .is_some_and(|extension| extension == "conf")
            {
                paths.insert(path);
            }
        }
    }
    let mut documents = Vec::new();
    for path in paths {
        let contents = runtime.read(&path)?;
        let exists = contents.is_some();
        let contents = contents.unwrap_or_default();
        let kind = if exists {
            classify_document(&path, utf8(&path, &contents)?)?
        } else {
            ConfigKind::Empty
        };
        documents.push(ObservedDocument {
            path,
            contents,
            exists,
            kind,
        });
    }
    Ok(documents)
}

fn classify_document(path: &Path, text: &str) -> Result<ConfigKind, AdapterError> {
    if text.trim().is_empty() {
        return Ok(ConfigKind::Empty);
    }
    let document = parse_document(path, text)?;
    if document.get("registries").is_some() {
        Ok(ConfigKind::V1)
    } else if document.get("registry").is_some() {
        if document["registry"].as_array_of_tables().is_none() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Podman registry entry in {} is not an array of tables",
                path.display()
            )));
        }
        Ok(ConfigKind::V2)
    } else {
        Ok(ConfigKind::Neutral)
    }
}

fn parse_document(path: &Path, text: &str) -> Result<DocumentMut, AdapterError> {
    text.parse::<DocumentMut>().map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Podman registry configuration {} is invalid TOML",
            path.display()
        ))
    })
}

fn inspect_registry_policy(
    observed: &ObservedDocument,
    managed_target: &Path,
    sources: &mut Vec<ConfiguredSource>,
) -> Result<(), AdapterError> {
    if !observed.exists || observed.kind != ConfigKind::V2 {
        return Ok(());
    }
    let document = parse_document(&observed.path, utf8(&observed.path, &observed.contents)?)?;
    let registries = document["registry"].as_array_of_tables().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Podman registry tables are invalid".into())
    })?;
    for table in registries.iter() {
        let prefix = table
            .get("prefix")
            .and_then(Item::as_str)
            .or_else(|| table.get("location").and_then(Item::as_str));
        let Some(prefix) = prefix else {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Podman registry entry in {} has no prefix or location",
                observed.path.display()
            )));
        };
        let Some(spec) = REGISTRIES.iter().find(|registry| {
            prefix == registry.source
                || prefix
                    .strip_prefix(registry.source)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) else {
            sources.push(policy_source(
                "non-target-registry-preserved",
                &observed.path,
            ));
            continue;
        };
        let blocked = bool_field(table.get("blocked"), "blocked", &observed.path)?;
        let insecure = bool_field(table.get("insecure"), "insecure", &observed.path)?;
        if observed.path != managed_target {
            let kind = if blocked {
                "target-registry-blocked"
            } else if insecure {
                "target-registry-insecure"
            } else {
                "existing-target-registry-policy"
            };
            sources.push(policy_source(kind, &observed.path));
            continue;
        }
        sources.push(ConfiguredSource {
            upstream_id: Some(spec.upstream.into()),
            url: format!("https://{}", spec.mirror),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["managed-registry-mirror".into()]),
                (
                    "config_path".into(),
                    vec![observed.path.display().to_string()],
                ),
            ]),
        });
    }
    Ok(())
}

fn bool_field(item: Option<&Item>, name: &str, path: &Path) -> Result<bool, AdapterError> {
    item.map(|item| {
        item.as_bool().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Podman {name} field in {} is not boolean",
                path.display()
            ))
        })
    })
    .transpose()
    .map(|value| value.unwrap_or(false))
}

fn podman_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = run_podman(runtime, &["--version"], "podman --version")?;
    output
        .split_whitespace()
        .find(|token| valid_version(token))
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("Podman version output is unrecognized".into()))
}

fn podman_rootless(runtime: &dyn Runtime) -> Result<bool, AdapterError> {
    let output = run_podman(
        runtime,
        &["info", "--format", "{{.Host.Security.Rootless}}"],
        "Podman rootless detection",
    )?;
    match output.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AdapterError::Unsupported(
            "Podman did not report a rootless boolean".into(),
        )),
    }
}

fn require_info(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let output = run_podman(
        runtime,
        &["info", "--format", "json"],
        "Podman configuration parse",
    )?;
    if !output.trim_start().starts_with('{') {
        return Err(AdapterError::Unsupported(
            "Podman info did not return JSON".into(),
        ));
    }
    Ok(())
}

fn run_podman(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    command_output(runtime.run("podman", &arguments)?, label)
}

fn command_output(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
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

fn valid_version(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
        && value.split(['.', '-', '+']).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn review_version(version: &str) -> Result<(), AdapterError> {
    let major = version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    if !matches!(major, Some(4 | 5)) {
        return Err(AdapterError::Unsupported(format!(
            "Podman {version} is outside the reviewed 4.x and 5.x registries.conf v2 model"
        )));
    }
    Ok(())
}

fn render_config() -> String {
    let mut output = format!("{MANAGED_MARKER}\n");
    for (index, registry) in REGISTRIES.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&format!(
            "[[registry]]\nprefix = \"{}\"\nlocation = \"{}\"\nblocked = false\ninsecure = false\n\n[[registry.mirror]]\nlocation = \"{}\"\ninsecure = false\npull-from-mirror = \"all\"\n",
            registry.source, registry.source, registry.mirror
        ));
    }
    output
}

fn validate_selections(selections: &[MirrorSelection]) -> Result<(), AdapterError> {
    if selections.len() != REGISTRIES.len() {
        return Err(AdapterError::InvalidConfiguration(
            "Podman registry mapping requires exactly three selections".into(),
        ));
    }
    for registry in REGISTRIES {
        let matches = selections
            .iter()
            .filter(|selection| {
                selection.tool_id == "podman-registry" && selection.upstream_id == registry.upstream
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Podman registry mapping requires one {} selection",
                registry.source
            )));
        }
        let selection = matches[0];
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.role == EndpointRole::Registry && endpoint.protocol == Protocol::Https
            })
            .collect::<Vec<_>>();
        if selection.provider_id != "nju"
            || endpoints.len() != 1
            || normalized_endpoint(&endpoints[0].url).as_deref()
                != Some(&format!("https://{}", registry.mirror))
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Podman {} mirror selection is not reviewed",
                registry.source
            )));
        }
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

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "legacy-v1-config" => {
                return Err(AdapterError::Unsupported(
                    "effective registries.conf v1 must be migrated before v2 mirrors can be added"
                        .into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Podman registry drop-in target contains data not managed by MirrorSwitch"
                        .into(),
                ));
            }
            "target-registry-blocked" => {
                return Err(AdapterError::Unsupported(
                    "an effective target registry is explicitly blocked and will remain blocked"
                        .into(),
                ));
            }
            "target-registry-insecure" => {
                return Err(AdapterError::Unsupported(
                    "an effective target registry uses insecure transport and will not be shadowed"
                        .into(),
                ));
            }
            "existing-target-registry-policy" => {
                return Err(AdapterError::Unsupported(
                    "an effective target registry already has user or administrator mirror policy"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<&'a ConfigurationDocument, AdapterError> {
    let matches = current
        .documents
        .iter()
        .filter(|document| document.format == format)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Podman current configuration must contain exactly one {format} document"
        )));
    }
    Ok(matches[0])
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("podman-registry-snapshot:{value}"),
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
        AdapterError::InvalidConfiguration(format!(
            "Podman registry source is missing {key} metadata"
        ))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Podman registry source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn path_string(path: &Path) -> Result<&str, AdapterError> {
    path.to_str().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("path {} is not UTF-8", path.display()))
    })
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "Podman {kind} {} is outside the user home",
            path.display()
        )));
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
            "Podman reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Podman registry configuration {} is not UTF-8",
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
        "{reason}; registry configuration restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
