use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use serde_json::{Map, Value};

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

const UPSTREAM: &str = "docker-hub--container-registry";
const DAOCLOUD: &str = "https://docker.m.daocloud.io";
const ONEPANEL: &str = "https://docker.1panel.live";

#[derive(Clone, Copy)]
struct ImageProbe {
    platform: &'static str,
    manifest: &'static str,
    config: &'static str,
    layer: &'static str,
}

const AMD64_PROBE: ImageProbe = ImageProbe {
    platform: "linux/amd64",
    manifest: "f27cad9117495d32d067133afff942cb2dc745dfe9163e949f6bfe8a6a245339",
    config: "2607caa9805847fac4de202017bb1b830deb09f4c07dc9964a0157abbc604577",
    layer: "897d797d2723cf0e318402f4d6f37d51b011517e5cf09246b22155f0fa90dc81",
};

const ARM64_PROBE: ImageProbe = ImageProbe {
    platform: "linux/arm64",
    manifest: "1832327faf048390adc33852575d37c7ba155e064a339e78b9bd81983a8c7a00",
    config: "2155344e09b47f8ea09459100e050bed74b5202316318fd0ad0f7f6856089efc",
    layer: "2dd7199cff98a7400e801cbfad6de906972a4e3dd0a749d4c1b80f5a1e3e4108",
};

#[derive(Clone, Copy, Debug, Default)]
pub struct DockerRegistryAdapter;

impl Adapter for DockerRegistryAdapter {
    fn key(&self) -> &'static str {
        "docker-registry"
    }

    fn tool_id(&self) -> &'static str {
        "docker-registry"
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
        require_linux(context)?;
        Ok(backend(runtime)?.scope())
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
        if !runtime.command_exists("docker") {
            return Ok(None);
        }
        let version = docker_version(runtime)?;
        review_version(&version)?;
        let backend = backend(runtime)?;
        let workloads = docker_output(runtime, &["ps", "--quiet"], "Docker workload query")?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        Ok(Some(DetectedTool {
            tool_id: "docker-registry".into(),
            executable: Some(PathBuf::from("docker")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Docker client {version}"),
                format!("effective Docker context is {}", backend.context),
                format!("effective Docker endpoint is local ({})", backend.endpoint),
                format!("Docker backend is {}", backend.kind.label()),
                format!("daemon configuration is {}", backend.config_path.display()),
                format!("service management is {}", backend.service_manager),
                format!("running containers: {workloads}"),
                format!(
                    "DOCKER_HOST/DOCKER_CONTEXT overrides are {}",
                    if ["DOCKER_HOST", "DOCKER_CONTEXT"].iter().any(|name| {
                        runtime
                            .environment_variable(name)
                            .is_some_and(|value| !value.trim().is_empty())
                    }) {
                        "set and preserved"
                    } else {
                        "unset"
                    }
                ),
                "Docker daemon restart is never automatic".into(),
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
        if detected.tool_id != "docker-registry" {
            return Err(AdapterError::InvalidConfiguration(
                "Docker registry read received another tool's detection result".into(),
            ));
        }
        let version = docker_version(runtime)?;
        review_version(&version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Docker client version changed after detection".into(),
            ));
        }
        let backend = backend(runtime)?;
        let contents = runtime.read(&backend.config_path)?;
        let document = parse_config(&backend.config_path, contents.as_deref().unwrap_or(b"{}"))?;
        let mut sources = vec![snapshot_source("docker-version", &version)];
        sources.push(snapshot_source("docker-context", &backend.context));
        sources.push(snapshot_source("docker-endpoint", &backend.endpoint));
        sources.push(snapshot_source("docker-backend", backend.kind.key()));
        sources.push(snapshot_source(
            "docker-config-path",
            path_string(&backend.config_path)?,
        ));
        sources.push(snapshot_source("service-manager", &backend.service_manager));
        if scope != backend.scope() {
            sources.push(policy_source("inactive-backend-scope"));
        }
        if backend.registry_mirror_flag {
            sources.push(policy_source("registry-mirror-startup-flag"));
        }
        if document.contains_key("insecure-registries") {
            sources.push(policy_source("insecure-registries-preserved"));
        }
        if document.contains_key("proxies") {
            sources.push(policy_source("daemon-proxies-preserved"));
        }
        for mirror in registry_mirrors(&backend.config_path, &document)? {
            sources.push(ConfiguredSource {
                upstream_id: Some(UPSTREAM.into()),
                url: mirror,
                enabled: true,
                metadata: BTreeMap::from([("kind".into(), vec!["registry-mirror".into()])]),
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "docker-registry".into(),
            scope,
            files: contents
                .is_some()
                .then(|| backend.config_path.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path: backend.config_path,
                format: "docker-daemon-json".into(),
                contents: contents.unwrap_or_else(|| b"{}".to_vec()),
            }],
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
        if has_policy(current, "inactive-backend-scope") {
            return Err(AdapterError::Unsupported(
                "the requested scope does not control the effective Docker backend".into(),
            ));
        }
        review_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Docker client version is missing".into())
        })?)?;
        let probe = image_probe(context.architecture);
        Ok(SelectionRequest {
            tool_id: "docker-registry".into(),
            adapter_key: "docker-registry".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("manifest_hash".into(), probe.manifest.into()),
                    ("config_hash".into(), probe.config.into()),
                    ("layer_hash".into(), probe.layer.into()),
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
        if has_policy(current, "inactive-backend-scope") {
            return Err(AdapterError::Unsupported(
                "the requested scope does not control the effective Docker backend".into(),
            ));
        }
        if has_policy(current, "registry-mirror-startup-flag") {
            return Err(AdapterError::Unsupported(
                "dockerd already sets --registry-mirror on its startup command; daemon.json would conflict"
                    .into(),
            ));
        }
        let selected = validate_selection(selections)?;
        let target = current
            .documents
            .iter()
            .find(|document| document.format == "docker-daemon-json")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Docker daemon configuration is missing".into())
            })?;
        let mut document = parse_config(&target.path, &target.contents)?;
        let existing = registry_mirrors(&target.path, &document)?;
        let mut mirrors = vec![Value::String(selected.into())];
        for mirror in existing {
            if normalized_mirror(&mirror).as_deref() != Some(selected) {
                mirrors.push(Value::String(mirror));
            }
        }
        document.insert("registry-mirrors".into(), Value::Array(mirrors));
        let mut rendered =
            serde_json::to_vec_pretty(&Value::Object(document)).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "could not render Docker daemon configuration: {error}"
                ))
            })?;
        rendered.push(b'\n');
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
                summary: "place the selected secure Docker Hub mirror first while preserving existing mirrors, insecure registries, proxies, and unrelated daemon settings".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "docker-registry".into(),
            tool_id: "docker-registry".into(),
            scope: current.scope,
            requires_elevation: current.scope == ConfigurationScope::System,
            service_impact: if changes.is_empty() {
                ServiceImpact::None
            } else {
                ServiceImpact::RestartRequired
            },
            changes,
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
            let backend = backend(runtime)?;
            let target = rooted(&context.root, &backend.config_path);
            if receipt.changed_targets.len() != 1 || !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "Docker registry transaction changed an unexpected target".into(),
                ));
            }
            let contents = runtime.read(&backend.config_path)?.ok_or_else(|| {
                AdapterError::Verification("Docker daemon configuration disappeared".into())
            })?;
            let document = parse_config(&backend.config_path, &contents)?;
            let mirrors = registry_mirrors(&backend.config_path, &document)?;
            let selected = mirrors
                .first()
                .and_then(|mirror| normalized_mirror(mirror))
                .filter(|mirror| matches!(mirror.as_str(), DAOCLOUD | ONEPANEL))
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "selected Docker Hub mirror is not first in daemon.json".into(),
                    )
                })?;
            let validated_by_dockerd = if runtime.command_exists("dockerd") {
                docker_daemon_output(
                    runtime,
                    &[
                        "--validate",
                        "--config-file",
                        path_string(&backend.config_path)?,
                    ],
                    "dockerd configuration validation",
                )?;
                true
            } else if backend.kind == BackendKind::Desktop {
                false
            } else {
                return Err(AdapterError::Verification(
                    "dockerd is required to validate Docker Engine daemon.json".into(),
                ));
            };
            let probe = image_probe(context.architecture);
            let image = format!(
                "{}/library/alpine@sha256:{}",
                selected.trim_start_matches("https://"),
                probe.manifest
            );
            docker_output(
                runtime,
                &["pull", "--platform", probe.platform, &image],
                "Docker mirror pull verification",
            )?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} daemon JSON and a digest-pinned Alpine pull for {} through {} succeeded; daemon restart was not performed{}",
                    backend.kind.label(),
                    probe.platform,
                    selected,
                    if validated_by_dockerd {
                        " after dockerd validation"
                    } else {
                        " (Docker Desktop will validate the engine setting when restarted)"
                    }
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
                "restored {} Docker daemon configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendKind {
    Engine,
    Rootless,
    Desktop,
}

impl BackendKind {
    fn key(self) -> &'static str {
        match self {
            Self::Engine => "engine",
            Self::Rootless => "rootless-engine",
            Self::Desktop => "desktop-linux",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Engine => "Docker Engine",
            Self::Rootless => "rootless Docker Engine",
            Self::Desktop => "Docker Desktop for Linux",
        }
    }
}

struct DockerBackend {
    kind: BackendKind,
    context: String,
    endpoint: String,
    config_path: PathBuf,
    service_manager: String,
    registry_mirror_flag: bool,
}

impl DockerBackend {
    fn scope(&self) -> ConfigurationScope {
        if self.kind == BackendKind::Engine {
            ConfigurationScope::System
        } else {
            ConfigurationScope::User
        }
    }
}

fn backend(runtime: &dyn Runtime) -> Result<DockerBackend, AdapterError> {
    let context = docker_output(runtime, &["context", "show"], "Docker context query")?;
    let context = one_line(&context, "Docker context")?;
    let endpoint = docker_output(
        runtime,
        &[
            "context",
            "inspect",
            &context,
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        "Docker context endpoint query",
    )?;
    let endpoint: String = serde_json::from_str(endpoint.trim()).map_err(|_| {
        AdapterError::InvalidConfiguration("Docker context endpoint is not valid JSON".into())
    })?;
    if !endpoint.starts_with("unix://") {
        return Err(AdapterError::Unsupported(format!(
            "Docker context {context} targets a remote or unsupported endpoint"
        )));
    }
    let info = docker_output(
        runtime,
        &["info", "--format", "{{json .}}"],
        "Docker daemon information query",
    )?;
    let info: Value = serde_json::from_str(info.trim()).map_err(|_| {
        AdapterError::InvalidConfiguration("Docker daemon information is not valid JSON".into())
    })?;
    let desktop = context == "desktop-linux"
        || endpoint.contains("/.docker/desktop/")
        || info
            .get("OperatingSystem")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("Docker Desktop"));
    let rootless = info
        .get("SecurityOptions")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .any(|value| value.contains("rootless"))
        });
    let kind = if desktop {
        BackendKind::Desktop
    } else if rootless {
        BackendKind::Rootless
    } else {
        BackendKind::Engine
    };
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Docker registry requires a user home".into()))?;
    validate_path(&home, "home")?;
    let default_path = match kind {
        BackendKind::Engine => PathBuf::from("/etc/docker/daemon.json"),
        BackendKind::Desktop => home.join(".docker/daemon.json"),
        BackendKind::Rootless => {
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
            config_home.join("docker/daemon.json")
        }
    };
    let (service_manager, service_command) = if kind == BackendKind::Desktop {
        ("Docker Desktop".into(), None)
    } else if runtime.command_exists("systemctl") {
        let mut arguments = Vec::new();
        if kind == BackendKind::Rootless {
            arguments.push("--user".into());
        }
        arguments.extend([
            "show".into(),
            "docker.service".into(),
            "--property=ExecStart".into(),
            "--value".into(),
        ]);
        let output = runtime.run("systemctl", &arguments)?;
        let command = output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .filter(|value| !value.is_empty());
        (
            if kind == BackendKind::Rootless {
                "systemd user service"
            } else {
                "systemd system service"
            }
            .into(),
            command,
        )
    } else {
        ("external/manual".into(), None)
    };
    let registry_mirror_flag = service_command
        .as_deref()
        .is_some_and(|value| has_argument(value, "--registry-mirror"));
    let config_path = service_command
        .as_deref()
        .and_then(config_file_argument)
        .unwrap_or(default_path);
    validate_path(&config_path, "daemon configuration")?;
    if kind != BackendKind::Engine {
        validate_user_path(&config_path, &home, "daemon configuration")?;
    }
    Ok(DockerBackend {
        kind,
        context,
        endpoint,
        config_path,
        service_manager,
        registry_mirror_flag,
    })
}

fn config_file_argument(command: &str) -> Option<PathBuf> {
    let mut arguments = command.split_whitespace();
    while let Some(argument) = arguments.next() {
        let argument = argument.trim_matches(['{', '}', ';', '"']);
        if let Some(path) = argument.strip_prefix("--config-file=") {
            return Some(PathBuf::from(path.trim_matches([';', '"'])));
        }
        if argument == "--config-file" {
            return arguments
                .next()
                .map(|path| PathBuf::from(path.trim_matches([';', '"'])));
        }
    }
    None
}

fn has_argument(command: &str, name: &str) -> bool {
    command.split_whitespace().any(|argument| {
        let argument = argument.trim_matches(['{', '}', ';', '"']);
        argument == name || argument.starts_with(&format!("{name}="))
    })
}

fn parse_config(path: &Path, contents: &[u8]) -> Result<Map<String, Value>, AdapterError> {
    let value: Value = serde_json::from_slice(contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Docker daemon configuration {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    value.as_object().cloned().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "Docker daemon configuration {} must be a JSON object",
            path.display()
        ))
    })
}

fn registry_mirrors(
    path: &Path,
    document: &Map<String, Value>,
) -> Result<Vec<String>, AdapterError> {
    let Some(value) = document.get("registry-mirrors") else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "Docker registry-mirrors in {} must be an array",
            path.display()
        ))
    })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Docker registry-mirrors in {} must contain non-empty strings",
                        path.display()
                    ))
                })
        })
        .collect()
}

fn validate_selection(selections: &[MirrorSelection]) -> Result<&'static str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "docker-registry"
        || selections[0].upstream_id != UPSTREAM
        || selections[0].endpoints.len() != 1
        || selections[0].endpoints[0].role != EndpointRole::Registry
        || selections[0].endpoints[0].protocol != Protocol::Https
    {
        return Err(AdapterError::InvalidConfiguration(
            "Docker registry requires one HTTPS Docker Hub proxy selection".into(),
        ));
    }
    let endpoint = normalized_mirror(&selections[0].endpoints[0].url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Docker registry mirror URL is invalid".into())
    })?;
    match (selections[0].provider_id.as_str(), endpoint.as_str()) {
        ("daocloud", DAOCLOUD) => Ok(DAOCLOUD),
        ("onepanel", ONEPANEL) => Ok(ONEPANEL),
        _ => Err(AdapterError::InvalidConfiguration(
            "Docker registry selection is not a reviewed public mirror".into(),
        )),
    }
}

fn normalized_mirror(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('/');
    if !value.starts_with("https://") || value[8..].contains('/') || value.contains('@') {
        return None;
    }
    Some(value.to_owned())
}

fn image_probe(architecture: Architecture) -> ImageProbe {
    match architecture {
        Architecture::X86_64 => AMD64_PROBE,
        Architecture::Arm64 => ARM64_PROBE,
    }
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Docker registry adapter supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "docker-registry"
        || !matches!(
            current.scope,
            ConfigurationScope::System | ConfigurationScope::User
        )
    {
        return Err(AdapterError::InvalidConfiguration(
            "Docker registry operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn docker_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    docker_output(
        runtime,
        &["version", "--format", "{{.Client.Version}}"],
        "Docker client version query",
    )
    .and_then(|value| one_line(&value, "Docker client version"))
}

fn review_version(version: &str) -> Result<(), AdapterError> {
    let major = version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    if !matches!(major, Some(20..=29)) {
        return Err(AdapterError::Unsupported(format!(
            "Docker client {version} is outside the reviewed 20.x-29.x range"
        )));
    }
    Ok(())
}

fn docker_output(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    command_output(
        runtime.run(
            "docker",
            &arguments
                .iter()
                .map(|value| (*value).into())
                .collect::<Vec<_>>(),
        )?,
        label,
    )
}

fn docker_daemon_output(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    command_output(
        runtime.run(
            "dockerd",
            &arguments
                .iter()
                .map(|value| (*value).into())
                .collect::<Vec<_>>(),
        )?,
        label,
    )
}

fn command_output(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = if detail.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", detail.trim())
        };
        return Err(AdapterError::Runtime(format!(
            "{label} failed with status {}{}",
            output.status, detail
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn one_line(value: &str, label: &str) -> Result<String, AdapterError> {
    let mut lines = value.lines().filter(|line| !line.trim().is_empty());
    let first = lines.next().map(str::trim).filter(|line| !line.is_empty());
    if first.is_none() || lines.next().is_some() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} output is not one non-empty line"
        )));
    }
    Ok(first.unwrap().to_owned())
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("docker-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn policy_source(kind: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "docker-policy:preserved".into(),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn has_policy(current: &CurrentConfiguration, kind: &str) -> bool {
    current.sources.iter().any(|source| {
        source
            .metadata
            .get("kind")
            .is_some_and(|values| values.iter().any(|value| value == kind))
    })
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
            "Docker {kind} {} is outside the user home",
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
            "Docker reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Err(AdapterError::Verification(format!(
        "{reason}; restored: {}",
        restored.verified
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
