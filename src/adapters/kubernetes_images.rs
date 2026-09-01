use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
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

const IMAGE_UPSTREAM: &str = "registry.k8s.io--container-registry";
const SOURCE_REGISTRY: &str = "registry.k8s.io";
const NJU_REGISTRY: &str = "https://k8s.nju.edu.cn";
const NJU_HOST: &str = "k8s.nju.edu.cn";
const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: kubeadm image mapping v1";

#[derive(Clone, Copy, Debug, Default)]
pub struct KubernetesImagesAdapter;

impl Adapter for KubernetesImagesAdapter {
    fn key(&self) -> &'static str {
        "kubernetes-images"
    }

    fn tool_id(&self) -> &'static str {
        "kubernetes-images"
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
        if !runtime.command_exists("kubeadm") {
            return Ok(None);
        }
        let kubeadm_version = kubeadm_version(runtime)?;
        review_kubeadm_version(&kubeadm_version)?;
        require_image_commands(runtime)?;
        let layout = layout(runtime)?;
        let configs = read_configs(runtime, &layout)?;
        let target_version = choose_target_version(&kubeadm_version, &configs)?;
        review_target_version(&kubeadm_version, &target_version)?;
        let images = list_images(runtime, &target_version, SOURCE_REGISTRY)?;
        let current_repository = selected_current_repository(&configs);
        let cri_socket = selected_cri_socket(&configs);
        Ok(Some(DetectedTool {
            tool_id: "kubernetes-images".into(),
            executable: Some(PathBuf::from("kubeadm")),
            version: Some(kubeadm_version.clone()),
            evidence: vec![
                format!("kubeadm {kubeadm_version}"),
                format!("target Kubernetes version is {target_version}"),
                format!("kubeadm reported {} required images", images.len()),
                format!(
                    "current imageRepository is {}",
                    current_repository.as_deref().unwrap_or("default")
                ),
                format!(
                    "CRI socket is {}",
                    if cri_socket.is_some() {
                        "declared"
                    } else {
                        "not declared"
                    }
                ),
                format!(
                    "CRI clients: crictl={}, ctr={}, docker={}",
                    runtime.command_exists("crictl"),
                    runtime.command_exists("ctr"),
                    runtime.command_exists("docker")
                ),
                format!("generated plan target is {}", layout.managed.display()),
                "kubeadm image pull capability is present but is never run automatically".into(),
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
        if detected.tool_id != "kubernetes-images" {
            return Err(AdapterError::InvalidConfiguration(
                "kubeadm image read received another tool's detection result".into(),
            ));
        }
        let kubeadm_version = kubeadm_version(runtime)?;
        review_kubeadm_version(&kubeadm_version)?;
        if detected.version.as_deref() != Some(kubeadm_version.as_str()) {
            return Err(AdapterError::Conflict(
                "kubeadm version changed after detection".into(),
            ));
        }
        require_image_commands(runtime)?;
        let layout = layout(runtime)?;
        let configs = read_configs(runtime, &layout)?;
        let target_version = choose_target_version(&kubeadm_version, &configs)?;
        review_target_version(&kubeadm_version, &target_version)?;
        let images = list_images(runtime, &target_version, SOURCE_REGISTRY)?;
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = vec![snapshot_source("kubeadm-version", &kubeadm_version)];
        sources.push(snapshot_source("target-version", &target_version));
        for image in &images {
            sources.push(image_source(image, &target_version)?);
        }
        for config in configs {
            if config.exists {
                files.push(config.path.clone());
            }
            if config.format == "kubeadm-images-managed-config"
                && config.exists
                && utf8(&config.path, &config.contents)?
                    .lines()
                    .next()
                    .is_none_or(|line| line != MANAGED_MARKER)
            {
                sources.push(policy_source("managed-target-conflict", &config.path));
            }
            if let Some(repository) = &config.cluster.image_repository {
                sources.push(if is_public_repository(repository) {
                    configured_repository_source(repository, &config.path)
                } else {
                    policy_source("private-image-repository-preserved", &config.path)
                });
            }
            if config.cluster.cri_socket.is_some() {
                sources.push(policy_source("cri-socket-preserved", &config.path));
            }
            if config.format != "kubeadm-images-managed-config" && config.exists {
                sources.push(policy_source(
                    "existing-kubeadm-config-preserved",
                    &config.path,
                ));
            }
            documents.push(ConfigurationDocument {
                path: config.path,
                format: config.format.into(),
                contents: config.contents,
            });
        }
        if runtime
            .environment_variable("CONTAINER_RUNTIME_ENDPOINT")
            .is_some_and(|value| !value.trim().is_empty())
        {
            sources.push(policy_source(
                "cri-environment-preserved",
                Path::new(":env:"),
            ));
        }
        Ok(CurrentConfiguration {
            tool_id: "kubernetes-images".into(),
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
        review_kubeadm_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("kubeadm version is missing".into())
        })?)?;
        let architecture = match context.architecture {
            Architecture::X86_64 => "amd64",
            Architecture::Arm64 => "arm64",
        };
        let mut contexts = Vec::new();
        for source in &current.sources {
            if metadata(source, "kind")? != "required-image" {
                continue;
            }
            contexts.push(BTreeMap::from([
                (
                    "repository_path".into(),
                    metadata(source, "repository_path")?.into(),
                ),
                ("tag".into(), metadata(source, "tag")?.into()),
                ("oci_arch".into(), architecture.into()),
            ]));
        }
        if contexts.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "kubeadm reported no required images".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "kubernetes-images".into(),
            adapter_key: "kubernetes-images".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![IMAGE_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(IMAGE_UPSTREAM.into(), contexts)]),
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
        selected_registry(selections)?;
        let target_version = current_value(current, "target-version")?;
        let api_version = kubeadm_api_version(&target_version)?;
        let managed = find_document(current, "kubeadm-images-managed-config")?;
        let rendered = render_config(api_version, &target_version).into_bytes();
        let changes = if managed.contents == rendered {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &managed.path),
                old_contents: current
                    .files
                    .contains(&managed.path)
                    .then(|| managed.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: "create a versioned kubeadm image mapping with an explicit CoreDNS repository override; do not modify cluster workloads or node images".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "kubernetes-images".into(),
            tool_id: "kubernetes-images".into(),
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
            let layout = layout(runtime)?;
            let target = rooted(&context.root, &layout.managed);
            if receipt.changed_targets.len() != 1 || !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "kubeadm image transaction changed an unexpected target".into(),
                ));
            }
            let contents = runtime.read(&layout.managed)?.ok_or_else(|| {
                AdapterError::Verification("generated kubeadm image config disappeared".into())
            })?;
            let text = utf8(&layout.managed, &contents)?;
            let parsed = parse_kubeadm_config(text, &layout.managed)?;
            let target_version = parsed.kubernetes_version.ok_or_else(|| {
                AdapterError::Verification("generated kubeadm config lacks a target version".into())
            })?;
            let expected = render_config(kubeadm_api_version(&target_version)?, &target_version);
            if text != expected {
                return Err(AdapterError::Verification(
                    "generated kubeadm image config is not canonical".into(),
                ));
            }
            run_kubeadm(
                runtime,
                &[
                    "config",
                    "validate",
                    "--config",
                    path_string(&layout.managed)?,
                ],
                "kubeadm config validation",
            )?;
            let official = list_images(runtime, &target_version, SOURCE_REGISTRY)?;
            let mapped = run_kubeadm(
                runtime,
                &[
                    "config",
                    "images",
                    "list",
                    "--config",
                    path_string(&layout.managed)?,
                ],
                "kubeadm mapped image list",
            )?;
            let mapped = parse_image_lines(&mapped, NJU_HOST)?;
            let expected = official
                .iter()
                .map(|image| mirror_image(image))
                .collect::<Result<BTreeSet<_>, _>>()?;
            if mapped.into_iter().collect::<BTreeSet<_>>() != expected {
                return Err(AdapterError::Verification(
                    "kubeadm mapped image list differs from the validated source image set".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "generated and validated {} explicit kubeadm image mappings for {target_version}; no image pull or cluster mutation was performed; optional pull command: kubeadm config images pull --config {}",
                    expected.len(),
                    layout.managed.display()
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
                "restored {} kubeadm image mapping files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug)]
struct Layout {
    managed: PathBuf,
}

#[derive(Debug)]
struct ObservedConfig {
    path: PathBuf,
    format: &'static str,
    contents: Vec<u8>,
    exists: bool,
    cluster: ParsedConfig,
}

#[derive(Clone, Debug, Default)]
struct ParsedConfig {
    kubernetes_version: Option<String>,
    image_repository: Option<String>,
    dns_image_repository: Option<String>,
    cri_socket: Option<String>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "kubeadm image mapping v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "kubeadm image adapter generates a user-owned plan only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "kubernetes-images" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "kubeadm image operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("kubeadm image plan requires a user home".into())
    })?;
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
    Ok(Layout {
        managed: config_home.join("mirrorswitch/kubeadm-images-nju.yaml"),
    })
}

fn read_configs(
    runtime: &dyn Runtime,
    layout: &Layout,
) -> Result<Vec<ObservedConfig>, AdapterError> {
    let mut paths = vec![
        (layout.managed.clone(), "kubeadm-images-managed-config"),
        (
            PathBuf::from("/etc/kubernetes/kubeadm-config.yaml"),
            "kubeadm-system-config",
        ),
    ];
    if let Some(project) = runtime.project_dir() {
        validate_path(&project, "project directory")?;
        paths.push((project.join("kubeadm.yaml"), "kubeadm-project-config"));
        paths.push((project.join("kubeadm.yml"), "kubeadm-project-config"));
    }
    let mut configs = Vec::new();
    for (path, format) in paths {
        let contents = runtime.read(&path)?;
        let exists = contents.is_some();
        let contents = contents.unwrap_or_default();
        let cluster = if exists {
            parse_kubeadm_config(utf8(&path, &contents)?, &path)?
        } else {
            ParsedConfig::default()
        };
        configs.push(ObservedConfig {
            path,
            format,
            contents,
            exists,
            cluster,
        });
    }
    let project_count = configs
        .iter()
        .filter(|config| config.format == "kubeadm-project-config" && config.exists)
        .count();
    if project_count > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "both kubeadm.yaml and kubeadm.yml exist in the selected project".into(),
        ));
    }
    Ok(configs)
}

fn choose_target_version(
    kubeadm_version: &str,
    configs: &[ObservedConfig],
) -> Result<String, AdapterError> {
    let mut values = configs
        .iter()
        .filter(|config| config.exists)
        .filter_map(|config| {
            config
                .cluster
                .kubernetes_version
                .as_ref()
                .map(|value| (config.format, value))
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|(format, _)| match *format {
        "kubeadm-project-config" => 0,
        "kubeadm-system-config" => 1,
        "kubeadm-images-managed-config" => 2,
        _ => 3,
    });
    Ok(values
        .first()
        .map_or(kubeadm_version, |(_, value)| value.as_str())
        .to_owned())
}

fn selected_current_repository(configs: &[ObservedConfig]) -> Option<String> {
    configs
        .iter()
        .filter(|config| config.exists)
        .find_map(|config| config.cluster.image_repository.clone())
}

fn selected_cri_socket(configs: &[ObservedConfig]) -> Option<String> {
    configs
        .iter()
        .filter(|config| config.exists)
        .find_map(|config| config.cluster.cri_socket.clone())
}

fn parse_kubeadm_config(text: &str, path: &Path) -> Result<ParsedConfig, AdapterError> {
    let documents = split_yaml_documents(text);
    let cluster = documents.iter().find(|document| {
        root_yaml_value(document, "kind").as_deref() == Some("ClusterConfiguration")
    });
    let init = documents
        .iter()
        .find(|document| root_yaml_value(document, "kind").as_deref() == Some("InitConfiguration"));
    let mut parsed = ParsedConfig::default();
    if let Some(cluster) = cluster {
        parsed.kubernetes_version = root_yaml_value(cluster, "kubernetesVersion")
            .map(|value| validate_version_value(&value, path))
            .transpose()?;
        parsed.image_repository = root_yaml_value(cluster, "imageRepository")
            .map(|value| validate_repository_value(&value, path))
            .transpose()?;
        parsed.dns_image_repository = nested_yaml_value(cluster, "dns", "imageRepository")
            .map(|value| validate_repository_value(&value, path))
            .transpose()?;
    }
    if let Some(init) = init {
        parsed.cri_socket = nested_yaml_value(init, "nodeRegistration", "criSocket")
            .map(|value| validate_literal(&value, path, "criSocket"))
            .transpose()?;
    }
    Ok(parsed)
}

fn split_yaml_documents(text: &str) -> Vec<Vec<&str>> {
    let mut documents = Vec::new();
    let mut current = Vec::new();
    for line in text.lines() {
        if line.trim() == "---" {
            documents.push(current);
            current = Vec::new();
        } else {
            current.push(line);
        }
    }
    documents.push(current);
    documents
}

fn root_yaml_value(document: &[&str], key: &str) -> Option<String> {
    document.iter().find_map(|line| {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        yaml_value(line, key)
    })
}

fn nested_yaml_value(document: &[&str], parent: &str, key: &str) -> Option<String> {
    let parent_index = document.iter().position(|line| {
        !line.starts_with(char::is_whitespace)
            && active_yaml(line).trim_end_matches(':').trim() == parent
    })?;
    document[parent_index + 1..]
        .iter()
        .take_while(|line| line.starts_with(char::is_whitespace) || active_yaml(line).is_empty())
        .find_map(|line| yaml_value(line.trim_start(), key))
}

fn yaml_value(line: &str, key: &str) -> Option<String> {
    let line = active_yaml(line);
    let (candidate, value) = line.split_once(':')?;
    (candidate.trim() == key).then(|| unquote(value.trim()))
}

fn active_yaml(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim_end()
}

fn unquote(value: &str) -> String {
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    if quoted {
        value[1..value.len() - 1].into()
    } else {
        value.into()
    }
}

fn validate_literal(value: &str, path: &Path, field: &str) -> Result<String, AdapterError> {
    if value.is_empty()
        || value.contains(['$', '`', '{', '}', '[', ']', '&', '*', '\n', '\r'])
        || value.chars().any(char::is_whitespace)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{field} in {} is not a literal value",
            path.display()
        )));
    }
    Ok(value.into())
}

fn validate_version_value(value: &str, path: &Path) -> Result<String, AdapterError> {
    validate_literal(value, path, "kubernetesVersion")?;
    parse_version(value)
        .map(|_| value.to_owned())
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "kubernetesVersion in {} is not recognized",
                path.display()
            ))
        })
}

fn validate_repository_value(value: &str, path: &Path) -> Result<String, AdapterError> {
    validate_literal(value, path, "imageRepository")?;
    let trimmed = value.trim_end_matches('/');
    if trimmed.contains("://")
        || trimmed.contains('@')
        || trimmed.contains(':')
        || trimmed.starts_with('/')
        || trimmed
            .split('/')
            .any(|segment| !safe_repository_segment(segment))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "imageRepository in {} is unsafe",
            path.display()
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn safe_repository_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn kubeadm_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = run_kubeadm(runtime, &["version", "-o", "short"], "kubeadm version")?;
    output
        .lines()
        .map(str::trim)
        .find(|line| parse_version(line).is_some())
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("kubeadm version output is unrecognized".into()))
}

fn require_image_commands(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let list_help = run_kubeadm(
        runtime,
        &["config", "images", "list", "--help"],
        "kubeadm image list help",
    )?;
    let pull_help = run_kubeadm(
        runtime,
        &["config", "images", "pull", "--help"],
        "kubeadm image pull help",
    )?;
    if !list_help.contains("--image-repository")
        || !list_help.contains("--kubernetes-version")
        || !pull_help.contains("--cri-socket")
    {
        return Err(AdapterError::Unsupported(
            "kubeadm lacks the required image list/pull interfaces".into(),
        ));
    }
    Ok(())
}

fn review_kubeadm_version(value: &str) -> Result<(), AdapterError> {
    let (_, minor, _) = parse_version(value).ok_or_else(|| {
        AdapterError::Unsupported(format!("kubeadm version {value} is unrecognized"))
    })?;
    if !(35..=37).contains(&minor) {
        return Err(AdapterError::Unsupported(format!(
            "kubeadm {value} is outside the reviewed maintained Kubernetes 1.35 through 1.37 v1beta4 model"
        )));
    }
    Ok(())
}

fn review_target_version(kubeadm: &str, target: &str) -> Result<(), AdapterError> {
    let (target_major, target_minor, _) = parse_version(target).ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "target Kubernetes version {target} is unrecognized"
        ))
    })?;
    let (_, kubeadm_minor, _) = parse_version(kubeadm).ok_or_else(|| {
        AdapterError::Unsupported(format!("kubeadm version {kubeadm} is unrecognized"))
    })?;
    if target_major != 1
        || !(35..=37).contains(&target_minor)
        || !(target_minor == kubeadm_minor || target_minor + 1 == kubeadm_minor)
    {
        return Err(AdapterError::Unsupported(format!(
            "target Kubernetes {target} is outside the reviewed kubeadm {kubeadm} version window"
        )));
    }
    Ok(())
}

fn kubeadm_api_version(version: &str) -> Result<&'static str, AdapterError> {
    let (_, minor, _) = parse_version(version).ok_or_else(|| {
        AdapterError::InvalidConfiguration("target Kubernetes version is invalid".into())
    })?;
    if (35..=37).contains(&minor) {
        Ok("kubeadm.k8s.io/v1beta4")
    } else {
        Err(AdapterError::Unsupported(format!(
            "Kubernetes {version} has no reviewed kubeadm config API"
        )))
    }
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let core = value.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    (parts.next().is_none()).then_some((major, minor, patch))
}

fn list_images(
    runtime: &dyn Runtime,
    target_version: &str,
    registry: &str,
) -> Result<Vec<String>, AdapterError> {
    let output = run_kubeadm(
        runtime,
        &[
            "config",
            "images",
            "list",
            "--kubernetes-version",
            target_version,
            "--image-repository",
            registry,
        ],
        "kubeadm source image list",
    )?;
    parse_image_lines(&output, registry)
}

fn parse_image_lines(output: &str, registry: &str) -> Result<Vec<String>, AdapterError> {
    let mut images = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let Some((repository, tag)) = line.rsplit_once(':') else {
            return Err(AdapterError::Unsupported(format!(
                "kubeadm reported an untagged image {line}"
            )));
        };
        let prefix = format!("{registry}/");
        let path = repository.strip_prefix(&prefix).ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "kubeadm image {line} does not use the requested registry"
            ))
        })?;
        if path
            .split('/')
            .any(|segment| !safe_repository_segment(segment))
            || !safe_image_tag(tag)
        {
            return Err(AdapterError::Unsupported(format!(
                "kubeadm reported an unsafe image reference {line}"
            )));
        }
        images.push(line.to_owned());
    }
    images.sort();
    images.dedup();
    if images.is_empty() {
        return Err(AdapterError::Unsupported(
            "kubeadm reported no required images".into(),
        ));
    }
    Ok(images)
}

fn safe_image_tag(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn mirror_image(source: &str) -> Result<String, AdapterError> {
    let path = source
        .strip_prefix(&format!("{SOURCE_REGISTRY}/"))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("source image registry changed".into())
        })?;
    Ok(format!("{NJU_HOST}/{path}"))
}

fn run_kubeadm(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    command_output(runtime.run("kubeadm", &arguments)?, label)
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

fn render_config(api_version: &str, target_version: &str) -> String {
    format!(
        "{MANAGED_MARKER}\n# Source registry: {SOURCE_REGISTRY}\n# Validated architectures: amd64, arm64\napiVersion: {api_version}\nkind: ClusterConfiguration\nkubernetesVersion: {target_version}\nimageRepository: {NJU_HOST}\ndns:\n  imageRepository: {NJU_HOST}/coredns\n"
    )
}

fn selected_registry(selections: &[MirrorSelection]) -> Result<(), AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "kubernetes-images" && selection.upstream_id == IMAGE_UPSTREAM
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "kubeadm images require exactly one registry selection".into(),
        ));
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
        || normalized_registry(&endpoints[0].url).as_deref() != Some(NJU_REGISTRY)
    {
        return Err(AdapterError::InvalidConfiguration(
            "kubeadm image selection is not the reviewed NJU registry proxy".into(),
        ));
    }
    Ok(())
}

fn normalized_registry(value: &str) -> Option<String> {
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

fn is_public_repository(value: &str) -> bool {
    matches!(
        value.trim_end_matches('/').to_ascii_lowercase().as_str(),
        SOURCE_REGISTRY | NJU_HOST
    )
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-image-repository-preserved" => {
                return Err(AdapterError::Unsupported(
                    "an existing kubeadm config uses a private or unreviewed imageRepository and will not be shadowed"
                        .into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "the kubeadm image plan target contains data not managed by MirrorSwitch"
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
            "kubeadm image configuration must contain exactly one {format} document"
        )));
    }
    Ok(matches[0])
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
            "kubeadm image state has an ambiguous {kind}"
        )));
    }
    Ok(values[0].clone())
}

fn image_source(image: &str, target_version: &str) -> Result<ConfiguredSource, AdapterError> {
    let (repository, tag) = image.rsplit_once(':').ok_or_else(|| {
        AdapterError::InvalidConfiguration("required kubeadm image is untagged".into())
    })?;
    let repository_path = repository
        .strip_prefix(&format!("{SOURCE_REGISTRY}/"))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("required kubeadm image registry changed".into())
        })?;
    Ok(ConfiguredSource {
        upstream_id: Some(IMAGE_UPSTREAM.into()),
        url: format!("https://{image}"),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["required-image".into()]),
            ("repository_path".into(), vec![repository_path.into()]),
            ("tag".into(), vec![tag.into()]),
            ("target_version".into(), vec![target_version.into()]),
        ]),
    })
}

fn configured_repository_source(value: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(IMAGE_UPSTREAM.into()),
        url: format!("https://{}", value.trim_end_matches('/')),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["existing-image-repository".into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("kubernetes-images-snapshot:{value}"),
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
            "kubeadm image source is missing {key} metadata"
        ))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "kubeadm image source has ambiguous {key} metadata"
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
            "kubeadm image {kind} {} is outside the user home",
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
            "kubeadm reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "kubeadm configuration {} is not UTF-8",
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
        "{reason}; generated configuration restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
