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

const UPSTREAM: &str = "docker-ce--repository-metadata";
const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: Docker CE package repository v1";
const DEFAULT_APT_KEYRING: &str = "/etc/apt/keyrings/docker.asc";
const ENDPOINTS: &[(&str, &str)] = &[
    ("aliyun", "https://mirrors.aliyun.com/docker-ce"),
    ("huaweicloud", "https://repo.huaweicloud.com/docker-ce"),
    ("nju", "https://mirrors.nju.edu.cn/docker-ce"),
    ("sjtug", "https://mirror.sjtu.edu.cn/docker-ce"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/docker-ce"),
    ("ustc", "https://mirrors.ustc.edu.cn/docker-ce"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct DockerCeAdapter;

impl Adapter for DockerCeAdapter {
    fn key(&self) -> &'static str {
        "docker-ce"
    }

    fn tool_id(&self) -> &'static str {
        "docker-ce"
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
        let platform = platform(context, runtime)?;
        let documents = read_documents(runtime, platform.manager)?;
        let source_count = documents
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        let docker_version = docker_version(runtime)?;
        if source_count == 0 && docker_version.is_none() {
            return Ok(None);
        }
        let channels = documents
            .iter()
            .filter_map(|document| document.source.as_ref())
            .flat_map(|source| source.channels.iter().cloned())
            .collect::<BTreeSet<_>>();
        Ok(Some(DetectedTool {
            tool_id: "docker-ce".into(),
            executable: Some(PathBuf::from(platform.manager.command())),
            version: docker_version.clone(),
            evidence: vec![
                format!("package manager is {}", platform.manager.name()),
                format!("Docker CE distribution path is {}", platform.distribution),
                format!("release/suite is {}", platform.release),
                format!("package architecture is {}", platform.package_architecture),
                format!("Docker CE repository files: {source_count}"),
                format!(
                    "configured channels: {}",
                    if channels.is_empty() {
                        "none".into()
                    } else {
                        channels.into_iter().collect::<Vec<_>>().join(",")
                    }
                ),
                format!(
                    "installed Docker version is {}",
                    docker_version.as_deref().unwrap_or("not detected")
                ),
                "Docker Hub registry-mirrors are not package repository URLs".into(),
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
        if detected.tool_id != "docker-ce" {
            return Err(AdapterError::InvalidConfiguration(
                "Docker CE read received another tool's detection result".into(),
            ));
        }
        let platform = platform(context, runtime)?;
        let docker_version = docker_version(runtime)?;
        if detected.version != docker_version {
            return Err(AdapterError::Conflict(
                "installed Docker version changed after detection".into(),
            ));
        }
        let observed = read_documents(runtime, platform.manager)?;
        let target = choose_target(platform.manager, &observed);
        let source_documents = observed
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = vec![snapshot_source("manager", platform.manager.name())];
        sources.push(snapshot_source("distribution", &platform.distribution));
        sources.push(snapshot_source("release", &platform.release));
        sources.push(snapshot_source(
            "package-arch",
            &platform.package_architecture,
        ));
        if source_documents > 1 {
            sources.push(policy_source("multiple-source-files", Path::new(":repo:")));
        }
        for document in observed {
            if document.exists {
                files.push(document.path.clone());
            }
            if document.path == target
                && document.exists
                && is_managed_path(&document.path)
                && utf8(&document.path, &document.contents)?.lines().next() != Some(MANAGED_MARKER)
            {
                sources.push(policy_source("managed-target-conflict", &document.path));
            }
            if let Some(source) = &document.source {
                sources.push(configured_source(source, &document.path));
                if source.distribution != platform.distribution {
                    sources.push(policy_source("distribution-mismatch", &document.path));
                }
                if platform.manager == Manager::Apt && source.release != platform.release {
                    sources.push(policy_source("release-mismatch", &document.path));
                }
                if source.channels.is_empty() {
                    sources.push(policy_source("channel-missing", &document.path));
                }
                match platform.manager {
                    Manager::Apt => {
                        let keyring = source.signed_by.as_deref().ok_or_else(|| {
                            AdapterError::Unsupported(
                                "Docker CE APT source has no explicit Signed-By keyring".into(),
                            )
                        })?;
                        let keyring = PathBuf::from(keyring);
                        validate_path(&keyring, "APT keyring")?;
                        if runtime.read(&keyring)?.is_none() {
                            sources.push(policy_source("keyring-missing", &keyring));
                        } else {
                            sources.push(policy_source("keyring-preserved", &keyring));
                        }
                    }
                    Manager::Rpm if source.gpgcheck != Some(true) => {
                        sources.push(policy_source("gpgcheck-disabled", &document.path));
                    }
                    Manager::Rpm => {}
                }
            }
            if document.path != target && document.exists {
                sources.push(policy_source(
                    "other-docker-config-preserved",
                    &document.path,
                ));
            }
            documents.push(ConfigurationDocument {
                path: document.path.clone(),
                format: if document.path == target {
                    "docker-ce-package-target".into()
                } else {
                    "docker-ce-package-read-only".into()
                },
                contents: document.contents,
            });
        }
        if platform.manager == Manager::Apt && source_documents == 0 {
            let keyring = PathBuf::from(DEFAULT_APT_KEYRING);
            if runtime.read(&keyring)?.is_none() {
                sources.push(policy_source("keyring-missing", &keyring));
            } else {
                sources.push(policy_source("keyring-preserved", &keyring));
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "docker-ce".into(),
            scope,
            files,
            sources,
            documents,
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        _detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_linux(context)?;
        require_current(current)?;
        let manager = Manager::from_name(&current_value(current, "manager")?)?;
        let distribution = current_value(current, "distribution")?;
        let release = current_value(current, "release")?;
        let package_arch = current_value(current, "package-arch")?;
        let (apt_distro, codename, apt_arch, rpm_distro, rpm_release, rpm_arch) = match manager {
            Manager::Apt => (
                distribution,
                release,
                package_arch,
                "fedora".into(),
                "42".into(),
                if context.architecture == Architecture::Arm64 {
                    "aarch64".into()
                } else {
                    "x86_64".into()
                },
            ),
            Manager::Rpm => (
                "debian".into(),
                "bookworm".into(),
                if context.architecture == Architecture::Arm64 {
                    "arm64".into()
                } else {
                    "amd64".into()
                },
                distribution,
                release,
                package_arch,
            ),
        };
        Ok(SelectionRequest {
            tool_id: "docker-ce".into(),
            adapter_key: "docker-ce".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("apt_distro".into(), apt_distro),
                    ("codename".into(), codename),
                    ("apt_arch".into(), apt_arch),
                    ("rpm_distro".into(), rpm_distro),
                    ("release".into(), rpm_release),
                    ("rpm_arch".into(), rpm_arch),
                ])],
            )]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![
                EndpointRole::Index,
                EndpointRole::Metadata,
                EndpointRole::Packages,
            ],
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let manager = Manager::from_name(&current_value(current, "manager")?)?;
        let distribution = current_value(current, "distribution")?;
        let release = current_value(current, "release")?;
        let target = find_document(current, "docker-ce-package-target")?;
        let rendered = if target.contents.is_empty() {
            render_new(manager, &endpoint, &distribution, &release)
        } else {
            rewrite_existing(
                manager,
                utf8(&target.path, &target.contents)?,
                &target.path,
                &endpoint,
                &distribution,
            )?
        }
        .into_bytes();
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
                summary: format!(
                    "map Docker CE {} package paths while preserving GPG, release channels, pins, and unrelated repositories",
                    manager.name()
                ),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "docker-ce".into(),
            tool_id: "docker-ce".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
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
            let platform = platform(context, runtime)?;
            let documents = read_documents(runtime, platform.manager)?;
            let target = choose_target(platform.manager, &documents);
            if !receipt
                .changed_targets
                .contains(&rooted(&context.root, &target))
            {
                return Err(AdapterError::Verification(
                    "Docker CE transaction contains no known target".into(),
                ));
            }
            let source = documents
                .iter()
                .find(|document| document.path == target)
                .and_then(|document| document.source.as_ref())
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "Docker CE repository is not active after apply".into(),
                    )
                })?;
            let output = match platform.manager {
                Manager::Apt => verify_apt(runtime, &target)?,
                Manager::Rpm => verify_rpm(
                    runtime,
                    &target,
                    source.repo_ids.first().map(String::as_str),
                )?,
            };
            if !output.contains("docker-ce") {
                return Err(AdapterError::Verification(
                    "system package manager did not expose docker-ce".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} refreshed and queried Docker CE through {} for {}/{}",
                    platform.manager.name(),
                    source.uri,
                    platform.distribution,
                    platform.release
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
                "restored {} Docker CE package repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Manager {
    Apt,
    Rpm,
}

impl Manager {
    fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Rpm => "rpm",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Apt => "apt-get",
            Self::Rpm => "dnf",
        }
    }

    fn from_name(value: &str) -> Result<Self, AdapterError> {
        match value {
            "apt" => Ok(Self::Apt),
            "rpm" => Ok(Self::Rpm),
            _ => Err(AdapterError::InvalidConfiguration(
                "unknown Docker CE package manager".into(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct Platform {
    manager: Manager,
    distribution: String,
    release: String,
    package_architecture: String,
}

#[derive(Clone, Debug)]
struct RepositorySource {
    uri: String,
    distribution: String,
    release: String,
    channels: Vec<String>,
    signed_by: Option<String>,
    gpgcheck: Option<bool>,
    repo_ids: Vec<String>,
}

#[derive(Clone, Debug)]
struct ObservedDocument {
    path: PathBuf,
    contents: Vec<u8>,
    exists: bool,
    source: Option<RepositorySource>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Docker CE package adapter supports Linux only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "Docker CE package repositories require system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "docker-ce" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "Docker CE operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn platform(context: &SystemContext, runtime: &dyn Runtime) -> Result<Platform, AdapterError> {
    let distribution = context.distribution.as_ref().ok_or_else(|| {
        AdapterError::Unsupported("Docker CE packages require a detected distribution".into())
    })?;
    let apt = runtime.command_exists("apt-get") && runtime.command_exists("apt-cache");
    let rpm = runtime.command_exists("dnf");
    let (manager, repository_distribution) =
        if apt && matches!(distribution.id.as_str(), "debian" | "ubuntu") {
            (Manager::Apt, distribution.id.as_str())
        } else if rpm && distribution.id == "fedora" {
            (Manager::Rpm, "fedora")
        } else if rpm
            && matches!(
                distribution.id.as_str(),
                "centos" | "rhel" | "rocky" | "almalinux"
            )
        {
            (Manager::Rpm, "centos")
        } else {
            return Err(AdapterError::Unsupported(format!(
                "Docker CE packages do not have a reviewed path for {}",
                distribution.id
            )));
        };
    let release = match manager {
        Manager::Apt => distribution.version_codename.clone().ok_or_else(|| {
            AdapterError::Unsupported("Docker CE APT path requires a codename".into())
        })?,
        Manager::Rpm => distribution
            .version_id
            .as_deref()
            .and_then(|value| value.split('.').next())
            .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
            .map(str::to_owned)
            .ok_or_else(|| {
                AdapterError::Unsupported("Docker CE RPM path requires a major release".into())
            })?,
    };
    let package_architecture = match (manager, context.architecture) {
        (Manager::Apt, Architecture::X86_64) => "amd64",
        (Manager::Apt, Architecture::Arm64) => "arm64",
        (Manager::Rpm, Architecture::X86_64) => "x86_64",
        (Manager::Rpm, Architecture::Arm64) => "aarch64",
    };
    Ok(Platform {
        manager,
        distribution: repository_distribution.into(),
        release,
        package_architecture: package_architecture.into(),
    })
}

fn read_documents(
    runtime: &dyn Runtime,
    manager: Manager,
) -> Result<Vec<ObservedDocument>, AdapterError> {
    let (main, directory, target, extensions) = match manager {
        Manager::Apt => (
            Some(PathBuf::from("/etc/apt/sources.list")),
            PathBuf::from("/etc/apt/sources.list.d"),
            PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-docker-ce.sources"),
            &["list", "sources"][..],
        ),
        Manager::Rpm => (
            None,
            PathBuf::from("/etc/yum.repos.d"),
            PathBuf::from("/etc/yum.repos.d/mirrorswitch-docker-ce.repo"),
            &["repo"][..],
        ),
    };
    let mut paths = BTreeSet::from([target]);
    if let Some(main) = main {
        paths.insert(main);
    }
    for path in runtime.list_files(&directory)? {
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.contains(&extension))
        {
            paths.insert(path);
        }
    }
    let mut documents = Vec::new();
    for path in paths {
        let contents = runtime.read(&path)?;
        let exists = contents.is_some();
        let contents = contents.unwrap_or_default();
        let source = if exists {
            parse_repository(manager, utf8(&path, &contents)?, &path)?
        } else {
            None
        };
        documents.push(ObservedDocument {
            path,
            contents,
            exists,
            source,
        });
    }
    Ok(documents)
}

fn parse_repository(
    manager: Manager,
    text: &str,
    path: &Path,
) -> Result<Option<RepositorySource>, AdapterError> {
    match manager {
        Manager::Apt => parse_apt(text, path),
        Manager::Rpm => parse_rpm(text, path),
    }
}

fn parse_apt(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut uris = BTreeSet::new();
    let mut release = None;
    let mut channels = BTreeSet::new();
    let mut signed_by = None;
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or_default().trim();
        if let Some(value) = active.strip_prefix("Signed-By:") {
            signed_by = Some(value.trim().into());
        }
        if let Some(value) = active.strip_prefix("Suites:") {
            release = value.split_whitespace().next().map(str::to_owned);
        }
        if let Some(value) = active.strip_prefix("Components:") {
            channels.extend(value.split_whitespace().map(str::to_owned));
        }
        let fields = active.split_whitespace().collect::<Vec<_>>();
        for (index, token) in fields.iter().enumerate() {
            let Some(distribution) = docker_uri_distribution(token) else {
                continue;
            };
            uris.insert((token.trim_end_matches('/').to_owned(), distribution));
            if active.starts_with("deb ") {
                if let Some(option) = fields.iter().find(|field| field.contains("signed-by=")) {
                    let value = option.split_once("signed-by=").map(|(_, value)| value);
                    if let Some(value) = value {
                        signed_by = Some(value.trim_end_matches(']').into());
                    }
                }
                release = fields.get(index + 1).map(|value| (*value).into());
                channels.extend(
                    fields
                        .iter()
                        .skip(index + 2)
                        .filter(|value| !value.starts_with('#'))
                        .map(|value| (*value).into()),
                );
            }
        }
    }
    if uris.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Docker CE APT sources in {} use multiple base URIs",
            path.display()
        )));
    }
    let Some((uri, distribution)) = uris.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(RepositorySource {
        uri,
        distribution,
        release: release.ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Docker CE APT source in {} has no suite",
                path.display()
            ))
        })?,
        channels: channels.into_iter().collect(),
        signed_by,
        gpgcheck: None,
        repo_ids: Vec::new(),
    }))
}

fn docker_uri_distribution(value: &str) -> Option<String> {
    let value = value.trim_end_matches('/');
    let (base, suffix) = value.rsplit_once("/linux/")?;
    let distribution = suffix.split('/').next()?;
    let known_base = base == "https://download.docker.com"
        || ENDPOINTS.iter().any(|(_, endpoint)| base == *endpoint);
    (known_base && matches!(distribution, "debian" | "ubuntu")).then(|| distribution.into())
}

fn parse_rpm(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut section = None::<String>;
    let mut sources = Vec::new();
    let mut values: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for line in text.lines() {
        let active = line.split(['#', ';']).next().unwrap_or_default().trim();
        if active.starts_with('[') && active.ends_with(']') {
            section = Some(active[1..active.len() - 1].trim().into());
            continue;
        }
        let Some((key, value)) = active.split_once('=') else {
            continue;
        };
        let Some(section) = &section else {
            continue;
        };
        values
            .entry(section.clone())
            .or_default()
            .insert(key.trim().to_ascii_lowercase(), value.trim().into());
        if key.trim().eq_ignore_ascii_case("baseurl")
            && let Some((uri, distribution, channel)) = docker_rpm_base(value.trim())
        {
            sources.push((section.clone(), uri, distribution, channel));
        }
    }
    if sources.is_empty() {
        return Ok(None);
    }
    let base_uris = sources
        .iter()
        .map(|(_, uri, distribution, _)| (uri, distribution))
        .collect::<BTreeSet<_>>();
    if base_uris.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Docker CE RPM repositories in {} use multiple distribution bases",
            path.display()
        )));
    }
    let (_, uri, distribution, _) = &sources[0];
    let channels = sources
        .iter()
        .map(|(_, _, _, channel)| channel.clone())
        .collect::<BTreeSet<_>>();
    let gpgcheck = sources.iter().all(|(repo_id, _, _, _)| {
        values[repo_id]
            .get("gpgcheck")
            .is_some_and(|value| value == "1")
    });
    Ok(Some(RepositorySource {
        uri: uri.clone(),
        distribution: distribution.clone(),
        release: "$releasever".into(),
        channels: channels.into_iter().collect(),
        signed_by: sources
            .first()
            .and_then(|(repo_id, _, _, _)| values[repo_id].get("gpgkey").cloned()),
        gpgcheck: Some(gpgcheck),
        repo_ids: sources
            .into_iter()
            .map(|(repo_id, _, _, _)| repo_id)
            .collect(),
    }))
}

fn docker_rpm_base(value: &str) -> Option<(String, String, String)> {
    let value = value.trim_end_matches('/');
    let (base, suffix) = value.rsplit_once("/linux/")?;
    let parts = suffix.split('/').collect::<Vec<_>>();
    if parts.len() < 4 {
        return None;
    }
    let distribution = parts[0];
    let channel = parts.last()?.to_string();
    let known_base = base == "https://download.docker.com"
        || ENDPOINTS.iter().any(|(_, endpoint)| base == *endpoint);
    (known_base && matches!(distribution, "fedora" | "centos")).then(|| {
        (
            format!("{base}/linux/{distribution}"),
            distribution.into(),
            channel,
        )
    })
}

fn choose_target(manager: Manager, documents: &[ObservedDocument]) -> PathBuf {
    documents
        .iter()
        .find(|document| document.source.is_some())
        .map(|document| document.path.clone())
        .unwrap_or_else(|| match manager {
            Manager::Apt => PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-docker-ce.sources"),
            Manager::Rpm => PathBuf::from("/etc/yum.repos.d/mirrorswitch-docker-ce.repo"),
        })
}

fn is_managed_path(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name == "mirrorswitch-docker-ce.sources" || name == "mirrorswitch-docker-ce.repo"
    })
}

fn docker_version(runtime: &dyn Runtime) -> Result<Option<String>, AdapterError> {
    for command in ["docker", "dockerd"] {
        if !runtime.command_exists(command) {
            continue;
        }
        let output = runtime.run(command, &["--version".into()])?;
        if !output.status.success() {
            continue;
        }
        let output = String::from_utf8(output.stdout)
            .map_err(|_| AdapterError::Runtime(format!("{command} version is not UTF-8")))?;
        if let Some(version) = output
            .split_whitespace()
            .map(|token| token.trim_end_matches(','))
            .find(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
                    && token.contains('.')
            })
        {
            return Ok(Some(version.into()));
        }
    }
    Ok(None)
}

fn render_new(manager: Manager, endpoint: &str, distribution: &str, release: &str) -> String {
    match manager {
        Manager::Apt => format!(
            "{MANAGED_MARKER}\nTypes: deb\nURIs: {endpoint}/linux/{distribution}\nSuites: {release}\nComponents: stable\nArchitectures: amd64 arm64\nSigned-By: {DEFAULT_APT_KEYRING}\n"
        ),
        Manager::Rpm => format!(
            "{MANAGED_MARKER}\n[docker-ce-stable]\nname=Docker CE Stable\nbaseurl={endpoint}/linux/{distribution}/$releasever/$basearch/stable\nenabled=1\ngpgcheck=1\ngpgkey={endpoint}/linux/{distribution}/gpg\n"
        ),
    }
}

fn rewrite_existing(
    manager: Manager,
    text: &str,
    path: &Path,
    endpoint: &str,
    distribution: &str,
) -> Result<String, AdapterError> {
    let source = parse_repository(manager, text, path)?.ok_or_else(|| {
        AdapterError::InvalidConfiguration("selected Docker CE repository disappeared".into())
    })?;
    let replacement = format!("{endpoint}/linux/{distribution}");
    let mut output = String::with_capacity(text.len());
    let mut replacements = 0;
    for line in text.split_inclusive('\n') {
        let active = line.split('#').next().unwrap_or_default();
        let eligible = match manager {
            Manager::Apt => {
                active.trim_start().starts_with("deb ") || active.trim_start().starts_with("URIs:")
            }
            Manager::Rpm => active
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("baseurl")),
        };
        if eligible {
            replacements += active.matches(&source.uri).count();
            output.push_str(&line.replacen(&source.uri, &replacement, usize::MAX));
        } else {
            output.push_str(line);
        }
    }
    if replacements == 0 {
        return Err(AdapterError::InvalidConfiguration(
            "Docker CE repository base URI disappeared".into(),
        ));
    }
    Ok(output)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "docker-ce"
        || selections[0].upstream_id != UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Docker CE requires exactly one package repository selection".into(),
        ));
    }
    let selection = &selections[0];
    let role_url = |role| -> Result<String, AdapterError> {
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if endpoints.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Docker CE selection needs one HTTPS {role:?} endpoint"
            )));
        }
        normalized_endpoint(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration("Docker CE endpoint is unsafe".into())
        })
    };
    let index = role_url(EndpointRole::Index)?;
    if role_url(EndpointRole::Metadata)? != index || role_url(EndpointRole::Packages)? != index {
        return Err(AdapterError::InvalidConfiguration(
            "Docker CE index, metadata, and packages endpoints must match".into(),
        ));
    }
    if !ENDPOINTS
        .iter()
        .any(|(provider, endpoint)| selection.provider_id == *provider && index == *endpoint)
    {
        return Err(AdapterError::InvalidConfiguration(
            "Docker CE provider and endpoint are not reviewed".into(),
        ));
    }
    Ok(index)
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
            "multiple-source-files" => {
                return Err(AdapterError::InvalidConfiguration(
                    "Docker CE repositories span multiple files".into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Docker CE managed target contains user data".into(),
                ));
            }
            "distribution-mismatch" | "release-mismatch" => {
                return Err(AdapterError::Unsupported(
                    "Docker CE repository distribution or release does not match the host".into(),
                ));
            }
            "channel-missing" => {
                return Err(AdapterError::InvalidConfiguration(
                    "Docker CE repository has no release channel".into(),
                ));
            }
            "keyring-missing" => {
                return Err(AdapterError::Unsupported(
                    "Docker CE APT keyring is missing".into(),
                ));
            }
            "gpgcheck-disabled" => {
                return Err(AdapterError::Unsupported(
                    "Docker CE RPM repository has gpgcheck disabled".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn verify_apt(runtime: &dyn Runtime, target: &Path) -> Result<String, AdapterError> {
    let target = path_string(target)?;
    let options = [
        format!("Dir::Etc::sourcelist={target}"),
        "Dir::Etc::sourceparts=-".into(),
        "APT::Get::List-Cleanup=0".into(),
    ];
    let mut update = vec!["update".into()];
    for option in &options {
        update.extend(["-o".into(), option.clone()]);
    }
    command_output(runtime.run("apt-get", &update)?, "Docker CE APT refresh")?;
    let mut query = Vec::new();
    for option in &options {
        query.extend(["-o".into(), option.clone()]);
    }
    query.extend(["policy".into(), "docker-ce".into()]);
    command_output(runtime.run("apt-cache", &query)?, "Docker CE APT query")
}

fn verify_rpm(
    runtime: &dyn Runtime,
    target: &Path,
    repo_id: Option<&str>,
) -> Result<String, AdapterError> {
    let repo_id = repo_id.unwrap_or("docker-ce-stable");
    let directory = target.parent().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Docker CE RPM path has no parent".into())
    })?;
    let common = [
        format!("--setopt=reposdir={}", path_string(directory)?),
        "--disablerepo=*".into(),
        format!("--enablerepo={repo_id}"),
        "--refresh".into(),
        "-y".into(),
    ];
    let mut refresh = common.to_vec();
    refresh.extend(["-q".into(), "makecache".into()]);
    command_output(runtime.run("dnf", &refresh)?, "Docker CE RPM refresh")?;
    let mut query = common.to_vec();
    query.extend([
        "-q".into(),
        "list".into(),
        "--showduplicates".into(),
        "docker-ce".into(),
    ]);
    command_output(runtime.run("dnf", &query)?, "Docker CE RPM query")
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
            "Docker CE state must contain one {format} document"
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
            "Docker CE state has ambiguous {kind}"
        )));
    }
    Ok(values[0].clone())
}

fn configured_source(source: &RepositorySource, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
        url: source.uri.clone(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["docker-ce-repository".into()]),
            ("distribution".into(), vec![source.distribution.clone()]),
            ("release".into(), vec![source.release.clone()]),
            ("channels".into(), source.channels.clone()),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("docker-ce-snapshot:{value}"),
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
        AdapterError::InvalidConfiguration(format!("Docker CE source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Docker CE source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn path_string(path: &Path) -> Result<&str, AdapterError> {
    path.to_str().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("path {} is not UTF-8", path.display()))
    })
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Docker CE {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Docker CE configuration {} is not UTF-8",
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
        "{reason}; repository configuration restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
