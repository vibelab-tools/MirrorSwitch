use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
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

const APT_UPSTREAM: &str = "ros2-apt--repository-metadata";
const RPM_UPSTREAM: &str = "ros2-rpm--repository-metadata";
const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: ROS 2 package repository v1";
const APT_PACKAGE_SOURCE: &str = "/usr/share/ros-apt-source/ros2.sources";
const APT_PACKAGE_LINK: &str = "/etc/apt/sources.list.d/ros2.sources";
const APT_MANAGED_TARGET: &str = "/etc/apt/sources.list.d/mirrorswitch-ros2.sources";
const RPM_MANAGED_TARGET: &str = "/etc/yum.repos.d/mirrorswitch-ros2.repo";
const APT_KEYRINGS: &[&str] = &[
    "/usr/share/keyrings/ros2-archive-keyring.gpg",
    "/usr/share/keyrings/ros-archive-keyring.gpg",
];
const APT_ENDPOINTS: &[(&str, &str)] = &[
    ("aliyun", "https://mirrors.aliyun.com/ros2/ubuntu"),
    ("huaweicloud", "https://repo.huaweicloud.com/ros2/ubuntu"),
    ("nju", "https://mirrors.nju.edu.cn/ros2/ubuntu"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/ros2/ubuntu"),
    ("ustc", "https://mirrors.ustc.edu.cn/ros2/ubuntu"),
    ("qlu", "https://mirrors.qlu.edu.cn/ros2/ubuntu"),
    ("zju", "https://mirrors.zju.edu.cn/ros2/ubuntu"),
    ("xjtu", "https://mirrors.xjtu.edu.cn/ros2/ubuntu"),
    ("nyist", "https://mirror.nyist.edu.cn/ros2/ubuntu"),
];
const RPM_ENDPOINTS: &[(&str, &str)] = &[("nju", "https://mirrors.nju.edu.cn/ros2-rhel")];

#[derive(Clone, Copy, Debug, Default)]
pub struct Ros2Adapter;

impl Adapter for Ros2Adapter {
    fn key(&self) -> &'static str {
        "ros2"
    }

    fn tool_id(&self) -> &'static str {
        "ros2"
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
        let manager = manager(context, runtime)?;
        let documents = read_documents(runtime, manager)?;
        let effective = effective_source_documents(&documents)?;
        let explicitly_selected = runtime
            .environment_variable("ROS_DISTRO")
            .is_some_and(|value| !value.trim().is_empty());
        if effective.is_empty() && !runtime.command_exists("ros2") && !explicitly_selected {
            return Ok(None);
        }
        let platform = platform(context, runtime, manager)?;
        if effective.len() > 1 {
            return Err(AdapterError::InvalidConfiguration(
                "multiple ROS 2 public package repositories are active".into(),
            ));
        }
        Ok(Some(DetectedTool {
            tool_id: "ros2".into(),
            executable: Some(PathBuf::from(manager.command())),
            version: Some(platform.ros_distribution.clone()),
            evidence: vec![
                format!("package manager is {}", manager.name()),
                format!("ROS 2 distribution is {}", platform.ros_distribution),
                format!("repository release is {}", platform.release),
                format!("repository architecture is {}", platform.architecture),
                format!("configured ROS 2 public repositories: {}", effective.len()),
                "ROS 2 package repositories, rosdistro metadata, and container images are separate surfaces".into(),
                if manager == Manager::Rpm {
                    "ROS 2 RPM binaries are available for x86_64 only; arm64 is rejected before planning".into()
                } else {
                    "ROS 2 APT binaries are verified independently for amd64 and arm64".into()
                },
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
        if detected.tool_id != "ros2" {
            return Err(AdapterError::InvalidConfiguration(
                "ROS 2 read received another tool's detection result".into(),
            ));
        }
        let manager = manager(context, runtime)?;
        let platform = platform(context, runtime, manager)?;
        if detected.version.as_deref() != Some(platform.ros_distribution.as_str()) {
            return Err(AdapterError::Conflict(
                "ROS 2 distribution changed after detection".into(),
            ));
        }
        let observed = read_documents(runtime, manager)?;
        let effective = effective_source_documents(&observed)?;
        let target = choose_target(manager, &effective);
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = vec![snapshot_source("manager", manager.name())];
        sources.push(snapshot_source(
            "ros-distribution",
            &platform.ros_distribution,
        ));
        sources.push(snapshot_source("release", &platform.release));
        sources.push(snapshot_source("architecture", &platform.architecture));
        sources.push(snapshot_source("package-name", &platform.package_name));
        sources.push(snapshot_source("package-path", &platform.package_path));
        if effective.len() > 1 {
            sources.push(policy_source(
                "multiple-public-repositories",
                Path::new(":repo:"),
            ));
        }
        let effective_paths = effective
            .iter()
            .map(|document| document.path.clone())
            .collect::<BTreeSet<_>>();
        let effective_empty = effective.is_empty();
        drop(effective);
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
            if document.custom_only && effective_empty {
                sources.push(policy_source("custom-only-ros2-repository", &document.path));
            }
            if let Some(source) = &document.source
                && effective_paths.contains(&document.path)
            {
                sources.push(configured_source(source, &document.path));
                if (!matches!(source.release.as_str(), "$releasever")
                    && source.release != platform.release)
                    || (!source.architectures.is_empty()
                        && !source.architectures.contains(&platform.architecture))
                    || source.components != ["main"]
                {
                    sources.push(policy_source("coverage-mismatch", &document.path));
                }
                match manager {
                    Manager::Apt => match source.signed_by.as_deref() {
                        Some("embedded") => {
                            sources.push(policy_source("embedded-key-preserved", &document.path))
                        }
                        Some(path) => {
                            let keyring = PathBuf::from(path);
                            validate_path(&keyring, "APT keyring")?;
                            if runtime.read(&keyring)?.is_none() {
                                sources.push(policy_source("keyring-missing", &keyring));
                            } else {
                                sources.push(policy_source("keyring-preserved", &keyring));
                            }
                        }
                        None => sources.push(policy_source("signed-by-missing", &document.path)),
                    },
                    Manager::Rpm => {
                        if source.repo_gpgcheck != Some(true) {
                            sources.push(policy_source("repo-gpgcheck-disabled", &document.path));
                        }
                        if source.signed_by.is_none() {
                            sources.push(policy_source("gpgkey-missing", &document.path));
                        }
                    }
                }
            }
            if document.path != target && document.exists {
                sources.push(policy_source("related-config-preserved", &document.path));
            }
            documents.push(ConfigurationDocument {
                path: document.path.clone(),
                format: if document.path == target {
                    "ros2-package-target".into()
                } else {
                    "ros2-package-read-only".into()
                },
                contents: document.contents,
            });
        }
        if manager == Manager::Apt && effective_empty {
            let keyring = APT_KEYRINGS
                .iter()
                .map(PathBuf::from)
                .find(|path| runtime.read(path).ok().flatten().is_some());
            match keyring {
                Some(path) => {
                    sources.push(snapshot_source("keyring", path_string(&path)?));
                    sources.push(policy_source("keyring-preserved", &path));
                }
                None => sources.push(policy_source("keyring-missing", Path::new(APT_KEYRINGS[0]))),
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "ros2".into(),
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
        validate_policy(current)?;
        let manager = Manager::from_name(&current_value(current, "manager")?)?;
        let upstream = manager.upstream();
        let mut probe = BTreeMap::from([
            ("release".into(), current_value(current, "release")?),
            (
                "repository_path".into(),
                current_value(current, "package-path")?,
            ),
        ]);
        if manager == Manager::Apt {
            probe.insert("suite".into(), current_value(current, "release")?);
            probe.insert("apt_arch".into(), current_value(current, "architecture")?);
        }
        Ok(SelectionRequest {
            tool_id: "ros2".into(),
            adapter_key: "ros2".into(),
            context: context.clone(),
            tool_version: Some(current_value(current, "ros-distribution")?),
            required_upstreams: vec![upstream.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(upstream.into(), vec![probe])]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: true,
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
        let manager = Manager::from_name(&current_value(current, "manager")?)?;
        let endpoint = selected_endpoint(manager, selections)?;
        let target = find_document(current, "ros2-package-target")?;
        let rendered = if target.contents.is_empty() {
            render_new(manager, current, &endpoint)?
        } else {
            rewrite_existing(
                manager,
                utf8(&target.path, &target.contents)?,
                &target.path,
                &endpoint,
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
                    "map only the ROS 2 {} package repository for {} while preserving GPG, pins, and unrelated repositories",
                    manager.name(),
                    current_value(current, "ros-distribution")?
                ),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "ros2".into(),
            tool_id: "ros2".into(),
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
            let manager = manager(context, runtime)?;
            let documents = read_documents(runtime, manager)?;
            let effective = effective_source_documents(&documents)?;
            let target = choose_target(manager, &effective);
            if !receipt
                .changed_targets
                .contains(&rooted(&context.root, &target))
            {
                return Err(AdapterError::Verification(
                    "ROS 2 transaction contains no known target".into(),
                ));
            }
            let selected = effective
                .iter()
                .find(|document| document.path == target)
                .and_then(|document| document.source.as_ref())
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "ROS 2 package repository is not active after apply".into(),
                    )
                })?;
            let platform = platform(context, runtime, manager)?;
            let output = match manager {
                Manager::Apt => verify_apt(runtime, &target, &platform.package_name)?,
                Manager::Rpm => verify_rpm(
                    runtime,
                    &target,
                    selected.repo_id.as_deref(),
                    &platform.package_name,
                )?,
            };
            if !output.to_ascii_lowercase().contains(&platform.package_name) {
                return Err(AdapterError::Verification(format!(
                    "{} did not expose {}",
                    manager.name(),
                    platform.package_name
                )));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} refreshed and queried ROS 2 {} for {} through {}",
                    manager.name(),
                    platform.ros_distribution,
                    platform.architecture,
                    selected.uri
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
                "restored {} ROS 2 package repository files from {}",
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

    fn upstream(self) -> &'static str {
        match self {
            Self::Apt => APT_UPSTREAM,
            Self::Rpm => RPM_UPSTREAM,
        }
    }

    fn from_name(value: &str) -> Result<Self, AdapterError> {
        match value {
            "apt" => Ok(Self::Apt),
            "rpm" => Ok(Self::Rpm),
            _ => Err(AdapterError::InvalidConfiguration(
                "unknown ROS 2 package manager".into(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct Platform {
    release: String,
    architecture: String,
    ros_distribution: String,
    package_name: String,
    package_path: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceIdentity {
    uri: String,
    release: String,
}

#[derive(Clone, Debug)]
struct RepositorySource {
    uri: String,
    release: String,
    components: Vec<String>,
    architectures: Vec<String>,
    signed_by: Option<String>,
    repo_gpgcheck: Option<bool>,
    repo_id: Option<String>,
}

#[derive(Clone, Debug)]
struct ObservedDocument {
    path: PathBuf,
    contents: Vec<u8>,
    exists: bool,
    source: Option<RepositorySource>,
    custom_only: bool,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "ROS 2 package adapter supports Linux only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "ROS 2 package repositories require system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "ros2" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 2 operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn manager(context: &SystemContext, runtime: &dyn Runtime) -> Result<Manager, AdapterError> {
    let distribution = context.distribution.as_ref().ok_or_else(|| {
        AdapterError::Unsupported("ROS 2 requires a detected Linux distribution".into())
    })?;
    if distribution.id == "ubuntu" {
        if runtime.command_exists("apt-get") && runtime.command_exists("apt-cache") {
            return Ok(Manager::Apt);
        }
        return Err(AdapterError::Unsupported(
            "ROS 2 Ubuntu packages require apt-get and apt-cache".into(),
        ));
    }
    if matches!(distribution.id.as_str(), "rhel" | "almalinux") {
        if context.architecture == Architecture::Arm64 {
            return Err(AdapterError::Unsupported(
                "upstream ROS 2 RPM repositories do not publish arm64 binaries".into(),
            ));
        }
        if runtime.command_exists("dnf") {
            return Ok(Manager::Rpm);
        }
        return Err(AdapterError::Unsupported(
            "ROS 2 RHEL packages require dnf".into(),
        ));
    }
    Err(AdapterError::Unsupported(format!(
        "ROS 2 binary repositories do not cover {}",
        distribution.id
    )))
}

fn platform(
    context: &SystemContext,
    runtime: &dyn Runtime,
    manager: Manager,
) -> Result<Platform, AdapterError> {
    let distribution = context.distribution.as_ref().ok_or_else(|| {
        AdapterError::Unsupported("ROS 2 requires a detected Linux distribution".into())
    })?;
    let (release, architecture, default_ros, allowed) = match manager {
        Manager::Apt => {
            let release = distribution.version_codename.as_deref().ok_or_else(|| {
                AdapterError::Unsupported("ROS 2 APT requires an Ubuntu codename".into())
            })?;
            let (default_ros, allowed) = match release {
                "jammy" => ("humble", &["humble"][..]),
                "noble" => ("jazzy", &["jazzy", "kilted"][..]),
                "resolute" => ("lyrical", &["lyrical"][..]),
                _ => {
                    return Err(AdapterError::Unsupported(format!(
                        "ROS 2 APT coverage excludes Ubuntu {release}"
                    )));
                }
            };
            let architecture = match context.architecture {
                Architecture::X86_64 => "amd64",
                Architecture::Arm64 => "arm64",
            };
            (release, architecture, default_ros, allowed)
        }
        Manager::Rpm => {
            let release = distribution
                .version_id
                .as_deref()
                .and_then(|value| value.split('.').next())
                .unwrap_or("unknown");
            if distribution.id == "almalinux" && release != "10" {
                return Err(AdapterError::Unsupported(format!(
                    "ROS 2 RPM coverage for AlmaLinux is version 10 only, not {release}"
                )));
            }
            let (default_ros, allowed) = match release {
                "8" => ("humble", &["humble"][..]),
                "9" => ("jazzy", &["jazzy", "kilted"][..]),
                "10" => ("lyrical", &["lyrical"][..]),
                _ => {
                    return Err(AdapterError::Unsupported(format!(
                        "ROS 2 RPM coverage excludes {} {release}",
                        distribution.id
                    )));
                }
            };
            (release, "x86_64", default_ros, allowed)
        }
    };
    let ros_distribution = ros_distribution(runtime, default_ros, allowed)?;
    let (package_name, package_path) =
        package_identity(manager, release, architecture, &ros_distribution)?;
    Ok(Platform {
        release: release.into(),
        architecture: architecture.into(),
        ros_distribution,
        package_name,
        package_path,
    })
}

fn ros_distribution(
    runtime: &dyn Runtime,
    default: &str,
    allowed: &[&str],
) -> Result<String, AdapterError> {
    let environment = runtime
        .environment_variable("ROS_DISTRO")
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_ascii_lowercase());
    let command = if runtime.command_exists("ros2") {
        let output = runtime.run("ros2", &["pkg".into(), "prefix".into(), "rclcpp".into()])?;
        output
            .status
            .success()
            .then(|| {
                String::from_utf8_lossy(&output.stdout)
                    .split('/')
                    .collect::<Vec<_>>()
                    .windows(2)
                    .find(|parts| parts[0] == "ros")
                    .map(|parts| parts[1].trim().to_ascii_lowercase())
            })
            .flatten()
    } else {
        None
    };
    if environment.is_some() && command.is_some() && environment != command {
        return Err(AdapterError::Conflict(
            "ROS_DISTRO and the active ros2 installation disagree".into(),
        ));
    }
    let selected = environment.or(command).unwrap_or_else(|| default.into());
    if !allowed.contains(&selected.as_str()) {
        return Err(AdapterError::Unsupported(format!(
            "ROS 2 {selected} does not match this operating-system release"
        )));
    }
    Ok(selected)
}

fn package_identity(
    manager: Manager,
    release: &str,
    architecture: &str,
    ros_distribution: &str,
) -> Result<(String, String), AdapterError> {
    let (name, path) = match (manager, release, architecture, ros_distribution) {
        (Manager::Apt, "jammy", "amd64", "humble") => (
            "ros-humble-ros-base",
            "pool/main/r/ros-humble-ros-base/ros-humble-ros-base_0.10.0-1jammy.20260804.204550_amd64.deb",
        ),
        (Manager::Apt, "jammy", "arm64", "humble") => (
            "ros-humble-ros-base",
            "pool/main/r/ros-humble-ros-base/ros-humble-ros-base_0.10.0-1jammy.20260804.223545_arm64.deb",
        ),
        (Manager::Apt, "noble", "amd64", "jazzy") => (
            "ros-jazzy-ros-base",
            "pool/main/r/ros-jazzy-ros-base/ros-jazzy-ros-base_0.11.0-1noble.20260616.084325_amd64.deb",
        ),
        (Manager::Apt, "noble", "arm64", "jazzy") => (
            "ros-jazzy-ros-base",
            "pool/main/r/ros-jazzy-ros-base/ros-jazzy-ros-base_0.11.0-1noble.20260614.091815_arm64.deb",
        ),
        (Manager::Apt, "noble", "amd64", "kilted") => (
            "ros-kilted-ros-base",
            "pool/main/r/ros-kilted-ros-base/ros-kilted-ros-base_0.12.0-2noble.20260813.100949_amd64.deb",
        ),
        (Manager::Apt, "noble", "arm64", "kilted") => (
            "ros-kilted-ros-base",
            "pool/main/r/ros-kilted-ros-base/ros-kilted-ros-base_0.12.0-2noble.20260813.172300_arm64.deb",
        ),
        (Manager::Apt, "resolute", "amd64", "lyrical") => (
            "ros-lyrical-ros-base",
            "pool/main/r/ros-lyrical-ros-base/ros-lyrical-ros-base_0.13.0-3resolute.20260812.070046_amd64.deb",
        ),
        (Manager::Apt, "resolute", "arm64", "lyrical") => (
            "ros-lyrical-ros-base",
            "pool/main/r/ros-lyrical-ros-base/ros-lyrical-ros-base_0.13.0-3resolute.20260812.124512_arm64.deb",
        ),
        (Manager::Rpm, "8", "x86_64", "humble") => (
            "ros-humble-ros-base",
            "8/x86_64/Packages/r/ros-humble-ros-base-0.10.0-1.el8.20260806.123335.x86_64.rpm",
        ),
        (Manager::Rpm, "9", "x86_64", "jazzy") => (
            "ros-jazzy-ros-base",
            "9/x86_64/Packages/r/ros-jazzy-ros-base-0.11.0-1.el9.20260615.121922.x86_64.rpm",
        ),
        (Manager::Rpm, "9", "x86_64", "kilted") => (
            "ros-kilted-ros-base",
            "9/x86_64/Packages/r/ros-kilted-ros-base-0.12.0-2.el9.20260813.090111.x86_64.rpm",
        ),
        (Manager::Rpm, "10", "x86_64", "lyrical") => (
            "ros-lyrical-ros-base-runtime",
            "10/x86_64/Packages/r/ros-lyrical-ros-base-runtime-0.13.0-3.el10.20260812.065801.x86_64.rpm",
        ),
        _ => {
            return Err(AdapterError::Unsupported(
                "ROS 2 package identity is unavailable for this platform".into(),
            ));
        }
    };
    Ok((name.into(), path.into()))
}

fn read_documents(
    runtime: &dyn Runtime,
    manager: Manager,
) -> Result<Vec<ObservedDocument>, AdapterError> {
    let (main, directory, target, extensions) = match manager {
        Manager::Apt => (
            Some(PathBuf::from("/etc/apt/sources.list")),
            PathBuf::from("/etc/apt/sources.list.d"),
            PathBuf::from(APT_MANAGED_TARGET),
            &["list", "sources"][..],
        ),
        Manager::Rpm => (
            None,
            PathBuf::from("/etc/yum.repos.d"),
            PathBuf::from(RPM_MANAGED_TARGET),
            &["repo"][..],
        ),
    };
    let mut paths = BTreeSet::from([target]);
    if let Some(main) = main {
        paths.insert(main);
        paths.insert(PathBuf::from(APT_PACKAGE_SOURCE));
        paths.insert(PathBuf::from(APT_PACKAGE_LINK));
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
        let text = utf8(&path, &contents)?;
        let source = exists
            .then(|| parse_repository(manager, text, &path))
            .transpose()?
            .flatten();
        let custom_only = exists && source.is_none() && contains_custom_ros2(manager, text);
        documents.push(ObservedDocument {
            path,
            contents,
            exists,
            source,
            custom_only,
        });
    }
    Ok(documents)
}

fn effective_source_documents(
    documents: &[ObservedDocument],
) -> Result<Vec<&ObservedDocument>, AdapterError> {
    let mut sources = documents
        .iter()
        .filter(|document| document.source.is_some())
        .collect::<Vec<_>>();
    let package_source = sources
        .iter()
        .position(|document| document.path == Path::new(APT_PACKAGE_SOURCE));
    let package_link = sources
        .iter()
        .position(|document| document.path == Path::new(APT_PACKAGE_LINK));
    if let (Some(source), Some(link)) = (package_source, package_link)
        && sources[source].contents == sources[link].contents
    {
        sources.remove(link);
    }
    let identities = sources
        .iter()
        .map(|document| {
            let source = document.source.as_ref().unwrap();
            SourceIdentity {
                uri: source.uri.clone(),
                release: source.release.clone(),
            }
        })
        .collect::<BTreeSet<_>>();
    if identities.len() != sources.len() {
        return Err(AdapterError::InvalidConfiguration(
            "duplicate ROS 2 repositories exist outside the package-managed symlink".into(),
        ));
    }
    Ok(sources)
}

fn parse_repository(
    manager: Manager,
    text: &str,
    path: &Path,
) -> Result<Option<RepositorySource>, AdapterError> {
    match manager {
        Manager::Apt => parse_apt_repository(text, path),
        Manager::Rpm => parse_rpm_repository(text, path),
    }
}

fn parse_apt_repository(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut matches = Vec::new();
    for stanza in text.split("\n\n") {
        let mut uri = None;
        let mut release = None;
        let mut components = Vec::new();
        let mut architectures = Vec::new();
        for line in stanza.lines() {
            let active = line.split('#').next().unwrap_or_default().trim();
            if let Some(value) = active.strip_prefix("URIs:") {
                for value in value
                    .split_whitespace()
                    .filter(|value| is_ros2_apt_uri(value))
                {
                    if uri
                        .replace(value.trim_end_matches('/').to_owned())
                        .is_some()
                    {
                        return Err(AdapterError::InvalidConfiguration(format!(
                            "multiple ROS 2 APT URIs exist in {}",
                            path.display()
                        )));
                    }
                }
            } else if let Some(value) = active.strip_prefix("Suites:") {
                release = value.split_whitespace().next().map(str::to_owned);
            } else if let Some(value) = active.strip_prefix("Components:") {
                components = value.split_whitespace().map(str::to_owned).collect();
            } else if let Some(value) = active.strip_prefix("Architectures:") {
                architectures = value.split_whitespace().map(str::to_owned).collect();
            } else if active.starts_with("deb ") {
                let fields = active.split_whitespace().collect::<Vec<_>>();
                for (index, value) in fields.iter().enumerate() {
                    if !is_ros2_apt_uri(value) {
                        continue;
                    }
                    uri = Some(value.trim_end_matches('/').to_owned());
                    release = fields.get(index + 1).map(|value| (*value).to_owned());
                    components = fields[index + 2..]
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect();
                    architectures = apt_architectures(active);
                }
            }
        }
        if let Some(uri) = uri {
            matches.push(RepositorySource {
                uri,
                release: release.ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "ROS 2 APT source in {} has no suite",
                        path.display()
                    ))
                })?,
                components,
                architectures,
                signed_by: apt_signed_by(stanza),
                repo_gpgcheck: None,
                repo_id: None,
            });
        }
    }
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "multiple ROS 2 APT repositories exist in {}",
            path.display()
        )));
    }
    Ok(matches.into_iter().next())
}

fn parse_rpm_repository(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut section = None::<String>;
    let mut values: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for line in text.lines() {
        let active = line.split(['#', ';']).next().unwrap_or_default().trim();
        if active.starts_with('[') && active.ends_with(']') {
            let name = active[1..active.len() - 1].trim();
            if name.is_empty() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "empty RPM repository section in {}",
                    path.display()
                )));
            }
            section = Some(name.into());
            continue;
        }
        let Some((key, value)) = active.split_once('=') else {
            continue;
        };
        if let Some(section) = &section {
            values
                .entry(section.clone())
                .or_default()
                .insert(key.trim().to_ascii_lowercase(), value.trim().into());
        }
    }
    let matches = values
        .iter()
        .filter_map(|(repo_id, values)| {
            let uri = values.get("baseurl")?;
            (values.get("enabled").is_none_or(|value| value != "0") && is_ros2_rpm_uri(uri))
                .then(|| (repo_id.clone(), uri.trim_end_matches('/').to_owned()))
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "multiple ROS 2 RPM repositories exist in {}",
            path.display()
        )));
    }
    matches
        .first()
        .map(|(repo_id, uri)| {
            let fields = &values[repo_id];
            Ok(RepositorySource {
                uri: uri.clone(),
                release: rpm_release(uri).unwrap_or_else(|| "$releasever".into()),
                components: vec!["main".into()],
                architectures: vec!["x86_64".into()],
                signed_by: fields.get("gpgkey").cloned(),
                repo_gpgcheck: fields.get("repo_gpgcheck").map(|value| value == "1"),
                repo_id: Some(repo_id.clone()),
            })
        })
        .transpose()
}

fn is_ros2_apt_uri(value: &str) -> bool {
    let normalized = value.trim_end_matches('/').to_ascii_lowercase();
    normalized == "http://packages.ros.org/ros2/ubuntu"
        || normalized == "https://packages.ros.org/ros2/ubuntu"
        || APT_ENDPOINTS
            .iter()
            .any(|(_, endpoint)| normalized == *endpoint)
}

fn is_ros2_rpm_uri(value: &str) -> bool {
    let normalized = value.trim_end_matches('/').to_ascii_lowercase();
    (normalized.starts_with("http://packages.ros.org/ros2/rhel/")
        || normalized.starts_with("https://packages.ros.org/ros2/rhel/")
        || normalized.starts_with("https://mirrors.nju.edu.cn/ros2-rhel/"))
        && (normalized.ends_with("/x86_64") || normalized.ends_with("/$basearch"))
}

fn contains_custom_ros2(manager: Manager, text: &str) -> bool {
    text.lines().any(|line| {
        let active = line.split(['#', ';']).next().unwrap_or_default().trim();
        match manager {
            Manager::Apt => {
                (active.starts_with("deb ") || active.starts_with("URIs:"))
                    && active.to_ascii_lowercase().contains("/ros2/")
            }
            Manager::Rpm => active.split_once('=').is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("baseurl")
                    && value.to_ascii_lowercase().contains("ros2")
            }),
        }
    })
}

fn apt_signed_by(text: &str) -> Option<String> {
    if text.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        return Some("embedded".into());
    }
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or_default().trim();
        if let Some(value) = active.strip_prefix("Signed-By:") {
            return Some(if value.contains("BEGIN PGP PUBLIC KEY BLOCK") {
                "embedded".into()
            } else {
                value.trim().into()
            });
        }
        if let Some(index) = active.find("signed-by=") {
            let value = &active[index + "signed-by=".len()..];
            let value = value.split([']', ' ', ',']).next().unwrap_or_default();
            if !value.is_empty() {
                return Some(value.into());
            }
        }
    }
    None
}

fn apt_architectures(text: &str) -> Vec<String> {
    text.find("arch=")
        .map(|index| &text[index + 5..])
        .and_then(|value| value.split([']', ' ']).next())
        .map(|value| value.split(',').map(str::to_owned).collect())
        .unwrap_or_default()
}

fn rpm_release(value: &str) -> Option<String> {
    let marker = "/ros2-rhel/";
    let tail = value.to_ascii_lowercase().split_once(marker)?.1.to_owned();
    tail.split('/').next().map(str::to_owned)
}

fn choose_target(manager: Manager, documents: &[&ObservedDocument]) -> PathBuf {
    documents
        .iter()
        .find(|document| document.path == Path::new(APT_PACKAGE_SOURCE))
        .or_else(|| documents.first())
        .map(|document| document.path.clone())
        .unwrap_or_else(|| match manager {
            Manager::Apt => PathBuf::from(APT_MANAGED_TARGET),
            Manager::Rpm => PathBuf::from(RPM_MANAGED_TARGET),
        })
}

fn is_managed_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some("mirrorswitch-ros2.sources" | "mirrorswitch-ros2.repo")
    )
}

fn render_new(
    manager: Manager,
    current: &CurrentConfiguration,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let release = current_value(current, "release")?;
    let architecture = current_value(current, "architecture")?;
    Ok(match manager {
        Manager::Apt => format!(
            "{MANAGED_MARKER}\nTypes: deb\nURIs: {endpoint}\nSuites: {release}\nComponents: main\nArchitectures: {architecture}\nSigned-By: {}\n",
            current_value(current, "keyring")?
        ),
        Manager::Rpm => format!(
            "{MANAGED_MARKER}\n[mirrorswitch-ros2]\nname=ROS 2 {release} - x86_64\nbaseurl={endpoint}/{release}/x86_64\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=1\ngpgkey=https://raw.githubusercontent.com/ros/rosdistro/master/ros.asc\n"
        ),
    })
}

fn rewrite_existing(
    manager: Manager,
    text: &str,
    path: &Path,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let source = parse_repository(manager, text, path)?.ok_or_else(|| {
        AdapterError::InvalidConfiguration("selected ROS 2 repository disappeared".into())
    })?;
    let replacement = match manager {
        Manager::Apt => endpoint.to_owned(),
        Manager::Rpm => format!("{endpoint}/$releasever/$basearch"),
    };
    replace_active_once(manager, text, &source.uri, &replacement, path)
}

fn replace_active_once(
    manager: Manager,
    text: &str,
    old: &str,
    new: &str,
    path: &Path,
) -> Result<String, AdapterError> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let active = line.split(['#', ';']).next().unwrap_or_default();
        let eligible = match manager {
            Manager::Apt => {
                active.trim_start().starts_with("deb ") || active.trim_start().starts_with("URIs:")
            }
            Manager::Rpm => active.split_once('=').is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("baseurl")
                    && value.trim().trim_end_matches('/') == old.trim_end_matches('/')
            }),
        };
        if eligible {
            for (index, _) in active.match_indices(old) {
                ranges.push(offset + index..offset + index + old.len());
            }
        }
        offset += line.len();
    }
    if ranges.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "ROS 2 repository URI in {} is missing or duplicated",
            path.display()
        )));
    }
    let range: Range<usize> = ranges.remove(0);
    Ok(format!(
        "{}{}{}",
        &text[..range.start],
        new,
        &text[range.end..]
    ))
}

fn selected_endpoint(
    manager: Manager,
    selections: &[MirrorSelection],
) -> Result<String, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "ros2"
        || selections[0].upstream_id != manager.upstream()
    {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 2 requires one matching package repository selection".into(),
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
                "ROS 2 selection needs one HTTPS {role:?} endpoint"
            )));
        }
        normalized_endpoint(&endpoints[0].url)
            .ok_or_else(|| AdapterError::InvalidConfiguration("ROS 2 endpoint is unsafe".into()))
    };
    let index = role_url(EndpointRole::Index)?;
    if role_url(EndpointRole::Metadata)? != index || role_url(EndpointRole::Packages)? != index {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 2 index, metadata, and package endpoints must match".into(),
        ));
    }
    let allowed = match manager {
        Manager::Apt => APT_ENDPOINTS,
        Manager::Rpm => RPM_ENDPOINTS,
    };
    if !allowed
        .iter()
        .any(|(provider, endpoint)| selection.provider_id == *provider && index == *endpoint)
    {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 2 provider and endpoint are not reviewed".into(),
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
            "multiple-public-repositories" => {
                return Err(AdapterError::InvalidConfiguration(
                    "multiple ROS 2 public repositories are active".into(),
                ));
            }
            "custom-only-ros2-repository" => {
                return Err(AdapterError::Unsupported(
                    "only a custom ROS 2 repository is configured; it is preserved".into(),
                ));
            }
            "coverage-mismatch" => {
                return Err(AdapterError::Unsupported(
                    "ROS 2 repository release, architecture, or component does not match the host"
                        .into(),
                ));
            }
            "keyring-missing" | "signed-by-missing" => {
                return Err(AdapterError::Unsupported(
                    "ROS 2 APT signature configuration is incomplete".into(),
                ));
            }
            "repo-gpgcheck-disabled" | "gpgkey-missing" => {
                return Err(AdapterError::Unsupported(
                    "ROS 2 RPM repository metadata signature verification is incomplete".into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "managed ROS 2 target contains user data".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn verify_apt(runtime: &dyn Runtime, target: &Path, package: &str) -> Result<String, AdapterError> {
    let options = [
        format!("Dir::Etc::sourcelist={}", path_string(target)?),
        "Dir::Etc::sourceparts=-".into(),
        "APT::Get::List-Cleanup=0".into(),
    ];
    let mut update = vec!["update".into()];
    for option in &options {
        update.extend(["-o".into(), option.clone()]);
    }
    command_output(runtime.run("apt-get", &update)?, "ROS 2 APT refresh")?;
    let mut query = Vec::new();
    for option in &options {
        query.extend(["-o".into(), option.clone()]);
    }
    query.extend(["policy".into(), package.into()]);
    command_output(runtime.run("apt-cache", &query)?, "ROS 2 APT query")
}

fn verify_rpm(
    runtime: &dyn Runtime,
    target: &Path,
    repo_id: Option<&str>,
    package: &str,
) -> Result<String, AdapterError> {
    let repo_id = repo_id.unwrap_or("mirrorswitch-ros2");
    let directory = target
        .parent()
        .ok_or_else(|| AdapterError::InvalidConfiguration("ROS 2 RPM path has no parent".into()))?;
    let common = [
        format!("--setopt=reposdir={}", path_string(directory)?),
        "--disablerepo=*".into(),
        format!("--enablerepo={repo_id}"),
        "--refresh".into(),
        "-y".into(),
    ];
    let mut refresh = common.to_vec();
    refresh.extend(["-q".into(), "makecache".into()]);
    command_output(runtime.run("dnf", &refresh)?, "ROS 2 RPM refresh")?;
    let mut query = common.to_vec();
    query.extend([
        "-q".into(),
        "list".into(),
        "--showduplicates".into(),
        package.into(),
    ]);
    command_output(runtime.run("dnf", &query)?, "ROS 2 RPM query")
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

fn configured_source(source: &RepositorySource, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(
            if source.repo_id.is_some() {
                RPM_UPSTREAM
            } else {
                APT_UPSTREAM
            }
            .into(),
        ),
        url: source.uri.clone(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["ros2-repository".into()]),
            ("release".into(), vec![source.release.clone()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
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
            "ROS 2 state must contain one {format} document"
        )));
    }
    Ok(matches[0])
}

fn current_value(current: &CurrentConfiguration, kind: &str) -> Result<String, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some(kind))
        .map(|source| {
            source
                .url
                .split_once(':')
                .map(|(_, value)| value)
                .unwrap_or(&source.url)
                .to_owned()
        })
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "ROS 2 state has ambiguous {kind}"
        )));
    }
    Ok(values[0].clone())
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("ros2-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
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
        AdapterError::InvalidConfiguration(format!("ROS 2 source lacks {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "ROS 2 source has ambiguous {key} metadata"
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
            "ROS 2 {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "ROS 2 repository {} is not UTF-8",
            path.display()
        ))
    })
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
