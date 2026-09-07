use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::ConfigurationScope,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::{CurrentConfiguration, DetectedTool},
    platform::compiled_os,
    transaction::TransactionEngine,
    wsl::{WslDistribution, discover as discover_wsl},
};

#[derive(Clone, Debug)]
pub struct LinuxDetectionOptions {
    pub root: PathBuf,
    pub home: PathBuf,
    pub project_dir: Option<PathBuf>,
    pub executable_path: Vec<PathBuf>,
    pub architecture: String,
    pub effective_uid: u32,
    pub container_hint: Option<String>,
}

impl LinuxDetectionOptions {
    pub fn current() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        let executable_path = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        Self {
            root: PathBuf::from("/"),
            home,
            project_dir: std::env::current_dir().ok(),
            executable_path,
            architecture: std::env::consts::ARCH.into(),
            effective_uid: effective_uid(),
            container_hint: std::env::var("container").ok(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostDetectionOptions {
    pub os: OperatingSystem,
    pub root: PathBuf,
    pub home: PathBuf,
    pub project_dir: Option<PathBuf>,
    pub executable_path: Vec<PathBuf>,
    pub architecture: String,
    pub platform_version: Option<String>,
    pub effective_uid: Option<u32>,
    pub elevated: bool,
    pub system_config: PathBuf,
    pub user_config: PathBuf,
    pub catalog_cache: PathBuf,
    pub transaction_root: PathBuf,
}

impl HostDetectionOptions {
    pub fn current() -> Self {
        let os = compiled_os();
        let home = current_home(os);
        let local_data = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Local"));
        let roaming_data = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Roaming"));
        let (effective_uid, elevated, system_config, user_config, catalog_cache, transaction_root) =
            match os {
                OperatingSystem::Linux => {
                    let uid = effective_uid();
                    let cache = std::env::var_os("XDG_CACHE_HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| home.join(".cache"));
                    (
                        Some(uid),
                        uid == 0,
                        PathBuf::from("/etc"),
                        home.join(".config"),
                        cache.join("mirrorswitch/catalog.json"),
                        PathBuf::from("/var/lib/mirrorswitch/transactions"),
                    )
                }
                OperatingSystem::Macos => {
                    let uid = effective_uid();
                    (
                        Some(uid),
                        uid == 0,
                        PathBuf::from("/Library/Application Support"),
                        home.join("Library/Application Support"),
                        home.join("Library/Caches/MirrorSwitch/catalog.json"),
                        home.join("Library/Application Support/MirrorSwitch/transactions"),
                    )
                }
                OperatingSystem::Windows => {
                    let program_data = std::env::var_os("ProgramData")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
                    (
                        None,
                        windows_elevated(),
                        program_data,
                        roaming_data,
                        local_data.join("MirrorSwitch/catalog.json"),
                        local_data.join("MirrorSwitch/transactions"),
                    )
                }
            };
        Self {
            os,
            root: PathBuf::from("/"),
            home,
            project_dir: std::env::current_dir().ok(),
            executable_path: std::env::var_os("PATH")
                .map(|value| std::env::split_paths(&value).collect())
                .unwrap_or_default(),
            architecture: std::env::consts::ARCH.into(),
            platform_version: platform_version(os),
            effective_uid,
            elevated,
            system_config,
            user_config,
            catalog_cache,
            transaction_root,
        }
    }

    pub fn runtime(&self) -> OsRuntime {
        let mut runtime = OsRuntime::new(&self.root, self.executable_path.clone())
            .with_home(self.home.clone())
            .with_transaction_root(self.transaction_root.clone());
        if let Some(project) = &self.project_dir {
            runtime = runtime.with_project_dir(project.clone());
        }
        runtime
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DetectionReport {
    pub context: SystemContext,
    pub container: Option<ContainerContext>,
    pub layout: ConfigurationLayout,
    pub permissions: PermissionContext,
    pub runtimes: Vec<ExecutableObservation>,
    pub related_tools: Vec<RelatedToolObservation>,
    pub tools: Vec<ToolDetection>,
    pub selections: Vec<TargetSelection>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wsl_distributions: Vec<WslDistribution>,
    pub notices: Vec<DetectionNotice>,
}

impl DetectionReport {
    /// Applies the same target decisions produced by a configuration file or
    /// TUI without changing which tools were actually detected.
    pub fn apply_overrides(&mut self, overrides: &BTreeMap<String, bool>, source: OverrideSource) {
        for (adapter_key, selected) in overrides {
            if let Some(target) = self
                .selections
                .iter_mut()
                .find(|target| target.adapter_key == *adapter_key)
            {
                target.selected = *selected;
                target.reason = match (source, selected) {
                    (OverrideSource::Configuration, true) => SelectionReason::ConfigurationEnabled,
                    (OverrideSource::Configuration, false) => {
                        SelectionReason::ConfigurationDisabled
                    }
                    (OverrideSource::Tui, true) => SelectionReason::TuiEnabled,
                    (OverrideSource::Tui, false) => SelectionReason::TuiDisabled,
                };
            } else {
                self.notices.push(DetectionNotice {
                    subject: adapter_key.clone(),
                    code: NoticeCode::ExplicitToolUnavailable,
                    message: "explicit selection ignored because the tool is not operable".into(),
                });
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConfigurationLayout {
    pub system: PathBuf,
    pub user: PathBuf,
    pub project: Option<PathBuf>,
    pub service_management_available: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PermissionContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_uid: Option<u32>,
    pub elevated: bool,
    pub system_scope_requires_elevation: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ContainerContext {
    pub kind: ContainerKind,
    pub evidence: Vec<String>,
    pub base_distribution: Distribution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerKind {
    Docker,
    Podman,
    Kubernetes,
    Lxc,
    Other,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutableObservation {
    pub runtime_id: String,
    pub executable: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelatedToolObservation {
    pub runtime_id: String,
    pub tool_id: String,
    pub executable: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolDetection {
    pub adapter_key: String,
    pub detected: DetectedTool,
    pub configurations: Vec<CurrentConfiguration>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetSelection {
    pub adapter_key: String,
    pub tool_id: String,
    pub scope: ConfigurationScope,
    pub selected: bool,
    pub reason: SelectionReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionReason {
    Automatic,
    ConfigurationEnabled,
    ConfigurationDisabled,
    TuiEnabled,
    TuiDisabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverrideSource {
    Configuration,
    Tui,
}

#[derive(Clone, Debug, Serialize)]
pub struct DetectionNotice {
    pub subject: String,
    pub code: NoticeCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeCode {
    UnsupportedDistribution,
    RelatedToolNotInstalled,
    ToolNotDetected,
    AdapterDetectionFailed,
    ConfigurationReadFailed,
    ConfigurationParseFailed,
    PermissionDenied,
    UnsupportedFormat,
    InvalidDefaultScope,
    ExplicitToolUnavailable,
}

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("Linux detection was requested on unsupported OS {0}")]
    UnsupportedOperatingSystem(String),
    #[error("unsupported Linux architecture {0}")]
    UnsupportedArchitecture(String),
    #[error("could not read /etc/os-release or /usr/lib/os-release: {0}")]
    OsReleaseUnavailable(io::Error),
    #[error("invalid os-release data: {0}")]
    InvalidOsRelease(String),
}

pub fn detect_linux(
    options: &LinuxDetectionOptions,
    adapters: &[&dyn Adapter],
) -> Result<DetectionReport, DetectionError> {
    if std::env::consts::OS != "linux" {
        return Err(DetectionError::UnsupportedOperatingSystem(
            std::env::consts::OS.into(),
        ));
    }

    let architecture = parse_architecture(&options.architecture)?;
    let distribution = read_distribution(&options.root)?;
    let mut runtime = OsRuntime::new(&options.root, options.executable_path.clone())
        .with_home(options.home.clone());
    if let Some(project_dir) = &options.project_dir {
        runtime = runtime.with_project_dir(project_dir.clone());
    }
    let (environment, container) = detect_container(options, &distribution);
    let context = SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
        distribution: Some(distribution.clone()),
        root: options.root.clone(),
    };
    let mut notices = Vec::new();
    if !supported_distribution(&distribution.id) {
        notices.push(DetectionNotice {
            subject: distribution.id.clone(),
            code: NoticeCode::UnsupportedDistribution,
            message: "distribution is detected but has no v0.1 support contract".into(),
        });
    }

    let detected = detect_adapters(&context, &runtime, adapters, &mut notices);

    Ok(DetectionReport {
        context,
        container,
        layout: ConfigurationLayout {
            system: PathBuf::from("/etc"),
            user: options.home.join(".config"),
            project: options.project_dir.clone(),
            service_management_available: environment == ExecutionEnvironment::Host
                && physical_path(&options.root, Path::new("/run/systemd/system")).is_dir(),
        },
        permissions: PermissionContext {
            effective_uid: Some(options.effective_uid),
            elevated: options.effective_uid == 0,
            system_scope_requires_elevation: options.effective_uid != 0,
        },
        runtimes: detected.runtimes,
        related_tools: detected.related_tools,
        tools: detected.tools,
        selections: detected.selections,
        wsl_distributions: Vec::new(),
        notices,
    })
}

pub fn detect_host(
    options: &HostDetectionOptions,
    adapters: &[&dyn Adapter],
) -> Result<DetectionReport, DetectionError> {
    if options.os != compiled_os() {
        return Err(DetectionError::UnsupportedOperatingSystem(format!(
            "requested {:?}, compiled for {:?}",
            options.os,
            compiled_os()
        )));
    }
    if options.os == OperatingSystem::Linux {
        return detect_linux(
            &LinuxDetectionOptions {
                root: options.root.clone(),
                home: options.home.clone(),
                project_dir: options.project_dir.clone(),
                executable_path: options.executable_path.clone(),
                architecture: options.architecture.clone(),
                effective_uid: options.effective_uid.unwrap_or_else(effective_uid),
                container_hint: std::env::var("container").ok(),
            },
            adapters,
        );
    }

    let architecture = parse_architecture(&options.architecture)?;
    let runtime = options.runtime();
    let context = SystemContext {
        os: options.os,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: match options.os {
                OperatingSystem::Macos => "macos",
                OperatingSystem::Windows => "windows",
                OperatingSystem::Linux => unreachable!(),
            }
            .into(),
            version_id: options.platform_version.clone(),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: options.root.clone(),
    };
    let mut notices = Vec::new();
    let wsl_distributions = if options.os == OperatingSystem::Windows {
        match discover_wsl(&runtime) {
            Ok(distributions) => distributions,
            Err(error) => {
                notices.push(DetectionNotice {
                    subject: "wsl".into(),
                    code: NoticeCode::AdapterDetectionFailed,
                    message: format!("WSL inventory is unavailable: {error}"),
                });
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let detected = detect_adapters(&context, &runtime, adapters, &mut notices);
    Ok(DetectionReport {
        context,
        container: None,
        layout: ConfigurationLayout {
            system: options.system_config.clone(),
            user: options.user_config.clone(),
            project: options.project_dir.clone(),
            service_management_available: true,
        },
        permissions: PermissionContext {
            effective_uid: options.effective_uid,
            elevated: options.elevated,
            system_scope_requires_elevation: !options.elevated,
        },
        runtimes: detected.runtimes,
        related_tools: detected.related_tools,
        tools: detected.tools,
        selections: detected.selections,
        wsl_distributions,
        notices,
    })
}

struct AdapterDetections {
    runtimes: Vec<ExecutableObservation>,
    related_tools: Vec<RelatedToolObservation>,
    tools: Vec<ToolDetection>,
    selections: Vec<TargetSelection>,
}

fn detect_adapters(
    context: &SystemContext,
    runtime: &OsRuntime,
    adapters: &[&dyn Adapter],
    notices: &mut Vec<DetectionNotice>,
) -> AdapterDetections {
    let (runtimes, related_tools) = detect_related_tools(runtime, notices);
    let mut tools = Vec::new();
    let mut selections = Vec::new();
    for adapter in adapters {
        let detected = match adapter.detect(context, runtime) {
            Ok(Some(detected)) => detected,
            Ok(None) => {
                notices.push(DetectionNotice {
                    subject: adapter.key().into(),
                    code: NoticeCode::ToolNotDetected,
                    message: "adapter found neither a callable tool nor valid configuration".into(),
                });
                continue;
            }
            Err(error) => {
                notices.push(adapter_notice(
                    adapter.key(),
                    NoticeCode::AdapterDetectionFailed,
                    &error,
                ));
                continue;
            }
        };

        let mut configurations = Vec::new();
        let mut configuration_failed = false;
        for &scope in adapter.supported_scopes() {
            match adapter.read_current(context, runtime, &detected, scope) {
                Ok(configuration) => configurations.push(configuration),
                Err(error) => {
                    configuration_failed = true;
                    notices.push(adapter_notice(
                        adapter.key(),
                        configuration_notice_code(&error),
                        &error,
                    ));
                }
            }
        }
        if configuration_failed {
            continue;
        }

        let default_scope = match adapter.default_scope_for(context, runtime, &detected) {
            Ok(scope) => scope,
            Err(error) => {
                notices.push(adapter_notice(
                    adapter.key(),
                    NoticeCode::InvalidDefaultScope,
                    &error,
                ));
                continue;
            }
        };
        if adapter.supported_scopes().contains(&default_scope)
            && matches!(
                default_scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
        {
            selections.push(TargetSelection {
                adapter_key: adapter.key().into(),
                tool_id: adapter.tool_id().into(),
                scope: default_scope,
                selected: true,
                reason: SelectionReason::Automatic,
            });
        } else {
            notices.push(DetectionNotice {
                subject: adapter.key().into(),
                code: NoticeCode::InvalidDefaultScope,
                message: "adapter default must be a declared system or user scope".into(),
            });
        }

        tools.push(ToolDetection {
            adapter_key: adapter.key().into(),
            detected,
            configurations,
        });
    }
    AdapterDetections {
        runtimes,
        related_tools,
        tools,
        selections,
    }
}

#[derive(Clone, Debug)]
pub struct OsRuntime {
    root: PathBuf,
    executable_path: Vec<PathBuf>,
    home: Option<PathBuf>,
    project_dir: Option<PathBuf>,
    environment: Option<BTreeMap<String, String>>,
    transaction_root: Option<PathBuf>,
}

impl OsRuntime {
    pub fn new(root: impl Into<PathBuf>, executable_path: Vec<PathBuf>) -> Self {
        Self {
            root: root.into(),
            executable_path,
            home: None,
            project_dir: None,
            environment: None,
            transaction_root: None,
        }
    }

    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    pub fn with_project_dir(mut self, project_dir: impl Into<PathBuf>) -> Self {
        self.project_dir = Some(project_dir.into());
        self
    }

    pub fn with_environment(mut self, environment: BTreeMap<String, String>) -> Self {
        self.environment = Some(environment);
        self
    }

    pub fn with_transaction_root(mut self, transaction_root: impl Into<PathBuf>) -> Self {
        self.transaction_root = Some(transaction_root.into());
        self
    }

    pub fn find_command(&self, command: &str) -> Option<PathBuf> {
        if command.contains('/') || (cfg!(windows) && command.contains('\\')) {
            let path = PathBuf::from(command);
            return executable(&physical_path(&self.root, &path)).then_some(path);
        }
        self.executable_path
            .iter()
            .find_map(|directory| find_command_in(directory, command, &self.root))
    }

    fn command_for_run(&self, command: &str) -> Option<PathBuf> {
        if command.contains('/') || (cfg!(windows) && command.contains('\\')) {
            Some(PathBuf::from(command))
        } else {
            self.find_command(command)
        }
    }
}

impl Runtime for OsRuntime {
    fn command_exists(&self, command: &str) -> bool {
        self.find_command(command).is_some()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }

    fn project_dir(&self) -> Option<PathBuf> {
        self.project_dir.clone()
    }

    fn environment_variable(&self, name: &str) -> Option<String> {
        self.environment.as_ref().map_or_else(
            || std::env::var(name).ok(),
            |values| values.get(name).cloned(),
        )
    }

    fn wsl_distribution_names(&self) -> Result<Option<Vec<String>>, AdapterError> {
        #[cfg(windows)]
        {
            crate::wsl::registered_distribution_names().map(Some)
        }
        #[cfg(not(windows))]
        {
            Ok(None)
        }
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
        match fs::read(physical_path(&self.root, path)) {
            Ok(contents) => Ok(Some(contents)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                Err(AdapterError::PermissionDenied(path.display().to_string()))
            }
            Err(error) => Err(AdapterError::Runtime(format!(
                "could not read {}: {error}",
                path.display()
            ))),
        }
    }

    fn list_files(&self, directory: &Path) -> Result<Vec<PathBuf>, AdapterError> {
        let physical_directory = physical_path(&self.root, directory);
        let entries = match fs::read_dir(&physical_directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(AdapterError::PermissionDenied(
                    directory.display().to_string(),
                ));
            }
            Err(error) => {
                return Err(AdapterError::Runtime(format!(
                    "could not list {}: {error}",
                    directory.display()
                )));
            }
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                AdapterError::Runtime(format!("could not list {}: {error}", directory.display()))
            })?;
            if entry
                .file_type()
                .map_err(|error| AdapterError::Runtime(error.to_string()))?
                .is_file()
            {
                paths.push(directory.join(entry.file_name()));
            }
        }
        paths.sort();
        Ok(paths)
    }

    fn run(&self, program: &str, arguments: &[String]) -> Result<Output, AdapterError> {
        let logical = self.command_for_run(program).ok_or_else(|| {
            AdapterError::Runtime(format!("command {program} is not available on PATH"))
        })?;
        run_command(&physical_path(&self.root, &logical), arguments, None)
            .map_err(|error| AdapterError::Runtime(format!("could not run {program}: {error}")))
    }

    fn run_in(
        &self,
        directory: &Path,
        program: &str,
        arguments: &[String],
    ) -> Result<Output, AdapterError> {
        let logical = self.command_for_run(program).ok_or_else(|| {
            AdapterError::Runtime(format!("command {program} is not available on PATH"))
        })?;
        run_command(
            &physical_path(&self.root, &logical),
            arguments,
            Some(&physical_path(&self.root, directory)),
        )
        .map_err(|error| {
            AdapterError::Runtime(format!(
                "could not run {program} in {}: {error}",
                directory.display()
            ))
        })
    }

    fn run_in_with_environment(
        &self,
        directory: &Path,
        program: &str,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        removed_environment: &[String],
    ) -> Result<Output, AdapterError> {
        let logical = self.command_for_run(program).ok_or_else(|| {
            AdapterError::Runtime(format!("command {program} is not available on PATH"))
        })?;
        run_command_with_environment(
            &physical_path(&self.root, &logical),
            arguments,
            Some(&physical_path(&self.root, directory)),
            environment,
            removed_environment,
        )
        .map_err(|error| {
            AdapterError::Runtime(format!(
                "could not run {program} in {} with an isolated environment: {error}",
                directory.display()
            ))
        })
    }

    fn run_with_environment(
        &self,
        program: &str,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        removed_environment: &[String],
    ) -> Result<Output, AdapterError> {
        let logical = self.command_for_run(program).ok_or_else(|| {
            AdapterError::Runtime(format!("command {program} is not available on PATH"))
        })?;
        run_command_with_environment(
            &physical_path(&self.root, &logical),
            arguments,
            None,
            environment,
            removed_environment,
        )
        .map_err(|error| {
            AdapterError::Runtime(format!(
                "could not run {program} with an isolated environment: {error}"
            ))
        })
    }

    fn apply_plan(
        &mut self,
        plan: &crate::plan::ChangePlan,
    ) -> Result<crate::transaction::ApplyOutcome, AdapterError> {
        TransactionEngine::new(self.transaction_root.clone().unwrap_or_else(|| {
            physical_path(&self.root, Path::new("/var/lib/mirrorswitch/transactions"))
        }))
        .apply(plan)
        .map_err(|error| AdapterError::Runtime(error.to_string()))
    }

    fn restore_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<crate::transaction::RestoreReceipt, AdapterError> {
        TransactionEngine::new(self.transaction_root.clone().unwrap_or_else(|| {
            physical_path(&self.root, Path::new("/var/lib/mirrorswitch/transactions"))
        }))
        .restore(transaction_id)
        .map_err(|error| AdapterError::Runtime(error.to_string()))
    }

    fn transaction_receipt(
        &self,
        transaction_id: &str,
    ) -> Result<crate::transaction::TransactionReceipt, AdapterError> {
        TransactionEngine::new(self.transaction_root.clone().unwrap_or_else(|| {
            physical_path(&self.root, Path::new("/var/lib/mirrorswitch/transactions"))
        }))
        .receipt(transaction_id)
        .map_err(|error| AdapterError::Runtime(error.to_string()))
    }
}

fn detect_related_tools(
    runtime: &OsRuntime,
    notices: &mut Vec<DetectionNotice>,
) -> (Vec<ExecutableObservation>, Vec<RelatedToolObservation>) {
    const PYTHON_TOOLS: &[RelatedToolSpec] = &[
        RelatedToolSpec {
            id: "pip",
            commands: &["pip3", "pip"],
        },
        RelatedToolSpec {
            id: "uv",
            commands: &["uv"],
        },
        RelatedToolSpec {
            id: "poetry",
            commands: &["poetry"],
        },
        RelatedToolSpec {
            id: "pdm",
            commands: &["pdm"],
        },
    ];
    const JAVA_TOOLS: &[RelatedToolSpec] = &[
        RelatedToolSpec {
            id: "maven",
            commands: &["mvn"],
        },
        RelatedToolSpec {
            id: "gradle",
            commands: &["gradle"],
        },
        RelatedToolSpec {
            id: "sbt",
            commands: &["sbt"],
        },
        RelatedToolSpec {
            id: "leiningen",
            commands: &["lein"],
        },
    ];
    const RUNTIMES: &[RuntimeSpec] = &[
        RuntimeSpec {
            id: "python",
            commands: &["python3", "python"],
            related_tools: PYTHON_TOOLS,
        },
        RuntimeSpec {
            id: "java",
            commands: &["java"],
            related_tools: JAVA_TOOLS,
        },
    ];

    let mut runtimes = Vec::new();
    let mut related = Vec::new();
    for runtime_spec in RUNTIMES {
        let Some(executable) = find_first(runtime, runtime_spec.commands) else {
            continue;
        };
        runtimes.push(ExecutableObservation {
            runtime_id: runtime_spec.id.into(),
            executable,
        });
        for tool_spec in runtime_spec.related_tools {
            let executable = find_first(runtime, tool_spec.commands);
            if executable.is_none() {
                notices.push(DetectionNotice {
                    subject: tool_spec.id.into(),
                    code: NoticeCode::RelatedToolNotInstalled,
                    message: format!(
                        "{} is present, but related tool {} is not callable",
                        runtime_spec.id, tool_spec.id
                    ),
                });
            }
            related.push(RelatedToolObservation {
                runtime_id: runtime_spec.id.into(),
                tool_id: tool_spec.id.into(),
                executable,
            });
        }
    }
    (runtimes, related)
}

struct RuntimeSpec {
    id: &'static str,
    commands: &'static [&'static str],
    related_tools: &'static [RelatedToolSpec],
}

struct RelatedToolSpec {
    id: &'static str,
    commands: &'static [&'static str],
}

fn find_first(runtime: &OsRuntime, commands: &[&str]) -> Option<PathBuf> {
    commands
        .iter()
        .find_map(|command| runtime.find_command(command))
}

fn adapter_notice(key: &str, code: NoticeCode, error: &AdapterError) -> DetectionNotice {
    DetectionNotice {
        subject: key.into(),
        code,
        message: error.to_string(),
    }
}

fn configuration_notice_code(error: &AdapterError) -> NoticeCode {
    match error {
        AdapterError::InvalidConfiguration(_) => NoticeCode::ConfigurationParseFailed,
        AdapterError::PermissionDenied(_) => NoticeCode::PermissionDenied,
        AdapterError::Unsupported(_) => NoticeCode::UnsupportedFormat,
        _ => NoticeCode::ConfigurationReadFailed,
    }
}

fn parse_architecture(value: &str) -> Result<Architecture, DetectionError> {
    match value {
        "x86_64" | "amd64" => Ok(Architecture::X86_64),
        "aarch64" | "arm64" => Ok(Architecture::Arm64),
        other => Err(DetectionError::UnsupportedArchitecture(other.into())),
    }
}

fn read_distribution(root: &Path) -> Result<Distribution, DetectionError> {
    let mut last_error = None;
    for logical in ["/etc/os-release", "/usr/lib/os-release"] {
        match fs::read_to_string(physical_path(root, Path::new(logical))) {
            Ok(contents) => return parse_distribution(&contents),
            Err(error) => last_error = Some(error),
        }
    }
    Err(DetectionError::OsReleaseUnavailable(
        last_error
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "os-release is missing")),
    ))
}

fn parse_distribution(contents: &str) -> Result<Distribution, DetectionError> {
    let mut values = BTreeMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            DetectionError::InvalidOsRelease(format!("line {} has no '='", index + 1))
        })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(DetectionError::InvalidOsRelease(format!(
                "line {} has an invalid key",
                index + 1
            )));
        }
        values.insert(key.to_owned(), unquote_os_release(raw_value.trim())?);
    }

    let id = values
        .remove("ID")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DetectionError::InvalidOsRelease("ID is missing".into()))?
        .to_ascii_lowercase();
    Ok(Distribution {
        id,
        version_id: values
            .remove("VERSION_ID")
            .filter(|value| !value.is_empty()),
        version_codename: values
            .remove("VERSION_CODENAME")
            .filter(|value| !value.is_empty()),
        id_like: values
            .remove("ID_LIKE")
            .map(|value| {
                value
                    .split_ascii_whitespace()
                    .map(|item| item.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn unquote_os_release(value: &str) -> Result<String, DetectionError> {
    let Some(quote) = value
        .as_bytes()
        .first()
        .copied()
        .filter(|byte| matches!(byte, b'\'' | b'"'))
    else {
        return Ok(value.into());
    };
    if value.as_bytes().last().copied() != Some(quote) || value.len() < 2 {
        return Err(DetectionError::InvalidOsRelease(
            "unterminated quoted value".into(),
        ));
    }
    let inner = &value[1..value.len() - 1];
    if quote == b'\'' {
        return Ok(inner.into());
    }
    let mut result = String::with_capacity(inner.len());
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            result.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            result.push(character);
        }
    }
    if escaped {
        return Err(DetectionError::InvalidOsRelease(
            "quoted value ends with an escape".into(),
        ));
    }
    Ok(result)
}

fn detect_container(
    options: &LinuxDetectionOptions,
    distribution: &Distribution,
) -> (ExecutionEnvironment, Option<ContainerContext>) {
    let mut evidence = Vec::new();
    let mut kind = None;
    if let Some(hint) = options
        .container_hint
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        evidence.push(format!("container environment variable: {hint}"));
        kind = Some(container_kind(hint));
    }
    if physical_path(&options.root, Path::new("/.dockerenv")).exists() {
        evidence.push("/.dockerenv".into());
        kind.get_or_insert(ContainerKind::Docker);
    }
    if physical_path(&options.root, Path::new("/run/.containerenv")).exists() {
        evidence.push("/run/.containerenv".into());
        kind.get_or_insert(ContainerKind::Podman);
    }
    if let Ok(cgroup) =
        fs::read_to_string(physical_path(&options.root, Path::new("/proc/1/cgroup")))
    {
        let lower = cgroup.to_ascii_lowercase();
        let detected = if lower.contains("kubepods") {
            Some(ContainerKind::Kubernetes)
        } else if lower.contains("docker") || lower.contains("containerd") {
            Some(ContainerKind::Docker)
        } else if lower.contains("libpod") || lower.contains("podman") {
            Some(ContainerKind::Podman)
        } else if lower.contains("lxc") {
            Some(ContainerKind::Lxc)
        } else {
            None
        };
        if let Some(detected) = detected {
            evidence.push("/proc/1/cgroup".into());
            kind.get_or_insert(detected);
        }
    }

    match kind {
        Some(kind) => (
            ExecutionEnvironment::Container,
            Some(ContainerContext {
                kind,
                evidence,
                base_distribution: distribution.clone(),
            }),
        ),
        None => (ExecutionEnvironment::Host, None),
    }
}

fn container_kind(value: &str) -> ContainerKind {
    match value.to_ascii_lowercase().as_str() {
        "docker" | "containerd" => ContainerKind::Docker,
        "podman" | "libpod" => ContainerKind::Podman,
        "kubernetes" | "kube" => ContainerKind::Kubernetes,
        "lxc" | "lxd" => ContainerKind::Lxc,
        _ => ContainerKind::Other,
    }
}

fn supported_distribution(id: &str) -> bool {
    const SUPPORTED: &[&str] = &[
        "debian",
        "ubuntu",
        "fedora",
        "rocky",
        "almalinux",
        "centos",
        "arch",
        "archarm",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "alpine",
        "gentoo",
        "void",
        "nixos",
        "guix",
        "openwrt",
        "immortalwrt",
    ];
    SUPPORTED.contains(&id)
}

fn current_home(os: OperatingSystem) -> PathBuf {
    match os {
        OperatingSystem::Windows => std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| {
                let drive = std::env::var_os("HOMEDRIVE")?;
                let path = std::env::var_os("HOMEPATH")?;
                Some(PathBuf::from(drive).join(path))
            })
            .unwrap_or_else(|| PathBuf::from(r"C:\")),
        OperatingSystem::Linux | OperatingSystem::Macos => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/")),
    }
}

fn platform_version(os: OperatingSystem) -> Option<String> {
    let output = match os {
        OperatingSystem::Macos => Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()?,
        OperatingSystem::Windows => Command::new("cmd.exe")
            .args(["/D", "/C", "ver"])
            .output()
            .ok()?,
        OperatingSystem::Linux => return None,
    };
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(windows)]
fn windows_elevated() -> bool {
    use std::{ffi::c_void, mem::size_of};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: Windows fills the provided token handle and elevation buffers; both
    // pointers remain valid for each call and the opened handle is always closed.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != 0;
        let _ = CloseHandle(token);
        success && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn windows_elevated() -> bool {
    false
}

fn find_command_in(directory: &Path, command: &str, root: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    if Path::new(command).extension().is_none() {
        let extensions = std::env::var_os("PATHEXT")
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
        for extension in extensions.split(';').filter(|value| !value.is_empty()) {
            let candidate = directory.join(format!("{command}{extension}"));
            if executable(&physical_path(root, &candidate)) {
                return Some(candidate);
            }
        }
    }
    let logical = directory.join(command);
    if executable(&physical_path(root, &logical)) {
        return Some(logical);
    }
    None
}

fn run_command(path: &Path, arguments: &[String], directory: Option<&Path>) -> io::Result<Output> {
    run_command_with_environment(path, arguments, directory, &BTreeMap::new(), &[])
}

fn run_command_with_environment(
    path: &Path,
    arguments: &[String],
    directory: Option<&Path>,
    environment: &BTreeMap<String, String>,
    removed_environment: &[String],
) -> io::Result<Output> {
    #[cfg(windows)]
    let mut command = if matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("cmd" | "bat")
    ) {
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/C"]).arg(path);
        command
    } else {
        Command::new(path)
    };
    #[cfg(not(windows))]
    let mut command = Command::new(path);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    for name in removed_environment {
        command.env_remove(name);
    }
    command.envs(environment);
    command.args(arguments).output()
}

fn physical_path(root: &Path, logical: &Path) -> PathBuf {
    if root == Path::new("/") {
        return logical.to_path_buf();
    }
    if logical.is_absolute() {
        root.join(logical.strip_prefix("/").unwrap_or(logical))
    } else {
        root.join(logical)
    }
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && executable_mode(&metadata)
}

#[cfg(unix)]
fn executable_mode(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_mode(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no arguments and no memory safety preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}
