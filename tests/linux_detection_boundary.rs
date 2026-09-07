use std::{collections::BTreeMap, fs, path::PathBuf};

use mirrorswitch::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope},
    context::{Architecture, ExecutionEnvironment, SystemContext},
    detection::{
        ContainerKind, DetectionError, LinuxDetectionOptions, NoticeCode, OverrideSource,
        SelectionReason, detect_linux,
    },
    frontend::{FrontendSource, RequestInput, normalize_request},
    plan::{
        ChangePlan, ConfiguredSource, CurrentConfiguration, DetectedTool, MirrorSelection,
        RestoreResult, VerificationResult,
    },
    transaction::{ApplyOutcome, TransactionReceipt},
};
use tempfile::TempDir;

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, b"fixture executable").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(not(unix))]
fn make_executable(path: &std::path::Path) {
    fs::write(path, b"fixture executable").unwrap();
}

#[test]
fn container_detection_and_adapter_inventory_are_read_only_and_machine_readable() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::create_dir_all(root.join("home/developer/.config/pip")).unwrap();
    fs::create_dir_all(root.join("work/project")).unwrap();
    fs::write(
        root.join("etc/os-release"),
        b"ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID_LIKE=\"debian\"\n",
    )
    .unwrap();
    fs::write(root.join(".dockerenv"), b"").unwrap();
    for command in ["python3", "pip3", "java", "mvn"] {
        make_executable(&root.join("usr/bin").join(command));
    }
    let pip_config = root.join("home/developer/.config/pip/pip.conf");
    fs::write(
        &pip_config,
        b"[global]\nindex-url = https://mirror.example.invalid/simple\nkeep = true\n",
    )
    .unwrap();
    let options = LinuxDetectionOptions {
        root: root.into(),
        home: PathBuf::from("/home/developer"),
        project_dir: Some(PathBuf::from("/work/project")),
        executable_path: vec![PathBuf::from("/usr/bin")],
        architecture: "aarch64".into(),
        effective_uid: 1000,
        container_hint: None,
    };
    let pip = FixtureAdapter {
        key: "pip",
        command: "pip3",
        config: Some("/home/developer/.config/pip/pip.conf"),
        read_failure: None,
        project_only: false,
    };
    let uv = FixtureAdapter {
        key: "uv",
        command: "uv",
        config: None,
        read_failure: None,
        project_only: false,
    };

    let mut report = detect_linux(&options, &[&pip, &uv]).unwrap();

    let distribution = report.context.distribution.as_ref().unwrap();
    assert_eq!(distribution.id, "ubuntu");
    assert_eq!(distribution.version_id.as_deref(), Some("24.04"));
    assert_eq!(distribution.version_codename.as_deref(), Some("noble"));
    assert_eq!(distribution.id_like, ["debian"]);
    assert_eq!(report.context.architecture, Architecture::Arm64);
    assert_eq!(report.context.environment, ExecutionEnvironment::Container);
    assert_eq!(
        report.container.as_ref().unwrap().kind,
        ContainerKind::Docker
    );
    assert!(!report.layout.service_management_available);
    assert!(report.permissions.system_scope_requires_elevation);

    assert_eq!(report.runtimes.len(), 2);
    assert!(report.related_tools.iter().any(|tool| {
        tool.tool_id == "pip"
            && tool.executable.as_deref() == Some(std::path::Path::new("/usr/bin/pip3"))
    }));
    assert!(report.related_tools.iter().any(|tool| {
        tool.tool_id == "maven"
            && tool.executable.as_deref() == Some(std::path::Path::new("/usr/bin/mvn"))
    }));
    assert_eq!(report.tools.len(), 1);
    assert_eq!(report.tools[0].adapter_key, "pip");
    assert_eq!(report.tools[0].configurations.len(), 3);
    let user_configuration = report.tools[0]
        .configurations
        .iter()
        .find(|configuration| configuration.scope == ConfigurationScope::User)
        .unwrap();
    assert_eq!(
        user_configuration.sources[0].url,
        "https://mirror.example.invalid/simple"
    );
    assert_eq!(
        user_configuration.files[0],
        PathBuf::from("/home/developer/.config/pip/pip.conf")
    );
    assert_eq!(report.selections.len(), 1);
    assert!(report.selections[0].selected);
    assert!(
        report
            .notices
            .iter()
            .any(|notice| { notice.subject == "uv" && notice.code == NoticeCode::ToolNotDetected })
    );

    report.apply_overrides(
        &BTreeMap::from([("pip".into(), false), ("uv".into(), true)]),
        OverrideSource::Configuration,
    );
    assert!(!report.selections[0].selected);
    assert!(report.notices.iter().any(|notice| {
        notice.subject == "uv" && notice.code == NoticeCode::ExplicitToolUnavailable
    }));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["context"]["architecture"], "arm64");
    assert_eq!(json["selections"][0]["reason"], "configuration-disabled");

    assert_eq!(
        fs::read(&pip_config).unwrap(),
        b"[global]\nindex-url = https://mirror.example.invalid/simple\nkeep = true\n"
    );
    assert!(!root.join("run/systemd/system").exists());
}

#[test]
fn rolling_host_can_use_usr_lib_os_release_without_a_version() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    fs::create_dir_all(root.join("usr/lib")).unwrap();
    fs::write(
        root.join("usr/lib/os-release"),
        b"ID=arch\nBUILD_ID=rolling\n",
    )
    .unwrap();
    let options = LinuxDetectionOptions {
        root: root.into(),
        home: PathBuf::from("/root"),
        project_dir: None,
        executable_path: Vec::new(),
        architecture: "x86_64".into(),
        effective_uid: 0,
        container_hint: None,
    };

    let report = detect_linux(&options, &[]).unwrap();

    assert_eq!(report.context.environment, ExecutionEnvironment::Host);
    assert_eq!(report.context.architecture, Architecture::X86_64);
    assert_eq!(report.context.distribution.unwrap().version_id, None);
    assert!(report.permissions.elevated);
}

#[test]
fn malformed_os_release_and_unsupported_architecture_are_explicit() {
    let fixture = TempDir::new().unwrap();
    fs::create_dir_all(fixture.path().join("etc")).unwrap();
    fs::write(fixture.path().join("etc/os-release"), b"NAME=Missing ID\n").unwrap();
    let mut options = LinuxDetectionOptions {
        root: fixture.path().into(),
        home: PathBuf::from("/root"),
        project_dir: None,
        executable_path: Vec::new(),
        architecture: "x86_64".into(),
        effective_uid: 0,
        container_hint: None,
    };

    assert!(matches!(
        detect_linux(&options, &[]),
        Err(DetectionError::InvalidOsRelease(_))
    ));
    options.architecture = "riscv64".into();
    assert!(matches!(
        detect_linux(&options, &[]),
        Err(DetectionError::UnsupportedArchitecture(value)) if value == "riscv64"
    ));
}

#[test]
fn unsafe_configuration_failures_are_distinct_and_not_operable() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::write(root.join("etc/os-release"), b"ID=debian\nVERSION_ID=13\n").unwrap();
    make_executable(&root.join("usr/bin/tool"));
    let options = LinuxDetectionOptions {
        root: root.into(),
        home: PathBuf::from("/home/developer"),
        project_dir: None,
        executable_path: vec![PathBuf::from("/usr/bin")],
        architecture: "x86_64".into(),
        effective_uid: 1000,
        container_hint: None,
    };
    let permission = FixtureAdapter {
        key: "permission-tool",
        command: "tool",
        config: None,
        read_failure: Some(ReadFailure::Permission),
        project_only: false,
    };
    let parse = FixtureAdapter {
        key: "parse-tool",
        command: "tool",
        config: None,
        read_failure: Some(ReadFailure::Parse),
        project_only: false,
    };
    let format = FixtureAdapter {
        key: "format-tool",
        command: "tool",
        config: None,
        read_failure: Some(ReadFailure::Format),
        project_only: false,
    };

    let report = detect_linux(&options, &[&permission, &parse, &format]).unwrap();

    assert!(report.tools.is_empty());
    assert!(report.selections.is_empty());
    assert!(report.notices.iter().any(|notice| {
        notice.subject == "permission-tool" && notice.code == NoticeCode::PermissionDenied
    }));
    assert!(report.notices.iter().any(|notice| {
        notice.subject == "parse-tool" && notice.code == NoticeCode::ConfigurationParseFailed
    }));
    assert!(report.notices.iter().any(|notice| {
        notice.subject == "format-tool" && notice.code == NoticeCode::UnsupportedFormat
    }));
}

#[test]
fn project_only_adapter_is_available_but_never_selected_implicitly() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::create_dir_all(root.join("work/project")).unwrap();
    fs::write(root.join("etc/os-release"), b"ID=debian\nVERSION_ID=13\n").unwrap();
    make_executable(&root.join("usr/bin/project-tool"));
    let options = LinuxDetectionOptions {
        root: root.into(),
        home: PathBuf::from("/home/developer"),
        project_dir: Some(PathBuf::from("/work/project")),
        executable_path: vec![PathBuf::from("/usr/bin")],
        architecture: "x86_64".into(),
        effective_uid: 1000,
        container_hint: None,
    };
    let adapter = FixtureAdapter {
        key: "project-tool",
        command: "project-tool",
        config: None,
        read_failure: None,
        project_only: true,
    };

    let report = detect_linux(&options, &[&adapter]).unwrap();

    assert_eq!(report.selections.len(), 1);
    assert_eq!(report.selections[0].scope, ConfigurationScope::Project);
    assert!(!report.selections[0].selected);
    assert_eq!(report.selections[0].reason, SelectionReason::ExplicitOnly);
    assert!(
        normalize_request(&report, &RequestInput::default(), FrontendSource::Cli)
            .unwrap()
            .tools
            .is_empty()
    );
    let explicit = RequestInput {
        tools: ["project-tool".into()].into_iter().collect(),
        scopes: [("project-tool".into(), ConfigurationScope::Project)]
            .into_iter()
            .collect(),
        ..RequestInput::default()
    };
    let normalized = normalize_request(&report, &explicit, FrontendSource::Cli).unwrap();
    assert_eq!(normalized.tools.len(), 1);
    assert_eq!(normalized.tools[0].scope, ConfigurationScope::Project);
}

struct FixtureAdapter {
    key: &'static str,
    command: &'static str,
    config: Option<&'static str>,
    read_failure: Option<ReadFailure>,
    project_only: bool,
}

#[derive(Clone, Copy)]
enum ReadFailure {
    Permission,
    Parse,
    Format,
}

impl Adapter for FixtureAdapter {
    fn key(&self) -> &'static str {
        self.key
    }

    fn tool_id(&self) -> &'static str {
        self.key
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        if self.project_only {
            &[ConfigurationScope::Project]
        } else {
            &[
                ConfigurationScope::System,
                ConfigurationScope::User,
                ConfigurationScope::Project,
            ]
        }
    }

    fn default_scope(&self) -> ConfigurationScope {
        if self.project_only {
            ConfigurationScope::Project
        } else {
            ConfigurationScope::User
        }
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        _context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        let has_config = self
            .config
            .map(|path| runtime.read(std::path::Path::new(path)))
            .transpose()?
            .flatten()
            .is_some_and(|contents| contents.starts_with(b"[global]"));
        if !runtime.command_exists(self.command) && !has_config {
            return Ok(None);
        }
        Ok(Some(DetectedTool {
            tool_id: self.key.into(),
            executable: runtime
                .command_exists(self.command)
                .then(|| PathBuf::from("/usr/bin").join(self.command)),
            version: None,
            evidence: vec![format!("{} command or valid config", self.command)],
        }))
    }

    fn read_current(
        &self,
        _context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        match self.read_failure {
            Some(ReadFailure::Permission) => {
                return Err(AdapterError::PermissionDenied("fixture path".into()));
            }
            Some(ReadFailure::Parse) => {
                return Err(AdapterError::InvalidConfiguration("fixture syntax".into()));
            }
            Some(ReadFailure::Format) => {
                return Err(AdapterError::Unsupported("fixture format".into()));
            }
            None => {}
        }
        if scope != ConfigurationScope::User {
            return Ok(CurrentConfiguration {
                tool_id: self.key.into(),
                scope,
                sources: Vec::new(),
                files: Vec::new(),
                documents: Vec::new(),
            });
        }
        let Some(path) = self.config else {
            return Ok(CurrentConfiguration {
                tool_id: self.key.into(),
                scope,
                sources: Vec::new(),
                files: Vec::new(),
                documents: Vec::new(),
            });
        };
        let contents = runtime
            .read(std::path::Path::new(path))?
            .ok_or_else(|| AdapterError::InvalidConfiguration("config disappeared".into()))?;
        let text = String::from_utf8(contents)
            .map_err(|_| AdapterError::InvalidConfiguration("config is not UTF-8".into()))?;
        let url = text
            .lines()
            .find_map(|line| line.split_once("index-url"))
            .and_then(|(_, value)| value.split_once('=').map(|(_, value)| value.trim()))
            .ok_or_else(|| AdapterError::InvalidConfiguration("index-url is missing".into()))?;
        Ok(CurrentConfiguration {
            tool_id: self.key.into(),
            scope,
            sources: vec![ConfiguredSource {
                upstream_id: Some("pypi".into()),
                url: url.into(),
                enabled: true,
                metadata: Default::default(),
            }],
            files: vec![PathBuf::from(path)],
            documents: Vec::new(),
        })
    }

    fn plan(
        &self,
        _context: &SystemContext,
        _current: &CurrentConfiguration,
        _selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        Err(AdapterError::Unsupported("fixture is read-only".into()))
    }

    fn apply(
        &self,
        _context: &SystemContext,
        _runtime: &mut dyn Runtime,
        _plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        Err(AdapterError::Unsupported("fixture is read-only".into()))
    }

    fn verify(
        &self,
        _context: &SystemContext,
        _runtime: &mut dyn Runtime,
        _receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        Err(AdapterError::Unsupported("fixture is read-only".into()))
    }

    fn restore(
        &self,
        _context: &SystemContext,
        _runtime: &mut dyn Runtime,
        _receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        Err(AdapterError::Unsupported("fixture is read-only".into()))
    }
}
