use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
};

use mirrorswitch::{
    Adapter, AdapterError, MirrorCatalog, Runtime,
    adapters::{CygwinAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::ChangePlan,
    transaction::{ApplyOutcome, RestoreReceipt, TransactionParticipant, TransactionReceipt},
};

const HUAWEI: &str = "https://repo.huaweicloud.com/cygwin";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/sourceware/cygwin";

#[cfg(unix)]
fn exit_status(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(code << 8)
}

#[cfg(windows)]
fn exit_status(code: i32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(code as u32)
}

fn output(code: i32, stdout: impl Into<Vec<u8>>) -> Output {
    Output {
        status: exit_status(code),
        stdout: stdout.into(),
        stderr: Vec::new(),
    }
}

fn root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\cygwin64")
    } else {
        PathBuf::from("/cygwin64")
    }
}

fn setup() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Users\test\Downloads\setup-x86_64.exe")
    } else {
        PathBuf::from("/Users/test/Downloads/setup-x86_64.exe")
    }
}

fn cache() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\cygwin-packages")
    } else {
        PathBuf::from("/cygwin-packages")
    }
}

fn context(architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Windows,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "windows".into(),
            version_id: Some("Microsoft Windows [Version 10.0.26100.1]".into()),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: PathBuf::from("/"),
    }
}

struct FakeRuntime {
    files: BTreeMap<PathBuf, Vec<u8>>,
    backups: BTreeMap<String, BTreeMap<PathBuf, Option<Vec<u8>>>>,
    calls: RefCell<Vec<String>>,
    fail_download: Cell<bool>,
}

impl FakeRuntime {
    fn new(mirror: &str) -> Self {
        let setup_rc = format!(
            "last-mirror\r\n\t{mirror}\r\nlast-cache\r\n\t{}\r\nnet-method\r\n\tIE5\r\n",
            cache().display()
        );
        Self {
            files: BTreeMap::from([
                (root().join("etc/setup/setup.rc"), setup_rc.into_bytes()),
                (
                    root().join("etc/setup/installed.db"),
                    b"INSTALLED PACKAGE SELECTION\r\n".to_vec(),
                ),
            ]),
            backups: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
            fail_download: Cell::new(false),
        }
    }
}

impl Runtime for FakeRuntime {
    fn command_exists(&self, command: &str) -> bool {
        command == setup().display().to_string()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        setup()
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
    }

    fn environment_variable(&self, name: &str) -> Option<String> {
        match name {
            "CYGWIN_ROOT" => Some(root().display().to_string()),
            "CYGWIN_SETUP" => Some(setup().display().to_string()),
            _ => None,
        }
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(self.files.get(path).cloned())
    }

    fn run(&self, program: &str, arguments: &[String]) -> Result<Output, AdapterError> {
        self.calls
            .borrow_mut()
            .push(format!("{program} {}", arguments.join(" ")));
        if program != setup().display().to_string() {
            return Err(AdapterError::Runtime(format!(
                "unexpected Cygwin command {program}"
            )));
        }
        if arguments == ["--version"] {
            Ok(output(0, "Cygwin setup 2.953 (64 bit)\r\n"))
        } else if arguments.iter().any(|argument| argument == "--download") {
            Ok(output(i32::from(self.fail_download.get()), Vec::new()))
        } else {
            Err(AdapterError::Runtime(format!(
                "unexpected setup arguments {}",
                arguments.join(" ")
            )))
        }
    }

    fn apply_plan(&mut self, plan: &ChangePlan) -> Result<ApplyOutcome, AdapterError> {
        let mut backup = BTreeMap::new();
        for change in &plan.changes {
            let current = self.files.get(&change.target).cloned();
            if current != change.old_contents {
                return Err(AdapterError::Conflict(change.target.display().to_string()));
            }
            backup.insert(change.target.clone(), current);
            self.files
                .insert(change.target.clone(), change.new_contents.clone());
        }
        let transaction_id = format!("cygwin-{}", self.backups.len() + 1);
        self.backups.insert(transaction_id.clone(), backup);
        Ok(ApplyOutcome::Applied(TransactionReceipt {
            transaction_id,
            participants: vec![TransactionParticipant {
                adapter_key: "cygwin".into(),
                tool_id: "cygwin".into(),
            }],
            changed_files: plan.changes.len(),
            changed_targets: plan
                .changes
                .iter()
                .map(|change| change.target.clone())
                .collect(),
        }))
    }

    fn restore_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<RestoreReceipt, AdapterError> {
        let backup = self
            .backups
            .get(transaction_id)
            .cloned()
            .ok_or_else(|| AdapterError::Runtime("unknown Cygwin test transaction".into()))?;
        for (path, contents) in &backup {
            if let Some(contents) = contents {
                self.files.insert(path.clone(), contents.clone());
            } else {
                self.files.remove(path);
            }
        }
        Ok(RestoreReceipt {
            transaction_id: transaction_id.into(),
            restored_files: backup.len(),
            verified: true,
        })
    }
}

fn selection(url: &str) -> mirrorswitch::plan::MirrorSelection {
    mirrorswitch::plan::MirrorSelection {
        candidate_id: "cygwin-test".into(),
        tool_id: "cygwin".into(),
        upstream_id: "cygwin--static-files".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: url.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: url.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn setup_rc_plan_preserves_cache_packages_crlf_and_is_reversible() {
    let context = context(Architecture::X86_64);
    let adapter = CygwinAdapter;
    let mut runtime = FakeRuntime::new("https://mirrors.kernel.org/sourceware/cygwin");
    let setup_rc = root().join("etc/setup/setup.rc");
    let installed = root().join("etc/setup/installed.db");
    let original = runtime.files[&setup_rc].clone();
    let installed_before = runtime.files[&installed].clone();

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.version.as_deref().unwrap().contains("2.953"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(
        current.sources[0].metadata["local_package_dir"][0],
        cache().display().to_string()
    );
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(plan.requires_elevation);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("last-mirror\r\n\t{HUAWEI}\r\n")));
    assert!(rendered.contains(&format!("last-cache\r\n\t{}\r\n", cache().display())));
    assert!(!rendered.replace("\r\n", "").contains('\n'));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Cygwin setup.rc should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let call = runtime
        .calls
        .borrow()
        .iter()
        .find(|call| call.contains("--download"))
        .unwrap()
        .clone();
    assert!(call.contains("--packages dash"));
    assert!(call.contains(&format!("--root {}", root().display())));
    assert!(call.contains(&format!("--local-package-dir {}", cache().display())));
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &[selection(HUAWEI)])
            .unwrap()
            .changes
            .is_empty()
    );
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(runtime.files[&setup_rc], original);
    assert_eq!(runtime.files[&installed], installed_before);
}

#[test]
fn failed_download_restores_and_arm64_or_custom_mirror_is_rejected() {
    let x64_context = context(Architecture::X86_64);
    let adapter = CygwinAdapter;
    let mut runtime = FakeRuntime::new("https://mirrors.kernel.org/sourceware/cygwin");
    let detected = adapter.detect(&x64_context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &x64_context,
            &runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    let plan = adapter
        .plan(&x64_context, &current, &[selection(TUNA)])
        .unwrap();
    let setup_rc = root().join("etc/setup/setup.rc");
    let before = runtime.files[&setup_rc].clone();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&x64_context, &mut runtime, &plan).unwrap()
    else {
        panic!("Cygwin mirror should change")
    };
    runtime.fail_download.set(true);
    let error = adapter
        .verify(&x64_context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(runtime.files[&setup_rc], before);
    assert!(
        adapter
            .detect(&context(Architecture::Arm64), &runtime)
            .is_err()
    );

    let custom = FakeRuntime::new("https://private.example/cygwin");
    let detected = adapter.detect(&x64_context, &custom).unwrap().unwrap();
    assert!(
        adapter
            .read_current(&x64_context, &custom, &detected, ConfigurationScope::System,)
            .is_err()
    );
}

#[test]
fn embedded_catalog_has_two_official_x86_64_setup_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "cygwin")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::System]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "cygwin")
        .collect::<Vec<_>>();
    let actionable = candidates
        .iter()
        .filter(|candidate| candidate.delivery_mode == DeliveryMode::Mirror)
        .collect::<Vec<_>>();
    assert_eq!(actionable.len(), 2);
    assert_eq!(
        actionable
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["huaweicloud", "tuna"])
    );
    assert!(actionable.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Windows]
            && candidate.compatibility.architectures == [Architecture::X86_64]
            && candidate.probes.len() == 4
            && candidate.probes[0].path == "/x86_64/setup.xz"
            && candidate.probes[1].path == "/x86_64/setup.xz.sig"
            && candidate.probes[3].sha256.as_deref()
                == Some("41a50947c79757b1bb5f49007c61c4dad4dd66bf814e9e054a48487acefb891e")
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate.provider_id == "aliyun" && candidate.delivery_mode != DeliveryMode::Mirror
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate.provider_id == "nju" && candidate.delivery_mode != DeliveryMode::Mirror
    }));
}
