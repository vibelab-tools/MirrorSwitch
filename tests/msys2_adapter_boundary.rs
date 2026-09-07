use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
};

use mirrorswitch::{
    Adapter, AdapterError, MirrorCatalog, Runtime,
    adapters::{Msys2Adapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::ChangePlan,
    transaction::{ApplyOutcome, RestoreReceipt, TransactionParticipant, TransactionReceipt},
};

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
        PathBuf::from(r"C:\msys64")
    } else {
        PathBuf::from("/msys64")
    }
}

fn context(architecture: Architecture, build: u32) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Windows,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "windows".into(),
            version_id: Some(format!("Microsoft Windows [Version 10.0.{build}.1]")),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: PathBuf::from("/"),
    }
}

struct FakeRuntime {
    files: BTreeMap<PathBuf, Vec<u8>>,
    environment: BTreeMap<String, String>,
    backups: BTreeMap<String, BTreeMap<PathBuf, Option<Vec<u8>>>>,
    calls: RefCell<Vec<String>>,
    fail_refresh: bool,
}

impl FakeRuntime {
    fn new(subsystem: &str) -> Self {
        let root = root();
        let config = b"[options]\r\nArchitecture = auto\r\nSigLevel = Required DatabaseOptional\r\nLocalFileSigLevel = Optional\r\n\r\n[msys]\r\nInclude = /etc/pacman.d/mirrorlist.msys\r\n\r\n[mingw32]\r\nInclude = /etc/pacman.d/mirrorlist.mingw\r\n[mingw64]\r\nInclude = /etc/pacman.d/mirrorlist.mingw\r\n[ucrt64]\r\nInclude = /etc/pacman.d/mirrorlist.mingw\r\n[clang32]\r\nInclude = /etc/pacman.d/mirrorlist.mingw\r\n[clang64]\r\nInclude = /etc/pacman.d/mirrorlist.mingw\r\n[clangarm64]\r\nInclude = /etc/pacman.d/mirrorlist.mingw\r\n";
        let msys = b"# preserve custom precedence\r\nServer = https://private.example/cache/msys/$arch/\r\nServer = https://repo.msys2.org/msys/$arch/\r\nServer = https://mirrors.tuna.tsinghua.edu.cn/msys2/msys/$arch/\r\n";
        let mingw = b"# preserve custom precedence\r\nServer = https://private.example/cache/mingw/$repo/\r\nServer = https://repo.msys2.org/mingw/$repo/\r\nServer = https://mirrors.tuna.tsinghua.edu.cn/msys2/mingw/$repo/\r\n";
        Self {
            files: BTreeMap::from([
                (root.join("etc").join("pacman.conf"), config.to_vec()),
                (
                    root.join("etc").join("pacman.d").join("mirrorlist.msys"),
                    msys.to_vec(),
                ),
                (
                    root.join("etc").join("pacman.d").join("mirrorlist.mingw"),
                    mingw.to_vec(),
                ),
            ]),
            environment: BTreeMap::from([
                ("MSYS2_ROOT".into(), root.display().to_string()),
                ("MSYSTEM".into(), subsystem.into()),
            ]),
            backups: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
            fail_refresh: false,
        }
    }
}

fn pacman() -> PathBuf {
    root().join("usr").join("bin").join("pacman.exe")
}

impl Runtime for FakeRuntime {
    fn command_exists(&self, command: &str) -> bool {
        command == pacman().display().to_string()
    }

    fn environment_variable(&self, name: &str) -> Option<String> {
        self.environment.get(name).cloned()
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(self.files.get(path).cloned())
    }

    fn run(&self, program: &str, arguments: &[String]) -> Result<Output, AdapterError> {
        self.calls
            .borrow_mut()
            .push(format!("{program} {}", arguments.join(" ")));
        if program != pacman().display().to_string() {
            return Err(AdapterError::Runtime(format!(
                "unexpected MSYS2 command {program}"
            )));
        }
        match arguments.first().map(String::as_str) {
            Some("--version") => Ok(output(
                0,
                " .--.                  Pacman v7.0.0 - libalpm v15.0.0\r\n",
            )),
            Some("-Syy") => Ok(output(i32::from(self.fail_refresh), Vec::new())),
            Some("-Si" | "-Sw") => Ok(output(0, Vec::new())),
            _ => Err(AdapterError::Runtime(format!(
                "unexpected pacman arguments {}",
                arguments.join(" ")
            ))),
        }
    }

    fn apply_plan(&mut self, plan: &ChangePlan) -> Result<ApplyOutcome, AdapterError> {
        if plan.changes.is_empty() {
            return Ok(ApplyOutcome::Unchanged);
        }
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
        let transaction_id = format!("msys2-{}", self.backups.len() + 1);
        self.backups.insert(transaction_id.clone(), backup);
        Ok(ApplyOutcome::Applied(TransactionReceipt {
            transaction_id,
            participants: vec![TransactionParticipant {
                adapter_key: "msys2".into(),
                tool_id: "msys2".into(),
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
            .ok_or_else(|| AdapterError::Runtime("unknown MSYS2 test transaction".into()))?;
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

fn selection(root: &str) -> mirrorswitch::plan::MirrorSelection {
    mirrorswitch::plan::MirrorSelection {
        candidate_id: "msys2-test".into(),
        tool_id: "msys2".into(),
        upstream_id: "msys2--static-files".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: root.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: root.into(),
            },
        ],
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn ucrt64_plan_preserves_custom_fallbacks_refreshes_and_is_reversible() {
    let context = context(Architecture::X86_64, 26_100);
    let adapter = Msys2Adapter;
    let mut runtime = FakeRuntime::new("UCRT64");
    let msys = root().join("etc/pacman.d/mirrorlist.msys");
    let mingw = root().join("etc/pacman.d/mirrorlist.mingw");
    let msys_before = runtime.files[&msys].clone();
    let mingw_before = runtime.files[&mingw].clone();
    let config_before = runtime.files[&root().join("etc/pacman.conf")].clone();

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.evidence.iter().any(|item| item.contains("UCRT64")));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(current.documents.len(), 2);
    assert!(
        current
            .sources
            .iter()
            .any(|source| source.url == "redacted://custom-msys2-mirror")
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts["msys2--static-files"][0];
    assert_eq!(probe["msys_arch"], "x86_64");
    assert_eq!(probe["mingw_repo"], "ucrt64");
    assert_eq!(
        probe["mingw_package"],
        "mingw-w64-ucrt-x86_64-jq-1.8.2-1-any.pkg.tar.zst"
    );
    let choice = [selection("https://mirrors.aliyun.com/msys2")];
    let plan = adapter.plan(&context, &current, &choice).unwrap();
    assert_eq!(plan.changes.len(), 2);
    assert!(plan.requires_elevation);
    for change in &plan.changes {
        let text = String::from_utf8(change.new_contents.clone()).unwrap();
        assert!(
            text.starts_with("# preserve custom precedence\r\nServer = https://private.example")
        );
        assert!(!text.replace("\r\n", "").contains('\n'));
        assert!(text.contains("https://repo.msys2.org"));
        assert!(text.contains("https://mirrors.tuna.tsinghua.edu.cn"));
    }

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MSYS2 mirrorlists should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let calls = runtime.calls.borrow();
    assert!(calls.iter().any(|call| call.contains("-Syy --noconfirm")));
    assert!(
        calls
            .iter()
            .any(|call| call.contains("-Sw --noconfirm mingw-w64-ucrt-x86_64-jq"))
    );
    drop(calls);
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &choice)
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
    assert_eq!(runtime.files[&msys], msys_before);
    assert_eq!(runtime.files[&mingw], mingw_before);
    assert_eq!(
        runtime.files[&root().join("etc/pacman.conf")],
        config_before
    );
}

#[test]
fn clangarm64_failure_restores_and_windows_or_signature_policy_is_enforced() {
    let arm_context = context(Architecture::Arm64, 26_100);
    let adapter = Msys2Adapter;
    let mut runtime = FakeRuntime::new("CLANGARM64");
    let detected = adapter.detect(&arm_context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &arm_context,
            &runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    let probe = &adapter
        .selection_request(&arm_context, &detected, &current)
        .unwrap()
        .probe_contexts["msys2--static-files"][0];
    assert_eq!(probe["mingw_repo"], "clangarm64");
    assert_eq!(
        probe["mingw_package"],
        "mingw-w64-clang-aarch64-jq-1.8.2-1-any.pkg.tar.zst"
    );
    let plan = adapter
        .plan(
            &arm_context,
            &current,
            &[selection("https://mirrors.ustc.edu.cn/msys2")],
        )
        .unwrap();
    let msys = root().join("etc/pacman.d/mirrorlist.msys");
    let before = runtime.files[&msys].clone();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&arm_context, &mut runtime, &plan).unwrap()
    else {
        panic!("MSYS2 ARM64 mirrorlists should change")
    };
    runtime.fail_refresh = true;
    let error = adapter
        .verify(&arm_context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(runtime.files[&msys], before);

    assert!(
        adapter
            .detect(&context(Architecture::Arm64, 19_045), &runtime)
            .is_err()
    );
    runtime.files.insert(
        root().join("etc/pacman.conf"),
        b"[options]\nSigLevel = Never\n[msys]\nInclude = /etc/pacman.d/mirrorlist.msys\n[clangarm64]\nInclude = /etc/pacman.d/mirrorlist.mingw\n".to_vec(),
    );
    assert!(adapter.detect(&arm_context, &runtime).is_err());
}

#[test]
fn mingw64_subsystem_selects_its_own_repository_package() {
    let context = context(Architecture::X86_64, 26_100);
    let adapter = Msys2Adapter;
    let runtime = FakeRuntime::new("MINGW64");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts["msys2--static-files"][0];
    assert_eq!(probe["mingw_repo"], "mingw64");
    assert_eq!(
        probe["mingw_package"],
        "mingw-w64-x86_64-jq-1.8.2-1-any.pkg.tar.zst"
    );
}

#[test]
fn embedded_catalog_has_six_complete_signed_msys2_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "msys2")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::System]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "msys2" && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud", "nju", "sjtug", "tuna", "ustc"])
    );
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Windows]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Metadata)
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
            && candidate.probes.len() == 8
            && candidate.probes[2].sha256.as_deref() == Some("{msys_package_digest}")
            && candidate.probes[6].sha256.as_deref() == Some("{mingw_package_digest}")
    }));
}
