use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
};

use mirrorswitch::{
    Adapter, AdapterError, MirrorCatalog, Runtime,
    adapters::{WinGetAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    frontend::restore_execution,
    plan::ChangePlan,
    transaction::{ApplyOutcome, RestoreReceipt, TransactionParticipant, TransactionReceipt},
};
use serde_json::{Value, json};

const OFFICIAL: &str = "https://cdn.winget.microsoft.com/cache";
const USTC: &str = "https://mirrors.ustc.edu.cn/winget-source";

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

fn local_data() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Users\test\AppData\Local")
    } else {
        PathBuf::from("/Users/test/AppData/Local")
    }
}

fn temp_dir() -> PathBuf {
    local_data().join("Temp")
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

fn source(
    name: &str,
    source_type: &str,
    argument: &str,
    trust: &[&str],
    explicit: Option<bool>,
    priority: Option<u32>,
) -> Value {
    json!({
        "Name": name,
        "Type": source_type,
        "Arg": argument,
        "Data": if name == "winget" { "Microsoft.Winget.Source_8wekyb3d8bbwe" } else { "" },
        "Identifier": if name == "winget" { "Microsoft.Winget.Source_8wekyb3d8bbwe" } else { name },
        "TrustLevel": trust,
        "Explicit": explicit,
        "Priority": priority,
    })
}

struct FakeRuntime {
    version: String,
    sources: RefCell<Vec<Value>>,
    files: BTreeMap<PathBuf, Vec<u8>>,
    backups: BTreeMap<String, BTreeMap<PathBuf, Option<Vec<u8>>>>,
    receipts: RefCell<BTreeMap<String, TransactionReceipt>>,
    calls: RefCell<Vec<String>>,
    fail_download: Cell<bool>,
    stale_remove_once: Cell<bool>,
}

impl FakeRuntime {
    fn new(version: &str) -> Self {
        Self {
            version: version.into(),
            sources: RefCell::new(vec![
                source(
                    "winget",
                    "Microsoft.PreIndexed.Package",
                    OFFICIAL,
                    &["none"],
                    Some(false),
                    Some(7),
                ),
                source(
                    "msstore",
                    "Microsoft.Rest",
                    "https://storeedgefd.dsx.mp.microsoft.com/v9.0",
                    &["trusted"],
                    None,
                    None,
                ),
                source(
                    "private",
                    "Microsoft.Rest",
                    "https://user:token@private.example/api",
                    &["trusted"],
                    Some(true),
                    Some(1),
                ),
            ]),
            files: BTreeMap::new(),
            backups: BTreeMap::new(),
            receipts: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
            fail_download: Cell::new(false),
            stale_remove_once: Cell::new(false),
        }
    }

    fn source_argument(&self, name: &str) -> Option<String> {
        self.sources
            .borrow()
            .iter()
            .find(|source| source["Name"].as_str() == Some(name))
            .and_then(|source| source["Arg"].as_str())
            .map(str::to_owned)
    }
}

impl Runtime for FakeRuntime {
    fn command_exists(&self, command: &str) -> bool {
        matches!(command, "winget" | "powershell")
    }

    fn environment_variable(&self, name: &str) -> Option<String> {
        match name {
            "LOCALAPPDATA" => Some(local_data().display().to_string()),
            "TEMP" => Some(temp_dir().display().to_string()),
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
        if program == "powershell" {
            return Ok(output(0, Vec::new()));
        }
        if program != "winget" {
            return Err(AdapterError::Runtime(format!(
                "unexpected WinGet test command {program}"
            )));
        }
        if arguments == ["--version"] {
            return Ok(output(0, format!("v{}\r\n", self.version)));
        }
        if arguments.starts_with(&["source".into(), "export".into()]) {
            let mut bytes = Vec::new();
            for source in self.sources.borrow().iter() {
                bytes.extend(serde_json::to_vec(source).unwrap());
                bytes.extend(b"\r\n");
            }
            return Ok(output(0, bytes));
        }
        if arguments.starts_with(&["source".into(), "remove".into()]) {
            if self.stale_remove_once.replace(false) {
                return Ok(output(0, Vec::new()));
            }
            self.sources
                .borrow_mut()
                .retain(|source| source["Name"].as_str() != Some("winget"));
            return Ok(output(0, Vec::new()));
        }
        if arguments.starts_with(&["source".into(), "add".into()]) {
            if self.source_argument("winget").is_some() {
                return Err(AdapterError::Runtime(
                    "winget source add failed with status exit code: 0x8a15000c".into(),
                ));
            }
            let argument = option(arguments, "--arg").unwrap();
            let trusted = option(arguments, "--trust-level").is_some();
            self.sources.borrow_mut().insert(
                0,
                source(
                    "winget",
                    "Microsoft.PreIndexed.Package",
                    argument,
                    if trusted { &["trusted"] } else { &["none"] },
                    Some(false),
                    Some(0),
                ),
            );
            return Ok(output(0, Vec::new()));
        }
        if arguments.starts_with(&["source".into(), "edit".into()]) {
            let mut sources = self.sources.borrow_mut();
            let winget = sources
                .iter_mut()
                .find(|source| source["Name"].as_str() == Some("winget"))
                .unwrap();
            if let Some(priority) = option(arguments, "--priority") {
                winget["Priority"] = json!(priority.parse::<u32>().unwrap());
            }
            if let Some(explicit) = option(arguments, "--explicit") {
                winget["Explicit"] = json!(explicit.parse::<bool>().unwrap());
            }
            return Ok(output(0, Vec::new()));
        }
        if arguments
            .first()
            .is_some_and(|value| matches!(value.as_str(), "search" | "show"))
            || arguments.starts_with(&["source".into(), "update".into()])
        {
            return Ok(output(0, Vec::new()));
        }
        if arguments.first().is_some_and(|value| value == "download") {
            return Ok(output(i32::from(self.fail_download.get()), Vec::new()));
        }
        Err(AdapterError::Runtime(format!(
            "unexpected winget arguments {}",
            arguments.join(" ")
        )))
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
        let transaction_id = format!("winget-{}", self.backups.len() + 1);
        self.backups.insert(transaction_id.clone(), backup);
        let receipt = TransactionReceipt {
            transaction_id: transaction_id.clone(),
            participants: vec![TransactionParticipant {
                adapter_key: "winget".into(),
                tool_id: "winget".into(),
            }],
            changed_files: plan.changes.len(),
            changed_targets: plan
                .changes
                .iter()
                .map(|change| change.target.clone())
                .collect(),
        };
        self.receipts
            .borrow_mut()
            .insert(transaction_id, receipt.clone());
        Ok(ApplyOutcome::Applied(receipt))
    }

    fn transaction_receipt(
        &self,
        transaction_id: &str,
    ) -> Result<TransactionReceipt, AdapterError> {
        self.receipts
            .borrow()
            .get(transaction_id)
            .cloned()
            .ok_or_else(|| AdapterError::Runtime("WinGet transaction is not applied".into()))
    }

    fn restore_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<RestoreReceipt, AdapterError> {
        let backup = self
            .backups
            .get(transaction_id)
            .cloned()
            .ok_or_else(|| AdapterError::Runtime("unknown WinGet test transaction".into()))?;
        for (path, contents) in &backup {
            if let Some(contents) = contents {
                self.files.insert(path.clone(), contents.clone());
            } else {
                self.files.remove(path);
            }
        }
        self.receipts.borrow_mut().remove(transaction_id);
        Ok(RestoreReceipt {
            transaction_id: transaction_id.into(),
            restored_files: backup.len(),
            verified: true,
        })
    }
}

fn option<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
}

fn selection(url: &str) -> mirrorswitch::plan::MirrorSelection {
    mirrorswitch::plan::MirrorSelection {
        candidate_id: "winget-test".into(),
        tool_id: "winget".into(),
        upstream_id: "winget-source--static-files".into(),
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
fn x64_command_state_apply_verify_and_explicit_restore_preserve_other_sources() {
    let context = context(Architecture::X86_64, 26_100);
    let adapter = WinGetAdapter;
    let mut runtime = FakeRuntime::new("1.12.350");
    let original_sources = runtime.sources.borrow().clone();
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(current.sources.len(), 3);
    assert!(current.sources.iter().any(|source| {
        source.url == "redacted://custom-winget-source"
            && source.metadata["kind"] == ["custom-read-only"]
    }));
    let community = current
        .sources
        .iter()
        .find(|source| source.upstream_id.is_some())
        .unwrap();
    assert_eq!(community.metadata["winget_arch"], ["x64"]);
    assert_eq!(community.metadata["priority"], ["7"]);
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts["winget-source--static-files"][0]["winget_installer_hash"],
        "A6FC67FEDAF9128A3309A1E2EBB8B986AECCF70122EE46D2CB4849E423F0C627"
    );
    let plan = adapter
        .plan(&context, &current, &[selection(USTC)])
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(plan.requires_elevation);
    assert!(!String::from_utf8_lossy(&plan.changes[0].new_contents).contains("private.example"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("WinGet command-state plan should apply")
    };
    assert_eq!(runtime.source_argument("winget").as_deref(), Some(USTC));
    assert!(
        runtime
            .calls
            .borrow()
            .iter()
            .any(|call| call.contains("source add") && call.contains("--trust-level trusted"))
    );
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(runtime.calls.borrow().iter().any(|call| {
        call.contains("powershell") && call.contains("New-Item -ItemType Directory -Force -Path")
    }));
    assert!(
        runtime
            .calls
            .borrow()
            .iter()
            .any(|call| call.contains("download") && call.contains("--architecture x64"))
    );
    runtime.stale_remove_once.set(true);
    let report =
        restore_execution(&context, &receipt.transaction_id, &[&adapter], &mut runtime).unwrap();
    assert!(report.receipt.verified);
    assert_eq!(*runtime.sources.borrow(), original_sources);
    assert!(!runtime.files.contains_key(&plan.changes[0].target));
}

#[test]
fn arm64_download_failure_restores_source_and_private_recovery_file() {
    let context = context(Architecture::Arm64, 26_100);
    let adapter = WinGetAdapter;
    let mut runtime = FakeRuntime::new("1.12.350");
    let original_sources = runtime.sources.borrow().clone();
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let community = current
        .sources
        .iter()
        .find(|source| source.upstream_id.is_some())
        .unwrap();
    assert_eq!(community.metadata["winget_arch"], ["arm64"]);
    let plan = adapter
        .plan(&context, &current, &[selection(USTC)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("WinGet ARM64 plan should apply")
    };
    runtime.fail_download.set(true);
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("source restored: true"));
    assert!(error.to_string().contains("recovery file restored: true"));
    assert_eq!(*runtime.sources.borrow(), original_sources);
    assert!(!runtime.files.contains_key(&plan.changes[0].target));
}

#[test]
fn winget_17_omits_trust_flag_and_old_windows_is_rejected() {
    let win_context = context(Architecture::X86_64, 19_045);
    let adapter = WinGetAdapter;
    let mut runtime = FakeRuntime::new("1.7.11261");
    for source in runtime.sources.get_mut() {
        source["Explicit"] = Value::Null;
        source["Priority"] = Value::Null;
    }
    let detected = adapter.detect(&win_context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &win_context,
            &runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    let plan = adapter
        .plan(&win_context, &current, &[selection(USTC)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&win_context, &mut runtime, &plan).unwrap()
    else {
        panic!("WinGet 1.7 plan should apply")
    };
    assert!(
        runtime
            .calls
            .borrow()
            .iter()
            .filter(|call| call.contains("source add"))
            .all(|call| !call.contains("--trust-level"))
    );
    adapter
        .restore(&win_context, &mut runtime, &receipt)
        .unwrap();
    assert!(
        adapter
            .detect(&context(Architecture::X86_64, 17_000), &runtime)
            .is_err()
    );
}

#[test]
fn embedded_catalog_has_two_preindexed_source_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "winget")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::System]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "winget" && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "ustc"])
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
            && candidate.probes.len() == 6
            && candidate.probes[0].path == "/source.msix"
            && candidate.probes[1].path == "/source2.msix"
            && candidate.probes[4].contains.as_deref()
                == Some("InstallerSha256: {winget_installer_hash}")
    }));
}
