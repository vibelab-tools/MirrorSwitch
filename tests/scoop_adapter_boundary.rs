use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
};

use mirrorswitch::{
    Adapter, AdapterError, MirrorCatalog, Runtime,
    adapters::{ScoopAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::{ChangePlan, MirrorSelection},
    transaction::{ApplyOutcome, RestoreReceipt, TransactionParticipant, TransactionReceipt},
};
use serde_json::json;

const MAIN_OFFICIAL: &str = "https://github.com/ScoopInstaller/Main.git";
const MAIN_MIRROR: &str = "https://mirrors.nju.edu.cn/git/scoop-main.git";
const EXTRAS_OFFICIAL: &str = "https://github.com/ScoopInstaller/Extras.git";
const EXTRAS_MIRROR: &str = "https://mirrors.nju.edu.cn/git/scoop-extras.git";

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

fn home() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Users\test")
    } else {
        PathBuf::from("/Users/test")
    }
}

fn context(architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Windows,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "windows".into(),
            version_id: Some("Microsoft Windows [Version 10.0.26100.6584]".into()),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: PathBuf::from("/"),
    }
}

struct FakeRuntime {
    files: BTreeMap<PathBuf, Vec<u8>>,
    buckets: Vec<(String, Option<String>)>,
    backups: BTreeMap<String, BTreeMap<PathBuf, Option<Vec<u8>>>>,
    calls: RefCell<Vec<String>>,
    fail_download: bool,
}

impl FakeRuntime {
    fn new(architecture: Architecture) -> Self {
        let home = home();
        let root = home.join("scoop");
        let config_path = home.join(".config").join("scoop").join("config.json");
        let architecture_name = match architecture {
            Architecture::X86_64 => "64bit",
            Architecture::Arm64 => "arm64",
        };
        let manifest = json!({
            "version": "1.8.2",
            "architecture": {
                "64bit": {
                    "url": "https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-windows-amd64.exe#/jq.exe",
                    "hash": "a6fc67fedaf9128a3309a1e2ebb8b986aeccf70122ee46d2cb4849e423f0c627"
                },
                "arm64": {
                    "url": "https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-windows-arm64.exe#/jq.exe",
                    "hash": "083b5377392bc57cf27052b6d20a2d927770683bca844632901ff38b4b7b0ac7"
                }
            }
        });
        let mut files = BTreeMap::from([
            (
                config_path,
                format!(
                    "{{\"default_architecture\":\"{architecture_name}\",\"proxy\":\"user:password@proxy.invalid\",\"gh_token\":\"secret\"}}"
                )
                .into_bytes(),
            ),
            (
                root.join("buckets").join("main").join(".git").join("config"),
                git_config(MAIN_OFFICIAL),
            ),
            (
                root.join("buckets").join("extras").join(".git").join("config"),
                git_config(EXTRAS_OFFICIAL),
            ),
            (
                root.join("buckets").join("main").join("bucket").join("jq.json"),
                serde_json::to_vec(&manifest).unwrap(),
            ),
        ]);
        files.insert(
            root.join("buckets")
                .join("custom-alias")
                .join(".git")
                .join("config"),
            git_config("https://user:token@private.example/bucket.git"),
        );
        Self {
            files,
            buckets: vec![
                (
                    "custom-alias".into(),
                    Some("https://user:token@private.example/bucket.git".into()),
                ),
                ("main".into(), None),
                ("extras".into(), None),
            ],
            backups: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
            fail_download: false,
        }
    }

    fn bucket_source(&self, name: &str, custom: &Option<String>) -> String {
        if let Some(source) = custom {
            return source.clone();
        }
        let config = home()
            .join("scoop")
            .join("buckets")
            .join(name)
            .join(".git")
            .join("config");
        let text = String::from_utf8_lossy(&self.files[&config]);
        text.lines()
            .find_map(|line| line.trim().strip_prefix("url = "))
            .unwrap()
            .into()
    }
}

impl Runtime for FakeRuntime {
    fn command_exists(&self, command: &str) -> bool {
        matches!(command, "scoop" | "powershell" | "git")
    }

    fn home_dir(&self) -> Option<PathBuf> {
        Some(home())
    }

    fn environment_variable(&self, _name: &str) -> Option<String> {
        None
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(self.files.get(path).cloned())
    }

    fn run(&self, program: &str, arguments: &[String]) -> Result<Output, AdapterError> {
        self.calls
            .borrow_mut()
            .push(format!("{program} {}", arguments.join(" ")));
        match (program, arguments.first().map(String::as_str)) {
            ("scoop", Some("--version")) => {
                Ok(output(0, "Current Scoop version:\r\nv0.5.3 - fixture\r\n"))
            }
            ("powershell", _) => {
                let values = self
                    .buckets
                    .iter()
                    .map(|(name, custom)| {
                        json!({"name": name, "source": self.bucket_source(name, custom)})
                    })
                    .collect::<Vec<_>>();
                Ok(output(0, serde_json::to_vec(&values).unwrap()))
            }
            ("git", Some("-C")) => Ok(output(
                0,
                "0123456789012345678901234567890123456789\tHEAD\r\n",
            )),
            ("scoop", Some("search")) => Ok(output(0, "main/jq 1.8.2\r\n")),
            ("scoop", Some("download")) => Ok(output(
                i32::from(self.fail_download),
                "jq was downloaded successfully\r\n",
            )),
            _ => Err(AdapterError::Runtime(format!(
                "unexpected command {program} {}",
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
        let transaction_id = format!("scoop-{}", self.backups.len() + 1);
        self.backups.insert(transaction_id.clone(), backup);
        Ok(ApplyOutcome::Applied(TransactionReceipt {
            transaction_id,
            participants: vec![TransactionParticipant {
                adapter_key: "scoop".into(),
                tool_id: "scoop".into(),
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
            .ok_or_else(|| AdapterError::Runtime("unknown Scoop test transaction".into()))?;
        for (path, contents) in &backup {
            match contents {
                Some(contents) => {
                    self.files.insert(path.clone(), contents.clone());
                }
                None => {
                    self.files.remove(path);
                }
            }
        }
        Ok(RestoreReceipt {
            transaction_id: transaction_id.into(),
            restored_files: backup.len(),
            verified: true,
        })
    }
}

fn git_config(url: &str) -> Vec<u8> {
    format!(
        "[core]\r\n\trepositoryformatversion = 0\r\n[remote \"origin\"]\r\n\turl = {url}\r\n\tfetch = +refs/heads/*:refs/remotes/origin/*\r\n"
    )
    .into_bytes()
}

fn selection(upstream: &str, url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("scoop-{upstream}"),
        tool_id: "scoop".into(),
        upstream_id: upstream.into(),
        provider_id: "nju".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Git,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn x64_plan_preserves_custom_bucket_alias_order_config_and_is_reversible() {
    let context = context(Architecture::X86_64);
    let adapter = ScoopAdapter;
    let mut runtime = FakeRuntime::new(Architecture::X86_64);
    let config_path = home().join(".config").join("scoop").join("config.json");
    let config_before = runtime.files[&config_path].clone();
    let main_config = home().join("scoop/buckets/main/.git/config");
    let extras_config = home().join("scoop/buckets/extras/.git/config");
    let main_before = runtime.files[&main_config].clone();
    let extras_before = runtime.files[&extras_config].clone();

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("0.5.3"));
    assert!(
        detected
            .evidence
            .iter()
            .all(|item| !item.contains("secret"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(current.documents.len(), 2);
    assert_eq!(current.sources[0].url, "redacted://custom-scoop-bucket");
    assert_eq!(current.sources[0].metadata["alias"], ["custom-alias"]);
    let main = current
        .sources
        .iter()
        .find(|source| {
            source
                .metadata
                .get("bucket_id")
                .is_some_and(|values| values == &["main"])
        })
        .unwrap();
    assert_eq!(main.metadata["architecture"], ["64bit"]);
    assert_eq!(main.metadata["manifest_version"], ["1.8.2"]);
    assert!(main.metadata["asset_url"][0].contains("jq-windows-amd64.exe"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        ["scoop-extras--git-mirror", "scoop-main--git-mirror"]
    );
    let choices = [
        selection("scoop-main--git-mirror", MAIN_MIRROR),
        selection("scoop-extras--git-mirror", EXTRAS_MIRROR),
    ];
    let plan = adapter.plan(&context, &current, &choices).unwrap();
    assert_eq!(plan.changes.len(), 2);
    assert!(!plan.requires_elevation);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Scoop bucket origins should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        runtime
            .calls
            .borrow()
            .iter()
            .any(|call| call.contains("scoop download --no-update-scoop --arch 64bit jq"))
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &choices)
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
    assert_eq!(runtime.files[&main_config], main_before);
    assert_eq!(runtime.files[&extras_config], extras_before);
    assert_eq!(runtime.files[&config_path], config_before);
}

#[test]
fn arm64_download_failure_restores_and_architecture_policy_is_enforced() {
    let context = context(Architecture::Arm64);
    let adapter = ScoopAdapter;
    let mut runtime = FakeRuntime::new(Architecture::Arm64);
    runtime.buckets.retain(|(name, _)| name != "extras");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let main = current
        .sources
        .iter()
        .find(|source| source.upstream_id.is_some())
        .unwrap();
    assert!(main.metadata["asset_url"][0].contains("jq-windows-arm64.exe"));
    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection("scoop-main--git-mirror", MAIN_MIRROR)],
        )
        .unwrap();
    let main_config = home().join("scoop/buckets/main/.git/config");
    let before = runtime.files[&main_config].clone();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Scoop main bucket should change")
    };
    runtime.fail_download = true;
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(runtime.files[&main_config], before);

    let config_path = home().join(".config").join("scoop").join("config.json");
    runtime
        .files
        .insert(config_path, br#"{"default_architecture":"64bit"}"#.to_vec());
    assert!(adapter.detect(&context, &runtime).is_err());
}

#[test]
fn embedded_catalog_has_seven_nju_bucket_candidates_and_keeps_core_partial() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "scoop")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "scoop")
        .collect::<Vec<_>>();
    let actionable = candidates
        .iter()
        .filter(|candidate| candidate.delivery_mode == DeliveryMode::Mirror)
        .collect::<Vec<_>>();
    assert_eq!(actionable.len(), 7);
    assert!(actionable.iter().all(|candidate| {
        candidate.provider_id == "nju"
            && candidate.compatibility.operating_systems == [OperatingSystem::Windows]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints[0].role == EndpointRole::Git
            && candidate.probes.len() == 2
            && candidate.probes[0].path == "/HEAD"
            && candidate.probes[1].path == "/objects/info/packs"
    }));
    assert_eq!(
        actionable
            .iter()
            .map(|candidate| candidate.upstream_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "scoop-extras--git-mirror",
            "scoop-java--git-mirror",
            "scoop-main--git-mirror",
            "scoop-nerd-fonts--git-mirror",
            "scoop-nirsoft--git-mirror",
            "scoop-nonportable--git-mirror",
            "scoop-versions--git-mirror",
        ])
    );
    assert!(candidates.iter().any(|candidate| {
        candidate.upstream_id == "scoop--git-mirror"
            && candidate.delivery_mode != DeliveryMode::Mirror
    }));
}
