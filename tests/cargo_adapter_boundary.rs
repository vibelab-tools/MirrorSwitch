#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{CargoAdapter, compiled_adapter_allowlist},
    catalog::{
        CandidateEvaluation, ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod,
        Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const SPARSE_UPSTREAM: &str = "crates.io-index--language-registry";
const GIT_UPSTREAM: &str = "crates.io-index--git-mirror";
const ALIYUN_INDEX: &str = "https://mirrors.aliyun.com/crates.io-index/";
const ALIYUN_CRATES: &str = "https://mirrors.aliyun.com/crates/api/v1/crates/";
const USTC_INDEX: &str = "https://mirrors.ustc.edu.cn/crates.io-index/";
const USTC_CRATES: &str = "https://mirrors.ustc.edu.cn/crates.io/api/v1/crates/";
const ARTIFACT_BODY: &[u8] = b"reviewed synthetic crate payload";
const CRATE_SHA256: &str = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682";

fn context(
    root: &Path,
    architecture: Architecture,
    environment: ExecutionEnvironment,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
        distribution: Some(Distribution {
            id: "debian".into(),
            version_id: Some("12".into()),
            version_codename: Some("bookworm".into()),
            id_like: Vec::new(),
        }),
        root: root.to_path_buf(),
    }
}

fn write(root: &Path, path: &str, contents: &[u8]) -> PathBuf {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn executable(root: &Path, path: &str, contents: String) {
    let path = write(root, path, contents.as_bytes());
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn install_cargo(
    root: &Path,
    version: &str,
    user_config: Option<&[u8]>,
    info_exit: i32,
) -> PathBuf {
    let physical_config = root.join("home/developer/.cargo/config.toml");
    if let Some(contents) = user_config {
        write(root, "/home/developer/.cargo/config.toml", contents);
    }
    executable(
        root,
        "/usr/bin/cargo",
        format!(
            r#"#!/bin/sh
config='{physical_config}'
case "$*" in
  "--version") printf '%s\n' 'cargo {version} (test 2026-08-29)' ;;
  "info itoa@1.0.18 --registry crates-io --verbose --color never")
    [ -f "$config" ] || exit 70
    grep -Eq 'sparse\+https://(mirrors\.aliyun\.com|mirrors\.nju\.edu\.cn|mirrors\.ustc\.edu\.cn)/crates\.io-index/' "$config" || exit 71
    [ {info_exit} -eq 0 ] || exit {info_exit}
    printf '%s\n' 'itoa #integer' 'version: 1.0.18' 'rust-version: 1.36'
    ;;
  *) exit 72 ;;
esac
"#,
            physical_config = physical_config.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/rustc",
        r#"#!/bin/sh
case "$*" in
  "--version") printf '%s\n' 'rustc 1.95.0 (test 2026-08-29)' ;;
  *) exit 73 ;;
esac
"#
        .into(),
    );
    physical_config
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection(index: &str, crates: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "cargo-sparse-test".into(),
        tool_id: "cargo".into(),
        upstream_id: SPARSE_UPSTREAM.into(),
        provider_id: if index.contains("aliyun") {
            "aliyun"
        } else {
            "ustc"
        }
        .into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: index.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: crates.into(),
            },
        ],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_mapping_preserves_private_registries_project_policy_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let original = br#"[source.crates-io]
replace-with = "china"

[source.china]
registry = "sparse+https://index.crates.io/"

[source.corp]
registry = "sparse+https://cargo.corp.example/index/"

[registries.corp]
index = "sparse+https://cargo.corp.example/index/"
token = "private-token"

[net]
git-fetch-with-cli = true
"#;
    let config = install_cargo(root, "1.95.0", Some(original), 0);
    write(
        root,
        "/work/project/.cargo/config.toml",
        br#"[source.project-private]
registry = "sparse+https://project.corp.example/index/"

[registries.project-private]
index = "sparse+https://project.corp.example/index/"
"#,
    );
    let adapter = CargoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.95.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Rust 1.95.0"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("protocol is sparse"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        current
            .sources
            .iter()
            .any(|source| source.url == "sparse+https://cargo.corp.example/index/")
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [SPARSE_UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Index, EndpointRole::Artifacts]
    );
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Mirror]);

    let chosen = [selection(ALIYUN_INDEX, ALIYUN_CRATES)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config_plan);
    assert_eq!(config_plan, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("replace-with = \"china\""));
    assert!(rendered.contains("registry = \"sparse+https://mirrors.aliyun.com/crates.io-index/\""));
    assert!(rendered.contains("sparse+https://cargo.corp.example/index/"));
    assert!(rendered.contains("token = \"private-token\""));
    assert!(rendered.contains("git-fetch-with-cli = true"));
    assert!(!format!("{cli:?}").contains("private-token"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Cargo config should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &chosen)
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
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn arm64_implicit_default_creates_only_the_user_sparse_mapping() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let config = install_cargo(root, "1.95.0", Some(b"[build]\njobs = 4\n"), 0);
    let adapter = CargoAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(USTC_INDEX, USTC_CRATES)])
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("[build]\njobs = 4"));
    assert!(rendered.contains("[source.crates-io]"));
    assert!(rendered.contains("replace-with = \"mirrorswitch-crates-io\""));
    assert!(rendered.contains("[source.mirrorswitch-crates-io]"));
    assert!(rendered.contains("sparse+https://mirrors.ustc.edu.cn/crates.io-index/"));
    assert_eq!(plan.changes[0].target, config);
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::Project,)
            .unwrap_err()
            .to_string()
            .contains("only the user")
    );
}

#[test]
fn project_environment_offline_include_and_private_replacements_are_blocked() {
    type PolicyCase<'a> = (
        &'a [u8],
        Option<&'a [u8]>,
        BTreeMap<String, String>,
        &'a str,
    );
    let cases: Vec<PolicyCase<'_>> = vec![
        (
            b"",
            Some(b"[source.crates-io]\nreplace-with = \"project\"\n[source.project]\nregistry = \"sparse+https://project.example/index/\"\n"),
            BTreeMap::new(),
            "project configuration",
        ),
        (
            b"",
            None,
            BTreeMap::from([(
                "CARGO_REGISTRIES_CRATES_IO_PROTOCOL".into(),
                "git".into(),
            )]),
            "overrides persistent",
        ),
        (
            b"",
            None,
            BTreeMap::from([(
                "CARGO_REGISTRIES_CRATES_IO_INDEX".into(),
                "https://cargo.example/index".into(),
            )]),
            "overrides persistent",
        ),
        (
            b"[net]\noffline = true\n",
            None,
            BTreeMap::new(),
            "offline mode",
        ),
        (
            b"include = [\"extra.toml\"]\n",
            None,
            BTreeMap::new(),
            "include configuration",
        ),
        (
            b"[source.crates-io]\nreplace-with = \"corp\"\n[source.corp]\nregistry = \"sparse+https://cargo.corp.example/index/\"\n",
            None,
            BTreeMap::new(),
            "private or unknown",
        ),
    ];
    let adapter = CargoAdapter;
    for (user, project, environment, expected) in cases {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_cargo(root, "1.95.0", Some(user), 0);
        if let Some(project) = project {
            write(root, "/work/project/.cargo/config.toml", project);
        }
        let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
        let runtime = runtime(root, environment);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let error = adapter
            .selection_request(&context, &detected, &current)
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn extensionless_user_config_wins_without_touching_config_toml() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let modern = install_cargo(
        root,
        "1.95.0",
        Some(b"[source.crates-io]\nreplace-with = \"modern\"\n"),
        0,
    );
    let legacy_contents = b"[source.crates-io]\nreplace-with = \"legacy\"\n[source.legacy]\nregistry = \"sparse+https://index.crates.io/\"\n";
    let legacy = write(root, "/home/developer/.cargo/config", legacy_contents);
    let adapter = CargoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection(ALIYUN_INDEX, ALIYUN_CRATES)],
        )
        .unwrap();
    assert_eq!(plan.changes[0].target, legacy);
    assert_eq!(
        fs::read(modern).unwrap(),
        b"[source.crates-io]\nreplace-with = \"modern\"\n"
    );
}

#[derive(Clone)]
struct CargoProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_artifact: bool,
}

impl CandidateProber for CargoProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let (content_type, body) = if url.ends_with("config.json") {
            (
                Some("application/json".into()),
                br#"{"dl":"https://mirror.example/crates"}"#.to_vec(),
            )
        } else if url.contains("/it/oa/itoa") {
            (None, CRATE_SHA256.as_bytes().to_vec())
        } else if self.corrupt_artifact {
            (None, b"corrupt".to_vec())
        } else {
            (None, ARTIFACT_BODY.to_vec())
        };
        Ok(ProbeObservation {
            status: 200,
            content_type,
            body,
            latency_ms: 1,
        })
    }
}

fn catalog_for_synthetic_artifact() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let digest = format!("{:x}", Sha256::digest(ARTIFACT_BODY));
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "cargo")
    {
        for probe in &mut candidate.probes {
            if probe.endpoint_role == EndpointRole::Artifacts {
                probe.sha256 = Some(digest.clone());
            }
        }
    }
    catalog
}

#[test]
fn sparse_catalog_checks_index_entry_download_and_checksum_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let artifact_probes = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "cargo")
        .flat_map(|candidate| &candidate.probes)
        .filter(|probe| probe.endpoint_role == EndpointRole::Artifacts)
        .collect::<Vec<_>>();
    assert_eq!(artifact_probes.len(), 3);
    assert!(
        artifact_probes
            .iter()
            .all(|probe| probe.sha256.as_deref() == Some(CRATE_SHA256))
    );

    let catalog = catalog_for_synthetic_artifact();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "cargo")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let actionable = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "cargo" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    let mut providers = actionable
        .iter()
        .map(|candidate| candidate.provider_id.as_str())
        .collect::<Vec<_>>();
    providers.sort_unstable();
    assert_eq!(providers, ["aliyun", "nju", "ustc"]);
    for candidate in actionable {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(candidate.endpoints.len(), 2);
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| { probe.path == "/config.json" && probe.method == HttpMethod::Get })
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.path == "/it/oa/itoa")
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.endpoint_role == EndpointRole::Artifacts)
        );
    }

    let adapter = CargoAdapter;
    let directory = tempdir().unwrap();
    install_cargo(directory.path(), "1.95.0", Some(b""), 0);
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let selected = MirrorSelector::with_prober(
        &catalog,
        CargoProtocolProber {
            calls: calls.clone(),
            corrupt_artifact: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable);
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 9);

    let rejected = MirrorSelector::with_prober(
        &catalog,
        CargoProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_artifact: true,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.repositories[0].candidates.iter().any(|candidate| {
        matches!(
            &candidate.evaluation,
            CandidateEvaluation::ProbeFailed { reason } if reason.contains("SHA-256")
        )
    }));
}

#[derive(Clone, Copy)]
struct NoopProber;

impl CandidateProber for NoopProber {
    fn probe(
        &self,
        _method: HttpMethod,
        _url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        panic!("incomplete git candidates must not reach network probing")
    }
}

#[test]
fn cargo_167_requests_git_but_no_incomplete_candidate_can_change_config() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_cargo(root, "1.67.1", Some(b""), 0);
    let adapter = CargoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [GIT_UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Git, EndpointRole::Artifacts]
    );
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let outcome = MirrorSelector::with_prober(&catalog, NoopProber, ProbeLimits::default())
        .select_at(&request, 100)
        .unwrap();
    assert!(!outcome.actionable);
    assert!(outcome.selections.is_empty());
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &[selection(ALIYUN_INDEX, ALIYUN_CRATES)],
            )
            .unwrap_err()
            .to_string()
            .contains("upgraded to 1.68+")
    );
}

#[test]
fn failed_cargo_info_restores_the_original_user_config() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let original = b"[build]\njobs = 2\n";
    let config = install_cargo(root, "1.95.0", Some(original), 74);
    let adapter = CargoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection(ALIYUN_INDEX, ALIYUN_CRATES)],
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Cargo config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn unsupported_platform_version_and_missing_rustc_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_cargo(root, "1.38.0", Some(b""), 0);
    let adapter = CargoAdapter;
    let supported_context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let installed_runtime = runtime(root, BTreeMap::new());
    assert!(
        adapter
            .detect(&supported_context, &installed_runtime)
            .unwrap_err()
            .to_string()
            .contains("1.39+")
    );

    let mut windows = supported_context.clone();
    windows.os = OperatingSystem::Windows;
    assert!(
        adapter
            .detect(&windows, &installed_runtime)
            .unwrap_err()
            .to_string()
            .contains("Linux")
    );

    let empty = tempdir().unwrap();
    let runtime = runtime(empty.path(), BTreeMap::new());
    let context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(adapter.detect(&context, &runtime).unwrap().is_none());
}
