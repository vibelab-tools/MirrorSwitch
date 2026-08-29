#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{CabalAdapter, compiled_adapter_allowlist},
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

const UPSTREAM: &str = "hackage--language-registry";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/hackage/";
const PACKAGE_BODY: &[u8] = b"synthetic StateVar-1.2.2 source tarball";

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
            version_id: Some("13".into()),
            version_codename: Some("trixie".into()),
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

fn install_cabal(root: &Path, version: &str, ghc: Option<&str>, failure: &str) {
    let physical_verification = root.join("home/developer/.mirrorswitch/verification/cabal/config");
    executable(
        root,
        "/usr/bin/cabal",
        format!(
            r#"#!/bin/sh
verify='{verify}'
root='{root}'
case "$*" in
  "--numeric-version") printf '%s\n' '{version}' ;;
  "--config-file=/home/developer/.mirrorswitch/verification/cabal/config update hackage.haskell.org")
    grep -q 'repository hackage.haskell.org' "$verify" || exit 70
    grep -q 'secure: True' "$verify" || exit 71
    grep -q 'root-keys:' "$verify" || exit 81
    grep -q 'key-threshold: 3' "$verify" || exit 82
    grep -Eq 'mirrors\.(nju|tuna|ustc)' "$verify" || exit 72
    [ '{failure}' != update ] || exit 73
    printf '%s\n' 'Downloading the latest package list from hackage.haskell.org'
    ;;
  "--config-file=/home/developer/.mirrorswitch/verification/cabal/config info StateVar-1.2.2")
    grep -Eq 'mirrors\.(nju|tuna|ustc)' "$verify" || exit 74
    [ '{failure}' != info ] || exit 75
    printf '%s\n' '* StateVar' '    Versions available: 1.2.2'
    ;;
  "--config-file=/home/developer/.mirrorswitch/verification/cabal/config get StateVar-1.2.2 --destdir="*" --pristine")
    grep -Eq 'mirrors\.(nju|tuna|ustc)' "$verify" || exit 76
    [ '{failure}' != get ] || exit 77
    destination=''
    for argument in "$@"; do
      case "$argument" in --destdir=*) destination="${{argument#--destdir=}}" ;; esac
    done
    [ -n "$destination" ] || exit 78
    physical="$root$destination/StateVar-1.2.2"
    mkdir -p "$physical"
    printf '%s\n' 'name: StateVar' 'version: 1.2.2' > "$physical/StateVar.cabal"
    printf '%s\n' 'Unpacking to StateVar-1.2.2/'
    ;;
  *) exit 79 ;;
esac
"#,
            verify = physical_verification.display(),
            root = root.display(),
        ),
    );
    if let Some(version) = ghc {
        executable(
            root,
            "/usr/bin/ghc",
            format!(
                "#!/bin/sh\n[ \"$1\" = --numeric-version ] || exit 80\nprintf '%s\\n' '{version}'\n"
            ),
        );
    }
}

fn runtime(root: &Path, environment: BTreeMap<String, String>, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selection(provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("cabal-{provider}-test"),
        tool_id: "cabal".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: provider.into(),
        endpoints: [
            EndpointRole::Metadata,
            EndpointRole::Index,
            EndpointRole::Artifacts,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: endpoint.into(),
        })
        .collect(),
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn xdg_user_plan_preserves_private_security_active_and_project_state() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_cabal(root, "3.16.1.0", Some("9.12.2"), "none");
    let original = br#"-- user policy
repository hackage.haskell.org
  url: https://hackage.haskell.org/
  secure: True
  root-keys:
    1111111111111111111111111111111111111111111111111111111111111111
    2222222222222222222222222222222222222222222222222222222222222222
  key-threshold: 2

repository private.corp
  url: https://build:credential@packages.corp.example/hackage
  secure: True

active-repositories:
  :rest,
  hackage.haskell.org,
  private.corp:override
index-state: 2026-08-01T00:00:00Z
http-transport: curl
"#;
    let user = write(root, "/home/developer/.config/cabal/config", original);
    let project = br#"packages: .
active-repositories: :rest, hackage.haskell.org, private.corp:override
index-state: 2026-07-01T00:00:00Z
"#;
    let project_path = write(root, "/work/project/cabal.project", project);
    let freeze = write(
        root,
        "/work/project/cabal.project.freeze",
        b"constraints: StateVar == 1.2.2\n",
    );
    let local = write(
        root,
        "/work/project/cabal.project.local",
        b"optimization: False\n",
    );
    let adapter = CabalAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new(), Some("/work/project"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("3.16.1.0"));
    assert!(detected.evidence.iter().any(|line| line == "GHC 9.12.2"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains(".config/cabal/config"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(current.documents.len(), 5);
    assert!(!format!("{current:?}").contains("build:credential@"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(request.repository_versions[UPSTREAM], "secure");
    assert_eq!(
        request.required_endpoint_roles,
        [
            EndpointRole::Metadata,
            EndpointRole::Index,
            EndpointRole::Artifacts
        ]
    );

    let selected = [selection("tuna", TUNA)];
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(cli, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(cli.changes.len(), 2);
    assert_eq!(cli.changes[0].target, user);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("url: https://mirrors.tuna.tsinghua.edu.cn/hackage"));
    assert!(changed.contains("https://build:credential@packages.corp.example/hackage"));
    assert!(changed.contains("key-threshold: 2"));
    assert!(changed.contains("private.corp:override"));
    assert!(changed.contains("index-state: 2026-08-01T00:00:00Z"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Cabal config should change")
    };
    let verification = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(verification.valid);
    assert!(verification.summary.contains("StateVar-1.2.2"));
    let detected_after = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current_after = adapter
        .read_current(
            &context,
            &runtime,
            &detected_after,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current_after, &selected)
            .unwrap()
            .changes
            .is_empty()
    );
    let restored = adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert!(restored.restored);
    assert_eq!(fs::read(user).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/cabal/config")
            .exists()
    );
    assert_eq!(fs::read(project_path).unwrap(), project);
    assert_eq!(
        fs::read(freeze).unwrap(),
        b"constraints: StateVar == 1.2.2\n"
    );
    assert_eq!(fs::read(local).unwrap(), b"optimization: False\n");
}

#[test]
fn arm64_legacy_remote_repo_failure_restores_user_and_managed_config() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_cabal(root, "3.8.1.0", None, "info");
    let original = br#"remote-repo: hackage.haskell.org:http://hackage.haskell.org/packages/archive
remote-repo: private.corp:https://token@packages.corp.example/hackage
remote-repo-cache: /home/developer/.cabal/packages
"#;
    let user = write(root, "/home/developer/.cabal/config", original);
    let adapter = CabalAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(!format!("{current:?}").contains("token@"));
    let plan = adapter
        .plan(&context, &current, &[selection("tuna", TUNA)])
        .unwrap();
    assert_eq!(plan.changes.len(), 2);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("repository hackage.haskell.org"));
    assert!(rendered.contains("url: https://mirrors.tuna.tsinghua.edu.cn/hackage"));
    assert!(rendered.contains("secure: True"));
    assert!(rendered.contains("root-keys:"));
    assert!(rendered.contains("key-threshold: 3"));
    assert!(rendered.contains("private.corp:https://token@packages.corp.example/hackage"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("legacy config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(user).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/cabal/config")
            .exists()
    );
}

#[test]
fn versioned_config_discovery_honors_xdg_legacy_and_user_environment_paths() {
    let adapter = CabalAdapter;
    let cases = [
        (
            "3.8.1.0",
            "/home/developer/.cabal/config",
            BTreeMap::from([("CABAL_CONFIG".into(), "/etc/ignored-by-cabal-3.8".into())]),
        ),
        (
            "3.10.3.0",
            "/home/developer/.config/cabal/config",
            BTreeMap::new(),
        ),
        ("3.10.3.0", "/home/developer/.cabal/config", BTreeMap::new()),
        (
            "3.16.1.0",
            "/home/developer/custom-cabal/config",
            BTreeMap::from([("CABAL_DIR".into(), "/home/developer/custom-cabal".into())]),
        ),
        (
            "3.16.1.0",
            "/home/developer/explicit/cabal.config",
            BTreeMap::from([(
                "CABAL_CONFIG".into(),
                "/home/developer/explicit/cabal.config".into(),
            )]),
        ),
    ];
    for (version, path, environment) in cases {
        let directory = tempdir().unwrap();
        install_cabal(directory.path(), version, Some("9.8.4"), "none");
        write(
            directory.path(),
            path,
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\n  secure: True\n",
        );
        let runtime = runtime(directory.path(), environment, None);
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(
            detected.evidence.iter().any(|line| line.contains(path)),
            "{detected:?}"
        );
    }
}

#[test]
fn unsafe_security_identity_active_project_and_environment_policy_are_blocked() {
    let adapter = CabalAdapter;
    type UnsafeCase<'a> = (&'a [u8], Option<&'a [u8]>, &'a str);
    let cases: &[UnsafeCase<'_>] = &[
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\n  secure: False\n",
            None,
            "disables secure",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\n  secure: True\n  root-keys: abc\n",
            None,
            "incomplete root-keys",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\nrepository hackage.haskell.org\n  url: https://mirrors.ustc.edu.cn/hackage/\n",
            None,
            "multiple public",
        ),
        (
            b"repository private\n  url: https://packages.corp.example/hackage\n",
            None,
            "only custom",
        ),
        (
            b"repository mirror\n  url: https://hackage.haskell.org/\n  secure: True\n",
            None,
            "instead of hackage.haskell.org",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://user:secret@hackage.haskell.org/\n",
            None,
            "credential-bearing",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\nactive-repositories: :none\n",
            None,
            "excludes hackage",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\n",
            Some(b"import: https://policy.example/cabal.project\n"),
            "project import",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\n",
            Some(b"repository project\n  url: https://packages.example/hackage\n"),
            "project repository",
        ),
        (
            b"repository hackage.haskell.org\n  url: https://hackage.haskell.org/\n",
            Some(b"if(os(linux))\n  active-repositories: :none\n"),
            "conditional",
        ),
    ];
    for (user, project, expected) in cases {
        let directory = tempdir().unwrap();
        install_cabal(directory.path(), "3.16.1.0", Some("9.12.2"), "none");
        write(
            directory.path(),
            "/home/developer/.config/cabal/config",
            user,
        );
        if let Some(project) = project {
            write(directory.path(), "/work/app/cabal.project", project);
        }
        let runtime = runtime(directory.path(), BTreeMap::new(), Some("/work/app"));
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let error = adapter.detect(&context, &runtime).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }

    let directory = tempdir().unwrap();
    install_cabal(directory.path(), "3.16.1.0", None, "none");
    let runtime = runtime(
        directory.path(),
        BTreeMap::from([("CABAL_CONFIG".into(), "/etc/cabal/config".into())]),
        None,
    );
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(
        adapter
            .detect(&context, &runtime)
            .unwrap_err()
            .to_string()
            .contains("inside /home/developer")
    );
}

#[derive(Clone)]
struct CabalProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_package: bool,
}

impl CandidateProber for CabalProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let (content_type, body) = if url.ends_with("StateVar-1.2.2.tar.gz") {
            (
                Some("application/octet-stream".into()),
                if self.corrupt_package {
                    b"corrupt".to_vec()
                } else {
                    PACKAGE_BODY.to_vec()
                },
            )
        } else if url.ends_with("01-index.tar.gz") {
            (Some("application/octet-stream".into()), Vec::new())
        } else if url.ends_with("root.json") {
            (
                Some("application/json".into()),
                br#"{"signed":{"_type":"Root"}}"#.to_vec(),
            )
        } else if url.ends_with("timestamp.json") {
            (
                Some("application/json".into()),
                br#"{"signed":{"_type":"Timestamp"}}"#.to_vec(),
            )
        } else if url.ends_with("snapshot.json") {
            (
                Some("application/json".into()),
                br#"{"signed":{"_type":"Snapshot","meta":{"<repo>/01-index.tar.gz":{}}}}"#.to_vec(),
            )
        } else {
            (
                Some("application/json".into()),
                br#"{"signed":{"_type":"Mirrorlist"}}"#.to_vec(),
            )
        };
        Ok(ProbeObservation {
            status: 200,
            content_type,
            body,
            latency_ms: 1,
        })
    }
}

fn catalog_for_synthetic_package() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "cabal")
    {
        for probe in &mut candidate.probes {
            if probe.path.ends_with("StateVar-1.2.2.tar.gz") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(PACKAGE_BODY)));
            } else if probe.path == "/root.json" {
                probe.sha256 = Some(format!(
                    "{:x}",
                    Sha256::digest(br#"{"signed":{"_type":"Root"}}"#)
                ));
            }
        }
    }
    catalog
}

#[test]
fn catalog_requires_signed_metadata_index_and_tarball_sha_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let candidates = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "cabal")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "tuna", "ustc"])
    );
    for candidate in &candidates {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(candidate.compatibility.repository_versions, ["secure"]);
        assert_eq!(candidate.probes.len(), 6);
        assert_eq!(
            candidate
                .probes
                .iter()
                .find(|probe| probe.path == "/root.json")
                .unwrap()
                .sha256
                .as_deref(),
            Some("f62e46cb51d4a499a8336894d7a46071b7e528135ad71614c7102c1de0aeeabc")
        );
        assert!(
            candidate.probes.iter().any(|probe| {
                probe.method == HttpMethod::Head && probe.path == "/01-index.tar.gz"
            })
        );
        assert_eq!(
            candidate
                .probes
                .iter()
                .find(|probe| probe.path.ends_with("StateVar-1.2.2.tar.gz"))
                .unwrap()
                .sha256
                .as_deref(),
            Some("5e4b39da395656a59827b0280508aafdc70335798b50e5d6fd52596026251825")
        );
    }
    assert_eq!(
        embedded
            .tools
            .iter()
            .find(|tool| tool.id == "cabal")
            .unwrap()
            .state,
        ToolCatalogState::Supported
    );

    let catalog = catalog_for_synthetic_package();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let directory = tempdir().unwrap();
    install_cabal(directory.path(), "3.16.1.0", Some("9.12.2"), "none");
    let adapter = CabalAdapter;
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), BTreeMap::new(), None);
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
        CabalProtocolProber {
            calls: calls.clone(),
            corrupt_package: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(
        selected.actionable,
        "{selected:#?}\ncalls={:#?}",
        calls.borrow()
    );
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 18);

    let rejected = MirrorSelector::with_prober(
        &catalog,
        CabalProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_package: true,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.repositories[0].candidates.iter().all(|candidate| {
        matches!(
            &candidate.evaluation,
            CandidateEvaluation::ProbeFailed { reason } if reason.contains("SHA-256")
        )
    }));
}

#[test]
fn unsupported_platform_versions_ghc_and_missing_client_are_inert() {
    let adapter = CabalAdapter;
    let directory = tempdir().unwrap();
    install_cabal(directory.path(), "2.2.0.0", None, "none");
    let linux = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    assert!(
        adapter
            .detect(&linux, &installed)
            .unwrap_err()
            .to_string()
            .contains("2.4 through 3.16")
    );

    let directory = tempdir().unwrap();
    install_cabal(directory.path(), "3.16.1.0", Some("10.0.1"), "none");
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    let linux = context(
        directory.path(),
        Architecture::Arm64,
        ExecutionEnvironment::Container,
    );
    assert!(
        adapter
            .detect(&linux, &installed)
            .unwrap_err()
            .to_string()
            .contains("8.x/9.x")
    );

    let directory = tempdir().unwrap();
    install_cabal(directory.path(), "3.16.1.0", None, "none");
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    let mut windows = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    windows.os = OperatingSystem::Windows;
    assert!(
        adapter
            .detect(&windows, &installed)
            .unwrap_err()
            .to_string()
            .contains("Linux")
    );

    let empty = tempdir().unwrap();
    let runtime = runtime(empty.path(), BTreeMap::new(), None);
    let context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(adapter.detect(&context, &runtime).unwrap().is_none());
}
