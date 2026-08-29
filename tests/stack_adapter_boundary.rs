#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{StackAdapter, compiled_adapter_allowlist},
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

const STACKAGE: &str = "stackage--language-registry";
const HACKAGE: &str = "hackage--language-registry";
const USTC_INDEX: &str = "https://mirrors.ustc.edu.cn/stackage/";
const USTC_METADATA: &str = "https://mirrors.ustc.edu.cn/stackage/stackage-content/stack/";
const USTC_ARTIFACTS: &str = "https://mirrors.ustc.edu.cn/stackage/";
const TUNA_HACKAGE: &str = "https://mirrors.tuna.tsinghua.edu.cn/hackage/";

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
            id: "ubuntu".into(),
            version_id: Some("24.04".into()),
            version_codename: Some("noble".into()),
            id_like: vec!["debian".into()],
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

fn install_stack(root: &Path, version: &str, failure: &str) {
    executable(
        root,
        "/usr/bin/env",
        format!(
            r#"#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    *=*) export "$1"; shift ;;
    *) break ;;
  esac
done
[ "$1" = stack ] || exit 90
shift
exec '{root}/usr/bin/stack' "$@"
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/stack",
        format!(
            r#"#!/bin/sh
root='{root}'
if [ "$1" = --numeric-version ]; then
  printf '%s\n' '{version}'
  exit 0
fi
config="${{STACK_CONFIG:-}}"
project="${{STACK_YAML:-}}"
destination=''
previous=''
for argument in "$@"; do
  case "$previous" in
    --stack-global-config) config="$argument" ;;
    --stack-yaml) project="$argument" ;;
    --to) destination="$argument" ;;
  esac
  previous="$argument"
done
[ -n "$config" ] || exit 70
[ -n "$project" ] || exit 71
physical_config="$root$config"
physical_project="$root$project"
grep -q 'latest-snapshot: https://mirrors.ustc.edu.cn/stackage/snapshots.json' "$physical_config" || exit 72
grep -q 'global-hints.yaml' "$physical_config" || exit 73
grep -q 'stack-setup.yaml' "$physical_config" || exit 74
grep -q 'download-prefix: https://mirrors.tuna.tsinghua.edu.cn/hackage/' "$physical_config" || exit 75
grep -q 'snapshot: lts-22.43' "$physical_project" || exit 76
case " $* " in
  *" ls dependencies --global-hints "*)
    [ '{failure}' != query ] || exit 77
    printf '%s\n' 'StateVar 1.2.2' 'base 4.18.2.1' 'mirrorswitch-stack-verification 0.0.0'
    ;;
  *" unpack StateVar-1.2.2 "*)
    [ '{failure}' != unpack ] || exit 78
    [ -n "$destination" ] || exit 79
    physical="$root$destination/StateVar-1.2.2"
    mkdir -p "$physical"
    printf '%s\n' 'name: StateVar' 'version: 1.2.2' > "$physical/StateVar.cabal"
    printf '%s\n' 'Unpacked StateVar-1.2.2'
    ;;
  *) exit 80 ;;
esac
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selections() -> Vec<MirrorSelection> {
    vec![
        MirrorSelection {
            candidate_id: "stack-ustc-test".into(),
            tool_id: "stack".into(),
            upstream_id: STACKAGE.into(),
            provider_id: "ustc".into(),
            endpoints: vec![
                Endpoint {
                    role: EndpointRole::Index,
                    protocol: Protocol::Https,
                    url: USTC_INDEX.into(),
                },
                Endpoint {
                    role: EndpointRole::Metadata,
                    protocol: Protocol::Https,
                    url: USTC_METADATA.into(),
                },
                Endpoint {
                    role: EndpointRole::Artifacts,
                    protocol: Protocol::Https,
                    url: USTC_ARTIFACTS.into(),
                },
            ],
            latency_ms: 3,
            selected_at_unix_ms: 100,
            user_override: false,
        },
        MirrorSelection {
            candidate_id: "stack-tuna-hackage-test".into(),
            tool_id: "stack".into(),
            upstream_id: HACKAGE.into(),
            provider_id: "tuna".into(),
            endpoints: [
                EndpointRole::Metadata,
                EndpointRole::Index,
                EndpointRole::Artifacts,
            ]
            .into_iter()
            .map(|role| Endpoint {
                role,
                protocol: Protocol::Https,
                url: TUNA_HACKAGE.into(),
            })
            .collect(),
            latency_ms: 2,
            selected_at_unix_ms: 100,
            user_override: false,
        },
    ]
}

#[test]
fn user_scope_preserves_project_private_and_security_state_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_stack(root, "3.11.1", "none");
    write(
        root,
        "/etc/stack/config.yaml",
        b"# system policy\nconnection-count: 4\n",
    );
    let original = br#"# user policy
urls:
  latest-snapshot: "https://www.stackage.org/snapshots" # keep comment
snapshot-location-base: https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/
package-index:
  download-prefix: https://hackage.haskell.org/
  hackage-security:
    keyids: ["reviewed-key"]
    key-threshold: 1
    ignore-expiry: false
color: never
"#;
    let user = write(root, "/home/developer/.stack/config.yaml", original);
    let project = br#"# project policy
resolver: lts-22.43
packages:
  - .
extra-deps:
  - archive: https://build:credential@packages.example/private.tar.gz
flags:
  private-package:
    feature: true
"#;
    let project_path = write(root, "/work/app/stack.yaml", project);
    let adapter = StackAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new(), Some("/work/app/subdir"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("3.11.1"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("resolver preserved"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(!format!("{current:?}").contains("build:credential@"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [STACKAGE, HACKAGE]);
    assert_eq!(request.repository_versions[STACKAGE], "lts-22");
    assert_eq!(request.repository_versions[HACKAGE], "secure");

    let selected = selections();
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(plan.changes.len(), 6);
    assert_eq!(plan.changes[0].target, user);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("# keep comment"));
    assert!(rendered.contains("keyids: [\"reviewed-key\"]"));
    assert!(rendered.contains("ignore-expiry: false"));
    assert!(rendered.contains("color: never"));
    assert_eq!(fs::read(&project_path).unwrap(), project);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Stack config should change")
    };
    let verified = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(verified.valid);
    assert!(verified.summary.contains("lts-22.43/ghc-9.6.6"));
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
    assert_eq!(fs::read(&user).unwrap(), original);
    assert_eq!(fs::read(&project_path).unwrap(), project);
}

#[test]
fn explicit_project_scope_changes_only_non_project_keys() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_stack(root, "3.5.1", "none");
    let user = write(
        root,
        "/home/developer/.stack/config.yaml",
        b"connection-count: 8\n",
    );
    let original = br#"# active project
snapshot: custom-snapshot.yaml # preserve resolver identity
packages:
  - .
extra-deps:
  - git: https://git.example/private/repository
    commit: 0123456789abcdef
"#;
    let project = write(root, "/work/app/stack.yaml", original);
    let adapter = StackAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let runtime = runtime(root, BTreeMap::new(), Some("/work/app"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    assert_eq!(plan.changes[0].target, project);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("snapshot: custom-snapshot.yaml # preserve resolver identity"));
    assert!(rendered.contains("git: https://git.example/private/repository"));
    assert_eq!(fs::read(user).unwrap(), b"connection-count: 8\n");
}

#[test]
fn project_override_dynamic_yaml_custom_sources_and_unreviewed_versions_are_blocked() {
    let adapter = StackAdapter;
    for (version, config, project, expected) in [
        (
            "3.11.1",
            b"connection-count: 4\n".as_slice(),
            b"snapshot: lts-22.43\npackage-index:\n  download-prefix: https://hackage.haskell.org/\n".as_slice(),
            "select project scope explicitly",
        ),
        (
            "3.11.1",
            b"urls: !include endpoints.yaml\n".as_slice(),
            b"snapshot: lts-22.43\n".as_slice(),
            "dynamic or complex",
        ),
        (
            "3.11.1",
            b"package-index:\n  download-prefix: https://packages.corp.example/hackage/\n".as_slice(),
            b"snapshot: lts-22.43\n".as_slice(),
            "unreviewed endpoint",
        ),
        (
            "3.11.1",
            b"package-indices: []\n".as_slice(),
            b"snapshot: lts-22.43\n".as_slice(),
            "deprecated package-indices",
        ),
        (
            "2.15.7",
            b"connection-count: 4\n".as_slice(),
            b"snapshot: lts-22.43\n".as_slice(),
            "outside the reviewed",
        ),
        (
            "4.1.1",
            b"connection-count: 4\n".as_slice(),
            b"snapshot: lts-22.43\n".as_slice(),
            "outside the reviewed",
        ),
    ] {
        let directory = tempdir().unwrap();
        install_stack(directory.path(), version, "none");
        write(
            directory.path(),
            "/home/developer/.stack/config.yaml",
            config,
        );
        write(directory.path(), "/work/app/stack.yaml", project);
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let runtime = runtime(directory.path(), BTreeMap::new(), Some("/work/app"));
        let result = (|| {
            let detected = adapter.detect(&context, &runtime)?.unwrap();
            let current = adapter.read_current(
                &context,
                &runtime,
                &detected,
                ConfigurationScope::User,
            )?;
            adapter.plan(&context, &current, &selections())
        })();
        let error = result.unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }

    let directory = tempdir().unwrap();
    install_stack(directory.path(), "3.11.1", "none");
    let runtime = runtime(
        directory.path(),
        BTreeMap::from([("STACK_CONFIG".into(), "/etc/stack/user.yaml".into())]),
        None,
    );
    let error = adapter
        .detect(
            &context(
                directory.path(),
                Architecture::X86_64,
                ExecutionEnvironment::Host,
            ),
            &runtime,
        )
        .unwrap_err();
    assert!(error.to_string().contains("inside /home/developer"));
}

#[test]
fn linux_architecture_and_environment_variants_produce_the_same_configuration_plan() {
    let mut rendered = Vec::new();
    let mut toolchain_files = Vec::new();
    for (architecture, environment) in [
        (Architecture::X86_64, ExecutionEnvironment::Host),
        (Architecture::X86_64, ExecutionEnvironment::Container),
        (Architecture::Arm64, ExecutionEnvironment::Host),
        (Architecture::Arm64, ExecutionEnvironment::Container),
    ] {
        let directory = tempdir().unwrap();
        install_stack(directory.path(), "3.11.1", "none");
        let context = context(directory.path(), architecture, environment);
        let runtime = runtime(directory.path(), BTreeMap::new(), None);
        let adapter = StackAdapter;
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        toolchain_files.push(request.probe_contexts[STACKAGE][0]["toolchain_file"].clone());
        rendered.push(
            adapter
                .plan(&context, &current, &selections())
                .unwrap()
                .changes[0]
                .new_contents
                .clone(),
        );
    }
    assert!(rendered.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        toolchain_files,
        [
            "ghc-9.6.6-x86_64-deb9-linux.tar.xz",
            "ghc-9.6.6-x86_64-deb9-linux.tar.xz",
            "ghc-9.6.6-aarch64-deb10-linux.tar.xz",
            "ghc-9.6.6-aarch64-deb10-linux.tar.xz",
        ]
    );
}

#[derive(Clone)]
struct StackProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_toolchain: bool,
}

impl CandidateProber for StackProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let (content_type, body) = if url.ends_with("snapshots.json") {
            (
                Some("application/json".into()),
                br#"{"lts-22":"lts-22.44"}"#.to_vec(),
            )
        } else if url.ends_with("lts/22/43.yaml") {
            (
                Some("application/octet-stream".into()),
                b"snapshot ghc-9.6.6 StateVar-1.2.2".to_vec(),
            )
        } else if url.ends_with("global-hints.yaml") {
            (
                Some("application/octet-stream".into()),
                b"ghc-9.6.6 hints".to_vec(),
            )
        } else if url.ends_with("stack-setup.yaml") {
            let body = if self.corrupt_toolchain {
                "missing toolchain metadata".into()
            } else {
                "ghc-9.6.6-x86_64-deb9-linux.tar.xz ff5b4929a4e89c536e7badb3b142e353dc4bda1f31d3ee446406ad88c3bebddf".into()
            };
            (Some("application/octet-stream".into()), body)
        } else if url.ends_with("root.json") {
            (
                Some("application/json".into()),
                br#"{"type":"Root"}"#.to_vec(),
            )
        } else if url.ends_with("timestamp.json") {
            (
                Some("application/json".into()),
                br#"{"type":"Timestamp"}"#.to_vec(),
            )
        } else if url.ends_with("snapshot.json") {
            (
                Some("application/json".into()),
                br#"{"01-index.tar.gz":{}}"#.to_vec(),
            )
        } else if url.ends_with("mirrors.json") {
            (
                Some("application/json".into()),
                br#"{"type":"Mirrorlist"}"#.to_vec(),
            )
        } else if url.ends_with("StateVar-1.2.2.tar.gz") {
            (
                Some("application/octet-stream".into()),
                b"StateVar source".to_vec(),
            )
        } else {
            (Some("application/octet-stream".into()), Vec::new())
        };
        Ok(ProbeObservation {
            status: 200,
            content_type,
            body,
            latency_ms: 1,
        })
    }
}

fn synthetic_catalog() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "stack")
    {
        for probe in &mut candidate.probes {
            if probe.path.ends_with("lts/22/43.yaml") {
                probe.sha256 = Some(format!(
                    "{:x}",
                    Sha256::digest(b"snapshot ghc-9.6.6 StateVar-1.2.2")
                ));
            } else if probe.path.ends_with("global-hints.yaml") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(b"ghc-9.6.6 hints")));
            } else if probe.path.ends_with("root.json") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(br#"{"type":"Root"}"#)));
            } else if probe.path.ends_with("StateVar-1.2.2.tar.gz") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(b"StateVar source")));
            }
        }
    }
    catalog
}

#[test]
fn catalog_gates_both_upstreams_and_architecture_toolchain_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    assert_eq!(
        embedded
            .tools
            .iter()
            .find(|tool| tool.id == "stack")
            .unwrap()
            .state,
        ToolCatalogState::Supported
    );
    let candidates = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "stack")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.upstream_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([STACKAGE, HACKAGE])
    );
    for candidate in &candidates {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(candidate.endpoints.len(), 3);
        assert_eq!(
            candidate
                .endpoints
                .iter()
                .map(|endpoint| endpoint.role)
                .collect::<HashSet<_>>(),
            HashSet::from([
                EndpointRole::Metadata,
                EndpointRole::Index,
                EndpointRole::Artifacts,
            ])
        );
        let paths = candidate
            .probes
            .iter()
            .map(|probe| probe.path.as_str())
            .collect::<Vec<_>>();
        if candidate.upstream_id == STACKAGE {
            assert!(paths.contains(&"/stackage-snapshots/lts/22/43.yaml"));
            assert!(paths.contains(&"/global-hints.yaml"));
            assert!(paths.contains(&"/stack-setup.yaml"));
            assert!(paths.contains(&"/ghc/{toolchain_file}"));
        } else {
            assert!(paths.contains(&"/root.json"));
            assert!(paths.contains(&"/01-index.tar.gz"));
            assert!(paths.contains(&"/package/StateVar-1.2.2.tar.gz"));
        }
    }

    let catalog = synthetic_catalog();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let directory = tempdir().unwrap();
    install_stack(directory.path(), "3.11.1", "none");
    let adapter = StackAdapter;
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
        StackProtocolProber {
            calls: calls.clone(),
            corrupt_toolchain: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable, "{selected:#?}");
    assert_eq!(selected.selections.len(), 2);
    assert_eq!(calls.borrow().len(), 36);

    let rejected = MirrorSelector::with_prober(
        &catalog,
        StackProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_toolchain: true,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 101)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.selections.is_empty());
    assert!(
        rejected.repositories[0]
            .candidates
            .iter()
            .all(|candidate| matches!(
                candidate.evaluation,
                CandidateEvaluation::ProbeFailed { .. }
            ))
    );
}

#[test]
fn failed_real_stack_verification_rolls_back_all_managed_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_stack(root, "3.11.1", "query");
    let original = b"connection-count: 4\n";
    let user = write(root, "/home/developer/.stack/config.yaml", original);
    let adapter = StackAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Stack config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(&user).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/stack/config.yaml")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/stack/stack.yaml")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/stack/system.yaml")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/stack/mirrorswitch-stack-verification.cabal")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/stack/src/MirrorSwitchVerification.hs")
            .exists()
    );
}
