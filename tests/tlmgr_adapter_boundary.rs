#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{TlmgrAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "ctan--language-registry";
const OFFICIAL: &str = "https://mirror.ctan.org/systems/texlive/tlnet";
const NJU: &str = "https://mirrors.nju.edu.cn/CTAN/systems/texlive/tlnet";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/CTAN/systems/texlive/tlnet";
const INFRA_SHA: &str = "c762f37bd7d99cba6d5b0799697768cd26028583d2f81ca2f630d8f403a5c491";
const X86_SHA: &str = "168ce3c58aa35cafaa38e1defb3c3e26553473b35951d64bf54b5b2f00fd086f";
const MUSL_SHA: &str = "bd32c86e19c774b7715824fceab5fe92ca33f6110e8d9d84fc62589249d581ba";
const ARM_SHA: &str = "01ad1b1457f65d4717b969b7ca27e08a559831d2c0658581b9659cf93c3c10ff";

fn context(root: &Path, architecture: Architecture, distribution: &str) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some("test".into()),
            version_codename: None,
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

fn tlpdb(location: &str) -> Vec<u8> {
    format!(
        "name 00texlive.config\ncategory TLCore\ndepend release/2026\n\nname 00texlive.installation\ncategory TLCore\ndepend opt_autobackup:1\ndepend opt_location:{location}\ndepend opt_require_verification:1\ndepend opt_verify_downloads:1\ndepend setting_available_architectures:x86_64-linux aarch64-linux\n\nname texlive.infra\ncategory TLCore\nrevision 79639\n"
    )
    .into_bytes()
}

fn user_tlpdb(location: &str) -> Vec<u8> {
    format!(
        "name 00texlive.installation\ncategory TLCore\ndepend opt_location:{location}\ndepend setting_available_architectures:\ndepend setting_usertree:1\n"
    )
    .into_bytes()
}

fn install_tlmgr(root: &Path, release: &str, platform: &str, verification_exit: i32) {
    executable(
        root,
        "/usr/bin/kpsewhich",
        "#!/bin/sh\n[ \"$1\" = -var-value=TEXMFHOME ] || exit 70\nprintf '%s\\n' /home/developer/texmf\n"
            .into(),
    );
    executable(
        root,
        "/usr/bin/tlmgr",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then
  printf '%s\n' 'tlmgr revision 79639 (2026-07-10)' 'tlmgr using installation: /opt/texlive' 'TeX Live (https://tug.org/texlive) version {release}'
  exit 0
fi
usermode=0
repository=
while [ $# -gt 0 ]; do
  case "$1" in
    --usermode) usermode=1; shift ;;
    --repository) repository=$2; shift 2 ;;
    *) break ;;
  esac
done
if [ "$1" = print-platform ]; then
  printf '%s\n' '{platform}'
  exit 0
fi
if [ "$usermode" -eq 1 ]; then
  database='{root}/home/developer/texmf/tlpkg/texlive.tlpdb'
else
  database='{root}/opt/texlive/tlpkg/texlive.tlpdb'
fi
if [ "$1" = repository ] && [ "$2" = list ]; then
  location=$(sed -n 's/^depend opt_location://p' "$database")
  printf '%s\n' 'List of repositories (with tags if set):'
  for item in $location; do
    case "$item" in
      *#main) printf '\t%s (main)\n' "${{item%#main}}" ;;
      *#*) tag=${{item##*#}}; printf '\t%s (%s)\n' "${{item%#*}}" "$tag" ;;
      *) printf '\t%s (main)\n' "$item" ;;
    esac
  done
  exit 0
fi
if [ -n "$repository" ] && [ "$1" = info ] && [ "$2" = texlive.infra ]; then
  [ {verification_exit} -eq 0 ] || exit {verification_exit}
  printf '%s\n' 'package:     texlive.infra' 'category:    TLCore' 'revision:    79639'
  exit 0
fi
if [ -n "$repository" ] && [ "$1" = platform ] && [ "$2" = list ]; then
  printf '%s\n' 'Available platforms:' 'aarch64-linux' 'x86_64-linux' 'x86_64-linuxmusl'
  exit 0
fi
exit 71
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(BTreeMap::new())
}

fn selection(provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("tlmgr-{provider}-test"),
        tool_id: "tlmgr".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: provider.into(),
        endpoints: [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: endpoint.into(),
        })
        .collect(),
        latency_ms: 7,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn tuna_selection() -> [MirrorSelection; 1] {
    [selection("tuna", TUNA)]
}

#[test]
fn system_plan_preserves_custom_pinning_and_verification_policy_and_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_tlmgr(root, "2026", "x86_64-linux", 0);
    let original = tlpdb(&format!(
        "{OFFICIAL}#main https://packages.example/texlive#corp"
    ));
    let database = write(root, "/opt/texlive/tlpkg/texlive.tlpdb", &original);
    let pinning = b"corp : company-*\n";
    let pinning_path = write(root, "/opt/texlive/texmf-local/tlpkg/pinning.txt", pinning);
    let adapter = TlmgrAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu");
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2026"));
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::System
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        current
            .sources
            .iter()
            .all(|source| !source.url.contains("packages.example"))
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "2026");
    let cli = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let config = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let tui = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert!(cli.requires_elevation);
    assert_eq!(cli.changes.len(), 1);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains(&format!("{TUNA}#main")));
    assert!(changed.contains("https://packages.example/texlive#corp"));
    assert!(changed.contains("depend opt_require_verification:1"));
    assert!(changed.contains("depend opt_verify_downloads:1"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("system TLPDB should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&pinning_path).unwrap(), pinning);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
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
    assert_eq!(fs::read(database).unwrap(), original);
    assert_eq!(fs::read(pinning_path).unwrap(), pinning);
}

#[test]
fn initialized_arm64_user_tree_is_the_unprivileged_default() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_tlmgr(root, "2026", "aarch64-linux", 0);
    let system = tlpdb(OFFICIAL);
    let system_path = write(root, "/opt/texlive/tlpkg/texlive.tlpdb", &system);
    let user = user_tlpdb(OFFICIAL);
    write(root, "/home/developer/texmf/tlpkg/texlive.tlpdb", &user);
    let adapter = TlmgrAdapter;
    let context = context(root, Architecture::Arm64, "debian");
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::User
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selected = [selection("nju", NJU)];
    let first = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(first, adapter.plan(&context, &current, &selected).unwrap());
    assert!(!first.requires_elevation);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &first).unwrap()
    else {
        panic!("user TLPDB should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(system_path).unwrap(), system);
}

#[test]
fn old_release_platform_private_ambiguous_and_mismatched_sources_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = TlmgrAdapter;
    let x86 = context(root, Architecture::X86_64, "ubuntu");
    assert!(adapter.detect(&x86, &runtime(root)).unwrap().is_none());

    install_tlmgr(root, "2025", "x86_64-linux", 0);
    write(root, "/opt/texlive/tlpkg/texlive.tlpdb", &tlpdb(OFFICIAL));
    assert!(adapter.detect(&x86, &runtime(root)).is_err());
    install_tlmgr(root, "2026", "aarch64-linuxmusl", 0);
    let arm = context(root, Architecture::Arm64, "alpine");
    assert!(adapter.detect(&arm, &runtime(root)).is_err());

    install_tlmgr(root, "2026", "x86_64-linux", 0);
    write(
        root,
        "/opt/texlive/tlpkg/texlive.tlpdb",
        &tlpdb("https://packages.example/texlive"),
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&x86, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&x86, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&x86, &current, &tuna_selection())
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    write(
        root,
        "/opt/texlive/tlpkg/texlive.tlpdb",
        &tlpdb(&format!("{OFFICIAL} https://packages.example/texlive")),
    );
    assert!(adapter.detect(&x86, &runtime).is_err());
    write(root, "/opt/texlive/tlpkg/texlive.tlpdb", &tlpdb(OFFICIAL));
    let detected = adapter.detect(&x86, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&x86, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let mut mismatched = tuna_selection();
    mismatched[0].endpoints[2].url = NJU.into();
    assert!(adapter.plan(&x86, &current, &mismatched).is_err());
}

#[test]
fn failed_real_remote_query_restores_the_original_tlpdb() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_tlmgr(root, "2026", "aarch64-linux", 9);
    let original = tlpdb(OFFICIAL);
    let database = write(root, "/opt/texlive/tlpkg/texlive.tlpdb", &original);
    let adapter = TlmgrAdapter;
    let context = context(root, Architecture::Arm64, "debian");
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("system TLPDB should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(database).unwrap(), original);
}

#[test]
fn embedded_catalog_has_four_release_and_platform_complete_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "tlmgr")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 4);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud", "nju", "tuna"])
    );
    for candidate in candidates {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [OperatingSystem::Linux]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(candidate.compatibility.repository_versions, ["2026"]);
        assert_eq!(candidate.probes.len(), 5);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert!(
            candidate.probes[0]
                .contains
                .as_deref()
                .is_some_and(|value| value.contains("texlive.tlpdb"))
        );
        assert_eq!(candidate.probes[1].sha256.as_deref(), Some(INFRA_SHA));
        assert_eq!(candidate.probes[2].sha256.as_deref(), Some(X86_SHA));
        assert_eq!(candidate.probes[3].sha256.as_deref(), Some(MUSL_SHA));
        assert_eq!(candidate.probes[4].sha256.as_deref(), Some(ARM_SHA));
        for role in [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ] {
            assert!(
                candidate
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.role == role)
            );
        }
    }
}
