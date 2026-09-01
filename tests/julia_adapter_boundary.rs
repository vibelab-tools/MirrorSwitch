#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{JuliaAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "julia--language-registry";
const NJU: &str = "https://mirrors.nju.edu.cn/julia";
const EXAMPLE_TREE: &str = "e1f0e1a832ccd8e97d6d0348dec33ee139a5aeaf";
const HELLO_TREE: &str = "370059fde9f8b780a2335dcbcf05ba224053d45f";
const EXAMPLE_SHA: &str = "87dd4f0b8977bbdc95ce08fa896d635aafaa3e65ddd06af5e9a2c3eaa432cad8";
const X64_ARTIFACT_SHA: &str = "ba2e68bc72a3e6cadefb8ff892bc7c76289b06b7606cc4d1f2613ce917c5425f";
const ARM64_ARTIFACT_SHA: &str = "7b56d8aa960fe3e540f945126c942f4be1bcb1da66f4fd530450a70efcd76955";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
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

fn install_julia(root: &Path, julia_version: &str, pkg_version: &str, verification_exit: i32) {
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
[ "$1" = julia ] || exit 90
shift
exec '{root}/usr/bin/julia' "$@"
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/julia",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then
  printf '%s\n' 'julia version {julia_version}'
  exit 0
fi
script=
while [ $# -gt 0 ]; do
  if [ "$1" = -e ]; then script=$2; break; fi
  shift
done
[ -n "$script" ] || exit 60
if printf '%s' "$script" | grep -F 'MIRRORSWITCH_PKG_VERSION=' >/dev/null; then
  printf '%s\n' \
    'MIRRORSWITCH_PKG_VERSION={pkg_version}' \
    'MIRRORSWITCH_DEPOT_COUNT=3' \
    'MIRRORSWITCH_FIRST_DEPOT=/home/developer/.julia' \
    'MIRRORSWITCH_ACTIVE_PROJECT=/work/project/Project.toml' \
    'MIRRORSWITCH_REGISTRY_COUNT=2' \
    'MIRRORSWITCH_NON_GENERAL_REGISTRY_COUNT=1' \
    'Registry Status' \
    ' [23338594] General' \
    ' [12345678] PrivateRegistry'
  exit 0
fi
[ "${{JULIA_PKG_SERVER:-}}" = '{nju}' ] || exit 61
case "${{JULIA_DEPOT_PATH:-}}" in
  /home/developer/.mirrorswitch/verification/julia/depot:) ;;
  *) exit 62 ;;
esac
[ "${{JULIA_PKG_PRECOMPILE_AUTO:-}}" = 0 ] || exit 63
[ "${{JULIA_PKG_SERVER_REGISTRY_PREFERENCE:-}}" = conservative ] || exit 64
printf '%s' "$script" | grep -F 'Pkg.Registry.status()' >/dev/null || exit 65
printf '%s' "$script" | grep -F 'Example' >/dev/null || exit 66
printf '%s' "$script" | grep -F 'HelloWorldC_jll' >/dev/null || exit 67
[ {verification_exit} -eq 0 ] || exit {verification_exit}
mkdir -p '{root}/home/developer/.mirrorswitch/verification/julia/depot/registries'
printf '%s\n' 'Registry Status' ' [23338594] General' \
  'MIRRORSWITCH_JULIA_VERIFY=registry:General example:{example_tree} hello:{hello_tree} artifact:ready'
"#,
            root = root.display(),
            nju = NJU,
            example_tree = EXAMPLE_TREE,
            hello_tree = HELLO_TREE,
        ),
    );
}

fn test_runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn environment(shell: &str, pkg_server: Option<&str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
        ("SHELL".into(), shell.into()),
        (
            "JULIA_DEPOT_PATH".into(),
            "/home/developer/custom-depot:".into(),
        ),
    ]);
    if let Some(value) = pkg_server {
        values.insert("JULIA_PKG_SERVER".into(), value.into());
    }
    values
}

fn selection() -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: "julia-nju-test".into(),
        tool_id: "julia".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "nju".into(),
        endpoints: [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: NJU.into(),
        })
        .collect(),
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn user_plan_preserves_depot_registries_authentication_and_project_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_julia(root, "1.12.1", "1.12.1", 0);
    let original_profile =
        b"# keep shell policy\nexport EDITOR=vim\nexport JULIA_PKG_SERVER=pkg.julialang.org\n";
    let profile = write(root, "/home/developer/.bashrc", original_profile);
    let auth = write(
        root,
        "/home/developer/.julia/servers/pkg.example/auth.toml",
        b"\xff\xfeopaque-authentication",
    );
    let project = b"name = \"PrivateProject\"\n[deps]\n";
    let manifest = b"julia_version = \"1.12.1\"\n";
    let project_path = write(root, "/work/project/Project.toml", project);
    let manifest_path = write(root, "/work/project/Manifest.toml", manifest);
    let adapter = JuliaAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = test_runtime(root, environment("/bin/bash", Some("pkg.julialang.org")));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.12.1"));
    assert!(detected.evidence.iter().any(|line| line == "Pkg 1.12.1"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "non-General registries preserved: 1")
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line
                == "Pkg server authentication directory is preserved without inspection")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        current
            .files
            .contains(&PathBuf::from("/work/project/Project.toml"))
    );
    assert!(
        current
            .files
            .contains(&PathBuf::from("/work/project/Manifest.toml"))
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts
        ]
    );
    let cli = adapter.plan(&context, &current, &selection()).unwrap();
    let config = adapter.plan(&context, &current, &selection()).unwrap();
    let tui = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("export EDITOR=vim"));
    assert!(rendered.contains("MirrorSwitch Julia Pkg server"));
    assert!(rendered.contains(NJU));
    assert!(!rendered.contains("pkg.julialang.org"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Julia profile should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&project_path).unwrap(), project);
    assert_eq!(fs::read(&manifest_path).unwrap(), manifest);
    assert_eq!(fs::read(&auth).unwrap(), b"\xff\xfeopaque-authentication");

    let refreshed = test_runtime(root, environment("/bin/bash", Some(NJU)));
    let current = adapter
        .read_current(&context, &refreshed, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
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
    assert_eq!(fs::read(profile).unwrap(), original_profile);
    assert_eq!(fs::read(project_path).unwrap(), project);
    assert_eq!(fs::read(manifest_path).unwrap(), manifest);
}

#[test]
fn arm64_fish_missing_profile_produces_stable_plan_and_real_pkg_verification() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_julia(root, "1.10.10", "1.10.10", 0);
    let adapter = JuliaAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = test_runtime(root, environment("/usr/bin/fish", None));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let first = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(
        first,
        adapter.plan(&context, &current, &selection()).unwrap()
    );
    let profile = String::from_utf8(first.changes[0].new_contents.clone()).unwrap();
    assert!(profile.contains("set -gx JULIA_PKG_SERVER"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &first).unwrap()
    else {
        panic!("Julia fish profile should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn disabled_private_dynamic_and_unreviewed_selections_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = JuliaAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(
                &context,
                &test_runtime(root, environment("/bin/bash", None))
            )
            .unwrap()
            .is_none()
    );
    install_julia(root, "1.12.1", "1.12.1", 0);

    write(
        root,
        "/home/developer/.bashrc",
        b"export JULIA_PKG_SERVER=''\n",
    );
    let runtime = test_runtime(root, environment("/bin/bash", None));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let error = adapter.plan(&context, &current, &selection()).unwrap_err();
    assert!(error.to_string().contains("explicitly empty"));

    write(
        root,
        "/home/developer/.bashrc",
        b"export JULIA_PKG_SERVER='https://packages.example/julia'\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    write(
        root,
        "/home/developer/.bashrc",
        b"export JULIA_PKG_SERVER=\"$PRIVATE_SERVER\"\n",
    );
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .is_err()
    );

    write(root, "/home/developer/.bashrc", b"# clean\n");
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let mut bad = selection();
    bad[0].provider_id = "huaweicloud".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());
    let mut bad = selection();
    bad[0].endpoints[2].url = "https://repo.huaweicloud.com/repository_archive/julia".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());

    let disabled_environment = test_runtime(root, environment("/bin/bash", Some("")));
    let current = adapter
        .read_current(
            &context,
            &disabled_environment,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
            .unwrap_err()
            .to_string()
            .contains("explicitly empty")
    );
}

#[test]
fn unsupported_versions_and_failed_pkg_query_restore_the_profile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = JuliaAdapter;
    let context = context(root, Architecture::Arm64);
    for version in ["1.5.4", "2.0.0"] {
        install_julia(root, version, version, 0);
        assert!(
            adapter
                .detect(
                    &context,
                    &test_runtime(root, environment("/bin/bash", None))
                )
                .unwrap_err()
                .to_string()
                .contains("outside the reviewed")
        );
    }

    install_julia(root, "1.11.7", "1.11.7", 9);
    let original = b"export EDITOR=nano\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let mut runtime = test_runtime(root, environment("/bin/bash", None));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Julia profile should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn embedded_catalog_keeps_only_nju_pkg_protocol_candidate_actionable() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "julia")
        .unwrap();
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "julia")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 1);
    let nju = complete[0];
    assert_eq!(nju.provider_id, "nju");
    assert_eq!(nju.delivery_mode, DeliveryMode::Proxy);
    assert_eq!(
        nju.compatibility.operating_systems,
        [OperatingSystem::Linux]
    );
    assert_eq!(
        nju.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );
    assert_eq!(nju.probes.len(), 6);
    assert_eq!(nju.probes[0].method, HttpMethod::Get);
    assert_eq!(nju.probes[1].method, HttpMethod::Head);
    assert_eq!(nju.probes[2].sha256.as_deref(), Some(EXAMPLE_SHA));
    assert_eq!(
        nju.probes
            .iter()
            .filter_map(|probe| probe.sha256.as_deref())
            .filter(|digest| matches!(*digest, X64_ARTIFACT_SHA | ARM64_ARTIFACT_SHA))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([X64_ARTIFACT_SHA, ARM64_ARTIFACT_SHA])
    );
    assert_eq!(
        nju.endpoints
            .iter()
            .map(|endpoint| endpoint.role)
            .collect::<HashSet<_>>(),
        HashSet::from([
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ])
    );
    let huawei = candidates
        .iter()
        .find(|candidate| candidate.provider_id == "huaweicloud")
        .unwrap();
    assert!(huawei.probes.is_empty());
    assert!(huawei.compatibility.architectures.is_empty());
}
