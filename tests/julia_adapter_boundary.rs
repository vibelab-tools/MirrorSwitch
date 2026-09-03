#![cfg(unix)]

use std::{
    collections::{BTreeMap, HashSet},
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

fn native_context(root: &Path, os: OperatingSystem, architecture: Architecture) -> SystemContext {
    SystemContext {
        os,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: None,
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
  /home/developer/.mirrorswitch/verification/julia/depot:|/home/developer/.mirrorswitch/verification/julia/depot\;) ;;
  *) exit 62 ;;
esac
[ "${{JULIA_PKG_PRECOMPILE_AUTO:-}}" = 0 ] || exit 63
[ "${{JULIA_PKG_SERVER_REGISTRY_PREFERENCE:-}}" = conservative ] || exit 64
printf '%s' "$script" | grep -F 'Pkg.Registry.status()' >/dev/null || exit 65
printf '%s' "$script" | grep -F 'Example' >/dev/null || exit 66
printf '%s' "$script" | grep -F 'HelloWorldC_jll' >/dev/null || exit 67
[ -n "${{MIRRORSWITCH_EXPECTED_ARTIFACT:-}}" ] || exit 68
[ {verification_exit} -eq 0 ] || exit {verification_exit}
mkdir -p '{root}/home/developer/.mirrorswitch/verification/julia/depot/registries'
printf '%s\n' 'Registry Status' ' [23338594] General' \
  "MIRRORSWITCH_JULIA_VERIFY=registry:General example:{example_tree} hello:{hello_tree} artifact:ready:${{MIRRORSWITCH_EXPECTED_ARTIFACT}}"
"#,
            root = root.display(),
            nju = NJU,
            example_tree = EXAMPLE_TREE,
            hello_tree = HELLO_TREE,
        ),
    );
}

fn install_windows_registry(root: &Path, initial: Option<&str>, mutation_exit: i32) -> PathBuf {
    let state = root.join("windows-registry/julia-pkg-server");
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    if let Some(initial) = initial {
        fs::write(&state, initial).unwrap();
    }
    executable(
        root,
        "/usr/bin/reg.exe",
        format!(
            r#"#!/bin/sh
state='{state}'
case "$1" in
  query)
    [ -f "$state" ] || exit 1
    printf '%s\n' 'HKEY_CURRENT_USER\Environment' "    JULIA_PKG_SERVER    REG_SZ    $(cat "$state")"
    ;;
  add)
    [ {mutation_exit} -eq 0 ] || exit {mutation_exit}
    printf '%s' "$8" > "$state"
    ;;
  delete)
    [ {mutation_exit} -eq 0 ] || exit {mutation_exit}
    rm -f "$state"
    ;;
  *) exit 91 ;;
esac
"#,
            state = state.display(),
        ),
    );
    state
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

fn windows_environment(pkg_server: Option<&str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
        (
            "LOCALAPPDATA".into(),
            "/home/developer/AppData/Local".into(),
        ),
        (
            "JULIA_DEPOT_PATH".into(),
            "/home/developer/custom-depot;".into(),
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
fn macos_profile_preserves_bom_depot_registry_and_project_state() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_julia(root, "1.11.7", "1.11.7", 0);
    let original =
        b"\xef\xbb\xbf# macOS shell policy\nexport JULIA_PKG_SERVER='https://pkg.julialang.org'\n";
    let profile = write(root, "/home/developer/.zshrc", original);
    let project_contents = b"[deps]\nPrivate = \"12345678-1234-1234-1234-123456789abc\"\n";
    let project = write(root, "/work/project/Project.toml", project_contents);
    let adapter = JuliaAdapter;
    let context = native_context(root, OperatingSystem::Macos, Architecture::Arm64);
    let mut runtime = test_runtime(root, environment("/bin/zsh", None));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Macos Arm64"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts[UPSTREAM][0];
    assert_eq!(
        probe["julia_artifact_tree"],
        "14e7b6ef22f415365b443e7c66bbb3cee64a8ebd"
    );
    let cli = adapter.plan(&context, &current, &selection()).unwrap();
    let config = adapter.plan(&context, &current, &selection()).unwrap();
    let tui = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert!(cli.changes[0].new_contents.starts_with(&[0xef, 0xbb, 0xbf]));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("macOS Julia profile should change")
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
            .plan(&context, &updated, &selection())
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
    assert_eq!(fs::read(profile).unwrap(), original);
    assert_eq!(fs::read(project).unwrap(), project_contents);
}

#[test]
fn windows_registry_persistence_is_private_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_julia(root, "1.11.7", "1.11.7", 0);
    let registry = install_windows_registry(root, Some("https://pkg.julialang.org"), 0);
    let project_contents = b"[deps]\nPrivate = \"12345678-1234-1234-1234-123456789abc\"\n";
    let project = write(root, "/work/project/Project.toml", project_contents);
    let adapter = JuliaAdapter;
    let context = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    let mut runtime = test_runtime(root, windows_environment(None));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Windows X86_64"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Windows user environment"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts[UPSTREAM][0];
    assert_eq!(
        probe["julia_artifact_tree"],
        "6e1eb164b0651aa44621eac4dfa340d6e60295ef"
    );
    let cli = adapter.plan(&context, &current, &selection()).unwrap();
    let config = adapter.plan(&context, &current, &selection()).unwrap();
    let tui = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert!(!format!("{cli:?}").contains("pkg.julialang.org"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Windows Julia state should change")
    };
    assert_eq!(fs::read_to_string(&registry).unwrap(), NJU);
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
            .plan(&context, &updated, &selection())
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
    assert_eq!(
        fs::read_to_string(registry).unwrap(),
        "https://pkg.julialang.org"
    );
    assert!(
        !root
            .join("home/developer/AppData/Local/MirrorSwitch/julia/environment-recovery.json")
            .exists()
    );
    assert_eq!(fs::read(project).unwrap(), project_contents);
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
fn non_native_platform_windows_arm_and_missing_registry_client_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_julia(root, "1.11.7", "1.11.7", 0);
    let adapter = JuliaAdapter;
    let macos_container = SystemContext {
        environment: ExecutionEnvironment::Container,
        ..native_context(root, OperatingSystem::Macos, Architecture::Arm64)
    };
    assert!(
        adapter
            .detect(&macos_container, &test_runtime(root, BTreeMap::new()))
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
    let windows_arm = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    assert!(
        adapter
            .detect(&windows_arm, &test_runtime(root, windows_environment(None)))
            .unwrap_err()
            .to_string()
            .contains("no reviewed native Windows arm64 runtime")
    );
    let windows = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    assert!(
        adapter
            .detect(&windows, &test_runtime(root, windows_environment(None)))
            .unwrap_err()
            .to_string()
            .contains("reg.exe")
    );
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
        [
            OperatingSystem::Linux,
            OperatingSystem::Macos,
            OperatingSystem::Windows,
        ]
    );
    assert_eq!(
        nju.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );
    assert_eq!(nju.probes.len(), 5);
    assert_eq!(nju.probes[0].method, HttpMethod::Get);
    assert_eq!(nju.probes[1].method, HttpMethod::Head);
    assert_eq!(nju.probes[2].sha256.as_deref(), Some(EXAMPLE_SHA));
    assert!(nju.probes.iter().any(|probe| {
        probe.path == "/artifact/{julia_artifact_tree}"
            && probe.sha256.as_deref() == Some("{julia_artifact_sha}")
    }));
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
