#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{BazelAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const RELEASE_UPSTREAM: &str = "bazel--release-artifacts";
const APT_UPSTREAM: &str = "bazel-apt--repository-metadata";
const HUAWEI: &str = "https://repo.huaweicloud.com/bazel";
const NJU_APT: &str = "https://mirrors.nju.edu.cn/bazel-apt";
const TUNA_APT: &str = "https://mirrors.tuna.tsinghua.edu.cn/bazel-apt";
const X64_SHA: &str = "7668a95db1250f12c40407251e4e203b4ec8bf39bc495d2f485b2d8c99048694";
const ARM64_SHA: &str = "049dd21f40ad979db11c3ee68c96a42ce75f1185e69ac61ab20de1501427a410";
const X64_FILE_SHA: &str = "b1703900c78dfc49f1f332aeee87217fe49741035c086d6a2131889a8df92c00";
const ARM64_FILE_SHA: &str = "e4e30d2abf88528f8046ffeeb2b1fd4e4abdc42c7db1f4de84f85856f93a1d80";
const DEB_SHA: &str = "7c54a526c195f1b1a404372eb05cf1d7a5ede898bf6f8e791febd0f25bff8e0b";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
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

fn env_wrapper(root: &Path) {
    executable(
        root,
        "/usr/bin/env",
        format!(
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    *=*) export \"$1\"; shift ;;\n    *) break ;;\n  esac\ndone\nprogram=$1\nshift\nexec '{root}/usr/bin/'\"$program\" \"$@\"\n",
            root = root.display()
        ),
    );
}

fn install_bazelisk(root: &Path, verify_exit: i32) {
    env_wrapper(root);
    executable(
        root,
        "/usr/bin/bazelisk",
        format!(
            "#!/bin/sh\nif [ \"$1\" = bazeliskVersion ]; then echo 'Bazelisk version: v1.27.0'; exit 0; fi\n[ \"$1\" = version ] || exit 70\n[ \"${{BAZELISK_BASE_URL:-}}\" = '{HUAWEI}' ] || exit 71\n[ \"${{USE_BAZEL_VERSION:-}}\" = 9.2.0 ] || exit 72\n[ -n \"${{BAZELISK_HOME:-}}\" ] || exit 73\ncase \"${{BAZELISK_VERIFY_SHA256:-}}\" in {X64_SHA}|{ARM64_SHA}) ;; *) exit 74 ;; esac\n[ {verify_exit} -eq 0 ] || exit {verify_exit}\nprintf '%s\\n' 'Build label: 9.2.0' 'Build target: linux'\n"
        ),
    );
}

fn install_apt_bazel(root: &Path, update_exit: i32) {
    env_wrapper(root);
    executable(
        root,
        "/usr/bin/apt-get",
        format!("#!/bin/sh\nexit {update_exit}\n"),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\nprintf '%s\n' 'bazel:' '  Installed: 9.1.1' '  Candidate: 9.2.0'\n".into(),
    );
    executable(
        root,
        "/usr/bin/bazel",
        "#!/bin/sh\n[ \"$1\" = --version ] && echo 'bazel 9.1.1'\n".into(),
    );
}

fn test_runtime(
    root: &Path,
    environment: BTreeMap<String, String>,
    project: Option<&str>,
) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selection(tool_upstream: &str, provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("bazel-{provider}-test"),
        tool_id: "bazel".into(),
        upstream_id: tool_upstream.into(),
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
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn bazelisk_user_plan_preserves_project_files_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_bazelisk(root, 0);
    let original = b"USE_BAZEL_VERSION=9.1.1\nBAZELISK_BASE_URL=https://releases.bazel.build\nBAZELISK_SHOW_PROGRESS=no\n";
    let config = write(root, "/home/developer/.bazeliskrc", original);
    let project_rc = b"USE_BAZEL_VERSION=9.2.0\n";
    let project_rc_path = write(root, "/work/project/.bazeliskrc", project_rc);
    let version = b"9.2.0\n";
    let version_path = write(root, "/work/project/.bazelversion", version);
    let module = b"module(name = \"private_app\")\n";
    let module_path = write(root, "/work/project/MODULE.bazel", module);
    let adapter = BazelAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = test_runtime(root, BTreeMap::new(), Some("/work/project"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.27.0"));
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::User
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [RELEASE_UPSTREAM]);
    let selected = selection(RELEASE_UPSTREAM, "huaweicloud", HUAWEI);
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config_plan = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config_plan);
    assert_eq!(config_plan, tui);
    assert_eq!(cli.changes.len(), 2);
    assert!(!cli.requires_elevation);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("USE_BAZEL_VERSION=9.1.1"));
    assert!(changed.contains("BAZELISK_SHOW_PROGRESS=no"));
    assert!(changed.contains(HUAWEI));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Bazelisk config and manifest should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selected)
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
    assert_eq!(fs::read(project_rc_path).unwrap(), project_rc);
    assert_eq!(fs::read(version_path).unwrap(), version);
    assert_eq!(fs::read(module_path).unwrap(), module);
}

#[test]
fn bazelisk_arm64_uses_the_architecture_specific_verified_binary() {
    let directory = tempdir().unwrap();
    install_bazelisk(directory.path(), 0);
    write(
        directory.path(),
        "/home/developer/.bazeliskrc",
        format!(
            "# >>> MirrorSwitch Bazelisk release mirror >>>\nBAZELISK_BASE_URL={HUAWEI}\n# <<< MirrorSwitch Bazelisk release mirror <<<\n"
        )
        .as_bytes(),
    );
    let adapter = BazelAdapter;
    let context = context(directory.path(), Architecture::Arm64);
    let mut runtime = test_runtime(directory.path(), BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection(RELEASE_UPSTREAM, "huaweicloud", HUAWEI),
        )
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Bazelisk user files should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn apt_plan_preserves_signature_policy_and_restores_on_success() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt_bazel(root, 0);
    let original = b"# Bazel packages\ndeb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8\ndeb https://packages.example/other stable main\n";
    let source = write(root, "/etc/apt/sources.list.d/bazel.list", original);
    let adapter = BazelAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::System
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [APT_UPSTREAM]);
    assert!(request.require_distribution);
    let selected = selection(APT_UPSTREAM, "tuna", TUNA_APT);
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    assert!(plan.requires_elevation);
    assert_eq!(plan.changes.len(), 2);
    let changed = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("arch=amd64"));
    assert!(changed.contains("signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg"));
    assert!(changed.contains("packages.example/other"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APT source and manifest should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(source).unwrap(), original);
}

#[test]
fn ambiguous_private_project_manual_and_arm64_apt_methods_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = BazelAdapter;
    let x64 = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&x64, &test_runtime(root, BTreeMap::new(), None))
            .unwrap()
            .is_none()
    );
    executable(
        root,
        "/usr/bin/bazel",
        "#!/bin/sh\necho 'bazel 9.2.0'\n".into(),
    );
    env_wrapper(root);
    assert!(
        adapter
            .detect(&x64, &test_runtime(root, BTreeMap::new(), None))
            .is_err()
    );

    install_bazelisk(root, 0);
    write(
        root,
        "/work/project/.bazeliskrc",
        b"BAZELISK_BASE_URL=https://packages.example/bazel\n",
    );
    let project_runtime = test_runtime(root, BTreeMap::new(), Some("/work/project"));
    let detected = adapter.detect(&x64, &project_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&x64, &project_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(
                &x64,
                &current,
                &selection(RELEASE_UPSTREAM, "huaweicloud", HUAWEI)
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/bazel.list",
        b"deb [arch=amd64 signed-by=/key.gpg] https://packages.example/bazel stable jdk1.8\n",
    );
    assert!(
        adapter
            .detect(&x64, &test_runtime(root, BTreeMap::new(), None))
            .is_err()
    );

    let other = tempdir().unwrap();
    install_apt_bazel(other.path(), 0);
    write(other.path(), "/etc/apt/sources.list.d/bazel.list", b"deb [arch=amd64 signed-by=/key.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8\n");
    assert!(
        adapter
            .detect(
                &context(other.path(), Architecture::Arm64),
                &test_runtime(other.path(), BTreeMap::new(), None)
            )
            .is_err()
    );
}

#[test]
fn failed_apt_refresh_restores_the_original_source() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt_bazel(root, 9);
    let original = b"deb [arch=amd64 signed-by=/key.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8\n";
    let source = write(root, "/etc/apt/sources.list.d/bazel.list", original);
    let adapter = BazelAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection(APT_UPSTREAM, "nju", NJU_APT))
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APT files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(source).unwrap(), original);
}

#[test]
fn embedded_catalog_separates_release_and_apt_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "bazel")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    let release = candidates
        .iter()
        .find(|candidate| candidate.upstream_id == RELEASE_UPSTREAM)
        .unwrap();
    assert_eq!(release.provider_id, "huaweicloud");
    assert_eq!(
        release.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );
    assert_eq!(release.compatibility.repository_versions, ["9.2.0"]);
    assert_eq!(release.probes.len(), 5);
    assert_eq!(release.probes[1].sha256.as_deref(), Some(X64_FILE_SHA));
    assert_eq!(release.probes[2].sha256.as_deref(), Some(ARM64_FILE_SHA));
    let apt = candidates
        .iter()
        .filter(|candidate| candidate.upstream_id == APT_UPSTREAM)
        .collect::<Vec<_>>();
    assert_eq!(
        apt.iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "tuna"])
    );
    for candidate in apt {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64]
        );
        assert_eq!(candidate.probes.len(), 4);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert_eq!(candidate.probes[3].method, HttpMethod::Head);
        assert!(
            candidate.probes[0]
                .contains
                .as_deref()
                .is_some_and(|value| value == DEB_SHA)
        );
    }
}
