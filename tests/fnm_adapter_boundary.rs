#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{FnmAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol,
        ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const NODE_UPSTREAM: &str = "nodejs--release-artifacts";
const HUAWEI: &str = "https://repo.huaweicloud.com/nodejs/";

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

fn install_fnm(root: &Path, version: &str, current: &str, remote_exit: i32) {
    install_fnm_for_arch(root, version, current, "x64", remote_exit);
}

fn install_fnm_for_arch(
    root: &Path,
    version: &str,
    current: &str,
    architecture: &str,
    remote_exit: i32,
) {
    executable(
        root,
        "/usr/bin/fnm",
        format!(
            r#"#!/bin/sh
case "$*" in
  "--version") printf 'fnm {version}\n' ;;
  "list-remote --help") printf '%s\n' '--filter --latest --node-dist-mirror --arch' ;;
  "current")
    if [ '{current}' = none ]; then exit 1; fi
    printf '{current}\n'
    ;;
  "list") printf '* v20.19.5 default\n  v22.22.0\n' ;;
  *"list-remote"*)
    printf '%s' "$*" | grep -F -- '--node-dist-mirror https://repo.huaweicloud.com/nodejs' >/dev/null || exit 71
    printf '%s' "$*" | grep -F -- '--filter v24.1.0' >/dev/null || exit 72
    printf '%s' "$*" | grep -F -- '--arch {architecture}' >/dev/null || exit 74
    [ {remote_exit} -eq 0 ] || exit {remote_exit}
    printf 'v24.1.0\n'
    ;;
  *) exit 73 ;;
esac
"#,
        ),
    );
}

fn install_powershell(root: &Path, executable_name: &str, profile: &str) {
    executable(
        root,
        &format!("/usr/bin/{executable_name}"),
        format!(
            r#"#!/bin/sh
printf '%s' "$*" | grep -F '$PROFILE.CurrentUserCurrentHost' >/dev/null || exit 81
printf '%s' '{profile}'
"#,
        ),
    );
}

fn environment(shell: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("SHELL".into(), shell.into())])
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn native_runtime(
    root: &Path,
    home: &str,
    project: &str,
    environment: BTreeMap<String, String>,
) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home(home)
        .with_project_dir(project)
        .with_environment(environment)
}

fn selection(endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "fnm-huawei-test".into(),
        tool_id: "fnm".into(),
        upstream_id: NODE_UPSTREAM.into(),
        provider_id: "huaweicloud".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Releases,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn bash_profile_plan_is_consistent_idempotent_reversible_and_real_query_checked() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_fnm(root, "1.39.0", "v22.22.0", 0);
    let original = b"# aliases\nalias ll='ls -l'\neval \"$(fnm env --use-on-cd --shell bash)\"\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = FnmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment("/bin/bash"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.39.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("v22.22.0"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("v20.19.5, v22.22.0"))
    );
    assert_eq!(adapter.supported_scopes(), [ConfigurationScope::User]);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [NODE_UPSTREAM]);
    assert_eq!(request.required_endpoint_roles, [EndpointRole::Releases]);
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Mirror]);
    assert_eq!(request.probe_contexts[NODE_UPSTREAM].len(), 1);
    assert_eq!(
        request.probe_contexts[NODE_UPSTREAM][0]["version"],
        "v22.22.0"
    );
    assert_eq!(
        request.probe_contexts[NODE_UPSTREAM][0]["artifact_filename"],
        "node-v22.22.0-linux-x64.tar.xz"
    );

    let chosen = [selection(HUAWEI)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("alias ll='ls -l'"));
    assert!(rendered.contains("eval \"$(fnm env --use-on-cd --shell bash)\""));
    assert!(rendered.contains("export FNM_NODE_DIST_MIRROR='https://repo.huaweicloud.com/nodejs'"));
    assert!(!rendered.contains("NVM_NODEJS_ORG_MIRROR"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("fnm shell profile should change")
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
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn arm64_fish_profile_uses_fish_syntax_and_fallback_target() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_fnm_for_arch(root, "1.35.1", "none", "arm64", 0);
    let original = b"# fnm setup\nfnm env --use-on-cd --shell fish | source\n";
    let profile = write(
        root,
        "/home/developer/.config/fish/conf.d/fnm.fish",
        original,
    );
    let adapter = FnmAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment("/usr/bin/fish"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(current.documents[0].format.contains("fish"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.context.architecture, Architecture::Arm64);
    assert!(
        request.probe_contexts[NODE_UPSTREAM]
            .iter()
            .all(|values| values["version"] == "v24.1.0")
    );
    assert_eq!(
        request.probe_contexts[NODE_UPSTREAM][0]["artifact_filename"],
        "node-v24.1.0-linux-arm64.tar.xz"
    );
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        rendered.contains("set -gx FNM_NODE_DIST_MIRROR 'https://repo.huaweicloud.com/nodejs'")
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("fish profile should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        fs::read_to_string(profile)
            .unwrap()
            .contains("FNM_NODE_DIST_MIRROR")
    );
}

#[test]
fn native_profiles_use_platform_archives_and_preserve_private_project_state() {
    for (os, architecture, home, profile, shell, expected_arch, artifact) in [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "/Users/developer",
            "/Users/developer/.zshrc",
            Some("/bin/zsh"),
            "x64",
            "node-v24.1.0-darwin-x64.tar.gz",
        ),
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            "/Users/developer",
            "/Users/developer/.zshrc",
            Some("/bin/zsh"),
            "arm64",
            "node-v24.1.0-darwin-arm64.tar.gz",
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            "/home/developer",
            "/home/developer/Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
            None,
            "x64",
            "node-v24.1.0-win-x64.zip",
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_fnm_for_arch(root, "1.39.0", "none", expected_arch, 0);
        if os == OperatingSystem::Windows {
            install_powershell(root, "pwsh", profile);
        }
        let original = if os == OperatingSystem::Windows {
            b"\xef\xbb\xbf# native PowerShell policy\r\n$env:PRIVATE_NODE_TOKEN = 'fixture-only'\r\nfnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression\r\n".as_slice()
        } else {
            b"# native zsh policy\nexport PRIVATE_NODE_TOKEN='fixture-only'\neval \"$(fnm env --use-on-cd --shell zsh)\"\n".as_slice()
        };
        let profile_path = write(root, profile, original);
        let mut permissions = fs::metadata(&profile_path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&profile_path, permissions).unwrap();
        let project = if os == OperatingSystem::Windows {
            "/home/developer/project"
        } else {
            "/Users/developer/project"
        };
        let project_file = write(
            root,
            &format!("{project}/.node-version"),
            b"private-project-fixture\n",
        );
        let environment = shell
            .map(|value| BTreeMap::from([("SHELL".into(), value.into())]))
            .unwrap_or_default();
        let context = native_context(root, os, architecture);
        let mut runtime = native_runtime(root, home, project, environment);
        let adapter = FnmAdapter;
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let evidence = detected.evidence.join("\n");
        assert!(evidence.contains(&format!("{os:?}")));
        assert!(evidence.contains(&format!("{architecture:?}")));
        assert!(evidence.contains(home));
        assert!(evidence.contains(profile));
        assert!(evidence.contains(project));
        assert!(!evidence.contains("fixture-only"));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        assert_eq!(request.probe_contexts[NODE_UPSTREAM].len(), 1);
        assert_eq!(
            request.probe_contexts[NODE_UPSTREAM][0]["artifact_filename"],
            artifact
        );
        let cli = adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap();
        let config = adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap();
        let tui = adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
        assert_eq!(cli.changes[0].target, profile_path);
        let rendered = &cli.changes[0].new_contents;
        assert_eq!(
            rendered.starts_with(&[0xef, 0xbb, 0xbf]),
            os == OperatingSystem::Windows
        );
        assert_eq!(
            String::from_utf8_lossy(rendered).contains("\r\n"),
            os == OperatingSystem::Windows
        );
        let rendered = String::from_utf8_lossy(rendered);
        assert!(rendered.contains("fixture-only"));
        if os == OperatingSystem::Windows {
            assert!(
                rendered
                    .contains("$env:FNM_NODE_DIST_MIRROR = 'https://repo.huaweicloud.com/nodejs'")
            );
        } else {
            assert!(
                rendered
                    .contains("export FNM_NODE_DIST_MIRROR='https://repo.huaweicloud.com/nodejs'")
            );
        }
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("native fnm profile should change")
        };
        assert!(
            adapter
                .verify(&context, &mut runtime, &receipt)
                .unwrap()
                .valid
        );
        assert_eq!(
            fs::read(&project_file).unwrap(),
            b"private-project-fixture\n"
        );
        assert_eq!(
            fs::metadata(&profile_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &[selection(HUAWEI)])
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
        assert_eq!(fs::read(&profile_path).unwrap(), original);
    }
}

#[test]
fn unsupported_native_contexts_and_untrusted_powershell_profiles_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_fnm(root, "1.39.0", "none", 0);
    install_powershell(root, "pwsh", "/outside/profile.ps1");
    let adapter = FnmAdapter;
    let runtime = native_runtime(
        root,
        "/home/developer",
        "/home/developer/project",
        BTreeMap::new(),
    );

    let mut mac_container = native_context(root, OperatingSystem::Macos, Architecture::X86_64);
    mac_container.environment = ExecutionEnvironment::Container;
    assert!(
        adapter
            .detect(&mac_container, &runtime)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );

    let windows_arm = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    assert!(
        adapter
            .detect(&windows_arm, &runtime)
            .unwrap_err()
            .to_string()
            .contains("x64 Windows binary")
    );

    let windows_x64 = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    assert!(
        adapter
            .detect(&windows_x64, &runtime)
            .unwrap_err()
            .to_string()
            .contains("outside the user home")
    );
}

#[test]
fn existing_variable_and_command_overrides_are_preserved_and_block_the_plan() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_fnm(root, "1.39.0", "v22.22.0", 0);
    let original = b"export FNM_NODE_DIST_MIRROR='https://private.example/node'\neval \"$(fnm env --shell bash --node-dist-mirror https://another.example/node)\"\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = FnmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime = runtime(root, environment("/bin/bash"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let error = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap_err();
    assert!(error.to_string().contains("outside the MirrorSwitch block"));
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn persistent_environment_must_be_initialized_or_explicitly_selected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_fnm(root, "1.39.0", "v22.22.0", 0);
    write(root, "/home/developer/.bashrc", b"# no fnm setup\n");
    let adapter = FnmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime_value = runtime(root, environment("/bin/bash"));

    let error = adapter.detect(&context, &runtime_value).unwrap_err();
    assert!(error.to_string().contains("does not initialize fnm"));

    let mut explicit = environment("/bin/bash");
    explicit.insert(
        "PROFILE".into(),
        "/home/developer/.config/fnm-env.sh".into(),
    );
    let runtime_value = runtime(root, explicit);
    let detected = adapter.detect(&context, &runtime_value).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_value,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert_eq!(
        current.documents[0].path,
        Path::new("/home/developer/.config/fnm-env.sh")
    );
}

#[test]
fn incompatible_list_remote_protocol_is_rejected_during_detection() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    executable(
        root,
        "/usr/bin/fnm",
        r#"#!/bin/sh
case "$*" in
  "--version") printf 'fnm 1.39.0\n' ;;
  "list-remote --help") printf '%s\n' '--filter --node-dist-mirror --arch' ;;
  *) exit 73 ;;
esac
"#
        .into(),
    );
    write(
        root,
        "/home/developer/.bashrc",
        b"eval \"$(fnm env --shell bash)\"\n",
    );
    let adapter = FnmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime = runtime(root, environment("/bin/bash"));

    let error = adapter.detect(&context, &runtime).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("lacks required protocol controls: --latest")
    );
}

#[test]
fn failed_remote_protocol_query_restores_the_original_profile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_fnm(root, "1.39.0", "v22.22.0", 79);
    let original = b"eval \"$(fnm env --shell bash)\"\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = FnmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment("/bin/bash"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("fnm shell profile should change")
    };

    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn embedded_catalog_activates_five_complete_fnm_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog.tools.iter().find(|tool| tool.id == "fnm").unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "fnm")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 5);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud", "nju", "tuna", "ustc"])
    );
    for candidate in candidates {
        assert_eq!(candidate.upstream_id, NODE_UPSTREAM);
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [
                OperatingSystem::Linux,
                OperatingSystem::Macos,
                OperatingSystem::Windows,
            ]
        );
        assert_eq!(candidate.compatibility.architectures.len(), 2);
        assert_eq!(candidate.probes.len(), 3);
        assert!(
            candidate
                .probes
                .iter()
                .all(|probe| probe.endpoint_role == EndpointRole::Releases)
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.method == HttpMethod::Get)
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.path == "/index.tab")
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.path.contains("SHASUMS256.txt"))
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.path.contains("{artifact_filename}"))
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.contains.as_deref() == Some("{artifact_filename}"))
        );
    }
}
