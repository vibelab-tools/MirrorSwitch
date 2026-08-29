#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{NvmAdapter, compiled_adapter_allowlist},
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
const IOJS_UPSTREAM: &str = "iojs--release-artifacts";
const ALIYUN_NODE: &str = "https://mirrors.aliyun.com/nodejs-release/";
const HUAWEI_IOJS: &str = "https://repo.huaweicloud.com/iojs/";

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

fn install_nvm(root: &Path, current: &str, remote_exit: i32, git_checkout: bool) {
    write(
        root,
        "/home/developer/.nvm/nvm.sh",
        b"# fake sourced nvm function\n",
    );
    if git_checkout {
        write(
            root,
            "/home/developer/.nvm/.git/HEAD",
            b"ref: refs/heads/master\n",
        );
    }
    executable(
        root,
        "/usr/bin/bash",
        format!(
            r#"#!/bin/sh
command_text=$2
case "$command_text" in
  *"ls-remote"*"iojs"*)
    printf '%s' "$command_text" | grep -F 'https://repo.huaweicloud.com/iojs' >/dev/null || exit 71
    [ {remote_exit} -eq 0 ] || exit {remote_exit}
    printf 'iojs-v3.3.1\n'
    ;;
  *"ls-remote"*)
    printf '%s' "$command_text" | grep -F 'https://mirrors.aliyun.com/nodejs-release' >/dev/null || exit 72
    [ {remote_exit} -eq 0 ] || exit {remote_exit}
    printf 'v24.1.0\n'
    ;;
  *"--version"*) printf '0.40.6\n' ;;
  *"current"*) printf '{current}\n' ;;
  *"ls"*"--no-colors"*) printf 'v20.19.5\niojs-v3.3.1\n' ;;
  *) exit 73 ;;
esac
"#,
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("SHELL".into(), "/bin/bash".into()),
        ("NVM_DIR".into(), "/home/developer/.nvm".into()),
    ])
}

fn selection(upstream: &str, provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("{provider}-{upstream}"),
        tool_id: "nvm".into(),
        upstream_id: upstream.into(),
        provider_id: provider.into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Releases,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn selections() -> Vec<MirrorSelection> {
    vec![
        selection(NODE_UPSTREAM, "aliyun", ALIYUN_NODE),
        selection(IOJS_UPSTREAM, "huaweicloud", HUAWEI_IOJS),
    ]
}

#[test]
fn selected_bash_profile_is_planned_verified_idempotent_and_restorable() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nvm(root, "v22.22.0", 0, true);
    let original = b"# user aliases\nalias ll='ls -l'\nexport NVM_DIR=\"$HOME/.nvm\"\n[ -s \"$NVM_DIR/nvm.sh\" ] && . \"$NVM_DIR/nvm.sh\"\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = NvmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("0.40.6"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("git checkout"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("v22.22.0"))
    );
    assert_eq!(adapter.supported_scopes(), [ConfigurationScope::User]);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [NODE_UPSTREAM, IOJS_UPSTREAM]);
    assert_eq!(request.required_endpoint_roles, [EndpointRole::Releases]);
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Mirror]);
    let node_contexts = &request.probe_contexts[NODE_UPSTREAM];
    assert_eq!(node_contexts.len(), 2);
    assert!(
        node_contexts
            .iter()
            .all(|values| values["version"] == "v22.22.0")
    );
    assert_eq!(
        node_contexts
            .iter()
            .map(|values| values["architecture"].as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["arm64", "x64"])
    );

    let chosen = selections();
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("alias ll='ls -l'"));
    assert!(rendered.contains("NVM_NODEJS_ORG_MIRROR='https://mirrors.aliyun.com/nodejs-release'"));
    assert!(rendered.contains("NVM_IOJS_ORG_MIRROR='https://repo.huaweicloud.com/iojs'"));
    assert_eq!(rendered.matches("MirrorSwitch nvm mirrors >>>").count(), 1);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("nvm shell profile should change")
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
    assert_eq!(fs::read(&profile).unwrap(), original);
}

#[test]
fn arm64_container_uses_explicit_bash_env_and_a_reviewed_fallback_version() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nvm(root, "none", 0, false);
    let profile = write(
        root,
        "/home/developer/.config/nvm-env.sh",
        b"# container shell\n",
    );
    let mut values = environment();
    values.insert(
        "BASH_ENV".into(),
        "/home/developer/.config/nvm-env.sh".into(),
    );
    let adapter = NvmAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = runtime(root, values);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("script or source checkout"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(
        current.documents[0].path,
        Path::new("/home/developer/.config/nvm-env.sh")
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.context.architecture, Architecture::Arm64);
    assert!(
        request.probe_contexts[NODE_UPSTREAM]
            .iter()
            .all(|values| values["version"] == "v24.1.0")
    );
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("BASH_ENV should change")
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
            .contains("NVM_IOJS_ORG_MIRROR")
    );
}

#[test]
fn unmanaged_mirrors_and_authorization_headers_are_never_redirected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nvm(root, "v22.22.0", 0, true);
    let original = b"export NVM_DIR=\"$HOME/.nvm\"\n. \"$NVM_DIR/nvm.sh\"\nexport NVM_NODEJS_ORG_MIRROR='https://private.example/node'\nexport NVM_AUTH_HEADER='Bearer keep-private'\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = NvmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime_value = runtime(root, environment());

    let detected = adapter.detect(&context, &runtime_value).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_value,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("keep-private"));
    let error = adapter.plan(&context, &current, &selections()).unwrap_err();
    assert!(error.to_string().contains("outside the MirrorSwitch block"));
    assert_eq!(fs::read(&profile).unwrap(), original);

    fs::write(
        &profile,
        b"export NVM_DIR=\"$HOME/.nvm\"\n. \"$NVM_DIR/nvm.sh\"\n",
    )
    .unwrap();
    let mut values = environment();
    values.insert(
        "NVM_AUTH_HEADER".into(),
        "Bearer environment-private".into(),
    );
    let runtime = runtime(root, values);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("environment-private"));
    assert!(
        adapter
            .plan(&context, &current, &selections())
            .unwrap_err()
            .to_string()
            .contains("NVM_AUTH_HEADER")
    );
}

#[test]
fn ambiguous_shell_initialization_requires_an_explicit_profile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nvm(root, "v22.22.0", 0, true);
    let loader = b"export NVM_DIR=\"$HOME/.nvm\"\n. \"$NVM_DIR/nvm.sh\"\n";
    write(root, "/home/developer/.bashrc", loader);
    write(root, "/home/developer/.profile", loader);
    let adapter = NvmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime_value = runtime(root, environment());

    let error = adapter.detect(&context, &runtime_value).unwrap_err();
    assert!(error.to_string().contains("multiple bash profiles"));

    let mut explicit = environment();
    explicit.insert("PROFILE".into(), "/home/developer/.bashrc".into());
    assert!(
        adapter
            .detect(&context, &runtime(root, explicit))
            .unwrap()
            .is_some()
    );
}

#[test]
fn failed_remote_query_restores_the_original_profile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nvm(root, "v22.22.0", 79, true);
    let original = b"export NVM_DIR=\"$HOME/.nvm\"\n. \"$NVM_DIR/nvm.sh\"\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = NvmAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("nvm shell profile should change")
    };

    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn embedded_catalog_activates_only_content_probed_nvm_release_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog.tools.iter().find(|tool| tool.id == "nvm").unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "nvm")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.upstream_id == NODE_UPSTREAM)
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud", "nju", "tuna", "ustc"])
    );
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.upstream_id == IOJS_UPSTREAM)
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<Vec<_>>(),
        ["huaweicloud"]
    );
    for candidate in candidates {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
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
                .any(|probe| probe.path.contains("{architecture}"))
        );
    }
}
