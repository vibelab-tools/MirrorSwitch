#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{CondaAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "anaconda--language-registry";
const USTC: &str = "https://mirrors.ustc.edu.cn/anaconda/";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/anaconda/";

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

fn install_client(
    root: &Path,
    client: &str,
    version: &str,
    selected: &str,
    query_exit: i32,
    sources: &[&str],
) {
    let user = root.join("home/developer/.condarc");
    let source_json = sources
        .iter()
        .map(|path| format!("\"{path}\":{{}}"))
        .collect::<Vec<_>>()
        .join(",");
    let source_lines = sources.join("\\n");
    executable(
        root,
        &format!("/usr/bin/{client}"),
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{client} {version}'; exit 0; fi\nif [ \"$1 $2\" = 'config --show-sources' ]; then printf '{{{source_json}}}\\n'; exit 0; fi\nif [ \"$1 $2\" = 'config sources' ]; then printf '{source_lines}\\n'; exit 0; fi\nif [ \"$1 $2\" = 'config --show' ] || [ \"$1 $2\" = 'config list' ]; then\n  grep -q '{selected}' '{user}' || exit 65\n  printf '{{\"default_channels\":[\"{selected}/pkgs/main\"],\"custom_channels\":{{\"conda-forge\":\"{selected}/cloud\"}}}}\\n'\n  exit 0\nfi\nif [ \"$1\" = search ] || [ \"$1 $2\" = 'repoquery search' ]; then\n  grep -q '{selected}' '{user}' || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  echo '{{\"name\":\"python\",\"version\":\"3.12.9\"}}'\n  exit 0\nfi\nexit 64\n",
            selected = selected.trim_end_matches('/'),
            user = user.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/home/developer")
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "conda-test".into(),
        tool_id: "conda".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Index,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn shared_user_plan_preserves_private_channels_order_tokens_and_priority_for_all_clients() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    for (client, version) in [
        ("conda", "26.7.1"),
        ("mamba", "2.1.1"),
        ("micromamba", "2.1.1"),
    ] {
        install_client(
            root,
            client,
            version,
            USTC,
            0,
            &["/opt/conda/.condarc", "/home/developer/.condarc"],
        );
    }
    write(root, "/opt/conda/.condarc", b"channels:\n  - defaults\n");
    let original = b"channels:\n  - https://reader:secret@private.example/t/path-secret/channel?token=value\n  - defaults\n  - conda-forge\ndefault_channels:\n  - https://repo.anaconda.com/pkgs/main\n  - https://private.example/defaults\n  - https://repo.anaconda.com/pkgs/r\ncustom_channels:\n  internal: https://private.example/cloud\n  conda-forge: https://conda.anaconda.org\nchannel_alias: https://private.example/channels\nchannel_priority: strict\nssl_verify: true\n";
    let user = write(root, "/home/developer/.condarc", original);
    let context = context(root, Architecture::X86_64);
    let adapter = CondaAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.evidence.iter().any(|item| item.contains("conda:")));
    assert!(detected.evidence.iter().any(|item| item.contains("mamba:")));
    assert!(
        detected
            .evidence
            .iter()
            .any(|item| item.contains("micromamba:"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("reader"));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("path-secret"));
    assert!(!serialized.contains("token=value"));
    assert!(current.sources.iter().any(|source| {
        source.metadata["kind"] == ["channel-priority"] && source.url == "strict"
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["subdir"], "linux-64");

    let chosen = [selection(USTC)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.ustc.edu.cn/anaconda/pkgs/main"));
    assert!(rendered.contains("https://mirrors.ustc.edu.cn/anaconda/pkgs/r"));
    assert!(rendered.contains("conda-forge: https://mirrors.ustc.edu.cn/anaconda/cloud"));
    assert!(
        rendered
            .contains("https://reader:secret@private.example/t/path-secret/channel?token=value")
    );
    assert!(rendered.contains("https://private.example/defaults"));
    assert!(rendered.contains("internal: https://private.example/cloud"));
    assert!(rendered.contains("channel_alias: https://private.example/channels"));
    assert!(rendered.contains("channel_priority: strict"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("shared .condarc should change")
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
    adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert_eq!(fs::read(user).unwrap(), original);
}

#[test]
fn arm64_micromamba_is_detected_without_conda_and_failure_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_client(root, "micromamba", "2.1.1", TUNA, 7, &["~/.condarc"]);
    let original = b"channels:\n  - defaults\nchannel_priority: flexible\n";
    let user = write(root, "/home/developer/.condarc", original);
    let context = context(root, Architecture::Arm64);
    let adapter = CondaAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.evidence.len(), 1);
    assert!(detected.evidence[0].contains("micromamba"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[UPSTREAM][0]["subdir"],
        "linux-aarch64"
    );
    assert!(request.probe_contexts[UPSTREAM][0]["representative_package"].contains("h8edadfe"));
    let plan = adapter
        .plan(&context, &current, &[selection(TUNA)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("micromamba .condarc should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(user).unwrap(), original);
}

#[test]
fn environment_override_tls_private_only_and_complex_shapes_are_not_rewritten() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_client(
        root,
        "conda",
        "26.7.1",
        USTC,
        0,
        &["/home/developer/.condarc", "/srv/environment/.condarc"],
    );
    write(
        root,
        "/home/developer/.condarc",
        b"channels:\n  - defaults\n",
    );
    write(
        root,
        "/srv/environment/.condarc",
        b"default_channels:\n  - https://private.example/pkgs/main\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = CondaAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC)])
            .unwrap_err()
            .to_string()
            .contains("environment-level")
    );

    install_client(
        root,
        "conda",
        "26.7.1",
        USTC,
        0,
        &["/home/developer/.condarc"],
    );
    write(
        root,
        "/home/developer/.condarc",
        b"channels:\n  - defaults\nssl_verify: false\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC)])
            .unwrap_err()
            .to_string()
            .contains("TLS")
    );

    write(
        root,
        "/home/developer/.condarc",
        b"channels:\n  - https://private.example/only\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC)])
            .unwrap_err()
            .to_string()
            .contains("only private")
    );

    write(
        root,
        "/home/developer/.condarc",
        b"channels:\n  - defaults\ndefault_channels: [https://repo.anaconda.com/pkgs/main]\n",
    );
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap_err()
            .to_string()
            .contains("inline or aliased")
    );
}

#[test]
fn embedded_catalog_has_three_arch_complete_conda_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "conda" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert!(candidates.iter().all(|candidate| {
        candidate.upstream_id == UPSTREAM
            && candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.compatibility.operating_systems == [OperatingSystem::Linux]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 5
            && candidate
                .probes
                .iter()
                .all(|probe| probe.method == HttpMethod::Get)
            && candidate.probes[1].path.contains("{subdir}")
            && candidate.probes[4]
                .path
                .contains("{representative_package}")
    }));
    let sjtug = catalog
        .candidates
        .iter()
        .find(|candidate| candidate.tool_id == "conda" && candidate.provider_id == "sjtug")
        .unwrap();
    assert!(sjtug.probes.is_empty());
    assert_eq!(sjtug.delivery_mode, DeliveryMode::Unknown);
}
