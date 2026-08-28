#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{ApkAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

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
            id: "alpine".into(),
            version_id: Some("3.22.1".into()),
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

fn install_apk(root: &Path, update_exit: i32) {
    let path = write(
        root,
        "/sbin/apk",
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'apk-tools 2.14.8'; exit 0; fi\nif [ \"$1\" = \"update\" ] && [ \"$2\" = \"--no-progress\" ]; then exit {update_exit}; fi\nexit 64\n"
        )
        .as_bytes(),
    );
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/sbin")])
}

fn selection(endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "alpine-test".into(),
        tool_id: "apk".into(),
        upstream_id: "alpine--repository-metadata".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn x86_64_host_preserves_tags_branches_comments_and_custom_repositories() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apk(root, 0);
    let original = b"# installed repositories\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community # stable\n@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing\n/media/cdrom/apks\nhttps://packages.example.internal/alpine/custom\n# https://dl-cdn.alpinelinux.org/alpine/edge/community\n";
    let path = write(root, "/etc/apk/repositories", original);
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let adapter = ApkAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("apk-tools 2.14.8"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(current.sources.len(), 5);
    assert_eq!(
        current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some("alpine--repository-metadata"))
            .count(),
        3
    );
    let testing = current
        .sources
        .iter()
        .find(|source| source.metadata.get("repository") == Some(&vec!["testing".into()]))
        .unwrap();
    assert_eq!(testing.metadata["branch"], ["edge"]);
    assert_eq!(testing.metadata["tag"], ["@testing"]);
    assert_eq!(testing.metadata["architecture"], ["x86_64"]);

    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let contexts = &request.probe_contexts["alpine--repository-metadata"];
    assert_eq!(contexts.len(), 3);
    assert!(contexts.iter().any(|probe| {
        probe["branch"] == "edge"
            && probe["repository"] == "testing"
            && probe["architecture"] == "x86_64"
    }));
    assert!(contexts.iter().any(|probe| {
        probe["branch"] == "v3.22"
            && probe["repository"] == "main"
            && probe["architecture"] == "x86_64"
    }));

    let selection = [selection("https://mirrors.aliyun.com/alpine/")];
    let plan = adapter.plan(&context, &current, &selection).unwrap();
    assert_eq!(plan.changes.len(), 1);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.aliyun.com/alpine/v3.22/main"));
    assert!(rendered.contains("https://mirrors.aliyun.com/alpine/v3.22/community # stable"));
    assert!(rendered.contains("@testing https://mirrors.aliyun.com/alpine/edge/testing"));
    assert!(rendered.contains("/media/cdrom/apks"));
    assert!(rendered.contains("https://packages.example.internal/alpine/custom"));
    assert!(rendered.contains("# https://dl-cdn.alpinelinux.org/alpine/edge/community"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APK plan should update the repository file")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &selection)
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
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn aarch64_container_uses_aarch64_probe_and_failed_update_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apk(root, 7);
    let original = b"https://dl-cdn.alpinelinux.org/alpine/v3.22/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community\n";
    let path = write(root, "/etc/apk/repositories", original);
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let adapter = ApkAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert!(
        request.probe_contexts["alpine--repository-metadata"]
            .iter()
            .all(|probe| probe["architecture"] == "aarch64")
    );
    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection("https://mirrors.nju.edu.cn/alpine/")],
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APK plan should update aarch64 container repositories")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn custom_only_configuration_is_not_rewritten() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apk(root, 0);
    write(
        root,
        "/etc/apk/repositories",
        b"/srv/apk/packages\nhttps://packages.example.internal/alpine/main\n",
    );
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let adapter = ApkAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        current
            .sources
            .iter()
            .all(|source| source.upstream_id.is_none())
    );
    let error = adapter
        .selection_request(&context, &detected, &current)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no recognized Alpine repositories")
    );
}

#[test]
fn embedded_catalog_has_six_arch_compatible_apkindex_probes() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "apk"
                && candidate.upstream_id == "alpine--repository-metadata"
                && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.compatibility.distributions[0].id == "alpine"
            && candidate.probes.len() == 1
            && candidate.probes[0].path == "/{branch}/{repository}/{architecture}/APKINDEX.tar.gz"
            && candidate.probes[0].expected_status == [200]
    }));
}
