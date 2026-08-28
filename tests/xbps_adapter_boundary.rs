#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{XbpsAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: "void".into(),
            version_id: None,
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

fn install_xbps(root: &Path, arch: &str, sync_exit: i32, query_exit: i32) {
    executable(
        root,
        "/usr/bin/xbps-uhelper",
        format!("#!/bin/sh\nif [ \"$1\" = arch ]; then echo '{arch}'; exit 0; fi\nexit 64\n"),
    );
    executable(
        root,
        "/usr/bin/xbps-install",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'XBPS: 0.60.7'; exit 0; fi\nif [ \"$1\" = -S ]; then exit {sync_exit}; fi\nexit 64\n"
        ),
    );
    executable(
        root,
        "/usr/bin/xbps-query",
        format!("#!/bin/sh\nif [ \"$1\" = -L ]; then exit {query_exit}; fi\nexit 64\n"),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "void-test".into(),
        tool_id: "xbps".into(),
        upstream_id: "void--repository-metadata".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn x86_64_glibc_uses_effective_override_order_and_preserves_custom_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_xbps(root, "x86_64", 0, 0);
    let main = b"# main\nrepository=https://repo-default.voidlinux.org/current\n";
    let system_nonfree = b"repository=https://repo-default.voidlinux.org/current/nonfree\n";
    let user_nonfree =
        b"# override\nrepository=https://repo-fastly.voidlinux.org/current/nonfree\n";
    let custom = b"repository=/srv/xbps/custom\nrepository=https://packages.example/custom\n";
    let system_main = write(root, "/usr/share/xbps.d/00-repository-main.conf", main);
    write(
        root,
        "/usr/share/xbps.d/10-repository-nonfree.conf",
        system_nonfree,
    );
    let user_nonfree_path = write(root, "/etc/xbps.d/10-repository-nonfree.conf", user_nonfree);
    let custom_path = write(root, "/etc/xbps.d/20-custom.conf", custom);
    let context = context(root, Architecture::X86_64);
    let adapter = XbpsAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("XBPS: 0.60.7"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(current.documents.len(), 3);
    assert!(
        current
            .documents
            .iter()
            .all(|document| document.path
                != Path::new("/usr/share/xbps.d/10-repository-nonfree.conf"))
    );
    assert!(
        current.documents.iter().any(|document| {
            document.path == Path::new("/etc/xbps.d/10-repository-nonfree.conf")
        })
    );
    assert_eq!(current.sources.len(), 4);
    assert_eq!(
        current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some("void--repository-metadata"))
            .count(),
        2
    );
    assert!(
        current
            .sources
            .iter()
            .any(|source| { source.url == "/srv/xbps/custom" && source.upstream_id.is_none() })
    );

    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probes = &request.probe_contexts["void--repository-metadata"];
    assert_eq!(probes.len(), 2);
    assert!(probes.iter().all(|probe| probe["xbps_arch"] == "x86_64"));
    assert!(
        probes
            .iter()
            .any(|probe| probe["repository_path"] == "current")
    );
    assert!(
        probes
            .iter()
            .any(|probe| probe["repository_path"] == "current/nonfree")
    );

    let selection = [selection("https://mirrors.nju.edu.cn/voidlinux/")];
    let plan = adapter.plan(&context, &current, &selection).unwrap();
    assert_eq!(plan.changes.len(), 2);
    let generated_main = root.join("etc/xbps.d/00-repository-main.conf");
    let main_change = plan
        .changes
        .iter()
        .find(|change| change.target == generated_main)
        .unwrap();
    assert!(main_change.old_contents.is_none());
    assert!(
        String::from_utf8_lossy(&main_change.new_contents)
            .contains("repository=https://mirrors.nju.edu.cn/voidlinux/current")
    );
    let nonfree_change = plan
        .changes
        .iter()
        .find(|change| change.target == user_nonfree_path)
        .unwrap();
    assert!(
        String::from_utf8_lossy(&nonfree_change.new_contents)
            .contains("https://mirrors.nju.edu.cn/voidlinux/current/nonfree")
    );

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("XBPS plan should create and update overrides")
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
    assert!(!generated_main.exists());
    assert_eq!(fs::read(system_main).unwrap(), main);
    assert_eq!(fs::read(user_nonfree_path).unwrap(), user_nonfree);
    assert_eq!(fs::read(custom_path).unwrap(), custom);
}

#[test]
fn x86_64_musl_keeps_musl_path_and_failed_sync_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_xbps(root, "x86_64-musl", 8, 0);
    let original = b"repository=https://repo-default.voidlinux.org/current/musl\nrepository=https://repo-default.voidlinux.org/current/musl/nonfree\n";
    let path = write(root, "/etc/xbps.d/00-repositories.conf", original);
    let context = context(root, Architecture::X86_64);
    let adapter = XbpsAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert!(
        request.probe_contexts["void--repository-metadata"]
            .iter()
            .all(|probe| probe["xbps_arch"] == "x86_64-musl")
    );
    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection("https://mirrors.tuna.tsinghua.edu.cn/voidlinux/")],
        )
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("/voidlinux/current/musl"));
    assert!(rendered.contains("/voidlinux/current/musl/nonfree"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("XBPS musl plan should update repositories")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn aarch64_glibc_and_musl_share_layout_but_probe_distinct_archives() {
    for arch in ["aarch64", "aarch64-musl"] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_xbps(root, arch, 0, 0);
        write(
            root,
            "/usr/share/xbps.d/00-repository-main.conf",
            b"repository=https://repo-default.voidlinux.org/current/aarch64\nrepository=https://repo-default.voidlinux.org/current/aarch64/nonfree\n",
        );
        let context = context(root, Architecture::Arm64);
        let adapter = XbpsAdapter;
        let runtime = runtime(root);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::System)
            .unwrap();
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        assert!(
            request.probe_contexts["void--repository-metadata"]
                .iter()
                .all(|probe| probe["xbps_arch"] == arch)
        );
        let plan = adapter
            .plan(
                &context,
                &current,
                &[selection("https://mirror.sjtu.edu.cn/voidlinux/")],
            )
            .unwrap();
        assert_eq!(plan.changes.len(), 1);
        assert!(
            String::from_utf8_lossy(&plan.changes[0].new_contents)
                .contains("/voidlinux/current/aarch64/nonfree")
        );
    }

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_xbps(root, "aarch64", 0, 0);
    write(
        root,
        "/etc/xbps.d/00-repository-main.conf",
        b"repository=https://repo-default.voidlinux.org/current\n",
    );
    let context = context(root, Architecture::Arm64);
    let adapter = XbpsAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("does not match target aarch64"));
}

#[test]
fn embedded_catalog_has_three_variant_aware_repodata_probes() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "xbps"
                && candidate.upstream_id == "void--repository-metadata"
                && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.compatibility.distributions[0].id == "void"
            && candidate.probes.len() == 1
            && candidate.probes[0].path == "/{repository_path}/{xbps_arch}-repodata"
            && candidate.probes[0].expected_status == [200]
    }));
}
