#![cfg(unix)]

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{MacPortsAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const ALIYUN_ROOT: &str = "https://mirrors.aliyun.com/macports";
const NJU_ROOT: &str = "https://mirrors.nju.edu.cn/macports";

fn context(root: &Path, architecture: Architecture, macos: &str) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Macos,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "macos".into(),
            version_id: Some(macos.into()),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: root.into(),
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

fn install(root: &Path, darwin: u32, build_from_source: &str, sync_exit: i32) {
    write(
        root,
        "/opt/local/etc/macports/macports.conf",
        format!(
            "prefix /opt/local\nsources_conf /opt/local/etc/macports/sources.conf\narchive_sites_conf /opt/local/etc/macports/archive_sites.conf\npubkeys_conf /opt/local/etc/macports/pubkeys.conf\nvariants_conf /opt/local/etc/macports/variants.conf\nbuildfromsource {build_from_source}\nportarchivetype tbz2\n"
        )
        .as_bytes(),
    );
    write(
        root,
        "/opt/local/etc/macports/sources.conf",
        b"# preserve local precedence\nfile:///Users/test/custom-ports [nosync]\nrsync://rsync.macports.org/macports/release/tarballs/ports.tar [default]\n",
    );
    write(
        root,
        "/opt/local/etc/macports/archive_sites.conf",
        b"# preserve private archive group\nname private_archives\nurls https://private.example/macports/packages\ntype tbz2\n",
    );
    write(
        root,
        "/opt/local/etc/macports/pubkeys.conf",
        b"# trusted archive keys\n/opt/local/share/macports/macports-pubkey.pem\n/opt/local/share/macports/private.pem\n",
    );
    write(
        root,
        "/opt/local/share/macports/macports-pubkey.pem",
        b"fixture public key\n",
    );
    write(
        root,
        "/opt/local/etc/macports/variants.conf",
        b"+universal\n",
    );
    let sources = root.join("opt/local/etc/macports/sources.conf");
    let archives = root.join("opt/local/etc/macports/archive_sites.conf");
    let calls = root.join("port-calls");
    executable(
        root,
        "/opt/local/bin/port",
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\nif [ \"$1\" = version ]; then echo 'Version: 2.11.6'; exit 0; fi\nif [ \"$1\" = sync ]; then grep -q 'mirrors.*macports/release/tarballs/ports.tar' '{sources}' || exit 65; if [ '{sync_exit}' -ne 0 ]; then echo 'signature verification failed at https://build:fixture-only@private.example/tree' >&2; fi; exit {sync_exit}; fi\nif [ \"$1\" = -q ] && [ \"$2\" = info ] && [ \"$3\" = zlib ]; then echo 'zlib @1.3.2_0'; exit 0; fi\nif [ \"$1\" = -q ] && [ \"$2\" = archivefetch ] && [ \"$3\" = zlib ]; then grep -q 'mirrors.*macports/packages' '{archives}'; exit 0; fi\nexit 64\n",
            calls = calls.display(),
            sources = sources.display(),
            archives = archives.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/uname",
        format!("#!/bin/sh\n[ \"$1\" = -r ] && echo '{darwin}.6.0'\n"),
    );
    executable(
        root,
        "/usr/bin/sw_vers",
        format!(
            "#!/bin/sh\n[ \"$1\" = -productVersion ] && echo '{}.6.1'\n",
            darwin - 9
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(
        root,
        vec![PathBuf::from("/opt/local/bin"), PathBuf::from("/usr/bin")],
    )
    .with_home("/Users/test")
    .with_environment(Default::default())
}

fn selection(root: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "macports-test".into(),
        tool_id: "macports".into(),
        upstream_id: "macports--static-files".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: format!("{root}/release/tarballs/"),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: format!("{root}/packages/"),
            },
        ],
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn arm64_system_plan_preserves_custom_sources_keys_variants_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install(root, 24, "ifneeded", 0);
    let sources = root.join("opt/local/etc/macports/sources.conf");
    let archives = root.join("opt/local/etc/macports/archive_sites.conf");
    let variants = root.join("opt/local/etc/macports/variants.conf");
    let original_sources = fs::read(&sources).unwrap();
    let original_archives = fs::read(&archives).unwrap();
    let original_variants = fs::read(&variants).unwrap();
    let context = context(root, Architecture::Arm64, "15");
    let adapter = MacPortsAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.11.6"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|item| item.contains("Darwin 24"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(current.sources.iter().any(|source| {
        source.url == "redacted://custom-macports-source" && source.metadata["position"] == ["0"]
    }));
    assert!(current.sources.iter().any(|source| {
        source.url == "redacted://custom-macports-archive"
            && source.metadata["name"] == ["private_archives"]
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts["macports--static-files"][0];
    assert_eq!(probe["macports_os_major"], "24");
    assert_eq!(probe["macports_index_arch"], "arm");
    assert_eq!(
        probe["macports_archive"],
        "zlib-1.3.2_0.darwin_24.arm64.tbz2"
    );
    assert_eq!(
        probe["macports_archive_digest"],
        "6df2d10ff4522a67610b49d872ba19342c92793a31b874c314c912a3bd452072"
    );
    let choice = [selection(ALIYUN_ROOT)];
    let plan = adapter.plan(&context, &current, &choice).unwrap();
    assert_eq!(plan.changes.len(), 2);
    assert!(plan.requires_elevation);
    assert_eq!(plan.service_impact, ServiceImpact::ReloadRequired);
    assert!(
        String::from_utf8(plan.changes[0].new_contents.clone())
            .unwrap()
            .starts_with("# preserve local precedence\nfile:///Users/test/custom-ports [nosync]\n")
    );

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MacPorts plan should change two configuration files")
    };
    assert!(fs::read_to_string(&sources).unwrap().contains(ALIYUN_ROOT));
    assert!(fs::read_to_string(&archives).unwrap().contains(ALIYUN_ROOT));
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let calls = fs::read_to_string(root.join("port-calls")).unwrap();
    assert!(calls.lines().any(|line| line == "sync"));
    assert!(calls.contains("-q info zlib"));
    assert!(calls.contains("-q archivefetch zlib"));
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &choice)
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
    assert_eq!(fs::read(sources).unwrap(), original_sources);
    assert_eq!(fs::read(archives).unwrap(), original_archives);
    assert_eq!(fs::read(variants).unwrap(), original_variants);
}

#[test]
fn x86_64_darwin23_uses_matching_index_archive_and_signature() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install(root, 23, "never", 0);
    let context = context(root, Architecture::X86_64, "14");
    let adapter = MacPortsAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts["macports--static-files"][0];
    assert_eq!(probe["macports_index_arch"], "i386");
    assert_eq!(
        probe["macports_archive"],
        "zlib-1.3.2_0.darwin_23.x86_64.tbz2"
    );
    assert_eq!(
        probe["macports_signature_digest"],
        "faa6c60f465a297949c6c90ba487e48582b718435b04361ffe21a150701c4f97"
    );
    let plan = adapter
        .plan(&context, &current, &[selection(NJU_ROOT)])
        .unwrap();
    assert!(
        plan.changes
            .iter()
            .all(|change| !String::from_utf8_lossy(&change.new_contents).contains("arm64"))
    );
}

#[test]
fn verification_failure_restores_and_unsafe_signature_or_binary_policy_is_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install(root, 24, "ifneeded", 9);
    let sources = root.join("opt/local/etc/macports/sources.conf");
    let archives = root.join("opt/local/etc/macports/archive_sites.conf");
    let original_sources = fs::read(&sources).unwrap();
    let original_archives = fs::read(&archives).unwrap();
    let context = context(root, Architecture::Arm64, "15");
    let adapter = MacPortsAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(ALIYUN_ROOT)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MacPorts plan should apply before sync failure")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert!(
        error
            .to_string()
            .contains("signature verification failed at <url>")
    );
    assert!(!error.to_string().contains("fixture-only"));
    assert_eq!(fs::read(&sources).unwrap(), original_sources);
    assert_eq!(fs::read(&archives).unwrap(), original_archives);

    install(root, 24, "always", 0);
    assert!(adapter.detect(&context, &runtime).is_err());
    install(root, 24, "ifneeded", 0);
    fs::write(
        root.join("opt/local/etc/macports/pubkeys.conf"),
        b"/custom/key.pem\n",
    )
    .unwrap();
    assert!(adapter.detect(&context, &runtime).is_err());
}

#[test]
fn embedded_catalog_has_three_paired_signed_tree_and_archive_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "macports")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::System]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "macports"
                && candidate.upstream_id == "macports--static-files"
                && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "nju", "sjtug"])
    );
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Macos]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Metadata)
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
            && candidate.probes.len() == 5
            && candidate.probes[2].path.contains("{macports_os_major}")
            && candidate.probes[3].sha256.as_deref() == Some("{macports_archive_digest}")
            && candidate.probes[4].sha256.as_deref() == Some("{macports_signature_digest}")
    }));
}
