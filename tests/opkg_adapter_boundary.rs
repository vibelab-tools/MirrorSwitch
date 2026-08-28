#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{OpkgAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const OPENWRT_UPSTREAM: &str = "openwrt--repository-metadata";
const IMMORTALWRT_UPSTREAM: &str = "immortalwrt--repository-metadata";
const SJTUG: &str = "https://mirror.sjtu.edu.cn/openwrt";
const USTC_IMMORTAL: &str = "https://mirrors.ustc.edu.cn/immortalwrt";

fn context(root: &Path, distribution: &str, version: &str, arch: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture: arch,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(version.into()),
            version_codename: None,
            id_like: vec!["lede".into(), "openwrt".into()],
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

fn install_opkg(root: &Path, selected: &str, arch: &str, update_exit: i32) {
    let distfeeds = root.join("etc/opkg/distfeeds.conf");
    let policy = root.join("etc/opkg.conf");
    executable(
        root,
        "/bin/opkg",
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'opkg version test-2024';;\n  print-architecture) printf 'arch all 1\\narch noarch 1\\narch {arch} 10\\n';;\n  update) grep -qs '{selected}' '{distfeeds}' && grep -qs '^option check_signature$' '{policy}' || exit 65; exit {update_exit};;\n  list) echo 'base-files - 1 - OpenWrt base files';;\n  *) exit 64;;\nesac\n",
            distfeeds = distfeeds.display(),
            policy = policy.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/bin")])
}

fn selection(upstream: &str, url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "opkg-test".into(),
        tool_id: "opkg".into(),
        upstream_id: upstream.into(),
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
fn openwrt_x86_plan_preserves_feed_order_custom_policy_and_is_idempotent() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opkg(root, SJTUG, "x86_64", 0);
    write(
        root,
        "/etc/os-release",
        b"NAME=\"OpenWrt\"\nID=\"openwrt\"\nVERSION_ID=\"24.10.6\"\nOPENWRT_BOARD=\"x86/64\"\nOPENWRT_ARCH=\"x86_64\"\n",
    );
    write(
        root,
        "/etc/opkg.conf",
        b"dest root /\nlists_dir ext /var/opkg-lists\noption check_signature\n",
    );
    let original = b"# release feeds\nsrc/gz openwrt_core https://downloads.openwrt.org/releases/24.10.6/targets/x86/64/packages\nsrc/gz vendor https://packages.example/router\nsrc/gz openwrt_kmods https://downloads.openwrt.org/releases/24.10.6/targets/x86/64/kmods/6.6.127-1-build\nsrc/gz openwrt_base https://downloads.openwrt.org/releases/24.10.6/packages/x86_64/base\n";
    let distfeeds = write(root, "/etc/opkg/distfeeds.conf", original);
    let custom = b"# custom feeds\nsrc/gz local https://custom.example/packages\n";
    let customfeeds = write(root, "/etc/opkg/customfeeds.conf", custom);
    let context = context(root, "openwrt", "24.10.6", Architecture::X86_64);
    let adapter = OpkgAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("opkg version test-2024"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(
        current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(OPENWRT_UPSTREAM))
            .count(),
        3
    );
    let core = current
        .sources
        .iter()
        .find(|source| source.metadata["feed_name"] == ["openwrt_core"])
        .unwrap();
    assert_eq!(core.metadata["version"], ["24.10.6"]);
    assert_eq!(core.metadata["target"], ["x86"]);
    assert_eq!(core.metadata["subtarget"], ["64"]);
    assert_eq!(core.metadata["opkg_arch"], ["x86_64"]);
    assert_eq!(
        core.metadata["architecture_priority"],
        ["all:1", "noarch:1", "x86_64:10"]
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [OPENWRT_UPSTREAM]);
    assert_eq!(request.probe_contexts[OPENWRT_UPSTREAM].len(), 3);

    let selected = [selection(OPENWRT_UPSTREAM, SJTUG)];
    let cli_plan = adapter.plan(&context, &current, &selected).unwrap();
    let config_plan = adapter.plan(&context, &current, &selected).unwrap();
    let tui_plan = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert!(cli_plan.requires_elevation);
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert_eq!(rendered.matches(SJTUG).count(), 3);
    assert!(rendered.contains("src/gz vendor https://packages.example/router"));
    assert_eq!(fs::read(&customfeeds).unwrap(), custom);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("OpenWrt feeds should change")
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
            .plan(&context, &updated, &selected)
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
    assert_eq!(fs::read(distfeeds).unwrap(), original);
}

#[test]
fn immortalwrt_arm64_query_failure_restores_exact_target_and_architecture() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opkg(root, USTC_IMMORTAL, "aarch64_generic", 7);
    write(
        root,
        "/etc/os-release",
        b"ID=immortalwrt\nVERSION_ID=24.10.5\nOPENWRT_BOARD=armsr/armv8\nOPENWRT_ARCH=aarch64_generic\n",
    );
    write(root, "/etc/opkg.conf", b"option check_signature\n");
    let original = b"src/gz immortalwrt_core https://downloads.immortalwrt.org/releases/24.10.5/targets/armsr/armv8/packages\nsrc/gz immortalwrt_base https://downloads.immortalwrt.org/releases/24.10.5/packages/aarch64_generic/base\n";
    let distfeeds = write(root, "/etc/opkg/distfeeds.conf", original);
    let context = context(root, "immortalwrt", "24.10.5", Architecture::Arm64);
    let adapter = OpkgAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [IMMORTALWRT_UPSTREAM]);
    assert!(
        request.probe_contexts[IMMORTALWRT_UPSTREAM]
            .iter()
            .any(|item| item["repository_path"].contains("packages/aarch64_generic/base"))
    );
    let selected = [selection(IMMORTALWRT_UPSTREAM, USTC_IMMORTAL)];
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("ImmortalWrt feeds should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(distfeeds).unwrap(), original);
}

#[test]
fn signature_cross_distribution_release_target_and_cpu_mismatches_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opkg(root, SJTUG, "x86_64", 0);
    write(
        root,
        "/etc/os-release",
        b"ID=openwrt\nVERSION_ID=24.10.6\nOPENWRT_BOARD=x86/64\nOPENWRT_ARCH=x86_64\n",
    );
    write(root, "/etc/opkg.conf", b"option check_signature 0\n");
    let feeds = write(
        root,
        "/etc/opkg/distfeeds.conf",
        b"src/gz wrong https://downloads.immortalwrt.org/releases/24.10.5/targets/x86/64/packages\n",
    );
    let context = context(root, "openwrt", "24.10.6", Architecture::X86_64);
    let adapter = OpkgAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("check_signature"));

    write(root, "/etc/opkg.conf", b"option check_signature\n");
    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("belongs to immortalwrt"));

    fs::write(
        &feeds,
        b"src/gz wrong https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/packages\n",
    )
    .unwrap();
    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("does not match release"));

    fs::write(
        feeds,
        b"src/gz wrong https://downloads.openwrt.org/releases/24.10.6/targets/armsr/armv8/packages\n",
    )
    .unwrap();
    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("does not match target"));

    write(
        root,
        "/etc/os-release",
        b"ID=openwrt\nVERSION_ID=24.10.6\nOPENWRT_BOARD=x86/64\nOPENWRT_ARCH=aarch64_generic\n",
    );
    let error = adapter.detect(&context, &runtime).unwrap_err();
    assert!(error.to_string().contains("does not match X86_64"));
}

#[test]
fn embedded_catalog_has_distribution_and_arch_checked_opkg_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let openwrt = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "opkg" && candidate.upstream_id == OPENWRT_UPSTREAM
        })
        .collect::<Vec<_>>();
    let immortalwrt = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "opkg" && candidate.upstream_id == IMMORTALWRT_UPSTREAM
        })
        .collect::<Vec<_>>();
    assert_eq!(openwrt.len(), 5);
    assert_eq!(immortalwrt.len(), 2);
    assert!(openwrt.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.compatibility.distributions[0].id == "openwrt"
            && candidate.probes.len() == 2
            && candidate.probes[0].method == HttpMethod::Head
            && candidate.probes[0].path == "/{repository_path}/Packages.gz"
            && candidate.probes[1].method == HttpMethod::Head
            && candidate.probes[1].path == "/{repository_path}/Packages.sig"
    }));
    assert!(immortalwrt.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.compatibility.distributions[0].id == "immortalwrt"
    }));
}
