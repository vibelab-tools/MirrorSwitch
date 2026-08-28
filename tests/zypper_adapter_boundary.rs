#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{ZypperAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

fn context(root: &Path, distribution: &str, architecture: Architecture) -> SystemContext {
    let version = match distribution {
        "opensuse-leap" => "15.6",
        "opensuse-tumbleweed" => "20260826",
        _ => unreachable!(),
    };
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(version.into()),
            version_codename: None,
            id_like: vec!["opensuse".into(), "suse".into()],
        }),
        root: root.to_path_buf(),
    }
}

fn install_zypper(root: &Path, refresh_exit: i32) {
    let path = root.join("usr/bin/zypper");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'zypper 1.14.98'; exit 0; fi\nif [ \"$1\" = \"--non-interactive\" ] && [ \"$2\" = \"refresh\" ] && [ \"$3\" = \"--force\" ]; then exit {refresh_exit}; fi\nexit 64\n"
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
}

fn write_repo(root: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = root.join("etc/zypp/repos.d").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn selection(upstream: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("test-{upstream}"),
        tool_id: "zypper".into(),
        upstream_id: upstream.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 6,
        selected_at_unix_ms: 987,
        user_override: false,
    }
}

#[test]
fn leap_keeps_repo_policy_and_selects_main_update_and_packman_independently() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_zypper(root, 0);
    let oss = b"[repo-oss]\nname=Main Repository\nenabled=1\nautorefresh=1\nbaseurl=http://download.opensuse.org/distribution/leap/$releasever/repo/oss/\npriority=99\ngpgcheck=1\ntype=rpm-md\nkeeppackages=0\n";
    let update = b"[repo-update]\nname=Main Update Repository\nenabled=1\nautorefresh=1\nbaseurl=http://download.opensuse.org/update/leap/$releasever/oss/\npriority=90\ngpgcheck=1\n";
    let extras = b"[packman]\nname=Packman\nenabled=1\nautorefresh=0\nbaseurl=https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Leap_$releasever/\npriority=70\ngpgcheck=1\n\n[nvidia]\nname=NVIDIA\nenabled=1\nautorefresh=1\nbaseurl=https://download.nvidia.com/opensuse/leap/$releasever/\npriority=80\ngpgcheck=1\n";
    let oss_path = write_repo(root, "repo-oss.repo", oss);
    let update_path = write_repo(root, "repo-update.repo", update);
    let extras_path = write_repo(root, "third-party.repo", extras);
    let context = context(root, "opensuse-leap", Architecture::X86_64);
    let adapter = ZypperAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("zypper 1.14.98"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let oss_source = current
        .sources
        .iter()
        .find(|source| source.metadata["section"] == ["repo-oss"])
        .unwrap();
    assert_eq!(oss_source.metadata["priority"], ["99"]);
    assert_eq!(oss_source.metadata["autorefresh"], ["1"]);
    assert_eq!(oss_source.metadata["gpgcheck"], ["1"]);
    assert_eq!(oss_source.metadata["type"], ["rpm-md"]);
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        [
            "opensuse--repository-metadata",
            "opensuse-update--repository-metadata",
            "packman--repository-metadata"
        ]
    );
    assert_eq!(
        request.probe_contexts["opensuse--repository-metadata"][0]["repository_path"],
        "distribution/leap/15.6/repo/oss/"
    );
    assert_eq!(
        request.probe_contexts["opensuse-update--repository-metadata"][0]["repository_path"],
        "leap/15.6/oss/"
    );
    assert_eq!(
        request.probe_contexts["packman--repository-metadata"][0]["repository_path"],
        "suse/openSUSE_Leap_15.6/"
    );

    let selections = [
        selection(
            "opensuse--repository-metadata",
            "https://mirrors.aliyun.com/opensuse/",
        ),
        selection(
            "opensuse-update--repository-metadata",
            "https://mirrors.nju.edu.cn/opensuse/update",
        ),
        selection(
            "packman--repository-metadata",
            "https://mirrors.ustc.edu.cn/packman/",
        ),
    ];
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    assert_eq!(plan.changes.len(), 3);
    let combined = plan
        .changes
        .iter()
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(combined.contains(
        "baseurl=https://mirrors.aliyun.com/opensuse/distribution/leap/$releasever/repo/oss/"
    ));
    assert!(
        combined
            .contains("baseurl=https://mirrors.nju.edu.cn/opensuse/update/leap/$releasever/oss/")
    );
    assert!(
        combined.contains(
            "baseurl=https://mirrors.ustc.edu.cn/packman/suse/openSUSE_Leap_$releasever/"
        )
    );
    assert!(combined.contains("baseurl=https://download.nvidia.com/opensuse/leap/$releasever/"));
    assert!(combined.contains("priority=70"));
    assert!(combined.contains("autorefresh=0"));
    assert!(combined.contains("gpgcheck=1"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Zypper plan should change three repository files")
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
            .plan(&context, &updated, &selections)
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
    assert_eq!(fs::read(oss_path).unwrap(), oss);
    assert_eq!(fs::read(update_path).unwrap(), update);
    assert_eq!(fs::read(extras_path).unwrap(), extras);
}

#[test]
fn tumbleweed_arm64_keeps_ports_and_updates_distinct_and_restores_on_failure() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_zypper(root, 9);
    let ports = b"[repo-oss]\nname=openSUSE-Tumbleweed-Ports-Oss\nenabled=1\nautorefresh=1\nbaseurl=http://download.opensuse.org/ports/aarch64/tumbleweed/repo/oss/\npriority=99\ngpgcheck=1\n";
    let update = b"[repo-update]\nname=openSUSE-Tumbleweed-Update\nenabled=1\nautorefresh=1\nbaseurl=http://download.opensuse.org/update/tumbleweed/\npriority=99\ngpgcheck=1\n";
    let ports_path = write_repo(root, "repo-oss.repo", ports);
    let update_path = write_repo(root, "repo-update.repo", update);
    let codec_path = write_repo(
        root,
        "repo-openh264.repo",
        b"[repo-openh264]\nenabled=1\nbaseurl=http://codecs.opensuse.org/openh264/openSUSE_Tumbleweed\ngpgcheck=1\n",
    );
    let context = context(root, "opensuse-tumbleweed", Architecture::Arm64);
    let adapter = ZypperAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert!(current.sources.iter().any(|source| {
        source.url.contains("codecs.opensuse.org") && source.upstream_id.is_none()
    }));
    assert_eq!(
        request.required_upstreams,
        [
            "opensuse-ports--repository-metadata",
            "opensuse-update--repository-metadata"
        ]
    );
    assert_eq!(
        request.probe_contexts["opensuse-ports--repository-metadata"][0]["repository_path"],
        "aarch64/tumbleweed/repo/oss/"
    );
    assert_eq!(
        request.probe_contexts["opensuse-update--repository-metadata"][0]["repository_path"],
        "tumbleweed/"
    );
    let plan = adapter
        .plan(
            &context,
            &current,
            &[
                selection(
                    "opensuse-ports--repository-metadata",
                    "https://mirrors.nju.edu.cn/opensuse/ports",
                ),
                selection(
                    "opensuse-update--repository-metadata",
                    "https://mirrors.nju.edu.cn/opensuse/update",
                ),
            ],
        )
        .unwrap();
    assert_eq!(plan.changes.len(), 2);
    let combined = plan
        .changes
        .iter()
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(combined.contains(
        "baseurl=https://mirrors.nju.edu.cn/opensuse/ports/aarch64/tumbleweed/repo/oss/"
    ));
    assert!(combined.contains("baseurl=https://mirrors.nju.edu.cn/opensuse/update/tumbleweed/"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Zypper ports plan should change repository files")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(ports_path).unwrap(), ports);
    assert_eq!(fs::read(update_path).unwrap(), update);
    assert_eq!(
        fs::read(codec_path).unwrap(),
        b"[repo-openh264]\nenabled=1\nbaseurl=http://codecs.opensuse.org/openh264/openSUSE_Tumbleweed\ngpgcheck=1\n"
    );
}

#[test]
fn tumbleweed_x86_64_uses_the_tumbleweed_upstream_not_leap_or_ports() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_zypper(root, 0);
    write_repo(
        root,
        "repo-oss.repo",
        b"[repo-oss]\nenabled=1\nautorefresh=1\nbaseurl=http://download.opensuse.org/tumbleweed/repo/oss/\ngpgcheck=1\n",
    );
    let context = context(root, "opensuse-tumbleweed", Architecture::X86_64);
    let adapter = ZypperAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();

    assert_eq!(
        request.required_upstreams,
        ["opensuse-tumbleweed--repository-metadata"]
    );
    assert_eq!(
        request.probe_contexts["opensuse-tumbleweed--repository-metadata"][0]["repository_path"],
        "tumbleweed/repo/oss/"
    );
}

#[test]
fn embedded_catalog_has_distinct_zypper_upstreams_with_repomd_probes() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "zypper"
                && matches!(
                    candidate.upstream_id.as_str(),
                    "opensuse--repository-metadata"
                        | "opensuse-update--repository-metadata"
                        | "opensuse-tumbleweed--repository-metadata"
                        | "opensuse-ports--repository-metadata"
                        | "packman--repository-metadata"
                )
        })
        .collect::<Vec<_>>();

    assert_eq!(candidates.len(), 17);
    assert!(candidates.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.probes.len() == 1
            && candidate.probes[0].path == "/{repository_path}repodata/repomd.xml"
            && candidate.probes[0].contains.as_deref() == Some("<repomd")
    }));
    assert!(candidates.iter().all(|candidate| {
        candidate.upstream_id != "opensuse-ports--repository-metadata"
            || candidate.compatibility.architectures == [Architecture::Arm64]
    }));
}
