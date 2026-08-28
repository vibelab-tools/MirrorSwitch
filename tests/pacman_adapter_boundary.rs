#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PacmanAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

fn context(root: &Path, distribution: &str, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: None,
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: root.to_path_buf(),
    }
}

fn install_pacman(root: &Path, refresh_exit: i32) {
    let path = root.join("usr/bin/pacman");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'Pacman v7.0.0'; exit 0; fi\nif [ \"$1\" = \"-Syy\" ] && [ \"$2\" = \"--noconfirm\" ]; then exit {refresh_exit}; fi\nexit 64\n"
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

fn write(root: &Path, logical: &str, contents: &[u8]) -> PathBuf {
    let path = root.join(logical.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn selection(upstream: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("test-{upstream}"),
        tool_id: "pacman".into(),
        upstream_id: upstream.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 3,
        selected_at_unix_ms: 789,
        user_override: false,
    }
}

#[test]
fn arch_x86_64_preserves_repository_order_and_rewrites_each_selected_upstream() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pacman(root, 0);
    let config = b"[options]\n\
Architecture = auto\n\
SigLevel = Required DatabaseOptional\n\
\n\
[core]\n\
Include = /etc/pacman.d/mirrorlist\n\
\n\
[extra]\n\
Include = /etc/pacman.d/mirrorlist\n\
\n\
[archlinuxcn]\n\
SigLevel = Optional TrustAll\n\
Server = https://repo.archlinuxcn.org/$arch\n\
\n\
[blackarch]\n\
Include = /etc/pacman.d/blackarch-mirrorlist\n\
\n\
[private]\n\
Include = /etc/pacman.d/private-mirrorlist\n";
    let mirrorlist = b"# Worldwide\nServer = https://geo.mirror.pkgbuild.com/$repo/os/$arch\nServer = https://mirror.rackspace.com/archlinux/$repo/os/$arch\n#Server = https://disabled.invalid/$repo/os/$arch\n";
    let blackarch = b"Server = https://www.blackarch.org/blackarch/$repo/os/$arch\nServer = https://mirror.example.invalid/blackarch/$repo/os/$arch\n";
    let private = b"Server = https://private.example.invalid/$repo/$arch\n";
    let config_path = write(root, "/etc/pacman.conf", config);
    let mirrorlist_path = write(root, "/etc/pacman.d/mirrorlist", mirrorlist);
    let blackarch_path = write(root, "/etc/pacman.d/blackarch-mirrorlist", blackarch);
    let private_path = write(root, "/etc/pacman.d/private-mirrorlist", private);
    let context = context(root, "arch", Architecture::X86_64);
    let adapter = PacmanAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(current.documents.len(), 3);
    assert!(
        !current
            .files
            .iter()
            .any(|path| path.ends_with("private-mirrorlist"))
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        [
            "archlinux--repository-metadata",
            "archlinuxcn--repository-metadata",
            "blackarch--repository-metadata"
        ]
    );
    assert_eq!(
        request.probe_contexts["archlinux--repository-metadata"]
            .iter()
            .map(|context| context["repository_path"].as_str())
            .collect::<Vec<_>>(),
        ["core/os/x86_64/core.db", "extra/os/x86_64/extra.db"]
    );
    assert_eq!(
        request.probe_contexts["archlinuxcn--repository-metadata"][0]["repository_path"],
        "x86_64/archlinuxcn.db"
    );
    assert_eq!(
        request.probe_contexts["blackarch--repository-metadata"][0]["repository_path"],
        "blackarch/os/x86_64/blackarch.db"
    );

    let selections = [
        selection(
            "archlinux--repository-metadata",
            "https://mirrors.ustc.edu.cn/archlinux/",
        ),
        selection(
            "archlinuxcn--repository-metadata",
            "https://mirrors.ustc.edu.cn/archlinuxcn/",
        ),
        selection(
            "blackarch--repository-metadata",
            "https://mirrors.ustc.edu.cn/blackarch/",
        ),
    ];
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    assert_eq!(plan.changes.len(), 3);
    let config_preview = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with("pacman.conf"))
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .unwrap();
    assert!(config_preview.find("[core]").unwrap() < config_preview.find("[extra]").unwrap());
    assert!(
        config_preview.find("[extra]").unwrap() < config_preview.find("[archlinuxcn]").unwrap()
    );
    assert!(config_preview.contains("SigLevel = Required DatabaseOptional"));
    assert!(config_preview.contains("SigLevel = Optional TrustAll"));
    assert!(config_preview.contains("Server = https://mirrors.ustc.edu.cn/archlinuxcn/$arch"));
    assert!(config_preview.contains("Include = /etc/pacman.d/private-mirrorlist"));

    let mirrorlist_preview = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with("pacman.d/mirrorlist"))
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .unwrap();
    assert_eq!(
        mirrorlist_preview
            .lines()
            .filter(|line| line.starts_with("Server ="))
            .collect::<Vec<_>>(),
        ["Server = https://mirrors.ustc.edu.cn/archlinux/$repo/os/$arch"]
    );
    assert_eq!(
        mirrorlist_preview
            .matches("# MirrorSwitch original:")
            .count(),
        2
    );
    assert!(mirrorlist_preview.contains("#Server = https://disabled.invalid"));

    let blackarch_preview = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with("blackarch-mirrorlist"))
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .unwrap();
    assert!(
        blackarch_preview.contains("Server = https://mirrors.ustc.edu.cn/blackarch/$repo/os/$arch")
    );

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Pacman plan should change three configuration files")
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
    assert_eq!(fs::read(config_path).unwrap(), config);
    assert_eq!(fs::read(mirrorlist_path).unwrap(), mirrorlist);
    assert_eq!(fs::read(blackarch_path).unwrap(), blackarch);
    assert_eq!(fs::read(private_path).unwrap(), private);
}

#[test]
fn arch_linux_arm_uses_its_own_layout_and_failed_refresh_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pacman(root, 9);
    let config = b"[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[alarm]\nInclude = /etc/pacman.d/mirrorlist\n\n[archlinuxcn]\nServer = https://repo.archlinuxcn.org/$arch\n\n[blackarch]\nServer = https://www.blackarch.org/blackarch/$repo/os/$arch\n";
    let mirrorlist = b"Server = http://mirror.archlinuxarm.org/$arch/$repo\n";
    let config_path = write(root, "/etc/pacman.conf", config);
    let mirrorlist_path = write(root, "/etc/pacman.d/mirrorlist", mirrorlist);
    let context = context(root, "archarm", Architecture::Arm64);
    let adapter = PacmanAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        current.sources.iter().all(|source| {
            source.upstream_id.as_deref() != Some("blackarch--repository-metadata")
        })
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        [
            "archlinuxarm--repository-metadata",
            "archlinuxcn--repository-metadata"
        ]
    );
    assert_eq!(
        request.probe_contexts["archlinuxarm--repository-metadata"]
            .iter()
            .map(|context| context["repository_path"].as_str())
            .collect::<Vec<_>>(),
        ["aarch64/alarm/alarm.db", "aarch64/core/core.db"]
    );
    let plan = adapter
        .plan(
            &context,
            &current,
            &[
                selection(
                    "archlinuxarm--repository-metadata",
                    "https://mirrors.aliyun.com/archlinuxarm/",
                ),
                selection(
                    "archlinuxcn--repository-metadata",
                    "https://mirrors.aliyun.com/archlinuxcn/",
                ),
            ],
        )
        .unwrap();
    let mirrorlist_preview = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with("pacman.d/mirrorlist"))
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .unwrap();
    assert!(
        mirrorlist_preview.contains("Server = https://mirrors.aliyun.com/archlinuxarm/$arch/$repo")
    );
    let config_preview = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with("pacman.conf"))
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .unwrap();
    assert!(config_preview.contains("https://www.blackarch.org/blackarch/$repo/os/$arch"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Pacman ARM plan should change configuration")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(config_path).unwrap(), config);
    assert_eq!(fs::read(mirrorlist_path).unwrap(), mirrorlist);
}

#[test]
fn one_include_cannot_be_shared_across_distinct_upstreams() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pacman(root, 0);
    write(
        root,
        "/etc/pacman.conf",
        b"[core]\nInclude = /etc/pacman.d/shared\n[archlinuxcn]\nInclude = /etc/pacman.d/shared\n",
    );
    write(
        root,
        "/etc/pacman.d/shared",
        b"Server = https://example.invalid/$repo/$arch\n",
    );
    let context = context(root, "arch", Architecture::X86_64);
    let runtime = runtime(root);
    let detected = PacmanAdapter.detect(&context, &runtime).unwrap().unwrap();

    let error = PacmanAdapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("shared by incompatible repositories")
    );
}

#[test]
fn embedded_catalog_has_distinct_arch_repository_models_and_head_probes() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "pacman"
                && matches!(
                    candidate.upstream_id.as_str(),
                    "archlinux--repository-metadata"
                        | "archlinuxarm--repository-metadata"
                        | "archlinuxcn--repository-metadata"
                        | "blackarch--repository-metadata"
                )
        })
        .collect::<Vec<_>>();

    assert_eq!(candidates.len(), 22);
    assert!(candidates.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.probes.len() == 1
            && candidate.probes[0].method == HttpMethod::Head
            && candidate.probes[0].path == "/{repository_path}"
            && candidate.probes[0].expected_status == [200]
    }));
    assert!(candidates.iter().all(|candidate| {
        match candidate.upstream_id.as_str() {
            "archlinux--repository-metadata" | "blackarch--repository-metadata" => {
                candidate.compatibility.architectures == [Architecture::X86_64]
            }
            "archlinuxarm--repository-metadata" => {
                candidate.compatibility.architectures == [Architecture::Arm64]
            }
            "archlinuxcn--repository-metadata" => {
                candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            }
            _ => false,
        }
    }));
}
