#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PortageAdapter, compiled_adapter_allowlist},
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
            id: "gentoo".into(),
            version_id: Some("2.18".into()),
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

fn install_commands(root: &Path, emerge_info_exit: i32, rsync_exit: i32) {
    let emerge = write(
        root,
        "/usr/bin/emerge",
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'Portage 3.0.81.3'; exit 0 ;;\n  --info) exit {emerge_info_exit} ;;\nesac\nexit 64\n"
        )
        .as_bytes(),
    );
    let rsync = write(
        root,
        "/usr/bin/rsync",
        format!("#!/bin/sh\nexit {rsync_exit}\n").as_bytes(),
    );
    for path in [emerge, rsync] {
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
}

fn distfiles_selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "distfiles-test".into(),
        tool_id: "portage".into(),
        upstream_id: "gentoo--repository-metadata".into(),
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

fn sync_selection(http: &str, rsync: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "sync-test".into(),
        tool_id: "portage".into(),
        upstream_id: "gentoo-portage--repository-metadata".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: http.into(),
            },
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Rsync,
                url: rsync.into(),
            },
        ],
        latency_ms: 7,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn amd64_rewrites_distfiles_and_only_the_main_rsync_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_commands(root, 0, 0);
    let make = b"COMMON_FLAGS=\"-O2 -pipe\"\nGENTOO_MIRRORS='https://old-one.example/gentoo https://old-two.example/gentoo/' # keep\n";
    let repos = b"[DEFAULT]\nmain-repo = gentoo\n\n[gentoo]\nlocation = /var/db/repos/gentoo\nsync-type = rsync\nsync-uri = rsync://rsync.gentoo.org/gentoo-portage\nauto-sync = yes\nsync-rsync-verify-metamanifest = yes\nsync-openpgp-key-path = /usr/share/openpgp-keys/gentoo-release.asc\n\n[local-overlay]\nlocation = /var/db/repos/local\nsync-type = git\nsync-uri = https://git.example/private-overlay.git\nauto-sync = no\n";
    let make_path = write(root, "/etc/portage/make.conf", make);
    let repos_path = write(root, "/etc/portage/repos.conf/00-gentoo.conf", repos);
    write(
        root,
        "/etc/portage/make.profile/parent",
        b"../../../../../../profiles/default/linux/amd64/23.0\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PortageAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("Portage 3.0.81.3"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(
        current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some("gentoo--repository-metadata"))
            .count(),
        2
    );
    let main = current
        .sources
        .iter()
        .find(|source| source.upstream_id.as_deref() == Some("gentoo-portage--repository-metadata"))
        .unwrap();
    assert_eq!(main.metadata["profile_architecture"], ["amd64"]);
    assert_eq!(main.metadata["main_repository"], ["true"]);
    assert_eq!(main.metadata["sync_type"], ["rsync"]);
    assert_eq!(main.metadata["auto_sync"], ["yes"]);
    assert_eq!(main.metadata["sync_rsync_verify_metamanifest"], ["yes"]);
    assert!(current.sources.iter().any(|source| {
        source.metadata.get("repository").map(Vec::as_slice) == Some(&["local-overlay".into()])
            && source.upstream_id.is_none()
    }));

    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        [
            "gentoo--repository-metadata",
            "gentoo-portage--repository-metadata"
        ]
    );
    assert_eq!(
        request.probe_contexts["gentoo--repository-metadata"][0]["gentoo_arch"],
        "amd64"
    );
    assert_eq!(
        request.probe_contexts["gentoo-portage--repository-metadata"][0]["gentoo_arch"],
        "amd64"
    );

    let selections = [
        distfiles_selection("https://mirrors.ustc.edu.cn/gentoo/"),
        sync_selection(
            "https://mirrors.nju.edu.cn/gentoo-portage/",
            "rsync://mirrors.nju.edu.cn/gentoo-portage/",
        ),
    ];
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    assert_eq!(plan.changes.len(), 2);
    let combined = plan
        .changes
        .iter()
        .map(|change| String::from_utf8(change.new_contents.clone()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(combined.contains("GENTOO_MIRRORS=\"https://mirrors.ustc.edu.cn/gentoo\" # keep"));
    assert!(combined.contains("sync-uri = rsync://mirrors.nju.edu.cn/gentoo-portage"));
    assert!(
        combined.contains("sync-openpgp-key-path = /usr/share/openpgp-keys/gentoo-release.asc")
    );
    assert!(combined.contains("sync-rsync-verify-metamanifest = yes"));
    assert!(combined.contains("sync-uri = https://git.example/private-overlay.git"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Portage plan should update make.conf and repos.conf")
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
    assert_eq!(fs::read(make_path).unwrap(), make);
    assert_eq!(fs::read(repos_path).unwrap(), repos);
}

#[test]
fn arm64_uses_packaged_default_and_failed_read_only_check_removes_override() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_commands(root, 0, 9);
    let make = b"COMMON_FLAGS=\"-O2 -pipe\"\n";
    let defaults = b"[DEFAULT]\nmain-repo = gentoo\n\n[gentoo]\nlocation = /var/db/repos/gentoo\nsync-type = rsync\nsync-uri = rsync://rsync.gentoo.org/gentoo-portage\nauto-sync = yes\nsync-openpgp-keyserver = hkps://keys.gentoo.org\nsync-git-verify-commit-signature = true\n";
    let make_path = write(root, "/etc/portage/make.conf", make);
    let defaults_path = write(root, "/usr/share/portage/config/repos.conf", defaults);
    let context = context(root, Architecture::Arm64);
    let adapter = PortageAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts["gentoo--repository-metadata"][0]["gentoo_arch"],
        "arm64"
    );
    assert_eq!(
        request.probe_contexts["gentoo-portage--repository-metadata"][0]["gentoo_arch"],
        "arm64"
    );
    let selections = [
        distfiles_selection("https://mirrors.tuna.tsinghua.edu.cn/gentoo/"),
        sync_selection(
            "https://mirrors.tuna.tsinghua.edu.cn/gentoo-portage/",
            "rsync://mirrors.tuna.tsinghua.edu.cn/gentoo-portage/",
        ),
    ];
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    let generated = root.join("etc/portage/repos.conf/gentoo.conf");
    let generated_change = plan
        .changes
        .iter()
        .find(|change| change.target == generated)
        .unwrap();
    assert!(generated_change.old_contents.is_none());
    let rendered = String::from_utf8(generated_change.new_contents.clone()).unwrap();
    assert!(rendered.contains("sync-openpgp-keyserver = hkps://keys.gentoo.org"));
    assert!(rendered.contains("sync-git-verify-commit-signature = true"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Portage plan should create a repository override")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert!(!generated.exists());
    assert_eq!(fs::read(make_path).unwrap(), make);
    assert_eq!(fs::read(defaults_path).unwrap(), defaults);
}

#[test]
fn git_main_and_rsync_overlay_are_not_treated_as_replaceable_rsync_main() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_commands(root, 0, 0);
    write(
        root,
        "/etc/portage/make.conf",
        b"GENTOO_MIRRORS=\"https://distfiles.gentoo.org\"\n",
    );
    let repos = b"[DEFAULT]\nmain-repo = gentoo\n\n[gentoo]\nlocation = /var/db/repos/gentoo\nsync-type = git\nsync-uri = https://github.com/gentoo-mirror/gentoo.git\nsync-git-verify-commit-signature = true\n\n[community]\nlocation = /var/db/repos/community\nsync-type = rsync\nsync-uri = rsync://mirrors.nju.edu.cn/gentoo-portage/\n";
    let repos_path = write(root, "/etc/portage/repos.conf/repos.conf", repos);
    let context = context(root, Architecture::X86_64);
    let adapter = PortageAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, ["gentoo--repository-metadata"]);
    assert!(
        current
            .sources
            .iter()
            .filter(|source| source.metadata.contains_key("repository"))
            .all(|source| source.upstream_id.is_none())
    );
    let plan = adapter
        .plan(
            &context,
            &current,
            &[distfiles_selection("https://mirrors.aliyun.com/gentoo/")],
        )
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert_ne!(plan.changes[0].target, repos_path);
    assert_eq!(fs::read(repos_path).unwrap(), repos);
}

#[test]
fn embedded_catalog_has_arch_probes_and_rsync_only_for_published_sync_modules() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "portage" && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 7);
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.compatibility.distributions[0].id == "gentoo"
    }));
    let distfiles = candidates
        .iter()
        .filter(|candidate| candidate.upstream_id == "gentoo--repository-metadata")
        .collect::<Vec<_>>();
    assert_eq!(distfiles.len(), 4);
    assert!(distfiles.iter().all(|candidate| {
        candidate
            .probes
            .iter()
            .any(|probe| probe.path == "/distfiles/")
            && candidate.probes.iter().any(|probe| {
                probe.path
                    == "/releases/{gentoo_arch}/autobuilds/latest-stage3-{stage3_arch}-openrc.txt"
            })
    }));
    let sync = candidates
        .iter()
        .filter(|candidate| candidate.upstream_id == "gentoo-portage--repository-metadata")
        .collect::<Vec<_>>();
    assert_eq!(sync.len(), 3);
    assert!(sync.iter().all(|candidate| {
        candidate
            .endpoints
            .iter()
            .any(|endpoint| endpoint.protocol == Protocol::Rsync)
            && candidate
                .probes
                .iter()
                .any(|probe| probe.path == "/profiles/repo_name")
            && candidate
                .probes
                .iter()
                .any(|probe| probe.path == "/profiles/arch/{gentoo_arch}/")
    }));
}
