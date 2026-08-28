#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{YumAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

fn context(root: &Path, version: &str, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: "centos".into(),
            version_id: Some(version.into()),
            version_codename: None,
            id_like: vec!["rhel".into(), "fedora".into()],
        }),
        root: root.to_path_buf(),
    }
}

fn install_yum(root: &Path, version: &str, clean_exit: i32, makecache_exit: i32) {
    let path = root.join("usr/bin/yum");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo '{version}'; exit 0 ;;\n  clean) exit {clean_exit} ;;\n  makecache) exit {makecache_exit} ;;\nesac\nexit 64\n"
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

fn write_repo(root: &Path, contents: &[u8]) -> PathBuf {
    let path = root.join("etc/yum.repos.d/CentOS-Base.repo");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn selection(upstream: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("test-{upstream}"),
        tool_id: "yum".into(),
        upstream_id: upstream.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 4,
        selected_at_unix_ms: 456,
        user_override: false,
    }
}

#[test]
fn centos_7_x86_64_moves_active_base_repositories_to_vault_and_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_yum(root, "3.4.3", 0, 0);
    let original = b"[base]\n\
name=CentOS-$releasever - Base\n\
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7\n\
priority=1\n\
\n\
[updates]\n\
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=updates\n\
gpgcheck=1\n\
\n\
[extras]\n\
baseurl=http://mirror.centos.org/centos/$releasever/extras/$basearch/\n\
gpgcheck=1\n\
\n\
[centosplus]\n\
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=centosplus\n\
enabled=0\n\
gpgcheck=1\n\
\n\
[epel]\n\
baseurl=https://download.fedoraproject.org/pub/epel/$releasever/$basearch/\n\
enabled=1\n\
gpgcheck=1\n\
priority=20\n";
    let repo_path = write_repo(root, original);
    let context = context(root, "7", Architecture::X86_64);
    let adapter = YumAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("3.4.3"));
    assert!(detected.evidence[0].contains("legacy YUM 3"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        ["centos-vault--repository-metadata"]
    );
    assert_eq!(
        request.probe_contexts["centos-vault--repository-metadata"]
            .iter()
            .map(|context| context["repository_path"].as_str())
            .collect::<Vec<_>>(),
        [
            "7.9.2009/extras/x86_64/",
            "7.9.2009/os/x86_64/",
            "7.9.2009/updates/x86_64/"
        ]
    );

    let selections = [selection(
        "centos-vault--repository-metadata",
        "https://mirrors.aliyun.com/centos-vault/",
    )];
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    let preview = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        preview.contains("baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/os/$basearch/")
    );
    assert!(
        preview.contains(
            "baseurl=https://mirrors.aliyun.com/centos-vault/7.9.2009/updates/$basearch/"
        )
    );
    assert!(preview.contains("repo=centosplus"));
    assert!(preview.contains("download.fedoraproject.org/pub/epel/$releasever/$basearch/"));
    assert!(preview.contains("priority=20"));
    assert!(preview.contains("gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("YUM plan should change the repository file")
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
    assert_eq!(fs::read(repo_path).unwrap(), original);
}

#[test]
fn centos_7_arm64_uses_altarch_and_failed_refresh_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_yum(root, "3.4.3", 0, 9);
    let original = b"[base]\nmirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os\nenabled=1\ngpgcheck=1\n";
    let repo_path = write_repo(root, original);
    let context = context(root, "7", Architecture::Arm64);
    let adapter = YumAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        ["centos-altarch--repository-metadata"]
    );
    assert_eq!(
        request.probe_contexts["centos-altarch--repository-metadata"][0]["repository_path"],
        "7/os/aarch64/"
    );
    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection(
                "centos-altarch--repository-metadata",
                "https://repo.huaweicloud.com/centos-altarch/",
            )],
        )
        .unwrap();
    let preview = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        preview.contains("baseurl=https://repo.huaweicloud.com/centos-altarch/7/os/$basearch/")
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("YUM plan should change the repository file")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("yum makecache failed"));
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(repo_path).unwrap(), original);
}

#[test]
fn dnf_backed_yum_and_rhel_are_not_treated_as_legacy_centos_yum() {
    let directory = tempdir().unwrap();
    install_yum(directory.path(), "4.14.0", 0, 0);
    let stream_context = context(directory.path(), "9", Architecture::X86_64);
    let runtime = runtime(directory.path());
    assert!(
        YumAdapter
            .detect(&stream_context, &runtime)
            .unwrap()
            .is_none()
    );

    let mut rhel_context = context(directory.path(), "7", Architecture::X86_64);
    rhel_context.distribution.as_mut().unwrap().id = "rhel".into();
    let error = YumAdapter.detect(&rhel_context, &runtime).unwrap_err();
    assert!(error.to_string().contains("no verified rules for rhel"));
}

#[test]
fn centos_6_uses_its_final_vault_release() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_yum(root, "3.2.29", 0, 0);
    write_repo(
        root,
        b"[base]\nmirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os\nenabled=1\ngpgcheck=1\n",
    );
    let context = context(root, "6.10", Architecture::X86_64);
    let adapter = YumAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();

    assert_eq!(
        request.probe_contexts["centos-vault--repository-metadata"][0]["repository_path"],
        "6.10/os/x86_64/"
    );
}

#[test]
fn embedded_catalog_has_arch_specific_yum_archive_probes() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "yum"
                && matches!(
                    candidate.upstream_id.as_str(),
                    "centos-vault--repository-metadata" | "centos-altarch--repository-metadata"
                )
        })
        .collect::<Vec<_>>();

    assert_eq!(candidates.len(), 8);
    assert!(candidates.iter().all(|candidate| {
        candidate.delivery_mode == mirrorswitch::catalog::DeliveryMode::Mirror
            && candidate.probes.len() == 1
            && candidate.probes[0].path == "/{repository_path}repodata/repomd.xml"
            && candidate.probes[0].contains.as_deref() == Some("<repomd")
            && match candidate.upstream_id.as_str() {
                "centos-vault--repository-metadata" => {
                    candidate.compatibility.architectures == [Architecture::X86_64]
                }
                "centos-altarch--repository-metadata" => {
                    candidate.compatibility.architectures == [Architecture::Arm64]
                }
                _ => false,
            }
    }));
}
