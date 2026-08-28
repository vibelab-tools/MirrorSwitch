#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{DnfAdapter, compiled_adapter_allowlist},
    catalog::{Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

fn context(root: &Path, distribution: &str, architecture: Architecture) -> SystemContext {
    let (version, id_like) = match distribution {
        "fedora" => ("42", Vec::new()),
        "rocky" | "almalinux" => ("9.4", vec!["rhel".into(), "centos".into()]),
        _ => unreachable!(),
    };
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(version.into()),
            version_codename: None,
            id_like,
        }),
        root: root.to_path_buf(),
    }
}

fn install_dnf(root: &Path, command: &str, makecache_exit: i32) {
    let path = root.join("usr/bin").join(command);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '{command} 5.2.0'; exit 0; fi\nexit {makecache_exit}\n"
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

fn selection(upstream: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("test-{upstream}"),
        tool_id: "dnf".into(),
        upstream_id: upstream.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn write_repo(root: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = root.join("etc/yum.repos.d").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn fedora_dnf5_converts_metalink_preserves_policy_and_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, "dnf5", 0);
    let original = b"[fedora]\n\
name=Fedora $releasever - $basearch\n\
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch\n\
enabled=1\n\
gpgcheck=1\n\
repo_gpgcheck=0\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch\n\
\n\
[updates]\n\
baseurl=https://download.fedoraproject.org/pub/fedora/linux/updates/$releasever/Everything/$basearch/\n\
enabled=1\n\
gpgcheck=1\n\
\n\
[copr:third-party]\n\
baseurl=https://download.copr.fedorainfracloud.org/results/example/repo/\n\
enabled=1\n\
gpgcheck=1\n";
    let repo_path = write_repo(root, "fedora.repo", original);
    let context = context(root, "fedora", Architecture::X86_64);
    let adapter = DnfAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.evidence.iter().any(|item| item.contains("DNF5")));
    let current = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, ["fedora--repository-metadata"]);
    assert_eq!(
        request.probe_contexts["fedora--repository-metadata"]
            .iter()
            .map(|context| context["repository_path"].as_str())
            .collect::<Vec<_>>(),
        [
            "releases/42/Everything/x86_64/os/",
            "updates/42/Everything/x86_64/"
        ]
    );

    let selections = [selection(
        "fedora--repository-metadata",
        "https://mirrors.tuna.tsinghua.edu.cn/fedora/",
    )];
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    let preview = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        preview.contains("# MirrorSwitch original: metalink=https://mirrors.fedoraproject.org")
    );
    assert!(preview.contains(
        "baseurl=https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/$releasever/Everything/$basearch/os/"
    ));
    assert!(preview.contains("gpgcheck=1"));
    assert!(preview.contains("repo_gpgcheck=0"));
    assert!(preview.contains("https://download.copr.fedorainfracloud.org/results/example/repo/"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("DNF plan should change the repository file")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
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
fn rocky_arm64_dnf4_failed_makecache_restores_mirrorlist_conversion() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, "dnf", 9);
    let original = b"[baseos]\n\
name=Rocky Linux $releasever - BaseOS\n\
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-$releasever\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9\n\
\n\
[epel]\n\
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$releasever&arch=$basearch\n\
enabled=1\n\
gpgcheck=1\n";
    let repo_path = write_repo(root, "rocky.repo", original);
    let context = context(root, "rocky", Architecture::Arm64);
    let adapter = DnfAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.evidence.iter().any(|item| item.contains("DNF4")));
    let current = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, ["rocky--repository-metadata"]);
    assert_eq!(
        request.probe_contexts["rocky--repository-metadata"][0]["repository_path"],
        "9/BaseOS/aarch64/os/"
    );

    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection(
                "rocky--repository-metadata",
                "https://mirrors.ustc.edu.cn/rocky/",
            )],
        )
        .unwrap();
    let preview = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        preview
            .contains("baseurl=https://mirrors.ustc.edu.cn/rocky/$releasever/BaseOS/$basearch/os/")
    );
    assert!(preview.contains("repo=epel-$releasever"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("DNF plan should change the repository file")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(repo_path).unwrap(), original);
}

#[test]
fn fedora_rocky_and_alma_expand_releasever_and_basearch_for_both_architectures() {
    for distribution in ["fedora", "rocky", "almalinux"] {
        for architecture in [Architecture::X86_64, Architecture::Arm64] {
            let directory = tempdir().unwrap();
            let root = directory.path();
            install_dnf(root, "dnf", 0);
            let (section, location) = match distribution {
                "fedora" => (
                    "fedora",
                    "metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch",
                ),
                "rocky" => (
                    "baseos",
                    "mirrorlist=https://mirrors.rockylinux.org/mirrorlist?repo=BaseOS-$releasever&arch=$basearch",
                ),
                "almalinux" => (
                    "baseos",
                    "mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/baseos",
                ),
                _ => unreachable!(),
            };
            write_repo(
                root,
                "base.repo",
                format!("[{section}]\n{location}\nenabled=1\ngpgcheck=1\n").as_bytes(),
            );
            let context = context(root, distribution, architecture);
            let adapter = DnfAdapter;
            let runtime = runtime(root);
            let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
            let current = adapter
                .read_current(
                    &context,
                    &runtime,
                    &detected,
                    mirrorswitch::catalog::ConfigurationScope::System,
                )
                .unwrap();
            let request = adapter
                .selection_request(&context, &detected, &current)
                .unwrap();
            let path =
                &request.probe_contexts[&request.required_upstreams[0]][0]["repository_path"];
            let expected_arch = match architecture {
                Architecture::X86_64 => "x86_64",
                Architecture::Arm64 => "aarch64",
            };
            assert!(path.contains(expected_arch));
            assert!(path.starts_with(if distribution == "fedora" {
                "releases/42/"
            } else {
                "9/"
            }));
        }
    }
}

#[test]
fn embedded_catalog_has_repomd_probes_for_supported_dnf_upstreams() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates: Vec<_> = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "dnf"
                && matches!(
                    candidate.upstream_id.as_str(),
                    "fedora--repository-metadata"
                        | "rocky--repository-metadata"
                        | "almalinux--repository-metadata"
                )
        })
        .collect();
    assert_eq!(candidates.len(), 15);
    assert!(candidates.iter().all(|candidate| {
        candidate.probes.len() == 1
            && candidate.probes[0].path == "/{repository_path}repodata/repomd.xml"
            && candidate.probes[0].contains.as_deref() == Some("<repomd")
    }));
}

#[test]
fn centos_is_not_conflated_with_the_verified_enterprise_linux_upstreams() {
    let directory = tempdir().unwrap();
    let context = SystemContext {
        os: OperatingSystem::Linux,
        architecture: Architecture::X86_64,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "centos".into(),
            version_id: Some("9".into()),
            version_codename: None,
            id_like: vec!["rhel".into()],
        }),
        root: directory.path().to_path_buf(),
    };
    let runtime = runtime(directory.path());

    let error = DnfAdapter.detect(&context, &runtime).unwrap_err();

    assert!(error.to_string().contains("no verified rules for centos"));
}
