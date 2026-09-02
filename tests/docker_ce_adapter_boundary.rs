#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{DockerCeAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "docker-ce--repository-metadata";

fn context(
    root: &Path,
    architecture: Architecture,
    distribution: &str,
    version: &str,
    codename: Option<&str>,
    environment: ExecutionEnvironment,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(version.into()),
            version_codename: codename.map(str::to_owned),
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

fn install_docker(root: &Path) {
    executable(
        root,
        "/usr/bin/docker",
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'Docker version 29.7.2, build test'; exit 0; fi\nexit 60\n".into(),
    );
}

fn install_apt(root: &Path, verification_exit: i32) {
    install_docker(root);
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/docker-ce/linux/debian' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: Docker CE mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'docker-ce:'\necho '  Candidate: 5:29.7.2-1~debian.12~bookworm'\n".into(),
    );
}

fn install_dnf(root: &Path, verification_exit: i32) {
    install_docker(root);
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
reposdir=
for argument in "$@"; do case "$argument" in --setopt=reposdir=*) reposdir=${{argument##*=}} ;; esac; done
[ -n "$reposdir" ] || exit 71
grep -F '/docker-ce/linux/fedora' '{root}'"$reposdir"/*.repo >/dev/null || exit 72
grep -F 'gpgcheck=1' '{root}'"$reposdir"/*.repo >/dev/null || exit 73
[ {verification_exit} -eq 0 ] || exit {verification_exit}
case " $* " in
  *' makecache '*) echo 'Metadata cache created' ;;
  *' list '*' docker-ce '*) echo 'docker-ce.x86_64 3:29.5.3-1.fc42 docker-ce-stable' ;;
  *) exit 74 ;;
esac
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/root")
        .with_environment(BTreeMap::new())
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("docker-ce-{provider}-test"),
        tool_id: "docker-ce".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: provider.into(),
        endpoints: [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Packages,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: endpoint.into(),
        })
        .collect(),
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn debian_host_plan_preserves_key_channel_pin_related_repo_and_comments() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0);
    let original = b"# keep https://download.docker.com/linux/debian in this comment\ndeb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable test\n";
    let source = write(root, "/etc/apt/sources.list.d/docker.list", original);
    let key = write(root, "/etc/apt/keyrings/docker.gpg", b"opaque-key");
    let nvidia = b"deb [signed-by=/etc/apt/keyrings/nvidia.gpg] https://nvidia.github.io/libnvidia-container/stable/deb/$(ARCH) /\n";
    let nvidia_path = write(
        root,
        "/etc/apt/sources.list.d/nvidia-container.list",
        nvidia,
    );
    let pin = b"Package: docker-ce\nPin: version 5:29.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/docker-ce", pin);
    let adapter = DockerCeAdapter;
    let context = context(
        root,
        Architecture::X86_64,
        "debian",
        "12",
        Some("bookworm"),
        ExecutionEnvironment::Host,
    );
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("29.7.2"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["apt_distro"], "debian");
    assert_eq!(request.probe_contexts[UPSTREAM][0]["codename"], "bookworm");
    let selected = selection("nju", "https://mirrors.nju.edu.cn/docker-ce");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(
        rendered.contains("https://mirrors.nju.edu.cn/docker-ce/linux/debian bookworm stable test")
    );
    assert!(rendered.contains("signed-by=/etc/apt/keyrings/docker.gpg"));
    assert!(rendered.contains("# keep https://download.docker.com/linux/debian"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Docker APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"opaque-key");
    assert_eq!(fs::read(&nvidia_path).unwrap(), nvidia);
    assert_eq!(fs::read(&pin_path).unwrap(), pin);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selected)
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
    assert_eq!(fs::read(source).unwrap(), original);
}

#[test]
fn fedora_arm64_rewrites_all_channels_but_preserves_gpg_urls_and_options() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, 0);
    let original = b"[docker-ce-stable]\nname=Docker Stable\nbaseurl=https://download.docker.com/linux/fedora/$releasever/$basearch/stable\nenabled=1\ngpgcheck=1\ngpgkey=https://download.docker.com/linux/fedora/gpg\nexclude=docker-ce-28*\n\n[docker-ce-test]\nname=Docker Test\nbaseurl=https://download.docker.com/linux/fedora/$releasever/$basearch/test\nenabled=0\ngpgcheck=1\ngpgkey=https://download.docker.com/linux/fedora/gpg\n";
    let repo = write(root, "/etc/yum.repos.d/docker-ce.repo", original);
    let adapter = DockerCeAdapter;
    let context = context(
        root,
        Architecture::Arm64,
        "fedora",
        "42",
        None,
        ExecutionEnvironment::Host,
    );
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["rpm_arch"], "aarch64");
    let selected = selection("ustc", "https://mirrors.ustc.edu.cn/docker-ce");
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert_eq!(
        rendered
            .matches("https://mirrors.ustc.edu.cn/docker-ce/linux/fedora")
            .count(),
        2
    );
    assert_eq!(
        rendered
            .matches("gpgkey=https://download.docker.com/linux/fedora/gpg")
            .count(),
        2
    );
    assert!(rendered.contains("exclude=docker-ce-28*"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Docker RPM repo should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(repo).unwrap(), original);
}

#[test]
fn ubuntu_container_build_layout_creates_independent_deb822_source() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0);
    write(root, "/etc/apt/keyrings/docker.asc", b"key");
    let adapter = DockerCeAdapter;
    let context = context(
        root,
        Architecture::Arm64,
        "ubuntu",
        "24.04",
        Some("noble"),
        ExecutionEnvironment::Container,
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/docker-ce"),
        )
        .unwrap();
    assert!(
        plan.changes[0]
            .target
            .ends_with("etc/apt/sources.list.d/mirrorswitch-docker-ce.sources")
    );
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("URIs: https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/ubuntu"));
    assert!(rendered.contains("Suites: noble"));
    assert!(rendered.contains("Architectures: amd64 arm64"));
}

#[test]
fn mismatched_distribution_missing_security_multiple_files_and_endpoint_pairs_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0);
    let adapter = DockerCeAdapter;
    let context = context(
        root,
        Architecture::X86_64,
        "debian",
        "12",
        Some("bookworm"),
        ExecutionEnvironment::Host,
    );
    write(root, "/etc/apt/sources.list.d/docker.list", b"deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable\n");
    write(root, "/etc/apt/keyrings/docker.gpg", b"key");
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/docker-ce")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/docker.list",
        b"deb https://download.docker.com/linux/debian bookworm stable\n",
    );
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(current.to_string().contains("Signed-By"));

    write(root, "/etc/apt/sources.list.d/docker.list", b"deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable\n");
    write(root, "/etc/apt/sources.list.d/duplicate.list", b"deb [signed-by=/etc/apt/keyrings/docker.gpg] https://mirrors.ustc.edu.cn/docker-ce/linux/debian bookworm stable\n");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/docker-ce")
            )
            .is_err()
    );

    fs::remove_file(root.join("etc/apt/sources.list.d/duplicate.list")).unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let mut bad = selection("nju", "https://mirrors.nju.edu.cn/docker-ce");
    bad[0].endpoints[2].url = "https://mirrors.aliyun.com/docker-ce".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());
}

#[test]
fn failed_package_refresh_restores_original_source() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9);
    let original = b"deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable\n";
    let source = write(root, "/etc/apt/sources.list.d/docker.list", original);
    write(root, "/etc/apt/keyrings/docker.gpg", b"key");
    let adapter = DockerCeAdapter;
    let context = context(
        root,
        Architecture::X86_64,
        "debian",
        "12",
        Some("bookworm"),
        ExecutionEnvironment::Host,
    );
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("ustc", "https://mirrors.ustc.edu.cn/docker-ce"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Docker CE source should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(source).unwrap(), original);
}

struct MetadataProber;

impl CandidateProber for MetadataProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let latency_ms = if url.contains("ustc") { 1 } else { 2 };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body: b"Origin: Docker\nPackage: docker-ce\nArchitecture: amd64\nArchitecture: arm64\n<data type=\"primary\">".to_vec(),
            latency_ms,
        })
    }
}

#[test]
fn catalog_has_six_cross_format_arch_complete_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "docker-ce")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud", "nju", "sjtug", "tuna", "ustc"])
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror
                && candidate.probes.len() == 7
                && candidate.compatibility.architectures
                    == [Architecture::X86_64, Architecture::Arm64])
    );

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0);
    write(root, "/etc/apt/keyrings/docker.asc", b"key");
    let adapter = DockerCeAdapter;
    let context = context(
        root,
        Architecture::X86_64,
        "debian",
        "12",
        Some("bookworm"),
        ExecutionEnvironment::Container,
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        MetadataProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections[0].provider_id, "ustc");
}
