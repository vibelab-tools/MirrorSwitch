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
    adapters::{RosAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "ros1-packages--repository-metadata";

fn context(
    root: &Path,
    architecture: Architecture,
    distribution: &str,
    codename: &str,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(
                if codename == "focal" {
                    "20.04"
                } else {
                    "22.04"
                }
                .into(),
            ),
            version_codename: Some(codename.into()),
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

fn install_apt(root: &Path, verification_exit: i32, rosversion: Option<&str>) {
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/ros/ubuntu' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: ROS Noetic Focal mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'ros-noetic-ros-base:'\necho '  Candidate: 1.5.0-1focal.20250521.010531'\n".into(),
    );
    if let Some(distribution) = rosversion {
        executable(
            root,
            "/usr/bin/rosversion",
            format!("#!/bin/sh\n[ \"$1\" = -d ] || exit 70\necho '{distribution}'\n"),
        );
    }
}

fn runtime(root: &Path, ros_distro: Option<&str>) -> OsRuntime {
    let environment = ros_distro
        .map(|value| BTreeMap::from([("ROS_DISTRO".into(), value.into())]))
        .unwrap_or_default();
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/root")
        .with_environment(environment)
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("ros-{provider}-test"),
        tool_id: "ros".into(),
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
fn noetic_focal_plan_preserves_key_other_sources_and_pin_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, Some("noetic"));
    let original = b"# ROS 1 only\ndeb [arch=amd64 signed-by=/usr/share/keyrings/ros.gpg] https://packages.ros.org/ros/ubuntu focal main\n";
    let source = write(root, "/etc/apt/sources.list.d/ros1.list", original);
    let key = write(root, "/usr/share/keyrings/ros.gpg", b"opaque-key");
    let ros2 = b"deb [signed-by=/usr/share/keyrings/ros2.gpg] https://packages.ros.org/ros2/ubuntu focal main\n";
    let ros2_path = write(root, "/etc/apt/sources.list.d/ros2.list", ros2);
    let pin = b"Package: ros-noetic-*\nPin: version *focal*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/ros-noetic", pin);
    let adapter = RosAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "focal");
    let mut runtime = runtime(root, None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("noetic"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "noetic-focal-final");
    let selected = selection("ustc", "https://mirrors.ustc.edu.cn/ros");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.ustc.edu.cn/ros/ubuntu focal main"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/ros.gpg"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("ROS 1 source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"opaque-key");
    assert_eq!(fs::read(&ros2_path).unwrap(), ros2);
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
fn arm64_missing_source_uses_explicit_noetic_environment_and_deb822() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, None);
    write(root, "/usr/share/keyrings/ros-archive-keyring.gpg", b"key");
    let adapter = RosAdapter;
    let context = context(root, Architecture::Arm64, "ubuntu", "focal");
    let runtime = runtime(root, Some("noetic"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("nju", "https://mirrors.nju.edu.cn/ros"),
        )
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("Architectures: amd64 arm64"));
    assert!(rendered.contains("Suites: focal"));
    assert_eq!(
        plan,
        adapter
            .plan(
                &context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/ros")
            )
            .unwrap()
    );
}

#[test]
fn unsupported_distribution_ros_release_missing_key_multiple_sources_and_mismatch_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, Some("melodic"));
    let adapter = RosAdapter;
    let focal = context(root, Architecture::X86_64, "ubuntu", "focal");
    assert!(
        adapter
            .detect(&focal, &runtime(root, None))
            .unwrap_err()
            .to_string()
            .contains("outside final")
    );
    install_apt(root, 0, Some("noetic"));
    let jammy = context(root, Architecture::X86_64, "ubuntu", "jammy");
    assert!(adapter.detect(&jammy, &runtime(root, None)).is_err());
    let debian = context(root, Architecture::X86_64, "debian", "bullseye");
    assert!(adapter.detect(&debian, &runtime(root, None)).is_err());

    write(
        root,
        "/etc/apt/sources.list.d/ros1.list",
        b"deb https://packages.ros.org/ros/ubuntu focal main\n",
    );
    let runtime = runtime(root, None);
    let detected = adapter.detect(&focal, &runtime).unwrap().unwrap();
    assert!(
        adapter
            .read_current(&focal, &runtime, &detected, ConfigurationScope::System)
            .is_err()
    );

    write(root, "/usr/share/keyrings/ros.gpg", b"key");
    write(root, "/etc/apt/sources.list.d/ros1.list", b"deb [signed-by=/usr/share/keyrings/ros.gpg] https://packages.ros.org/ros/ubuntu bionic main\n");
    let current = adapter
        .read_current(&focal, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &focal,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/ros")
            )
            .is_err()
    );

    write(root, "/etc/apt/sources.list.d/ros1.list", b"deb [signed-by=/usr/share/keyrings/ros.gpg] https://packages.ros.org/ros/ubuntu focal main\n");
    write(root, "/etc/apt/sources.list.d/duplicate.list", b"deb [signed-by=/usr/share/keyrings/ros.gpg] https://mirrors.ustc.edu.cn/ros/ubuntu focal main\n");
    let current = adapter
        .read_current(&focal, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &focal,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/ros")
            )
            .is_err()
    );
}

#[test]
fn failed_apt_refresh_restores_source() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9, Some("noetic"));
    let original = b"deb [signed-by=/usr/share/keyrings/ros.gpg] https://packages.ros.org/ros/ubuntu focal main\n";
    let source = write(root, "/etc/apt/sources.list.d/ros1.list", original);
    write(root, "/usr/share/keyrings/ros.gpg", b"key");
    let adapter = RosAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "focal");
    let mut runtime = runtime(root, None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("nju", "https://mirrors.nju.edu.cn/ros"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("ROS source should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(source).unwrap(), original);
}

struct RosProber;

impl CandidateProber for RosProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body: b"Origin: ROS\nArchitectures: i386 amd64 arm64 armhf".to_vec(),
            latency_ms: if url.contains("ustc") { 1 } else { 3 },
        })
    }
}

#[test]
fn catalog_reports_final_snapshot_coverage_and_keeps_aliyun_inert() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "ros")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 5);
    assert_eq!(
        complete
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["huaweicloud", "nju", "sjtug", "tuna", "ustc"])
    );
    assert!(
        complete
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror
                && candidate.compatibility.repository_versions == ["noetic-focal-final"])
    );
    let aliyun = candidates
        .iter()
        .find(|candidate| candidate.provider_id == "aliyun")
        .unwrap();
    assert!(aliyun.probes.is_empty());

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, None);
    write(root, "/usr/share/keyrings/ros-archive-keyring.gpg", b"key");
    let adapter = RosAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "focal");
    let runtime = runtime(root, Some("noetic"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        RosProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections[0].provider_id, "ustc");
}
