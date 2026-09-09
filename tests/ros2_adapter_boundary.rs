#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::{fs::PermissionsExt, fs::symlink},
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{Ros2Adapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const APT_UPSTREAM: &str = "ros2-apt--repository-metadata";
const RPM_UPSTREAM: &str = "ros2-rpm--repository-metadata";

fn context(
    root: &Path,
    distribution: &str,
    version: &str,
    codename: Option<&str>,
    architecture: Architecture,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Host,
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

fn install_apt(root: &Path, package: &str, verify_exit: i32) {
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do
  case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac
done
[ "$1" = update ] || exit 61
grep -F '/ros2/ubuntu' '{root}'"$source_file" >/dev/null || exit 62
[ {verify_exit} -eq 0 ] || exit {verify_exit}
echo 'Hit: ROS 2 mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        format!("#!/bin/sh\necho '{package}:'\necho '  Candidate: 1.0-test'\n"),
    );
}

fn install_dnf(root: &Path, package: &str, verify_exit: i32) {
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
reposdir=
for argument in "$@"; do
  case "$argument" in --setopt=reposdir=*) reposdir=${{argument#--setopt=reposdir=}} ;; esac
done
[ "$reposdir" = /etc/yum.repos.d ] || exit 70
grep -F 'mirrors.nju.edu.cn/ros2-rhel' '{root}/etc/yum.repos.d/ros2.repo' >/dev/null || exit 71
[ {verify_exit} -eq 0 ] || exit {verify_exit}
case " $* " in
  *' list '*' {package} '*) echo '{package}.x86_64 1.0-test mirrorswitch-ros2' ;;
  *) echo 'Metadata cache created' ;;
esac
"#,
            root = root.display(),
        ),
    );
}

fn install_ros2(root: &Path, distribution: &str) {
    executable(
        root,
        "/usr/bin/ros2",
        format!(
            "#!/bin/sh\n[ \"$1 $2 $3\" = 'pkg prefix rclcpp' ] || exit 60\necho '/opt/ros/{distribution}'\n"
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/root")
        .with_environment(BTreeMap::new())
}

fn selection(provider: &str, upstream: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("ros2-{provider}-test"),
        tool_id: "ros2".into(),
        upstream_id: upstream.into(),
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
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn jammy_legacy_source_preserves_key_third_party_pin_and_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "ros-humble-ros-base", 0);
    install_ros2(root, "humble");
    let original = b"# keep\ndeb [arch=amd64 signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu jammy main\ndeb https://private.example/apt stable main\n";
    let source = write(root, "/etc/apt/sources.list.d/ros2.list", original);
    write(root, "/usr/share/keyrings/ros-archive-keyring.gpg", b"key");
    let pin = b"Package: ros-humble-*\nPin: version 0.10.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/ros2", pin);
    let adapter = Ros2Adapter;
    let context = context(root, "ubuntu", "22.04", Some("jammy"), Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("humble"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [APT_UPSTREAM]);
    assert_eq!(request.probe_contexts[APT_UPSTREAM][0]["suite"], "jammy");
    assert_eq!(request.probe_contexts[APT_UPSTREAM][0]["apt_arch"], "amd64");
    let selected = selection(
        "qlu",
        APT_UPSTREAM,
        "https://mirrors.qlu.edu.cn/ros2/ubuntu/",
    );
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.qlu.edu.cn/ros2/ubuntu jammy main"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/ros-archive-keyring.gpg"));
    assert!(rendered.contains("https://private.example/apt"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("ROS 2 APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
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
    assert_eq!(fs::read(pin_path).unwrap(), pin);
}

#[test]
fn package_managed_embedded_key_source_updates_its_real_target_on_arm64() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "ros-kilted-ros-base", 0);
    install_ros2(root, "kilted");
    let original = b"Types: deb\nURIs: https://packages.ros.org/ros2/ubuntu\nSuites: noble\nComponents: main\nArchitectures: arm64\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n test\n -----END PGP PUBLIC KEY BLOCK-----\n";
    let target = write(root, "/usr/share/ros-apt-source/ros2.sources", original);
    let link = root.join("etc/apt/sources.list.d/ros2.sources");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    symlink("../../../usr/share/ros-apt-source/ros2.sources", &link).unwrap();
    let adapter = Ros2Adapter;
    let context = context(root, "ubuntu", "24.04", Some("noble"), Architecture::Arm64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection(
                "zju",
                APT_UPSTREAM,
                "https://mirrors.zju.edu.cn/ros2/ubuntu/",
            ),
        )
        .unwrap();
    assert!(
        plan.changes[0]
            .target
            .ends_with("usr/share/ros-apt-source/ros2.sources")
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("package-managed ROS 2 source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        String::from_utf8(fs::read(&link).unwrap())
            .unwrap()
            .contains("mirrors.zju.edu.cn")
    );
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(target).unwrap(), original);
}

#[test]
fn rhel9_preserves_repo_signature_policy_and_queries_the_selected_distribution() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, "ros-jazzy-ros-base", 0);
    install_ros2(root, "jazzy");
    let original = b"[ros2]\nname=ROS 2\nbaseurl=http://packages.ros.org/ros2/rhel/$releasever/$basearch/\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=1\ngpgkey=https://raw.githubusercontent.com/ros/rosdistro/master/ros.asc\n\n[ros2-debug]\nbaseurl=http://packages.ros.org/ros2/rhel/$releasever/$basearch/debug/\nenabled=0\nrepo_gpgcheck=1\n";
    let repo = write(root, "/etc/yum.repos.d/ros2.repo", original);
    let adapter = Ros2Adapter;
    let context = context(root, "rhel", "9.6", None, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [RPM_UPSTREAM]);
    assert_eq!(request.probe_contexts[RPM_UPSTREAM][0]["release"], "9");
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("nju", RPM_UPSTREAM, "https://mirrors.nju.edu.cn/ros2-rhel/"),
        )
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        rendered.contains("baseurl=https://mirrors.nju.edu.cn/ros2-rhel/$releasever/$basearch")
    );
    assert!(rendered.contains("gpgcheck=0"));
    assert!(rendered.contains("repo_gpgcheck=1"));
    assert!(rendered.contains("packages.ros.org/ros2/rhel/$releasever/$basearch/debug/"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("ROS 2 RPM source should change")
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
fn unsupported_architecture_distribution_and_custom_only_source_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, "ros-jazzy-ros-base", 0);
    install_ros2(root, "jazzy");
    let adapter = Ros2Adapter;
    let arm = context(root, "rhel", "9", None, Architecture::Arm64);
    assert!(
        adapter
            .detect(&arm, &runtime(root))
            .unwrap_err()
            .to_string()
            .contains("do not publish arm64")
    );
    let alma9 = context(root, "almalinux", "9.6", None, Architecture::X86_64);
    assert!(
        adapter
            .detect(&alma9, &runtime(root))
            .unwrap_err()
            .to_string()
            .contains("AlmaLinux is version 10 only")
    );

    install_apt(root, "ros-jazzy-ros-base", 0);
    let debian = context(root, "debian", "12", Some("bookworm"), Architecture::X86_64);
    assert!(adapter.detect(&debian, &runtime(root)).is_err());

    let ubuntu = context(root, "ubuntu", "24.04", Some("noble"), Architecture::X86_64);
    write(
        root,
        "/etc/apt/sources.list.d/private-ros2.list",
        b"deb [signed-by=/private/key.gpg] https://private.example/ros2/ubuntu noble main\n",
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&ubuntu, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&ubuntu, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .selection_request(&ubuntu, &detected, &current)
            .unwrap_err()
            .to_string()
            .contains("custom")
    );
}

#[test]
fn failed_package_manager_refresh_restores_the_ros2_source() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "ros-humble-ros-base", 9);
    install_ros2(root, "humble");
    let original = b"deb [arch=amd64 signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] https://packages.ros.org/ros2/ubuntu jammy main\n";
    let source = write(root, "/etc/apt/sources.list.d/ros2.list", original);
    write(root, "/usr/share/keyrings/ros-archive-keyring.gpg", b"key");
    let adapter = Ros2Adapter;
    let context = context(root, "ubuntu", "22.04", Some("jammy"), Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection(
                "qlu",
                APT_UPSTREAM,
                "https://mirrors.qlu.edu.cn/ros2/ubuntu/",
            ),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("ROS 2 source should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(source).unwrap(), original);
}

struct RepositoryProber;

impl CandidateProber for RepositoryProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let body = if method == HttpMethod::Get {
            if url.ends_with("repomd.xml") {
                b"<repomd><data type=\"primary\"></data></repomd>".to_vec()
            } else {
                b"Origin: ROS\n".to_vec()
            }
        } else {
            Vec::new()
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body,
            latency_ms: if url.contains("qlu") { 1 } else { 5 },
        })
    }
}

#[test]
fn catalog_selects_nine_apt_mirrors_and_one_x86_only_rpm_mirror() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let apt = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "ros2" && candidate.upstream_id == APT_UPSTREAM)
        .collect::<Vec<_>>();
    let rpm = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "ros2" && candidate.upstream_id == RPM_UPSTREAM)
        .collect::<Vec<_>>();
    assert_eq!(apt.len(), 9);
    assert_eq!(rpm.len(), 1);
    assert!(apt.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 4
    }));
    assert_eq!(rpm[0].compatibility.architectures, [Architecture::X86_64]);
    assert_eq!(rpm[0].probes.len(), 3);

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "ros-jazzy-ros-base", 0);
    install_ros2(root, "jazzy");
    write(root, "/usr/share/keyrings/ros2-archive-keyring.gpg", b"key");
    let adapter = Ros2Adapter;
    let context = context(root, "ubuntu", "24.04", Some("noble"), Architecture::X86_64);
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let outcome = MirrorSelector::with_prober(
        &catalog,
        RepositoryProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024,
        },
    )
    .select_at(&request, 123)
    .unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections[0].provider_id, "qlu");
}
