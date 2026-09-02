#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{InfluxDbAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "influxdata-packages--repository-metadata";

fn context(
    root: &Path,
    architecture: Architecture,
    distribution: &str,
    version: &str,
    codename: Option<&str>,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
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

fn install_influxdb(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/influxd",
        format!("#!/bin/sh\necho 'InfluxDB v{version}'\n"),
    );
}

fn install_apt(root: &Path, verification_exit: i32, version: &str) {
    install_influxdb(root, version);
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/influxdata/ubuntu' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: InfluxDB 2.9 LTS mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'influxdb2:'\necho '  Candidate: 2.9.1-1'\n".into(),
    );
}

fn install_dnf(root: &Path, verification_exit: i32, version: &str) {
    install_influxdb(root, version);
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
repo_dir=
for argument in "$@"; do case "$argument" in --setopt=reposdir=*) repo_dir=${{argument##*=}} ;; esac; done
[ -n "$repo_dir" ] || exit 71
grep -F 'influxdata/yum/el9-x86_64' '{root}'"$repo_dir"/*.repo >/dev/null || exit 72
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'influxdb2.x86_64 2.9.1-1 mirrorswitch-influxdb'
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/root")
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("influxdb-{provider}-test"),
        tool_id: "influxdb".into(),
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
fn apt_stable_plan_preserves_private_sources_key_pin_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "2.9.1");
    let original = b"deb [signed-by=/usr/share/keyrings/influxdb.gpg] https://repos.influxdata.com/ubuntu stable main\n";
    let source = write(root, "/etc/apt/sources.list.d/influxdb.list", original);
    let key = write(root, "/usr/share/keyrings/influxdb.gpg", b"influxdb-key");
    let private = b"deb [signed-by=/usr/share/keyrings/private.gpg] https://packages.example.invalid/apt stable main\n";
    let private_path = write(root, "/etc/apt/sources.list.d/private.list", private);
    let mariadb = b"deb https://mirror.example.invalid/mariadb/repo/11.8/ubuntu noble main\n";
    let mariadb_path = write(root, "/etc/apt/sources.list.d/mariadb.list", mariadb);
    let pin = b"Package: influxdb2*\nPin: version 2.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/influxdb", pin);
    let adapter = InfluxDbAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.9.1"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.repository_versions[UPSTREAM],
        "ubuntu-stable-2-amd64"
    );
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/influxdata");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.service_impact, ServiceImpact::None);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.tuna.tsinghua.edu.cn/influxdata/ubuntu"));
    assert!(rendered.contains("stable main"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/influxdb.gpg"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("InfluxDB APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"influxdb-key");
    assert_eq!(fs::read(&private_path).unwrap(), private);
    assert_eq!(fs::read(&mariadb_path).unwrap(), mariadb);
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
fn rpm_el9_x86_64_preserves_private_repo_and_gpg_configuration() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, 0, "2.9.1");
    let original = b"[influxdata]\nname=InfluxData stable\nbaseurl=https://repos.influxdata.com/rhel/9/x86_64/stable\nenabled=1\ngpgcheck=1\ngpgkey=https://repos.influxdata.com/influxdata-archive.key\n";
    let source = write(root, "/etc/yum.repos.d/influxdb-community.repo", original);
    let private =
        b"[private]\nbaseurl=https://packages.example.invalid/rpm/\nenabled=1\ngpgcheck=1\n";
    let private_path = write(root, "/etc/yum.repos.d/private.repo", private);
    let adapter = InfluxDbAdapter;
    let context = context(root, Architecture::X86_64, "rocky", "9.6", None);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.repository_versions[UPSTREAM],
        "el-9-stable-2-x86_64"
    );
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/influxdata");
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("influxdata/yum/el9-x86_64"));
    assert!(rendered.contains("gpgcheck=1"));
    assert!(rendered.contains("influxdata-archive.key"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("InfluxDB RPM source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&private_path).unwrap(), private);
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
fn unsupported_version_channel_missing_key_and_disabled_gpg_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "2.9.1");
    let arm = context(root, Architecture::Arm64, "ubuntu", "24.04", Some("noble"));
    assert!(
        InfluxDbAdapter
            .detect(&arm, &runtime(root))
            .unwrap()
            .is_some()
    );

    install_apt(root, 0, "1.12.4");
    let x64 = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    assert!(InfluxDbAdapter.detect(&x64, &runtime(root)).is_err());

    install_apt(root, 0, "2.9.1");
    write(
        root,
        "/etc/apt/sources.list.d/influxdb.list",
        b"deb [signed-by=/usr/share/keyrings/influxdb.gpg] https://repos.influxdata.com/ubuntu nightly main\n",
    );
    write(root, "/usr/share/keyrings/influxdb.gpg", b"key");
    let apt_runtime = runtime(root);
    assert!(InfluxDbAdapter.detect(&x64, &apt_runtime).is_err());
    write(
        root,
        "/etc/apt/sources.list.d/influxdb.list",
        b"deb [signed-by=/usr/share/keyrings/influxdb.gpg] https://repos.influxdata.com/ubuntu stable main\n",
    );
    let detected = InfluxDbAdapter.detect(&x64, &apt_runtime).unwrap().unwrap();
    let current = InfluxDbAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        InfluxDbAdapter
            .plan(
                &x64,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/influxdata")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/influxdb.list",
        b"deb [signed-by=/usr/share/keyrings/missing-influxdb.gpg] https://repos.influxdata.com/ubuntu stable main\n",
    );
    let current = InfluxDbAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        InfluxDbAdapter
            .plan(
                &x64,
                &current,
                &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/influxdata")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/influxdb-second.list",
        b"deb [signed-by=/usr/share/keyrings/influxdb.gpg] https://mirrors.nju.edu.cn/influxdata/ubuntu stable main\n",
    );
    assert!(InfluxDbAdapter.detect(&x64, &apt_runtime).is_err());

    let rpm_root = tempdir().unwrap();
    install_dnf(rpm_root.path(), 0, "2.9.1");
    write(
        rpm_root.path(),
        "/etc/yum.repos.d/influxdb.repo",
        b"[influxdb]\nbaseurl=https://repos.influxdata.com/rhel/9/x86_64/stable\nenabled=1\ngpgcheck=0\ngpgkey=https://repos.influxdata.com/influxdata-archive.key\n",
    );
    let rpm_context = context(rpm_root.path(), Architecture::X86_64, "rhel", "9.6", None);
    let rpm_runtime = runtime(rpm_root.path());
    let detected = InfluxDbAdapter
        .detect(&rpm_context, &rpm_runtime)
        .unwrap()
        .unwrap();
    let current = InfluxDbAdapter
        .read_current(
            &rpm_context,
            &rpm_runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        InfluxDbAdapter
            .plan(
                &rpm_context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/influxdata")
            )
            .is_err()
    );
}

#[test]
fn failed_package_refresh_restores_influxdb_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9, "2.9.1");
    let original = b"deb [signed-by=/usr/share/keyrings/influxdb.gpg] https://repos.influxdata.com/ubuntu stable main\n";
    let source = write(root, "/etc/apt/sources.list.d/influxdb.list", original);
    write(root, "/usr/share/keyrings/influxdb.gpg", b"key");
    let adapter = InfluxDbAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/influxdata"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("InfluxDB source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap_err()
            .to_string()
            .contains("restored: true")
    );
    assert_eq!(fs::read(source).unwrap(), original);
}

struct InfluxDbProber;

impl CandidateProber for InfluxDbProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body: if url.ends_with("InRelease") {
                b"Origin: InfluxDB".to_vec()
            } else if url.ends_with("repomd.xml") {
                b"<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">".to_vec()
            } else {
                Vec::new()
            },
            latency_ms: if url.contains("ustc") { 1 } else { 3 },
        })
    }
}

#[test]
fn catalog_selects_only_reviewed_apt_or_rpm_surfaces() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "influxdb")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 5);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 5);
    assert!(
        complete
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror)
    );
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "2.9.1");
    write(
        root,
        "/usr/share/keyrings/influxdata-archive-keyring.gpg",
        b"key",
    );
    let context = context(root, Architecture::X86_64, "debian", "12", Some("bookworm"));
    let runtime = runtime(root);
    let detected = InfluxDbAdapter.detect(&context, &runtime).unwrap().unwrap();
    let current = InfluxDbAdapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = InfluxDbAdapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        InfluxDbProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable, "{:?}", outcome.repositories);
    assert_eq!(outcome.selections[0].provider_id, "ustc");
}
