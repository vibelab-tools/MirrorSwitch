#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{MariaDbAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "mariadb-packages--repository-metadata";

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

fn install_mariadb(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/mariadb",
        format!("#!/bin/sh\necho 'mariadb Ver 15.1 Distrib {version}-MariaDB'\n"),
    );
}

fn install_apt(root: &Path, verification_exit: i32, version: &str) {
    install_mariadb(root, version);
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/mariadb/repo/11.8/ubuntu' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: MariaDB 11.8 LTS mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'mariadb-server:'\necho '  Candidate: 1:11.8.9+maria~ubu2404'\n".into(),
    );
}

fn install_dnf(root: &Path, verification_exit: i32, version: &str) {
    install_mariadb(root, version);
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
repo_dir=
for argument in "$@"; do case "$argument" in --setopt=reposdir=*) repo_dir=${{argument##*=}} ;; esac; done
[ -n "$repo_dir" ] || exit 71
grep -F 'mariadb/yum/11.8/rhel/9/aarch64' '{root}'"$repo_dir"/*.repo >/dev/null || exit 72
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'MariaDB-server.aarch64 11.8.9-1.el9 mirrorswitch-mariadb'
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
        candidate_id: format!("mariadb-{provider}-test"),
        tool_id: "mariadb".into(),
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
fn apt_118_plan_preserves_private_sources_key_pin_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "11.8.9");
    let original = b"deb [signed-by=/usr/share/keyrings/mariadb.gpg] https://mirror.mariadb.org/repo/11.8/ubuntu noble main\n";
    let source = write(root, "/etc/apt/sources.list.d/mariadb.list", original);
    let key = write(root, "/usr/share/keyrings/mariadb.gpg", b"mariadb-key");
    let private = b"deb [signed-by=/usr/share/keyrings/private.gpg] https://packages.example.invalid/apt stable main\n";
    let private_path = write(root, "/etc/apt/sources.list.d/private.list", private);
    let other = b"deb https://mirror.example.invalid/mysql/repo noble main\n";
    let other_path = write(root, "/etc/apt/sources.list.d/mysql.list", other);
    let pin = b"Package: mariadb-*\nPin: version 1:11.8.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/mariadb", pin);
    let adapter = MariaDbAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("11.8.9"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.repository_versions[UPSTREAM],
        "ubuntu-noble-11.8-amd64"
    );
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mariadb");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.service_impact, ServiceImpact::None);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.tuna.tsinghua.edu.cn/mariadb/repo/11.8/ubuntu"));
    assert!(rendered.contains("noble main"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/mariadb.gpg"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("MariaDB APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"mariadb-key");
    assert_eq!(fs::read(&private_path).unwrap(), private);
    assert_eq!(fs::read(&other_path).unwrap(), other);
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
fn rpm_el9_arm64_preserves_tools_private_repo_and_gpg_configuration() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, 0, "11.8.9");
    let original = b"[mariadb-11.8]\nname=MariaDB 11.8\nbaseurl=https://mirror.mariadb.org/yum/11.8/rhel/9/$basearch/\nenabled=1\ngpgcheck=1\ngpgkey=https://supplychain.mariadb.com/MariaDB-Server-GPG-KEY\n";
    let source = write(root, "/etc/yum.repos.d/mariadb-community.repo", original);
    let tools = b"[mysql-tools]\nbaseurl=https://repo.mysql.com/yum/mysql-tools-community/el/9/$basearch/\nenabled=1\ngpgcheck=1\n";
    let tools_path = write(root, "/etc/yum.repos.d/mariadb-tools.repo", tools);
    let private =
        b"[private]\nbaseurl=https://packages.example.invalid/rpm/\nenabled=1\ngpgcheck=1\n";
    let private_path = write(root, "/etc/yum.repos.d/private.repo", private);
    let adapter = MariaDbAdapter;
    let context = context(root, Architecture::Arm64, "rocky", "9.6", None);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "el-9-11.8-aarch64");
    let selected = selection("ustc", "https://mirrors.ustc.edu.cn/mariadb");
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("mariadb/yum/11.8/rhel/9/aarch64"));
    assert!(rendered.contains("gpgcheck=1"));
    assert!(rendered.contains("MariaDB-Server-GPG-KEY"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MariaDB RPM source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&tools_path).unwrap(), tools);
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
fn unsupported_arch_version_release_missing_key_and_disabled_gpg_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "11.8.9");
    let arm = context(root, Architecture::Arm64, "ubuntu", "24.04", Some("noble"));
    assert!(
        MariaDbAdapter
            .detect(&arm, &runtime(root))
            .unwrap()
            .is_some()
    );

    install_apt(root, 0, "11.4.8");
    let x64 = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    assert!(MariaDbAdapter.detect(&x64, &runtime(root)).is_err());

    install_apt(root, 0, "11.8.9");
    write(
        root,
        "/etc/apt/sources.list.d/mariadb.list",
        b"deb [signed-by=/usr/share/keyrings/mariadb.gpg] https://mirror.mariadb.org/repo/11.8/ubuntu jammy main\n",
    );
    write(root, "/usr/share/keyrings/mariadb.gpg", b"key");
    let apt_runtime = runtime(root);
    let detected = MariaDbAdapter.detect(&x64, &apt_runtime).unwrap().unwrap();
    let current = MariaDbAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        MariaDbAdapter
            .plan(
                &x64,
                &current,
                &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mariadb")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/mariadb.list",
        b"deb [signed-by=/usr/share/keyrings/missing-mariadb.gpg] https://mirror.mariadb.org/repo/11.8/ubuntu noble main\n",
    );
    let current = MariaDbAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        MariaDbAdapter
            .plan(
                &x64,
                &current,
                &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mariadb")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/mariadb-second.list",
        b"deb [signed-by=/usr/share/keyrings/mariadb.gpg] https://mirrors.ustc.edu.cn/mariadb/repo/11.8/ubuntu noble main\n",
    );
    assert!(MariaDbAdapter.detect(&x64, &apt_runtime).is_err());

    let rpm_root = tempdir().unwrap();
    install_dnf(rpm_root.path(), 0, "11.8.9");
    write(
        rpm_root.path(),
        "/etc/yum.repos.d/mariadb.repo",
        b"[mariadb]\nbaseurl=https://mirror.mariadb.org/yum/11.8/rhel/9/$basearch/\nenabled=1\ngpgcheck=0\ngpgkey=https://supplychain.mariadb.com/MariaDB-Server-GPG-KEY\n",
    );
    let rpm_context = context(rpm_root.path(), Architecture::Arm64, "rhel", "9.6", None);
    let rpm_runtime = runtime(rpm_root.path());
    let detected = MariaDbAdapter
        .detect(&rpm_context, &rpm_runtime)
        .unwrap()
        .unwrap();
    let current = MariaDbAdapter
        .read_current(
            &rpm_context,
            &rpm_runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        MariaDbAdapter
            .plan(
                &rpm_context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/mariadb")
            )
            .is_err()
    );
}

#[test]
fn failed_package_refresh_restores_mariadb_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9, "11.8.9");
    let original = b"deb [signed-by=/usr/share/keyrings/mariadb.gpg] https://mirror.mariadb.org/repo/11.8/ubuntu noble main\n";
    let source = write(root, "/etc/apt/sources.list.d/mariadb.list", original);
    write(root, "/usr/share/keyrings/mariadb.gpg", b"key");
    let adapter = MariaDbAdapter;
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
            &selection("ustc", "https://mirrors.ustc.edu.cn/mariadb"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MariaDB source should change")
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

struct MariaDbProber;

impl CandidateProber for MariaDbProber {
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
                b"Origin: MariaDB".to_vec()
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
        .filter(|candidate| candidate.tool_id == "mariadb")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 10);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 10);
    assert!(
        complete
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror)
    );
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "11.8.9");
    write(root, "/etc/apt/keyrings/mariadb-keyring.pgp", b"key");
    let context = context(root, Architecture::X86_64, "debian", "12", Some("bookworm"));
    let runtime = runtime(root);
    let detected = MariaDbAdapter.detect(&context, &runtime).unwrap().unwrap();
    let current = MariaDbAdapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = MariaDbAdapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        MariaDbProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable, "{:?}", outcome.repositories);
    assert_eq!(outcome.selections[0].provider_id, "ustc");
}
