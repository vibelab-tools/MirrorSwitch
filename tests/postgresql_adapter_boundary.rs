#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PostgreSqlAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "postgresql-pgdg--repository-metadata";

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

fn install_postgresql(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/psql",
        format!("#!/bin/sh\necho 'psql (PostgreSQL) {version}'\n"),
    );
}

fn install_apt(root: &Path, verification_exit: i32, version: &str) {
    install_postgresql(root, version);
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/postgresql/repos/apt' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: PostgreSQL 17 LTS mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'postgresql-17:'\necho '  Candidate: 17.11-1.pgdg24.04+2'\n".into(),
    );
}

fn install_dnf(root: &Path, verification_exit: i32, version: &str) {
    install_postgresql(root, version);
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
repo_dir=
for argument in "$@"; do case "$argument" in --setopt=reposdir=*) repo_dir=${{argument##*=}} ;; esac; done
[ -n "$repo_dir" ] || exit 71
grep -F 'postgresql/repos/yum/17/redhat/rhel-9-aarch64' '{root}'"$repo_dir"/*.repo >/dev/null || exit 72
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'postgresql17-server.aarch64 17.9-1PGDG.rhel9.7 mirrorswitch-postgresql'
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
        candidate_id: format!("postgresql-{provider}-test"),
        tool_id: "postgresql".into(),
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
fn apt_pgdg17_plan_preserves_common_private_sources_key_pin_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "17.11");
    let original = b"deb [signed-by=/usr/share/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt noble-pgdg main\n";
    let source = write(root, "/etc/apt/sources.list.d/postgresql.list", original);
    let key = write(
        root,
        "/usr/share/keyrings/postgresql.gpg",
        b"postgresql-key",
    );
    let private = b"deb [signed-by=/usr/share/keyrings/private.gpg] https://packages.example.invalid/apt stable main\n";
    let private_path = write(root, "/etc/apt/sources.list.d/private.list", private);
    let mariadb = b"deb https://mirror.example.invalid/mariadb/repo/11.8/ubuntu noble main\n";
    let mariadb_path = write(root, "/etc/apt/sources.list.d/mariadb.list", mariadb);
    let pin = b"Package: postgresql-17*\nPin: version 17.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/postgresql", pin);
    let adapter = PostgreSqlAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("17.11"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.repository_versions[UPSTREAM],
        "ubuntu-noble-17-amd64"
    );
    let selected = selection("nju", "https://mirrors.nju.edu.cn/postgresql");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.service_impact, ServiceImpact::None);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.nju.edu.cn/postgresql/repos/apt"));
    assert!(rendered.contains("noble-pgdg main"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/postgresql.gpg"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("PostgreSQL APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"postgresql-key");
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
fn rpm_el9_arm64_preserves_tools_private_repo_and_gpg_configuration() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, 0, "17.9");
    let original = b"[pgdg17]\nname=PostgreSQL 17\nbaseurl=https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-9-$basearch\nenabled=1\ngpgcheck=1\ngpgkey=https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-AARCH64-RHEL\n";
    let source = write(root, "/etc/yum.repos.d/postgresql-community.repo", original);
    let tools = b"[pgdg-common]\nbaseurl=https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-9-$basearch\nenabled=1\ngpgcheck=1\n";
    let tools_path = write(root, "/etc/yum.repos.d/postgresql-tools.repo", tools);
    let private =
        b"[private]\nbaseurl=https://packages.example.invalid/rpm/\nenabled=1\ngpgcheck=1\n";
    let private_path = write(root, "/etc/yum.repos.d/private.repo", private);
    let adapter = PostgreSqlAdapter;
    let context = context(root, Architecture::Arm64, "rocky", "9.6", None);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "el-9-17-aarch64");
    let selected = selection("nju", "https://mirrors.nju.edu.cn/postgresql");
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("postgresql/repos/yum/17/redhat/rhel-9-aarch64"));
    assert!(rendered.contains("gpgcheck=1"));
    assert!(rendered.contains("PGDG-RPM-GPG-KEY-AARCH64-RHEL"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("PostgreSQL RPM source should change")
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
fn unsupported_version_release_missing_key_and_disabled_gpg_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "17.11");
    let arm = context(root, Architecture::Arm64, "ubuntu", "24.04", Some("noble"));
    assert!(
        PostgreSqlAdapter
            .detect(&arm, &runtime(root))
            .unwrap()
            .is_some()
    );

    install_apt(root, 0, "16.11");
    let x64 = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    assert!(PostgreSqlAdapter.detect(&x64, &runtime(root)).is_err());

    install_apt(root, 0, "17.11");
    write(
        root,
        "/etc/apt/sources.list.d/postgresql.list",
        b"deb [signed-by=/usr/share/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt jammy-pgdg main\n",
    );
    write(root, "/usr/share/keyrings/postgresql.gpg", b"key");
    let apt_runtime = runtime(root);
    let detected = PostgreSqlAdapter
        .detect(&x64, &apt_runtime)
        .unwrap()
        .unwrap();
    let current = PostgreSqlAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        PostgreSqlAdapter
            .plan(
                &x64,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/postgresql")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/postgresql.list",
        b"deb [signed-by=/usr/share/keyrings/missing-postgresql.gpg] https://apt.postgresql.org/pub/repos/apt noble-pgdg main\n",
    );
    let current = PostgreSqlAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        PostgreSqlAdapter
            .plan(
                &x64,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/postgresql")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/postgresql-second.list",
        b"deb [signed-by=/usr/share/keyrings/postgresql.gpg] https://mirrors.nju.edu.cn/postgresql/repos/apt noble-pgdg main\n",
    );
    assert!(PostgreSqlAdapter.detect(&x64, &apt_runtime).is_err());

    let rpm_root = tempdir().unwrap();
    install_dnf(rpm_root.path(), 0, "17.9");
    write(
        rpm_root.path(),
        "/etc/yum.repos.d/postgresql.repo",
        b"[pgdg17]\nbaseurl=https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-9-$basearch\nenabled=1\ngpgcheck=0\ngpgkey=https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL\n",
    );
    let rpm_context = context(rpm_root.path(), Architecture::Arm64, "rhel", "9.6", None);
    let rpm_runtime = runtime(rpm_root.path());
    let detected = PostgreSqlAdapter
        .detect(&rpm_context, &rpm_runtime)
        .unwrap()
        .unwrap();
    let current = PostgreSqlAdapter
        .read_current(
            &rpm_context,
            &rpm_runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        PostgreSqlAdapter
            .plan(
                &rpm_context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/postgresql")
            )
            .is_err()
    );
}

#[test]
fn failed_package_refresh_restores_postgresql_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9, "17.11");
    let original = b"deb [signed-by=/usr/share/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt noble-pgdg main\n";
    let source = write(root, "/etc/apt/sources.list.d/postgresql.list", original);
    write(root, "/usr/share/keyrings/postgresql.gpg", b"key");
    let adapter = PostgreSqlAdapter;
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
            &selection("nju", "https://mirrors.nju.edu.cn/postgresql"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("PostgreSQL source should change")
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

struct PostgreSqlProber;

impl CandidateProber for PostgreSqlProber {
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
                b"Origin: apt.postgresql.org".to_vec()
            } else if url.ends_with("repomd.xml") {
                b"<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">".to_vec()
            } else {
                Vec::new()
            },
            latency_ms: if url.contains("nju") { 1 } else { 3 },
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
        .filter(|candidate| candidate.tool_id == "postgresql")
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
    install_apt(root, 0, "17.11");
    write(
        root,
        "/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc",
        b"key",
    );
    let context = context(root, Architecture::X86_64, "debian", "12", Some("bookworm"));
    let runtime = runtime(root);
    let detected = PostgreSqlAdapter
        .detect(&context, &runtime)
        .unwrap()
        .unwrap();
    let current = PostgreSqlAdapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = PostgreSqlAdapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        PostgreSqlProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable, "{:?}", outcome.repositories);
    assert_eq!(outcome.selections[0].provider_id, "nju");
}
