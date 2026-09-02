#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{MongoDbAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "mongodb-community--repository-metadata";

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

fn install_mongodb(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/mongod",
        format!("#!/bin/sh\necho 'db version v{version}'\n"),
    );
}

fn install_apt(root: &Path, verification_exit: i32, version: &str) {
    install_mongodb(root, version);
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/mongodb/apt/' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: MongoDB Community 8.0 mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'mongodb-org-server:'\necho '  Candidate: 8.0.28'\n".into(),
    );
}

fn install_dnf(root: &Path, verification_exit: i32, version: &str) {
    install_mongodb(root, version);
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
repo_dir=
for argument in "$@"; do case "$argument" in --setopt=reposdir=*) repo_dir=${{argument##*=}} ;; esac; done
[ -n "$repo_dir" ] || exit 71
grep -F 'mongodb/yum/el9-8.0' '{root}'"$repo_dir"/*.repo >/dev/null || exit 72
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'mongodb-org-server.x86_64 8.0.28-1.el9 mirrorswitch-mongodb'
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
        candidate_id: format!("mongodb-{provider}-test"),
        tool_id: "mongodb".into(),
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
fn apt_80_plan_preserves_private_sources_key_pin_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "8.0.28");
    let original = b"deb [signed-by=/usr/share/keyrings/mongodb.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse\n";
    let source = write(root, "/etc/apt/sources.list.d/mongodb.list", original);
    let key = write(root, "/usr/share/keyrings/mongodb.gpg", b"mongodb-key");
    let private = b"deb [signed-by=/usr/share/keyrings/private.gpg] https://packages.example.invalid/apt stable main\n";
    let private_path = write(root, "/etc/apt/sources.list.d/private.list", private);
    let other = b"deb https://mirror.example.invalid/vendor noble main\n";
    let other_path = write(root, "/etc/apt/sources.list.d/vendor.list", other);
    let pin = b"Package: mongodb-org-*\nPin: version 8.0.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/mongodb", pin);
    let adapter = MongoDbAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("8.0.28"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.repository_versions[UPSTREAM],
        "ubuntu-noble-8.0-amd64"
    );
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mongodb");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.service_impact, ServiceImpact::None);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.tuna.tsinghua.edu.cn/mongodb/apt/ubuntu"));
    assert!(rendered.contains("noble/mongodb-org/8.0 multiverse"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/mongodb.gpg"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("MongoDB APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"mongodb-key");
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
fn rpm_el9_x86_64_preserves_old_major_private_repo_and_gpg_configuration() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, 0, "8.0.28");
    let original = b"[mongodb-org-8.0]\nname=MongoDB 8.0\nbaseurl=https://repo.mongodb.org/yum/redhat/9/mongodb-org/8.0/$basearch/\nenabled=1\ngpgcheck=1\ngpgkey=https://www.mongodb.org/static/pgp/server-8.0.asc\n";
    let source = write(root, "/etc/yum.repos.d/mongodb-community.repo", original);
    let old_major = b"[mongodb-org-7.0]\nbaseurl=https://repo.mongodb.org/yum/redhat/9/mongodb-org/7.0/$basearch/\nenabled=0\ngpgcheck=1\n";
    let old_major_path = write(root, "/etc/yum.repos.d/mongodb-old.repo", old_major);
    let private =
        b"[private]\nbaseurl=https://packages.example.invalid/rpm/\nenabled=1\ngpgcheck=1\n";
    let private_path = write(root, "/etc/yum.repos.d/private.repo", private);
    let adapter = MongoDbAdapter;
    let context = context(root, Architecture::X86_64, "rocky", "9.6", None);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "el-9-8.0-x86_64");
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mongodb");
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("mongodb/yum/el9-8.0"));
    assert!(rendered.contains("gpgcheck=1"));
    assert!(rendered.contains("server-8.0.asc"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MongoDB RPM source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&old_major_path).unwrap(), old_major);
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
    install_apt(root, 0, "8.0.28");
    let arm = context(root, Architecture::Arm64, "ubuntu", "24.04", Some("noble"));
    assert!(
        MongoDbAdapter
            .detect(&arm, &runtime(root))
            .unwrap()
            .is_some()
    );

    install_apt(root, 0, "7.0.14");
    let x64 = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    assert!(MongoDbAdapter.detect(&x64, &runtime(root)).is_err());

    install_apt(root, 0, "8.0.28");
    write(
        root,
        "/etc/apt/sources.list.d/mongodb.list",
        b"deb [signed-by=/usr/share/keyrings/mongodb.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/8.0 multiverse\n",
    );
    write(root, "/usr/share/keyrings/mongodb.gpg", b"key");
    let apt_runtime = runtime(root);
    let detected = MongoDbAdapter.detect(&x64, &apt_runtime).unwrap().unwrap();
    let current = MongoDbAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        MongoDbAdapter
            .plan(
                &x64,
                &current,
                &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mongodb")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/mongodb.list",
        b"deb [signed-by=/usr/share/keyrings/missing-mongodb.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse\n",
    );
    let current = MongoDbAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        MongoDbAdapter
            .plan(
                &x64,
                &current,
                &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mongodb")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/mongodb-second.list",
        b"deb [signed-by=/usr/share/keyrings/mongodb.gpg] https://repo.huaweicloud.com/mongodb/apt/ubuntu noble/mongodb-org/8.0 multiverse\n",
    );
    assert!(MongoDbAdapter.detect(&x64, &apt_runtime).is_err());

    let rpm_root = tempdir().unwrap();
    install_dnf(rpm_root.path(), 0, "8.0.28");
    write(
        rpm_root.path(),
        "/etc/yum.repos.d/mongodb.repo",
        b"[mongodb]\nbaseurl=https://repo.mongodb.org/yum/redhat/9/mongodb-org/8.0/$basearch/\nenabled=1\ngpgcheck=0\ngpgkey=https://www.mongodb.org/static/pgp/server-8.0.asc\n",
    );
    let rpm_context = context(rpm_root.path(), Architecture::X86_64, "rhel", "9.6", None);
    let rpm_runtime = runtime(rpm_root.path());
    let detected = MongoDbAdapter
        .detect(&rpm_context, &rpm_runtime)
        .unwrap()
        .unwrap();
    let current = MongoDbAdapter
        .read_current(
            &rpm_context,
            &rpm_runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        MongoDbAdapter
            .plan(
                &rpm_context,
                &current,
                &selection("nju", "https://mirrors.nju.edu.cn/mongodb")
            )
            .is_err()
    );
}

#[test]
fn failed_package_refresh_restores_mongodb_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9, "8.0.28");
    let original = b"deb [signed-by=/usr/share/keyrings/mongodb.gpg] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse\n";
    let source = write(root, "/etc/apt/sources.list.d/mongodb.list", original);
    write(root, "/usr/share/keyrings/mongodb.gpg", b"key");
    let adapter = MongoDbAdapter;
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
            &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/mongodb"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("MongoDB source should change")
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

struct MongoDbProber;

impl CandidateProber for MongoDbProber {
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
                b"Origin: mongodb".to_vec()
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
        .filter(|candidate| candidate.tool_id == "mongodb")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 7);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 6);
    assert!(
        complete
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror)
    );
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun"])
    );
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "8.0.28");
    write(root, "/usr/share/keyrings/mongodb-server-8.0.gpg", b"key");
    let context = context(root, Architecture::X86_64, "debian", "12", Some("bookworm"));
    let runtime = runtime(root);
    let detected = MongoDbAdapter.detect(&context, &runtime).unwrap().unwrap();
    let current = MongoDbAdapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = MongoDbAdapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        MongoDbProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable, "{:?}", outcome.repositories);
    assert_eq!(outcome.selections[0].provider_id, "nju");
}
