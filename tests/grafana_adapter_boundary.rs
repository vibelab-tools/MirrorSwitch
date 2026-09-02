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
    adapters::{GrafanaAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "grafana-packages--repository-metadata";

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

fn install_grafana(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/grafana-server",
        format!("#!/bin/sh\necho 'Version {version}'\n"),
    );
}

fn install_apt(root: &Path, verification_exit: i32, version: &str) {
    install_grafana(root, version);
    executable(
        root,
        "/usr/bin/apt-get",
        format!(
            r#"#!/bin/sh
source_file=
for argument in "$@"; do case "$argument" in Dir::Etc::sourcelist=*) source_file=${{argument#*=}} ;; esac; done
[ "$1" = update ] || exit 61
grep -F '/grafana/apt' '{root}'"$source_file" >/dev/null || exit 62
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: Grafana stable mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'grafana:'\necho '  Candidate: 13.2.0'\necho 'grafana-enterprise:'\necho '  Candidate: 13.2.0'\n".into(),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/root")
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("grafana-{provider}-test"),
        tool_id: "grafana".into(),
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
    install_apt(root, 0, "13.2.0");
    let original =
        b"deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main\n";
    let source = write(root, "/etc/apt/sources.list.d/grafana.list", original);
    let key = write(root, "/usr/share/keyrings/grafana.gpg", b"grafana-key");
    let private = b"deb [signed-by=/usr/share/keyrings/private.gpg] https://packages.example.invalid/apt stable main\n";
    let private_path = write(root, "/etc/apt/sources.list.d/private.list", private);
    let mariadb = b"deb https://mirror.example.invalid/mariadb/repo/11.8/ubuntu noble main\n";
    let mariadb_path = write(root, "/etc/apt/sources.list.d/mariadb.list", mariadb);
    let pin = b"Package: grafana grafana-enterprise\nPin: version 13.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/grafana", pin);
    let adapter = GrafanaAdapter;
    let context = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("13.2.0"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "apt-stable-13-amd64");
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/grafana");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.service_impact, ServiceImpact::None);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.tuna.tsinghua.edu.cn/grafana/apt"));
    assert!(rendered.contains("stable main"));
    assert!(rendered.contains("signed-by=/usr/share/keyrings/grafana.gpg"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Grafana APT source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key).unwrap(), b"grafana-key");
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
fn stale_rpm_repository_is_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_grafana(root, "13.2.0");
    executable(root, "/usr/bin/dnf", "#!/bin/sh\nexit 0\n".into());
    let context = context(root, Architecture::X86_64, "rocky", "9.6", None);
    assert!(GrafanaAdapter.detect(&context, &runtime(root)).is_err());
}

#[test]
fn unsupported_version_beta_missing_key_and_multiple_sources_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "13.2.0");
    let arm = context(root, Architecture::Arm64, "ubuntu", "24.04", Some("noble"));
    assert!(
        GrafanaAdapter
            .detect(&arm, &runtime(root))
            .unwrap()
            .is_some()
    );

    install_apt(root, 0, "12.4.9");
    let x64 = context(root, Architecture::X86_64, "ubuntu", "24.04", Some("noble"));
    assert!(GrafanaAdapter.detect(&x64, &runtime(root)).is_err());

    install_apt(root, 0, "13.2.0");
    write(
        root,
        "/etc/apt/sources.list.d/grafana.list",
        b"deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com beta main\n",
    );
    write(root, "/usr/share/keyrings/grafana.gpg", b"key");
    let apt_runtime = runtime(root);
    assert!(GrafanaAdapter.detect(&x64, &apt_runtime).is_err());

    write(
        root,
        "/etc/apt/sources.list.d/grafana.list",
        b"deb [signed-by=/usr/share/keyrings/missing-grafana.gpg] https://apt.grafana.com stable main\n",
    );
    let detected = GrafanaAdapter.detect(&x64, &apt_runtime).unwrap().unwrap();
    let current = GrafanaAdapter
        .read_current(&x64, &apt_runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        GrafanaAdapter
            .plan(
                &x64,
                &current,
                &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/grafana")
            )
            .is_err()
    );

    write(
        root,
        "/etc/apt/sources.list.d/grafana-second.list",
        b"deb [signed-by=/usr/share/keyrings/grafana.gpg] https://mirrors.nju.edu.cn/grafana/apt stable main\n",
    );
    assert!(GrafanaAdapter.detect(&x64, &apt_runtime).is_err());
}

#[test]
fn failed_package_refresh_restores_grafana_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 9, "13.2.0");
    let original =
        b"deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main\n";
    let source = write(root, "/etc/apt/sources.list.d/grafana.list", original);
    write(root, "/usr/share/keyrings/grafana.gpg", b"key");
    let adapter = GrafanaAdapter;
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
            &selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/grafana"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Grafana source should change")
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

struct GrafanaProber;

impl CandidateProber for GrafanaProber {
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
                b"Architectures: amd64 arm64".to_vec()
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
        .filter(|candidate| candidate.tool_id == "grafana")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 4);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 3);
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
        BTreeSet::from(["huaweicloud"])
    );
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, 0, "13.2.0");
    write(root, "/etc/apt/keyrings/grafana.gpg", b"key");
    let context = context(root, Architecture::X86_64, "debian", "12", Some("bookworm"));
    let runtime = runtime(root);
    let detected = GrafanaAdapter.detect(&context, &runtime).unwrap().unwrap();
    let current = GrafanaAdapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = GrafanaAdapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        GrafanaProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable, "{:?}", outcome.repositories);
    assert_eq!(outcome.selections[0].provider_id, "nju");
}
