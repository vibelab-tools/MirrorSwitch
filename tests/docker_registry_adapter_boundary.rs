#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{DockerRegistryAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "docker-hub--container-registry";
const DAOCLOUD: &str = "https://docker.m.daocloud.io";
const ONEPANEL: &str = "https://docker.1panel.live";
const ACCEPT: &str = "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "debian".into(),
            version_id: Some("12".into()),
            version_codename: Some("bookworm".into()),
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

fn install_docker(
    root: &Path,
    docker_context: &str,
    endpoint: &str,
    operating_system: &str,
    rootless: bool,
    pull_exit: i32,
    install_dockerd: bool,
) {
    let security = if rootless {
        r#"["name=rootless"]"#
    } else {
        "[]"
    };
    executable(
        root,
        "/usr/bin/docker",
        format!(
            r#"#!/bin/sh
case "$1 $2" in
  'version --format') echo '29.7.2'; exit 0 ;;
  'context show') echo '{docker_context}'; exit 0 ;;
  'context inspect') echo '"{endpoint}"'; exit 0 ;;
  'info --format') echo '{{"OperatingSystem":"{operating_system}","SecurityOptions":{security}}}'; exit 0 ;;
  'ps --quiet') echo 'running-container'; exit 0 ;;
  'pull --platform')
    case "$4" in
      docker.m.daocloud.io/library/alpine@sha256:*|docker.1panel.live/library/alpine@sha256:*) ;;
      *) exit 71 ;;
    esac
    [ "$3" = linux/amd64 ] || [ "$3" = linux/arm64 ] || exit 72
    [ {pull_exit} -eq 0 ] || exit {pull_exit}
    echo "Pulled $4"
    exit 0
    ;;
esac
exit 60
"#,
        ),
    );
    if install_dockerd {
        executable(
            root,
            "/usr/bin/dockerd",
            format!(
                r#"#!/bin/sh
[ "$1" = --validate ] || exit 61
[ "$2" = --config-file ] || exit 62
config='{root}'"$3"
grep -F '"registry-mirrors"' "$config" >/dev/null || exit 63
echo 'configuration OK'
"#,
                root = root.display(),
            ),
        );
    }
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/test")
        .with_environment(BTreeMap::new())
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("docker-registry-{provider}-test"),
        tool_id: "docker-registry".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: provider.into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Registry,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn system_engine_preserves_daemon_policy_and_verifies_a_digest_pinned_pull() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_docker(
        root,
        "default",
        "unix:///var/run/docker.sock",
        "Docker Engine - Community",
        false,
        0,
        true,
    );
    let original = br#"{
  "log-driver": "journald",
  "registry-mirrors": ["https://private.example", "https://docker.1panel.live"],
  "insecure-registries": ["legacy.internal:5000"],
  "proxies": {"http-proxy": "http://proxy.internal:3128"},
  "features": {"containerd-snapshotter": true}
}
"#;
    let path = write(root, "/etc/docker/daemon.json", original);
    let adapter = DockerRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::System
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[UPSTREAM][0]["manifest_hash"],
        "f27cad9117495d32d067133afff942cb2dc745dfe9163e949f6bfe8a6a245339"
    );
    let cli = adapter
        .plan(&context, &current, &selection("daocloud", DAOCLOUD))
        .unwrap();
    let config = adapter
        .plan(&context, &current, &selection("daocloud", DAOCLOUD))
        .unwrap();
    let tui = adapter
        .plan(&context, &current, &selection("daocloud", DAOCLOUD))
        .unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.service_impact, ServiceImpact::RestartRequired);
    assert!(cli.requires_elevation);
    let rendered: serde_json::Value = serde_json::from_slice(&cli.changes[0].new_contents).unwrap();
    assert_eq!(
        rendered["registry-mirrors"],
        serde_json::json!([DAOCLOUD, "https://private.example", ONEPANEL])
    );
    assert_eq!(rendered["log-driver"], "journald");
    assert_eq!(rendered["insecure-registries"][0], "legacy.internal:5000");
    assert_eq!(
        rendered["proxies"]["http-proxy"],
        "http://proxy.internal:3128"
    );
    assert_eq!(rendered["features"]["containerd-snapshotter"], true);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Docker daemon configuration should change")
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
            .plan(&context, &current, &selection("daocloud", DAOCLOUD))
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
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn rootless_and_desktop_backends_use_their_documented_user_paths() {
    for (name, docker_context, endpoint, operating_system, config_path, dockerd) in [
        (
            "rootless",
            "rootless",
            "unix:///run/user/1000/docker.sock",
            "Docker Engine - Community",
            "/home/test/.config/docker/daemon.json",
            true,
        ),
        (
            "desktop",
            "desktop-linux",
            "unix:///home/test/.docker/desktop/docker.sock",
            "Docker Desktop 4.47.0 (209601)",
            "/home/test/.docker/daemon.json",
            false,
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_docker(
            root,
            docker_context,
            endpoint,
            operating_system,
            name == "rootless",
            0,
            dockerd,
        );
        let adapter = DockerRegistryAdapter;
        let context = context(root, Architecture::Arm64);
        let mut runtime = runtime(root);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert_eq!(
            adapter
                .default_scope_for(&context, &runtime, &detected)
                .unwrap(),
            ConfigurationScope::User
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert_eq!(current.documents[0].path, PathBuf::from(config_path));
        let plan = adapter
            .plan(&context, &current, &selection("onepanel", ONEPANEL))
            .unwrap();
        assert!(!plan.requires_elevation);
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
        else {
            panic!("Docker user daemon configuration should change")
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
        assert!(!root.join(config_path.trim_start_matches('/')).exists());
    }
}

#[test]
fn remote_context_and_startup_registry_mirror_flag_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_docker(
        root,
        "remote",
        "ssh://builder.example",
        "Docker Engine - Community",
        false,
        0,
        true,
    );
    let adapter = DockerRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root))
            .unwrap_err()
            .to_string()
            .contains("remote")
    );

    install_docker(
        root,
        "default",
        "unix:///var/run/docker.sock",
        "Docker Engine - Community",
        false,
        0,
        true,
    );
    executable(
        root,
        "/usr/bin/systemctl",
        "#!/bin/sh\necho '{ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd --config-file=/etc/docker/custom.json --registry-mirror=https://private.example ; }'\n"
            .into(),
    );
    write(root, "/etc/docker/custom.json", b"{}");
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert_eq!(
        current.documents[0].path,
        PathBuf::from("/etc/docker/custom.json")
    );
    assert!(
        adapter
            .plan(&context, &current, &selection("daocloud", DAOCLOUD))
            .unwrap_err()
            .to_string()
            .contains("startup command")
    );
}

#[test]
fn failed_real_pull_restores_the_daemon_configuration() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_docker(
        root,
        "default",
        "unix:///var/run/docker.sock",
        "Docker Engine - Community",
        false,
        9,
        true,
    );
    let original = b"{\"log-level\":\"info\"}\n";
    let path = write(root, "/etc/docker/daemon.json", original);
    let adapter = DockerRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("daocloud", DAOCLOUD))
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Docker daemon configuration should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(path).unwrap(), original);
}

struct OciProber;

impl CandidateProber for OciProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.probe_with_accept(method, url, None, limits)
    }

    fn probe_with_accept(
        &self,
        method: HttpMethod,
        url: &str,
        accept: Option<&str>,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        if accept != Some(ACCEPT) {
            return Err(ProbeError::Http("OCI Accept header is missing".into()));
        }
        let body = if method == HttpMethod::Get {
            br#"{"schemaVersion":2,"config":{"digest":"sha256:2607caa9805847fac4de202017bb1b830deb09f4c07dc9964a0157abbc604577"},"layers":[{"digest":"sha256:897d797d2723cf0e318402f4d6f37d51b011517e5cf09246b22155f0fa90dc81"}]}"#.to_vec()
        } else {
            Vec::new()
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: (method == HttpMethod::Get)
                .then(|| "application/vnd.oci.image.manifest.v1+json".into()),
            body,
            latency_ms: if url.contains("daocloud") { 2 } else { 5 },
        })
    }
}

#[test]
fn catalog_selects_the_lowest_latency_complete_docker_hub_proxy() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "docker-registry")
        .unwrap();
    assert_eq!(
        tool.supported_scopes,
        [ConfigurationScope::System, ConfigurationScope::User]
    );
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "docker-registry")
        .filter(|candidate| candidate.delivery_mode == DeliveryMode::Proxy)
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Proxy
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 4
    }));

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_docker(
        root,
        "default",
        "unix:///var/run/docker.sock",
        "Docker Engine - Community",
        false,
        0,
        true,
    );
    let adapter = DockerRegistryAdapter;
    let context = context(root, Architecture::X86_64);
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
        OciProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 64 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections.len(), 1);
    assert_eq!(outcome.selections[0].provider_id, "daocloud");
}
