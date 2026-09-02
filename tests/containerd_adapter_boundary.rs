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
    adapters::{ContainerdAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::{MirrorSelection, ServiceImpact},
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "registry.k8s.io--container-registry";
const MIRROR: &str = "https://k8s.nju.edu.cn";
const ACCEPT: &str = "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
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

fn install_containerd(root: &Path, version: &str, verification_exit: i32) {
    executable(
        root,
        "/usr/bin/containerd",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then echo 'containerd containerd.io {version} test'; exit 0; fi
if [ "$1" = --config ] && [ "$3 $4" = 'config dump' ]; then
  config='{root}'"$2"
  grep -F 'config_path = "/etc/containerd/certs.d"' "$config" >/dev/null || exit 61
  cat "$config"
  exit 0
fi
exit 60
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/ctr",
        format!(
            r#"#!/bin/sh
if [ "$1 $2" = 'plugins ls' ]; then
  echo 'io.containerd.grpc.v1 cri linux/amd64 ok'
  exit 0
fi
last=
hosts=
for argument in "$@"; do
  [ "$last" = --hosts-dir ] && hosts=$argument
  last=$argument
done
[ "$last" = registry.k8s.io/pause:3.10.1 ] || exit 71
[ "$hosts" = /etc/containerd/certs.d ] || exit 72
grep -F 'https://k8s.nju.edu.cn' '{root}'"$hosts"/registry.k8s.io/hosts.toml >/dev/null || exit 73
grep -F 'skip_verify = false' '{root}'"$hosts"/registry.k8s.io/hosts.toml >/dev/null || exit 74
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'DEBU fetching blob from k8s.nju.edu.cn'
echo 'unpacking linux image done'
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

fn selection() -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: "containerd-nju-test".into(),
        tool_id: "containerd".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "nju".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Registry,
            protocol: Protocol::Https,
            url: MIRROR.into(),
        }],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn containerd_one_with_config_path_changes_only_hosts_and_preserves_custom_order() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_containerd(root, "1.7.28", 0);
    let config = b"version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n[plugins.\"io.containerd.grpc.v1.cri\".containerd]\n  snapshotter = \"overlayfs\"\n";
    let config_path = write(root, "/etc/containerd/config.toml", config);
    let hosts = b"server = \"https://registry.k8s.io\"\n\n[host.\"https://cache-one.example\"]\n  capabilities = [\"pull\"]\n  ca = \"private-ca.crt\"\n\n[host.\"https://cache-two.example\"]\n  capabilities = [\"pull\"]\n  [host.\"https://cache-two.example\".header]\n    authorization = \"<preserved>\"\n";
    let hosts_path = write(
        root,
        "/etc/containerd/certs.d/registry.k8s.io/hosts.toml",
        hosts,
    );
    let adapter = ContainerdAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.7.28"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["oci_arch"], "amd64");
    let cli = adapter.plan(&context, &current, &selection()).unwrap();
    let config_plan = adapter.plan(&context, &current, &selection()).unwrap();
    let tui = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(cli, config_plan);
    assert_eq!(config_plan, tui);
    assert_eq!(cli.changes.len(), 1);
    assert_eq!(cli.service_impact, ServiceImpact::None);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.find(MIRROR).unwrap() < rendered.find("cache-one.example").unwrap());
    assert!(
        rendered.find("cache-one.example").unwrap() < rendered.find("cache-two.example").unwrap()
    );
    assert!(rendered.contains("private-ca.crt"));
    assert!(rendered.contains("authorization"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("containerd hosts should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&config_path).unwrap(), config);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
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
    assert_eq!(fs::read(hosts_path).unwrap(), hosts);
}

#[test]
fn containerd_two_adds_v3_config_path_and_marks_restart_without_restarting() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_containerd(root, "2.1.5", 0);
    let config =
        b"version = 3\n[plugins.'io.containerd.cri.v1.runtime']\n  enable_selinux = true\n";
    let config_path = write(root, "/etc/containerd/config.toml", config);
    let adapter = ContainerdAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["oci_arch"], "arm64");
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(plan.changes.len(), 2);
    assert_eq!(plan.service_impact, ServiceImpact::RestartRequired);
    let config_change = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with("config.toml"))
        .unwrap();
    let rendered = String::from_utf8(config_change.new_contents.clone()).unwrap();
    assert!(rendered.contains("io.containerd.cri.v1.images"));
    assert!(rendered.contains("enable_selinux = true"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("containerd config and hosts should change")
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
    assert_eq!(fs::read(config_path).unwrap(), config);
}

#[test]
fn legacy_disabled_custom_server_unsafe_and_mismatched_selection_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_containerd(root, "1.6.39", 0);
    let adapter = ContainerdAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root))
            .unwrap_err()
            .to_string()
            .contains("outside reviewed")
    );
    install_containerd(root, "1.7.28", 0);
    let cases = [
        (
            "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"registry.k8s.io\"]\n  endpoint = [\"https://old.example\"]\n",
            "deprecated",
        ),
        ("version = 2\ndisabled_plugins = [\"cri\"]\n", "disabled"),
    ];
    for (config, message) in cases {
        write(root, "/etc/containerd/config.toml", config.as_bytes());
        let runtime = runtime(root);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::System)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &selection())
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
    write(root, "/etc/containerd/config.toml", b"version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n");
    write(
        root,
        "/etc/containerd/certs.d/registry.k8s.io/hosts.toml",
        b"server = \"https://private.example\"\n",
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
            .unwrap_err()
            .to_string()
            .contains("custom primary")
    );

    write(root, "/etc/containerd/certs.d/registry.k8s.io/hosts.toml", b"server = \"https://registry.k8s.io\"\n[host.\"https://k8s.nju.edu.cn\"]\n  capabilities = [\"pull\", \"push\"]\n  skip_verify = true\n");
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
            .unwrap_err()
            .to_string()
            .contains("unsafe")
    );

    write(
        root,
        "/etc/containerd/certs.d/registry.k8s.io/hosts.toml",
        b"",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let mut bad = selection();
    bad[0].endpoints[0].url = "https://unreviewed.example".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());
}

#[test]
fn failed_ctr_pull_restores_config_and_hosts() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_containerd(root, "2.1.5", 9);
    let config = b"version = 3\n";
    let config_path = write(root, "/etc/containerd/config.toml", config);
    let adapter = ContainerdAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("containerd files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(config_path).unwrap(), config);
    assert!(
        !root
            .join("etc/containerd/certs.d/registry.k8s.io/hosts.toml")
            .exists()
    );
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
        _method: HttpMethod,
        _url: &str,
        accept: Option<&str>,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        if accept != Some(ACCEPT) {
            return Err(ProbeError::Http("OCI Accept missing".into()));
        }
        Ok(ProbeObservation {
            status: 200,
            content_type: Some("application/vnd.docker.distribution.manifest.list.v2+json".into()),
            body: br#"{"manifests":[{"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"architecture": "amd64","os":"linux"}},{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"architecture": "arm64","os":"linux"}}]}"#.to_vec(),
            latency_ms: 2,
        })
    }
}

#[test]
fn catalog_exposes_one_arch_complete_registry_candidate() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "containerd")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 1);
    let candidate = candidates[0];
    assert_eq!(candidate.provider_id, "nju");
    assert_eq!(candidate.delivery_mode, DeliveryMode::Proxy);
    assert_eq!(
        candidate.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );
    assert_eq!(candidate.probes.len(), 2);

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_containerd(root, "1.7.28", 0);
    write(root, "/etc/containerd/config.toml", b"version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n");
    let adapter = ContainerdAdapter;
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
    assert_eq!(outcome.selections[0].provider_id, "nju");
}
