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
    adapters::{PodmanRegistryAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const ACCEPT: &str = "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json";

struct Spec {
    upstream: &'static str,
    mirror: &'static str,
}

const SPECS: &[Spec] = &[
    Spec {
        upstream: "gcr.io--container-registry",
        mirror: "https://gcr.nju.edu.cn",
    },
    Spec {
        upstream: "ghcr.io--container-registry",
        mirror: "https://ghcr.nju.edu.cn",
    },
    Spec {
        upstream: "quay.io--container-registry",
        mirror: "https://quay.nju.edu.cn",
    },
];

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: "fedora".into(),
            version_id: Some("42".into()),
            version_codename: None,
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

fn install_podman(root: &Path, version: &str, rootless: bool, verification_exit: i32) {
    executable(
        root,
        "/usr/bin/podman",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then
  echo 'podman version {version}'
  exit 0
fi
if [ "$1 $2 $3" = 'info --format {{{{.Host.Security.Rootless}}}}' ]; then
  echo '{rootless}'
  exit 0
fi
if [ "$1 $2 $3" = 'info --format json' ]; then
  echo '{{}}'
  exit 0
fi
last=
for argument in "$@"; do last=$argument; done
case "$last" in
  gcr.io/distroless/static-debian12:nonroot) mirror=gcr.nju.edu.cn ;;
  ghcr.io/oras-project/oras:v1.2.0) mirror=ghcr.nju.edu.cn ;;
  quay.io/prometheus/node-exporter:v1.9.1) mirror=quay.nju.edu.cn ;;
  *) exit 63 ;;
esac
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo "DEBU Trying to pull $mirror representative manifest"
echo 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
"#,
        ),
    );
}

fn runtime(root: &Path, auth: bool) -> OsRuntime {
    let environment = if auth {
        BTreeMap::from([(
            "REGISTRY_AUTH_FILE".into(),
            "/home/developer/private/auth.json".into(),
        )])
    } else {
        BTreeMap::new()
    };
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn selections() -> Vec<MirrorSelection> {
    SPECS
        .iter()
        .map(|spec| MirrorSelection {
            candidate_id: format!("podman-{}-test", spec.upstream),
            tool_id: "podman-registry".into(),
            upstream_id: spec.upstream.into(),
            provider_id: "nju".into(),
            endpoints: vec![Endpoint {
                role: EndpointRole::Registry,
                protocol: Protocol::Https,
                url: spec.mirror.into(),
            }],
            latency_ms: 4,
            selected_at_unix_ms: 123,
            user_override: false,
        })
        .collect()
}

fn system_config() -> &'static [u8] {
    br#"unqualified-search-registries = ["registry.fedoraproject.org", "docker.io"]
short-name-mode = "enforcing"

[[registry]]
prefix = "registry.private.example/team"
location = "registry.private.example/cache"
blocked = false
insecure = false
"#
}

#[test]
fn rootless_user_plan_preserves_system_short_names_private_policy_and_auth() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_podman(root, "5.8.4", true, 0);
    let system = write(root, "/etc/containers/registries.conf", system_config());
    let aliases = b"[aliases]\n\"ubi8\" = \"registry.access.redhat.com/ubi8/ubi\"\n";
    let aliases_path = write(
        root,
        "/etc/containers/registries.conf.d/000-shortnames.conf",
        aliases,
    );
    let auth = write(
        root,
        "/home/developer/private/auth.json",
        b"\xff\xfeopaque-auth",
    );
    let adapter = PodmanRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, true);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("5.8.4"));
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::User
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams.len(), 3);
    assert!(
        request
            .probe_contexts
            .values()
            .all(|contexts| { contexts.len() == 1 && contexts[0]["oci_arch"] == "amd64" })
    );
    let cli = adapter.plan(&context, &current, &selections()).unwrap();
    let config = adapter.plan(&context, &current, &selections()).unwrap();
    let tui = adapter.plan(&context, &current, &selections()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    for host in ["gcr.nju.edu.cn", "ghcr.nju.edu.cn", "quay.nju.edu.cn"] {
        assert!(rendered.contains(host));
    }
    assert!(rendered.contains("pull-from-mirror = \"all\""));
    assert!(!rendered.contains("insecure = true"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("rootless Podman drop-in should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&system).unwrap(), system_config());
    assert_eq!(fs::read(&aliases_path).unwrap(), aliases);
    assert_eq!(fs::read(&auth).unwrap(), b"\xff\xfeopaque-auth");
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections())
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
    assert_eq!(fs::read(system).unwrap(), system_config());
}

#[test]
fn rootful_arm64_system_scope_requires_elevation_and_keeps_user_scope_untouched() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_podman(root, "4.9.5", false, 0);
    write(root, "/etc/containers/registries.conf", system_config());
    let user = b"short-name-mode = \"permissive\"\n";
    let user_path = write(
        root,
        "/home/developer/.config/containers/registries.conf",
        user,
    );
    let adapter = PodmanRegistryAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, false);
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
    assert!(
        request
            .probe_contexts
            .values()
            .all(|contexts| { contexts[0]["oci_arch"] == "arm64" })
    );
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    assert!(plan.requires_elevation);
    assert!(
        plan.changes[0]
            .target
            .ends_with("etc/containers/registries.conf.d/99-mirrorswitch.conf")
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("rootful Podman drop-in should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(user_path).unwrap(), user);
}

#[test]
fn legacy_blocked_insecure_existing_and_mismatched_policies_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = PodmanRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, false))
            .unwrap()
            .is_none()
    );
    install_podman(root, "3.4.4", true, 0);
    assert!(
        adapter
            .detect(&context, &runtime(root, false))
            .unwrap_err()
            .to_string()
            .contains("outside the reviewed")
    );
    install_podman(root, "5.8.4", true, 0);

    let cases = [
        ("[registries.search]\nregistries = ['docker.io']\n", "v1"),
        (
            "[[registry]]\nprefix='quay.io'\nlocation='quay.io'\nblocked=true\n",
            "blocked",
        ),
        (
            "[[registry]]\nprefix='ghcr.io'\nlocation='ghcr.io'\ninsecure=true\n",
            "insecure",
        ),
        (
            "[[registry]]\nprefix='gcr.io'\nlocation='gcr.io'\n",
            "already has",
        ),
    ];
    for (contents, message) in cases {
        write(root, "/etc/containers/registries.conf", contents.as_bytes());
        let runtime = runtime(root, false);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &selections())
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }

    write(root, "/etc/containers/registries.conf", system_config());
    let runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let mut bad = selections();
    bad[0].endpoints[0].url = "https://unreviewed.example".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());
}

#[test]
fn failed_representative_pull_restores_the_selected_drop_in() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_podman(root, "5.8.4", true, 9);
    write(root, "/etc/containers/registries.conf", system_config());
    let original = b"# Managed by MirrorSwitch: Podman registry mirrors v1\n";
    let target = write(
        root,
        "/home/developer/.config/containers/registries.conf.d/99-mirrorswitch.conf",
        original,
    );
    let adapter = PodmanRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("managed Podman drop-in should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(target).unwrap(), original);
}

#[derive(Default)]
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
            return Err(ProbeError::Http("OCI Accept header is missing".into()));
        }
        Ok(ProbeObservation {
            status: 200,
            content_type: Some("application/vnd.oci.image.index.v1+json".into()),
            body: br#"{"manifests":[{"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"architecture": "amd64","os":"linux"}},{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"architecture": "arm64","os":"linux"}}]}"#.to_vec(),
            latency_ms: 2,
        })
    }
}

#[test]
fn catalog_requires_all_three_arch_complete_registry_proxies_before_planning() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "podman-registry")
        .unwrap();
    assert_eq!(
        tool.supported_scopes,
        [ConfigurationScope::System, ConfigurationScope::User]
    );
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "podman-registry")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.upstream_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "gcr.io--container-registry",
            "ghcr.io--container-registry",
            "quay.io--container-registry",
        ])
    );
    assert!(candidates.iter().all(|candidate| {
        candidate.provider_id == "nju"
            && candidate.delivery_mode == DeliveryMode::Proxy
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 2
    }));

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_podman(root, "5.8.4", true, 0);
    write(root, "/etc/containers/registries.conf", system_config());
    let adapter = PodmanRegistryAdapter;
    let context = context(root, Architecture::X86_64);
    let runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
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
    assert_eq!(outcome.selections.len(), 3);
}
