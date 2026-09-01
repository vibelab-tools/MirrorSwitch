#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{KubernetesImagesAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "registry.k8s.io--container-registry";
const NJU: &str = "https://k8s.nju.edu.cn";
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

fn install_kubeadm(root: &Path, version: &str, verification_exit: i32) {
    executable(
        root,
        "/usr/bin/kubeadm",
        format!(
            r#"#!/bin/sh
if [ "$1 $2 $3" = 'version -o short' ]; then
  echo '{version}'
  exit 0
fi
if [ "$1 $2 $3 $4" = 'config images list --help' ]; then
  echo '--image-repository --kubernetes-version --config'
  exit 0
fi
if [ "$1 $2 $3 $4" = 'config images pull --help' ]; then
  echo '--cri-socket --image-repository --kubernetes-version --config'
  exit 0
fi
if [ "$1 $2" = 'config validate' ] && [ "$3" = --config ]; then
  config='{root}'"$4"
  grep -F 'Managed by MirrorSwitch: kubeadm image mapping v1' "$config" >/dev/null || exit 61
  grep -F 'imageRepository: k8s.nju.edu.cn' "$config" >/dev/null || exit 62
  grep -F '  imageRepository: k8s.nju.edu.cn/coredns' "$config" >/dev/null || exit 63
  [ {verification_exit} -eq 0 ] || exit {verification_exit}
  echo ok
  exit 0
fi
if [ "$1 $2 $3" = 'config images list' ] && [ "$4" = --config ]; then
  config='{root}'"$5"
  version=$(sed -n 's/^kubernetesVersion: //p' "$config")
  [ -n "$version" ] || exit 64
  printf '%s\n' \
    "k8s.nju.edu.cn/kube-apiserver:$version" \
    "k8s.nju.edu.cn/kube-controller-manager:$version" \
    "k8s.nju.edu.cn/kube-scheduler:$version" \
    "k8s.nju.edu.cn/kube-proxy:$version" \
    'k8s.nju.edu.cn/coredns/coredns:v1.13.1' \
    'k8s.nju.edu.cn/pause:3.10.1' \
    'k8s.nju.edu.cn/etcd:3.6.6-0'
  exit 0
fi
if [ "$1 $2 $3" = 'config images list' ] && [ "$4" = --kubernetes-version ] && [ "$6" = --image-repository ]; then
  version=$5
  [ "$7" = registry.k8s.io ] || exit 65
  printf '%s\n' \
    "registry.k8s.io/kube-apiserver:$version" \
    "registry.k8s.io/kube-controller-manager:$version" \
    "registry.k8s.io/kube-scheduler:$version" \
    "registry.k8s.io/kube-proxy:$version" \
    'registry.k8s.io/coredns/coredns:v1.13.1' \
    'registry.k8s.io/pause:3.10.1' \
    'registry.k8s.io/etcd:3.6.6-0'
  exit 0
fi
if [ "$1 $2 $3" = 'config images pull' ]; then
  exit 99
fi
exit 60
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(BTreeMap::new())
}

fn project_config(version: &str, repository: &str) -> String {
    format!(
        "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\nkubernetesVersion: {version}\nimageRepository: {repository}\n---\napiVersion: kubeadm.k8s.io/v1beta4\nkind: InitConfiguration\nnodeRegistration:\n  criSocket: unix:///run/containerd/containerd.sock\n"
    )
}

fn selection() -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: "kubernetes-images-nju-test".into(),
        tool_id: "kubernetes-images".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "nju".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Registry,
            protocol: Protocol::Https,
            url: NJU.into(),
        }],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn user_plan_preserves_cluster_config_and_maps_coredns_explicitly() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_kubeadm(root, "v1.35.8", 0);
    let project = project_config("v1.35.8", "registry.k8s.io");
    let project_path = write(root, "/work/project/kubeadm.yaml", project.as_bytes());
    let adapter = KubernetesImagesAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("v1.35.8"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "kubeadm reported 7 required images")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        current
            .files
            .contains(&PathBuf::from("/work/project/kubeadm.yaml"))
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    let contexts = &request.probe_contexts[UPSTREAM];
    assert_eq!(contexts.len(), 7);
    assert!(contexts.iter().all(|item| item["oci_arch"] == "amd64"));
    assert!(
        contexts
            .iter()
            .any(|item| item["repository_path"] == "coredns/coredns")
    );

    let cli = adapter.plan(&context, &current, &selection()).unwrap();
    let config = adapter.plan(&context, &current, &selection()).unwrap();
    let tui = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("imageRepository: k8s.nju.edu.cn"));
    assert!(rendered.contains("  imageRepository: k8s.nju.edu.cn/coredns"));
    assert_eq!(fs::read(&project_path).unwrap(), project.as_bytes());

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("kubeadm image plan should create one file")
    };
    let verified = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(verified.valid);
    assert!(verified.summary.contains("no image pull"));
    assert_eq!(fs::read(&project_path).unwrap(), project.as_bytes());
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
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
    assert_eq!(fs::read(project_path).unwrap(), project.as_bytes());
}

#[test]
fn arm64_uses_every_exact_image_as_a_probe_context() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_kubeadm(root, "v1.37.0", 0);
    let adapter = KubernetesImagesAdapter;
    let context = context(root, Architecture::Arm64);
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM].len(), 7);
    assert!(
        request.probe_contexts[UPSTREAM]
            .iter()
            .all(|item| item["oci_arch"] == "arm64")
    );
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    assert_eq!(
        plan,
        adapter.plan(&context, &current, &selection()).unwrap()
    );
    assert!(
        String::from_utf8(plan.changes[0].new_contents.clone())
            .unwrap()
            .contains("kubernetesVersion: v1.37.0")
    );
}

#[test]
fn private_configs_old_versions_and_mismatched_registry_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = KubernetesImagesAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(adapter.detect(&context, &runtime(root)).unwrap().is_none());

    install_kubeadm(root, "v1.30.14", 0);
    assert!(
        adapter
            .detect(&context, &runtime(root))
            .unwrap_err()
            .to_string()
            .contains("outside the reviewed")
    );
    install_kubeadm(root, "v1.35.8", 0);
    write(
        root,
        "/work/project/kubeadm.yaml",
        project_config("v1.35.8", "registry.private.example/team").as_bytes(),
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection())
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    write(
        root,
        "/work/project/kubeadm.yaml",
        project_config("v1.33.9", "registry.k8s.io").as_bytes(),
    );
    assert!(
        adapter
            .detect(&context, &runtime)
            .unwrap_err()
            .to_string()
            .contains("version window")
    );

    write(
        root,
        "/work/project/kubeadm.yaml",
        project_config("v1.35.8", "registry.k8s.io").as_bytes(),
    );
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let mut bad = selection();
    bad[0].endpoints[0].url = "https://registry.cn-hangzhou.aliyuncs.com/google_containers".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());
}

#[test]
fn failed_kubeadm_validation_restores_generated_file() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_kubeadm(root, "v1.35.8", 9);
    let original = b"# Managed by MirrorSwitch: kubeadm image mapping v1\n# old managed state\n";
    let managed = write(
        root,
        "/home/developer/.config/mirrorswitch/kubeadm-images-nju.yaml",
        original,
    );
    let adapter = KubernetesImagesAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("managed kubeadm file should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(managed).unwrap(), original);
}

#[derive(Default)]
struct OciProber {
    calls: RefCell<Vec<(String, Option<String>)>>,
}

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
        url: &str,
        accept: Option<&str>,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        if accept != Some(ACCEPT) {
            return Err(ProbeError::Http(
                "OCI manifest negotiation header is missing".into(),
            ));
        }
        self.calls
            .borrow_mut()
            .push((url.into(), accept.map(str::to_owned)));
        Ok(ProbeObservation {
            status: 200,
            content_type: Some(
                "application/vnd.docker.distribution.manifest.list.v2+json".into(),
            ),
            body: br#"{"manifests":[{"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"architecture": "amd64","os":"linux"}},{"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"architecture": "arm64","os":"linux"}}]}"#.to_vec(),
            latency_ms: 2,
        })
    }
}

#[test]
fn catalog_negotiates_manifest_indexes_and_probes_every_exact_image_before_selection() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "kubernetes-images")
        .unwrap();
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "kubernetes-images")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 1);
    let candidate = candidates[0];
    assert_eq!(candidate.provider_id, "nju");
    assert_eq!(candidate.delivery_mode, DeliveryMode::Proxy);
    assert_eq!(candidate.probes.len(), 2);
    assert!(candidate.probes.iter().all(|probe| {
        probe.endpoint_role == EndpointRole::Registry
            && probe.method == HttpMethod::Get
            && probe.accept.as_deref() == Some(ACCEPT)
    }));
    assert_eq!(
        candidate.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_kubeadm(root, "v1.35.8", 0);
    let adapter = KubernetesImagesAdapter;
    let context = context(root, Architecture::X86_64);
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let prober = OciProber::default();
    let selector = MirrorSelector::with_prober(
        &catalog,
        prober,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 64 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections.len(), 1);
    assert_eq!(outcome.selections[0].provider_id, "nju");
    let contexts = &request.probe_contexts[UPSTREAM];
    let expected_paths = contexts
        .iter()
        .map(|item| {
            format!(
                "https://k8s.nju.edu.cn/v2/{}/manifests/{}",
                item["repository_path"], item["tag"]
            )
        })
        .collect::<BTreeSet<_>>();
    assert!(expected_paths.contains("https://k8s.nju.edu.cn/v2/coredns/coredns/manifests/v1.13.1"));
}
