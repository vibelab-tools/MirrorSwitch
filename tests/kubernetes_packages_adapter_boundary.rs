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
    adapters::{KubernetesPackagesAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "kubernetes--repository-metadata";

fn context(root: &Path, architecture: Architecture, distribution: &str) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(if distribution == "debian" { "12" } else { "42" }.into()),
            version_codename: (distribution == "debian").then(|| "bookworm".into()),
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

fn install_kubeadm(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/kubeadm",
        format!(
            "#!/bin/sh\nif [ \"$1 $2 $3\" = 'version -o short' ]; then echo '{version}'; exit 0; fi\nexit 60\n"
        ),
    );
}

fn install_apt(root: &Path, version: &str, verification_exit: i32) {
    install_kubeadm(root, version);
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
[ -n "$source_file" ] || exit 62
grep -F '/kubernetes/core:/stable:/v1.35/deb' '{root}'"$source_file" >/dev/null || exit 63
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'Hit: Kubernetes v1.35 mirror'
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/apt-cache",
        "#!/bin/sh\necho 'kubeadm:'\necho '  Candidate: 1.35.8-1.1'\n".into(),
    );
}

fn install_dnf(root: &Path, version: &str, verification_exit: i32) {
    install_kubeadm(root, version);
    executable(
        root,
        "/usr/bin/dnf",
        format!(
            r#"#!/bin/sh
reposdir=
for argument in "$@"; do
  case "$argument" in --setopt=reposdir=*) reposdir=${{argument##*=}} ;; esac
done
[ -n "$reposdir" ] || exit 71
grep -F '/kubernetes/core:/stable:/v1.35/rpm' '{root}'"$reposdir"/*.repo >/dev/null || exit 72
grep -F 'gpgcheck=1' '{root}'"$reposdir"/*.repo >/dev/null || exit 73
[ {verification_exit} -eq 0 ] || exit {verification_exit}
case " $* " in
  *' makecache '*) echo 'Metadata cache created' ;;
  *' list '*' kubeadm '*) echo 'kubeadm.aarch64 1.35.8-150500.1.1 mirrorswitch-kubernetes' ;;
  *) exit 74 ;;
esac
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path, paths: &[&str]) -> OsRuntime {
    OsRuntime::new(root, paths.iter().map(PathBuf::from).collect())
        .with_home("/root")
        .with_environment(BTreeMap::new())
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("kubernetes-packages-{provider}-test"),
        tool_id: "kubernetes-packages".into(),
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
fn apt_plan_preserves_keyring_pinning_related_repositories_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "v1.35.8", 0);
    let original = b"deb [arch=amd64 signed-by=/etc/apt/keyrings/kubernetes.gpg] https://pkgs.k8s.io/core:/stable:/v1.35/deb/ /\n";
    let source = write(root, "/etc/apt/sources.list.d/kubernetes.list", original);
    let key = b"opaque-keyring";
    let key_path = write(root, "/etc/apt/keyrings/kubernetes.gpg", key);
    let crio = b"deb [signed-by=/etc/apt/keyrings/cri-o.gpg] https://pkgs.k8s.io/addons:/cri-o:/stable:/v1.35/deb/ /\n";
    let crio_path = write(root, "/etc/apt/sources.list.d/cri-o.list", crio);
    let pin = b"Package: kubelet kubeadm kubectl\nPin: version 1.35.*\nPin-Priority: 1001\n";
    let pin_path = write(root, "/etc/apt/preferences.d/kubernetes", pin);
    let adapter = KubernetesPackagesAdapter;
    let context = context(root, Architecture::X86_64, "debian");
    let mut runtime = runtime(root, &["/usr/bin"]);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("v1.35.8"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["minor"], "v1.35");
    assert_eq!(request.probe_contexts[UPSTREAM][0]["deb_arch"], "amd64");
    let selected = selection("ustc", "https://mirrors.ustc.edu.cn/kubernetes");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert!(cli.requires_elevation);
    assert_eq!(cli.changes.len(), 1);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://mirrors.ustc.edu.cn/kubernetes/core:/stable:/v1.35/deb/"));
    assert!(rendered.contains("signed-by=/etc/apt/keyrings/kubernetes.gpg"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("APT Kubernetes source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&key_path).unwrap(), key);
    assert_eq!(fs::read(&crio_path).unwrap(), crio);
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
fn arm64_rpm_plan_preserves_gpg_and_repo_policy() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, "v1.35.8", 0);
    let original = b"[kubernetes]\nname=Kubernetes\nbaseurl=https://pkgs.k8s.io/core:/stable:/v1.35/rpm/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=https://pkgs.k8s.io/core:/stable:/v1.35/rpm/repodata/repomd.xml.key\nexclude=kubelet\n";
    let repo = write(root, "/etc/yum.repos.d/kubernetes.repo", original);
    let other =
        b"[cri-o]\nbaseurl=https://pkgs.k8s.io/addons:/cri-o:/stable:/v1.35/rpm/\ngpgcheck=1\n";
    let other_path = write(root, "/etc/yum.repos.d/cri-o.repo", other);
    let adapter = KubernetesPackagesAdapter;
    let context = context(root, Architecture::Arm64, "fedora");
    let mut runtime = runtime(root, &["/usr/bin"]);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.probe_contexts[UPSTREAM][0]["rpm_arch"], "aarch64");
    let selected = selection("tuna", "https://mirrors.tuna.tsinghua.edu.cn/kubernetes");
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(
        "baseurl=https://mirrors.tuna.tsinghua.edu.cn/kubernetes/core:/stable:/v1.35/rpm/"
    ));
    assert!(rendered.contains("gpgkey=https://pkgs.k8s.io/"));
    assert!(rendered.contains("exclude=kubelet"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("RPM Kubernetes source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&other_path).unwrap(), other);
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(repo).unwrap(), original);
}

#[test]
fn missing_source_creates_deb822_only_when_keyring_exists() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "v1.35.8", 0);
    write(root, "/etc/apt/keyrings/kubernetes-apt-keyring.gpg", b"key");
    let adapter = KubernetesPackagesAdapter;
    let context = context(root, Architecture::Arm64, "debian");
    let runtime = runtime(root, &["/usr/bin"]);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("nju", "https://mirrors.nju.edu.cn/kubernetes"),
        )
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.starts_with("# Managed by MirrorSwitch"));
    assert!(rendered.contains("Types: deb"));
    assert!(rendered.contains("Signed-By: /etc/apt/keyrings/kubernetes-apt-keyring.gpg"));
}

#[test]
fn legacy_cross_minor_multiple_and_disabled_gpg_policies_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "v1.35.8", 0);
    write(root, "/etc/apt/keyrings/kubernetes.gpg", b"key");
    let adapter = KubernetesPackagesAdapter;
    let apt_context = context(root, Architecture::X86_64, "debian");

    write(
        root,
        "/etc/apt/sources.list.d/kubernetes.list",
        b"deb https://apt.kubernetes.io/ kubernetes-xenial main\n",
    );
    let apt_runtime = runtime(root, &["/usr/bin"]);
    let detected = adapter.detect(&apt_context, &apt_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &apt_context,
            &apt_runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        adapter
            .plan(
                &apt_context,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/kubernetes")
            )
            .unwrap_err()
            .to_string()
            .contains("legacy")
    );

    write(
        root,
        "/etc/apt/sources.list.d/kubernetes.list",
        b"deb [signed-by=/etc/apt/keyrings/kubernetes.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /\n",
    );
    assert!(adapter.detect(&apt_context, &apt_runtime).is_err());

    write(
        root,
        "/etc/apt/sources.list.d/kubernetes.list",
        b"deb [signed-by=/etc/apt/keyrings/kubernetes.gpg] https://pkgs.k8s.io/core:/stable:/v1.35/deb/ /\n",
    );
    write(
        root,
        "/etc/apt/sources.list.d/duplicate.list",
        b"deb [signed-by=/etc/apt/keyrings/kubernetes.gpg] https://mirrors.ustc.edu.cn/kubernetes/core:/stable:/v1.35/deb/ /\n",
    );
    let detected = adapter.detect(&apt_context, &apt_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &apt_context,
            &apt_runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        adapter
            .plan(
                &apt_context,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/kubernetes")
            )
            .is_err()
    );

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dnf(root, "v1.35.8", 0);
    write(
        root,
        "/etc/yum.repos.d/kubernetes.repo",
        b"[kubernetes]\nbaseurl=https://pkgs.k8s.io/core:/stable:/v1.35/rpm/\ngpgcheck=0\n",
    );
    let runtime = runtime(root, &["/usr/bin"]);
    let context = context(root, Architecture::X86_64, "fedora");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/kubernetes")
            )
            .unwrap_err()
            .to_string()
            .contains("gpgcheck")
    );
}

#[test]
fn failed_package_manager_query_restores_repository() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "v1.35.8", 9);
    let original = b"deb [signed-by=/etc/apt/keyrings/kubernetes.gpg] https://pkgs.k8s.io/core:/stable:/v1.35/deb/ /\n";
    let source = write(root, "/etc/apt/sources.list.d/kubernetes.list", original);
    write(root, "/etc/apt/keyrings/kubernetes.gpg", b"key");
    let adapter = KubernetesPackagesAdapter;
    let context = context(root, Architecture::X86_64, "debian");
    let mut runtime = runtime(root, &["/usr/bin"]);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("ustc", "https://mirrors.ustc.edu.cn/kubernetes"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APT source should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(source).unwrap(), original);
}

struct MetadataProber;

impl CandidateProber for MetadataProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let latency_ms = if url.contains("ustc") {
            1
        } else if url.contains("tuna") {
            2
        } else {
            3
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body: b"Origin: obs://build.opensuse.org/isv:kubernetes:core:stable:v1.35/deb\nPackage: kubeadm\nArchitecture: amd64\nArchitecture: arm64\n<data type=\"primary\">".to_vec(),
            latency_ms,
        })
    }
}

#[test]
fn catalog_keeps_legacy_directories_inert_and_probes_three_complete_obs_mirrors() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "kubernetes-packages")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 5);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 3);
    assert_eq!(
        complete
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "tuna", "ustc"])
    );
    assert!(
        complete
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror
                && candidate.probes.len() == 8)
    );
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud"])
    );

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt(root, "v1.35.8", 0);
    write(root, "/etc/apt/keyrings/kubernetes-apt-keyring.gpg", b"key");
    let adapter = KubernetesPackagesAdapter;
    let context = context(root, Architecture::X86_64, "debian");
    let runtime = runtime(root, &["/usr/bin"]);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let selector = MirrorSelector::with_prober(
        &catalog,
        MetadataProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024 * 1024,
        },
    );
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections[0].provider_id, "ustc");
}
