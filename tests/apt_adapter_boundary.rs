#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{AptAdapter, compiled_adapter_allowlist},
    catalog::{Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

fn context(
    root: &Path,
    distribution: &str,
    version: &str,
    codename: &str,
    architecture: Architecture,
    environment: ExecutionEnvironment,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: Some(version.into()),
            version_codename: Some(codename.into()),
            id_like: if distribution == "ubuntu" {
                vec!["debian".into()]
            } else {
                Vec::new()
            },
        }),
        root: root.to_path_buf(),
    }
}

fn install_apt_get(root: &Path, exit_code: i32) {
    let path = root.join("usr/bin/apt-get");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
}

fn selection(upstream: &str, provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("{provider}-{upstream}"),
        tool_id: "apt".into(),
        upstream_id: upstream.into(),
        provider_id: provider.into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Metadata,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 10,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

struct AptMetadataProber;

impl CandidateProber for AptMetadataProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        assert_eq!(method, HttpMethod::Get);
        let body = if url.ends_with("/InRelease") {
            b"-----BEGIN PGP SIGNED MESSAGE-----".to_vec()
        } else if url.contains("/binary-amd64/Release") {
            b"Architecture: amd64".to_vec()
        } else {
            return Err(ProbeError::Http(format!("unexpected APT probe {url}")));
        };
        let latency_ms = if url.contains("mirrors.tuna.tsinghua.edu.cn") {
            1
        } else if url.contains("mirrors.ustc.edu.cn") {
            2
        } else {
            10
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body,
            latency_ms,
        })
    }
}

#[test]
fn debian_legacy_host_plan_preserves_options_third_party_and_restores_exactly() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt_get(root, 0);
    let source_path = root.join("etc/apt/sources.list");
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    let original = b"# Debian base\n\
deb [arch=amd64 signed-by=/usr/share/keyrings/debian.gpg] http://deb.debian.org/debian bookworm main contrib # keep\n\
deb http://security.debian.org/debian-security bookworm-security main\n\
deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://vendor.example/repo stable main\n\
# deb https://disabled.example/debian bookworm main\n";
    fs::write(&source_path, original).unwrap();
    let context = context(
        root,
        "debian",
        "12",
        "bookworm",
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let adapter = AptAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();

    assert_eq!(
        request.required_upstreams,
        [
            "debian--repository-metadata",
            "debian-security--repository-metadata"
        ]
    );
    assert_eq!(
        request.probe_contexts["debian--repository-metadata"].len(),
        2
    );
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let outcome = MirrorSelector::with_prober(&catalog, AptMetadataProber, ProbeLimits::default())
        .select_at(&request, 123)
        .unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections.len(), 2);
    assert!(
        outcome
            .selections
            .iter()
            .all(|selection| selection.provider_id == "tuna")
    );
    let selections = outcome.selections;
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    assert_eq!(plan.changes.len(), 1);
    let preview = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(preview.contains("[arch=amd64 signed-by=/usr/share/keyrings/debian.gpg]"));
    assert!(preview.contains("https://mirrors.tuna.tsinghua.edu.cn/debian bookworm"));
    assert!(
        preview.contains("https://mirrors.tuna.tsinghua.edu.cn/debian-security bookworm-security")
    );
    assert!(preview.contains("https://vendor.example/repo stable main"));
    assert!(preview.contains("# deb https://disabled.example/debian"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APT plan should change the source file")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_ne!(fs::read(&source_path).unwrap(), original);
    let updated = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &selections)
            .unwrap()
            .changes
            .is_empty()
    );
    let restored = adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert!(restored.restored);
    assert_eq!(fs::read(&source_path).unwrap(), original);
}

#[test]
fn ubuntu_arm64_container_deb822_uses_ports_and_failed_refresh_rolls_back() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_apt_get(root, 7);
    let source_path = root.join("etc/apt/sources.list.d/ubuntu.sources");
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    let original = b"Types: deb deb-src\n\
URIs: http://archive.ubuntu.com/ubuntu\n\
# keep this deb822 comment\n\
Suites: noble noble-updates\n\
Components: main universe\n\
Architectures: arm64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
X-MirrorSwitch-Test: preserve\n\
\n\
Types: deb\n\
URIs: https://ppa.launchpadcontent.net/example/stable/ubuntu\n\
Suites: noble\n\
Components: main\n\
Signed-By: /etc/apt/keyrings/example.gpg\n";
    fs::write(&source_path, original).unwrap();
    let context = context(
        root,
        "ubuntu",
        "24.04",
        "noble",
        Architecture::Arm64,
        ExecutionEnvironment::Container,
    );
    let adapter = AptAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        ["ubuntu-ports--repository-metadata"]
    );
    assert_eq!(
        request.probe_contexts["ubuntu-ports--repository-metadata"].len(),
        4
    );
    assert!(
        request.probe_contexts["ubuntu-ports--repository-metadata"]
            .iter()
            .all(|values| values["architecture"] == "arm64")
    );

    let plan = adapter
        .plan(
            &context,
            &current,
            &[selection(
                "ubuntu-ports--repository-metadata",
                "aliyun",
                "https://mirrors.aliyun.com/ubuntu-ports/",
            )],
        )
        .unwrap();
    let preview = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(preview.contains("URIs: https://mirrors.aliyun.com/ubuntu-ports"));
    assert!(preview.contains("# keep this deb822 comment"));
    assert!(preview.contains("Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"));
    assert!(preview.contains("X-MirrorSwitch-Test: preserve"));
    assert!(preview.contains("URIs: https://ppa.launchpadcontent.net/example/stable/ubuntu"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("APT plan should change the source file")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(&source_path).unwrap(), original);
}

#[test]
fn malformed_active_apt_entry_is_reported_without_a_plan() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let source_path = root.join("etc/apt/sources.list");
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    fs::write(
        source_path,
        b"deb [arch=amd64 http://deb.debian.org/debian bookworm main\n",
    )
    .unwrap();
    let context = context(
        root,
        "debian",
        "12",
        "bookworm",
        Architecture::X86_64,
        ExecutionEnvironment::Container,
    );
    let adapter = AptAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();

    let error = adapter
        .read_current(
            &context,
            &runtime,
            &detected,
            mirrorswitch::catalog::ConfigurationScope::System,
        )
        .unwrap_err();
    assert!(error.to_string().contains("APT list entry has no URI"));
    assert_eq!(
        fs::read(root.join("etc/apt/sources.list")).unwrap(),
        b"deb [arch=amd64 http://deb.debian.org/debian bookworm main\n"
    );
}

#[test]
fn embedded_catalog_exposes_only_arch_compatible_apt_metadata_probes() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates: Vec<_> = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "apt"
                && matches!(
                    candidate.upstream_id.as_str(),
                    "debian--repository-metadata"
                        | "debian-security--repository-metadata"
                        | "ubuntu--repository-metadata"
                        | "ubuntu-ports--repository-metadata"
                )
        })
        .collect();
    assert_eq!(candidates.len(), 24);
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.probes.len() == 2)
    );
    assert!(candidates.iter().all(|candidate| {
        candidate
            .probes
            .iter()
            .all(|probe| probe.path.starts_with("/dists/{suite}/"))
    }));
    assert!(candidates.iter().all(|candidate| {
        match candidate.upstream_id.as_str() {
            "ubuntu--repository-metadata" => {
                candidate.compatibility.architectures == [Architecture::X86_64]
            }
            "ubuntu-ports--repository-metadata" => {
                candidate.compatibility.architectures == [Architecture::Arm64]
            }
            _ => {
                candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            }
        }
    }));
}
