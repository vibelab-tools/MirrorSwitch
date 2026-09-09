#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{JenkinsAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::{LinuxDetectionOptions, OsRuntime, SelectionReason, detect_linux},
    frontend::{FrontendSource, RequestInput, normalize_request},
    plan::{MirrorSelection, ServiceImpact},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "jenkins-update-center--repository-metadata";
const COMMIT: &str = "3df56b0ada4fc57ca1329946697eb0f896389047";
const CERTIFICATE: &[u8] = include_bytes!("../src/adapters/assets/lework-update-center.crt");

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "ubuntu".into(),
            version_id: Some("24.04".into()),
            version_codename: Some("noble".into()),
            id_like: vec!["debian".into()],
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

fn install_jenkins(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/jenkins",
        format!(
            "#!/bin/sh\n[ \"$1\" = --version ] || exit 60\n[ ! -f '{}/tmp/jenkins-version-fail' ] || exit 9\necho '{version}'\n",
            root.display()
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/root")
        .with_environment(BTreeMap::new())
}

fn selection(variant: &str, packages: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("jenkins-{variant}-test"),
        tool_id: "jenkins".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "lework".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: format!(
                    "https://cdn.jsdelivr.net/gh/lework/jenkins-update-center@{COMMIT}/rootCA/"
                ),
            },
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: format!(
                    "https://cdn.jsdelivr.net/gh/lework/jenkins-update-center@{COMMIT}/updates/{variant}/"
                ),
            },
            Endpoint {
                role: EndpointRole::Packages,
                protocol: Protocol::Https,
                url: packages.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

fn update_center(default_url: &str) -> Vec<u8> {
    format!(
        "<?xml version='1.1' encoding='UTF-8'?>\n<sites>\n  <site>\n    <id>default</id>\n    <url>{default_url}</url>\n  </site>\n  <site>\n    <id>private</id>\n    <url>https://user:secret@private.example/update-center.json</url>\n  </site>\n</sites>\n"
    )
    .into_bytes()
}

#[test]
fn explicit_plan_preserves_private_sites_installs_pinned_root_and_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_jenkins(root, "2.581");
    let original = update_center("https://updates.jenkins.io/update-center.json");
    let update_path = write(
        root,
        "/var/lib/jenkins/hudson.model.UpdateCenter.xml",
        &original,
    );
    let adapter = JenkinsAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.581"));
    assert!(!adapter.selected_by_default());
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.tool_version.as_deref(), Some("2.581"));
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    let selected = selection("tsinghua", "https://mirrors.tuna.tsinghua.edu.cn/jenkins/");
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 2);
    assert_eq!(cli.service_impact, ServiceImpact::RestartRequired);
    assert!(cli.requires_elevation);
    let rendered = cli
        .changes
        .iter()
        .find(|change| change.target.ends_with("hudson.model.UpdateCenter.xml"))
        .unwrap();
    let rendered = String::from_utf8(rendered.new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!(
        "jenkins-update-center@{COMMIT}/updates/tsinghua/update-center.json"
    )));
    assert!(rendered.contains("https://user:secret@private.example/update-center.json"));
    assert_eq!(
        cli.changes
            .iter()
            .find(|change| change.target.ends_with("update-center.crt"))
            .unwrap()
            .new_contents,
        CERTIFICATE
    );

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Jenkins Update Center files should change")
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
    assert_eq!(fs::read(update_path).unwrap(), original);
    assert!(
        !root
            .join("var/lib/jenkins/update-center-rootCAs/update-center.crt")
            .exists()
    );
}

#[test]
fn linux_detection_keeps_jenkins_unselected_until_an_explicit_frontend_request() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    write(
        root,
        "/etc/os-release",
        b"ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n",
    );
    install_jenkins(root, "2.581");
    write(
        root,
        "/var/lib/jenkins/hudson.model.UpdateCenter.xml",
        &update_center("https://updates.jenkins.io/update-center.json"),
    );
    let adapter = JenkinsAdapter;
    let report = detect_linux(
        &LinuxDetectionOptions {
            root: root.into(),
            home: PathBuf::from("/root"),
            project_dir: None,
            executable_path: vec![PathBuf::from("/usr/bin")],
            architecture: "x86_64".into(),
            effective_uid: 0,
            container_hint: None,
        },
        &[&adapter],
    )
    .unwrap();
    assert_eq!(report.selections.len(), 1);
    assert!(!report.selections[0].selected);
    assert_eq!(report.selections[0].reason, SelectionReason::ExplicitOnly);
    assert!(
        normalize_request(&report, &RequestInput::default(), FrontendSource::Cli)
            .unwrap()
            .tools
            .is_empty()
    );
    let explicit = RequestInput {
        tools: BTreeSet::from(["jenkins".into()]),
        ..RequestInput::default()
    };
    let normalized = normalize_request(&report, &explicit, FrontendSource::Cli).unwrap();
    assert_eq!(normalized.tools.len(), 1);
    assert_eq!(normalized.tools[0].tool_id, "jenkins");
}

#[test]
fn custom_default_conflicting_certificate_version_and_endpoint_pairs_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_jenkins(root, "2.581");
    let adapter = JenkinsAdapter;
    let context = context(root, Architecture::Arm64);
    write(
        root,
        "/var/lib/jenkins/hudson.model.UpdateCenter.xml",
        &update_center("https://private.example/update-center.json"),
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .selection_request(&context, &detected, &current)
            .unwrap_err()
            .to_string()
            .contains("custom")
    );

    write(
        root,
        "/var/lib/jenkins/hudson.model.UpdateCenter.xml",
        &update_center("https://updates.jenkins.io/update-center.json"),
    );
    write(
        root,
        "/var/lib/jenkins/update-center-rootCAs/update-center.crt",
        b"another certificate",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/jenkins/"),
            )
            .unwrap_err()
            .to_string()
            .contains("another certificate")
    );

    write(
        root,
        "/var/lib/jenkins/update-center-rootCAs/update-center.crt",
        CERTIFICATE,
    );
    install_jenkins(root, "2.568.3");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &selection("ustc", "https://mirrors.ustc.edu.cn/jenkins/"),
            )
            .unwrap_err()
            .to_string()
            .contains("targets Jenkins 2.581")
    );

    install_jenkins(root, "2.581");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let mut mismatched = selection("ustc", "https://mirrors.aliyun.com/jenkins/");
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
    mismatched[0].endpoints[1].url = "http://unsafe.example/update-center/".into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
    let mut unreviewed = selection("ustc", "https://mirrors.ustc.edu.cn/jenkins/");
    unreviewed[0].endpoints[0].url = unreviewed[0].endpoints[0]
        .url
        .replace(COMMIT, &"0".repeat(40));
    unreviewed[0].endpoints[1].url = unreviewed[0].endpoints[1]
        .url
        .replace(COMMIT, &"0".repeat(40));
    assert!(adapter.plan(&context, &current, &unreviewed).is_err());
}

#[test]
fn verification_failure_restores_both_update_center_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_jenkins(root, "2.581");
    let original = update_center("https://updates.jenkins.io/update-center.json");
    let update_path = write(
        root,
        "/var/lib/jenkins/hudson.model.UpdateCenter.xml",
        &original,
    );
    let adapter = JenkinsAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &selection("tencent", "https://mirrors.cloud.tencent.com/jenkins/"),
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Jenkins Update Center files should change")
    };
    write(root, "/tmp/jenkins-version-fail", b"fail");
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(update_path).unwrap(), original);
    assert!(
        !root
            .join("var/lib/jenkins/update-center-rootCAs/update-center.crt")
            .exists()
    );
}

#[test]
fn catalog_pins_five_complete_signed_metadata_and_plugin_chains() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "jenkins"
                && candidate.upstream_id == UPSTREAM
                && candidate.catalog_state == mirrorswitch::catalog::CatalogEntryState::Cataloged
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 5);
    assert!(candidates.iter().all(|candidate| {
        candidate.provider_id == "lework"
            && candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.compatibility.tool_version.as_deref() == Some("2.581")
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 3
            && candidate.probes.iter().all(|probe| probe.sha256.is_some())
    }));
    let package_endpoints = candidates
        .iter()
        .flat_map(|candidate| &candidate.endpoints)
        .filter(|endpoint| endpoint.role == EndpointRole::Packages)
        .map(|endpoint| endpoint.url.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        package_endpoints,
        BTreeSet::from([
            "https://mirrors.aliyun.com/jenkins/",
            "https://mirrors.cloud.tencent.com/jenkins/",
            "https://mirrors.huaweicloud.com/jenkins/",
            "https://mirrors.tuna.tsinghua.edu.cn/jenkins/",
            "https://mirrors.ustc.edu.cn/jenkins/",
        ])
    );
}
