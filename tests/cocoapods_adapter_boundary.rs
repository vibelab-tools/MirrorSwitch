#![cfg(unix)]

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{CocoaPodsAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const OFFICIAL: &str = "https://github.com/CocoaPods/Specs.git";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/git/CocoaPods/Specs.git";
const NJU: &str = "https://mirrors.nju.edu.cn/git/CocoaPods/Specs.git";
const SAMPLE_PATH: &str = "Specs/a/7/5/AFNetworking/4.0.1/AFNetworking.podspec.json";
const SAMPLE: &str = r#"{"name":"AFNetworking","version":"4.0.1","source":{"git":"https://github.com/AFNetworking/AFNetworking.git","tag":"4.0.1"}}"#;

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Macos,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "macos".into(),
            version_id: Some("15.6".into()),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: root.into(),
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

fn install(root: &Path, version: &str, git_exit: i32, ipc_exit: i32) {
    let repo = root.join("Users/test/.cocoapods/repos/master");
    let config = repo.join(".git/config");
    write(
        root,
        "/Users/test/.cocoapods/repos/master/.git/config",
        format!(
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = {OFFICIAL}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )
        .as_bytes(),
    );
    write(
        root,
        &format!("/Users/test/.cocoapods/repos/master/{SAMPLE_PATH}"),
        SAMPLE.as_bytes(),
    );
    let project = root.join("workspace/Podfile");
    executable(
        root,
        "/usr/bin/pod",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nif [ \"$1\" = repo ] && [ \"$2\" = list ]; then\n  origin=$(sed -n 's/^[[:space:]]*url[[:space:]]*=[[:space:]]*//p' '{config}')\n  printf 'private-specs\\n- Type: git (main)\\n- URL:  ssh://private.example/specs.git\\n- Path: /Users/test/.cocoapods/repos/private-specs\\n\\nmaster\\n- Type: git (master)\\n- URL:  %s\\n- Path: /Users/test/.cocoapods/repos/master\\n\\ntrunk\\n- Type: CDN\\n- URL:  https://cdn.cocoapods.org/\\n- Path: /Users/test/.cocoapods/repos/trunk\\n\\n3 repos\\n' \"$origin\"\n  exit 0\nfi\nif [ \"$1\" = ipc ] && [ \"$2\" = spec ]; then cat '{sample}'; exit {ipc_exit}; fi\nif [ \"$1\" = ipc ] && [ \"$2\" = podfile ]; then test \"$3\" = '/workspace/Podfile'; test -f '{project}'; exit {ipc_exit}; fi\nexit 64\n",
            config = config.display(),
            sample = repo.join(SAMPLE_PATH).display(),
            project = project.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/git",
        format!(
            "#!/bin/sh\nif [ \"$1\" = -C ]; then\n  repo=$2; shift 2\n  if [ \"$1\" = ls-remote ]; then echo '0123456789012345678901234567890123456789 HEAD'; exit {git_exit}; fi\n  if [ \"$1\" = show ]; then cat '{sample}'; exit 0; fi\nfi\nif [ \"$1\" = ls-remote ]; then echo '0123456789012345678901234567890123456789 HEAD'; exit {git_exit}; fi\nexit 64\n",
            sample = repo.join(SAMPLE_PATH).display(),
        ),
    );
    executable(
        root,
        "/usr/bin/ruby",
        "#!/bin/sh\necho 'ruby 3.3.8 (2026-01-01 revision fixture) [arm64-darwin]'\n".into(),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/Users/test")
        .with_project_dir("/workspace")
        .with_environment(Default::default())
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "cocoapods-test".into(),
        tool_id: "cocoapods".into(),
        upstream_id: "cocoapods--git-mirror".into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Git,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_repo_plan_preserves_private_and_cdn_state_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install(root, "1.16.2", 0, 0);
    write(root, "/workspace/Podfile", b"platform :ios, '15.0'\n");
    write(root, "/workspace/Podfile.lock", b"LOCKED\n");
    let config = root.join("Users/test/.cocoapods/repos/master/.git/config");
    let original = fs::read(&config).unwrap();
    let lock = fs::read(root.join("workspace/Podfile.lock")).unwrap();
    let context = context(root, Architecture::Arm64);
    let adapter = CocoaPodsAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.16.2"));
    assert!(detected.evidence.iter().any(|item| item.contains("Ruby")));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(current.documents.len(), 1);
    assert_eq!(current.sources.len(), 3);
    assert!(current.sources.iter().any(|source| {
        source.url == "redacted://private-cocoapods-source" && source.metadata["position"] == ["0"]
    }));
    assert!(current.sources.iter().any(|source| {
        source.url == "https://cdn.cocoapods.org/" && source.metadata["kind"] == ["cdn-read-only"]
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_endpoint_roles, [EndpointRole::Git]);
    let choice = [selection(TUNA)];
    let plan = adapter.plan(&context, &current, &choice).unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert_eq!(plan.changes[0].target, config);
    assert!(!plan.requires_elevation);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("CocoaPods user plan should change the Git origin")
    };
    assert!(fs::read_to_string(&config).unwrap().contains(TUNA));
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &choice)
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
    assert_eq!(fs::read(config).unwrap(), original);
    assert_eq!(fs::read(root.join("workspace/Podfile.lock")).unwrap(), lock);
}

#[test]
fn explicit_project_plan_preserves_source_order_and_lockfile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install(root, "1.16.2", 0, 0);
    let original = b"source 'ssh://private.example/specs.git' # first-match policy\nsource(\"https://github.com/CocoaPods/Specs.git\")\nplatform :ios, '15.0'\ntarget 'Fixture' do\n  pod 'AFNetworking', '4.0.1'\nend\n";
    let podfile = write(root, "/workspace/Podfile", original);
    let lockfile = write(
        root,
        "/workspace/Podfile.lock",
        b"PODS:\n  - AFNetworking (4.0.1)\n",
    );
    let lock = fs::read(&lockfile).unwrap();
    let context = context(root, Architecture::X86_64);
    let adapter = CocoaPodsAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    assert_eq!(current.sources[0].metadata["position"], ["0"]);
    assert_eq!(current.sources[1].metadata["position"], ["1"]);
    let plan = adapter.plan(&context, &current, &[selection(NJU)]).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.starts_with("source 'ssh://private.example/specs.git'"));
    assert!(rendered.contains(&format!("source(\"{NJU}\")")));
    assert!(!rendered.contains(OFFICIAL));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("explicit Podfile source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&lockfile).unwrap(), lock);
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(podfile).unwrap(), original);
}

#[test]
fn failed_git_query_restores_user_repo_and_unsafe_models_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install(root, "1.16.2", 7, 0);
    write(
        root,
        "/workspace/Podfile",
        b"source ENV.fetch('PODS_SOURCE')\n",
    );
    let config = root.join("Users/test/.cocoapods/repos/master/.git/config");
    let original = fs::read(&config).unwrap();
    let context = context(root, Architecture::Arm64);
    let adapter = CocoaPodsAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(TUNA)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("user Git origin should change before verification")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(config).unwrap(), original);

    fs::write(
        root.join("Users/test/.cocoapods/repos/master/.git/config"),
        b"[remote \"origin\"]\n\turl = https://cdn.cocoapods.org/\n",
    )
    .unwrap();
    let cdn_only = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(cdn_only.documents.is_empty());
    assert!(
        adapter
            .selection_request(&context, &detected, &cdn_only)
            .is_err()
    );

    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap_err();
    assert!(error.to_string().contains("dynamic CocoaPods source"));

    install(root, "2.0.0", 0, 0);
    assert!(adapter.detect(&context, &runtime).is_err());
}

#[test]
fn embedded_catalog_has_two_complete_specs_git_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "cocoapods")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(
        tool.supported_scopes,
        [ConfigurationScope::User, ConfigurationScope::Project]
    );
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "cocoapods"
                && candidate.upstream_id == "cocoapods--git-mirror"
                && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "tuna"])
    );
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Macos]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints.len() == 1
            && candidate.endpoints[0].role == EndpointRole::Git
            && candidate.probes.len() == 2
            && candidate.probes[0].path == "/HEAD"
            && candidate.probes[1].path == "/objects/info/packs"
    }));
}
