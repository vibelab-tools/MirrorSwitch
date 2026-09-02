#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::HomebrewAdapter,
    catalog::{ConfigurationScope, HttpMethod},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
};
use tempfile::tempdir;

fn write(root: &Path, path: &str, contents: &[u8]) -> PathBuf {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn executable(root: &Path, path: &str, contents: &str) {
    let path = write(root, path, contents.as_bytes());
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn runtime(root: &Path, architecture: Architecture, shell: &str, profile: &str) -> OsRuntime {
    let prefix = match architecture {
        Architecture::X86_64 => "/usr/local",
        Architecture::Arm64 => "/opt/homebrew",
    };
    executable(
        root,
        "/bin/brew",
        &format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'Homebrew 6.0.18' ;;\n  --prefix) echo '{prefix}' ;;\n  --repository) echo '{prefix}/Homebrew' ;;\n  *) exit 64 ;;\nesac\n"
        ),
    );
    executable(
        root,
        "/bin/git",
        "#!/bin/sh\nsed -n 's/^[[:space:]]*url[[:space:]]*=[[:space:]]*//p' .git/config\n",
    );
    executable(
        root,
        "/bin/env",
        "#!/bin/sh\nwhile [ \"${1#*=}\" != \"$1\" ]; do shift; done\n[ \"$1\" = brew ] || exit 64\nshift\ncase \"$1\" in\n  config) echo 'HOMEBREW_API_DOMAIN: https://mirrors.ustc.edu.cn/homebrew-bottles/api' ;;\n  info) echo '{\"formulae\":[{\"name\":\"jq\"}]}' ;;\n  update|fetch) exit 0 ;;\n  *) exit 64 ;;\nesac\n",
    );
    let repository = root.join(prefix.trim_start_matches('/')).join("Homebrew");
    fs::create_dir_all(repository.join(".git")).unwrap();
    fs::write(
        repository.join(".git/config"),
        b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/Homebrew/brew\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
    )
    .unwrap();
    OsRuntime::new(root, vec![PathBuf::from("/bin")])
        .with_home("/Users/test")
        .with_project_dir("/workspace")
        .with_environment(BTreeMap::from([
            ("SHELL".into(), shell.into()),
            ("PROFILE".into(), profile.into()),
        ]))
}

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

struct HomebrewProber;

impl CandidateProber for HomebrewProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let (content_type, body) = if url.ends_with("/HEAD") {
            (
                Some("application/octet-stream".into()),
                b"ref: refs/heads/main".to_vec(),
            )
        } else if url.ends_with("/api/formula.jws.json") {
            (Some("application/json".into()), Vec::new())
        } else if url.ends_with("/api/formula/jq.json") {
            (
                Some("application/json".into()),
                br#"{"arm64_sequoia":{},"sonoma":{}}"#.to_vec(),
            )
        } else if url.contains("/v2/homebrew/core/jq/blobs/sha256:") {
            (Some("application/octet-stream".into()), Vec::new())
        } else {
            return Err(ProbeError::Http(format!("unexpected URL {url}")));
        };
        Ok(ProbeObservation {
            status: 200,
            content_type,
            body,
            latency_ms: 2,
        })
    }
}

fn select(
    adapter: &HomebrewAdapter,
    context: &SystemContext,
    detected: &mirrorswitch::plan::DetectedTool,
    current: &mirrorswitch::plan::CurrentConfiguration,
) -> Vec<mirrorswitch::plan::MirrorSelection> {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    MirrorSelector::with_prober(&catalog, HomebrewProber, Default::default())
        .select(
            &adapter
                .selection_request(context, detected, current)
                .unwrap(),
        )
        .unwrap()
        .selections
}

#[test]
fn zsh_api_mode_is_consistent_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let profile = "/Users/test/.zprofile";
    let original = b"export EDITOR=vim\n";
    write(directory.path(), profile, original);
    let context = context(directory.path(), Architecture::X86_64);
    let mut runtime = runtime(directory.path(), Architecture::X86_64, "/bin/zsh", profile);
    let adapter = HomebrewAdapter;
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value == "brew repository origin is official")
    );
    assert!(
        detected
            .evidence
            .iter()
            .all(|value| !value.contains("github.com"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selections = select(&adapter, &context, &detected, &current);
    assert_eq!(selections.len(), 2);
    assert!(
        selections
            .iter()
            .all(|selection| selection.provider_id == "ustc")
    );
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    let preview = plan.preview();
    assert!(!preview.requires_elevation);
    assert_eq!(preview.changes.len(), 2);
    let outcome = adapter.apply(&context, &mut runtime, &plan).unwrap();
    let mirrorswitch::ApplyOutcome::Applied(receipt) = outcome else {
        panic!("Homebrew plan must apply");
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let applied = fs::read_to_string(directory.path().join("Users/test/.zprofile")).unwrap();
    assert!(applied.contains("export EDITOR=vim"));
    assert!(applied.contains("HOMEBREW_BREW_GIT_REMOTE"));
    assert!(applied.contains("HOMEBREW_API_DOMAIN"));
    assert!(applied.contains("HOMEBREW_ARTIFACT_DOMAIN"));
    assert!(!applied.contains("HOMEBREW_BOTTLE_DOMAIN"));
    assert!(
        fs::read_to_string(directory.path().join("usr/local/Homebrew/.git/config"))
            .unwrap()
            .contains("url = https://mirrors.ustc.edu.cn/brew.git")
    );

    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections)
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
    assert_eq!(
        fs::read(directory.path().join("Users/test/.zprofile")).unwrap(),
        original
    );
    assert!(
        fs::read_to_string(directory.path().join("usr/local/Homebrew/.git/config"))
            .unwrap()
            .contains("url = https://github.com/Homebrew/brew")
    );
}

#[test]
fn arm64_fish_uses_the_architecture_specific_bottle_probe() {
    let directory = tempdir().unwrap();
    let profile = "/Users/test/.config/fish/conf.d/homebrew.fish";
    write(directory.path(), profile, b"set -gx EDITOR vim\n");
    let context = context(directory.path(), Architecture::Arm64);
    let runtime = runtime(
        directory.path(),
        Architecture::Arm64,
        "/usr/bin/fish",
        profile,
    );
    let adapter = HomebrewAdapter;
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selections = select(&adapter, &context, &detected, &current);
    let plan = adapter.plan(&context, &current, &selections).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("set -gx HOMEBREW_API_DOMAIN"));
    assert!(rendered.contains("set -gx HOMEBREW_ARTIFACT_DOMAIN"));
}

#[test]
fn legacy_git_mode_unmanaged_policy_and_wrong_prefix_are_inert() {
    let directory = tempdir().unwrap();
    let profile = "/Users/test/.zprofile";
    write(
        directory.path(),
        profile,
        b"export HOMEBREW_NO_INSTALL_FROM_API=1\n",
    );
    let context = context(directory.path(), Architecture::X86_64);
    let runtime = runtime(directory.path(), Architecture::X86_64, "/bin/zsh", profile)
        .with_environment(BTreeMap::from([
            ("SHELL".into(), "/bin/zsh".into()),
            ("PROFILE".into(), profile.into()),
            ("HOMEBREW_NO_INSTALL_FROM_API".into(), "1".into()),
        ]));
    let adapter = HomebrewAdapter;
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .selection_request(&context, &detected, &current)
            .is_err()
    );

    executable(
        directory.path(),
        "/bin/brew",
        "#!/bin/sh\ncase \"$1\" in --version) echo 'Homebrew 6.0.18' ;; --prefix) echo '/custom' ;; --repository) echo '/custom/Homebrew' ;; esac\n",
    );
    assert!(adapter.detect(&context, &runtime).is_err());
}

#[test]
fn embedded_catalog_exposes_only_the_complete_ustc_homebrew_pair() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "homebrew")
        .unwrap();
    assert_eq!(
        tool.state,
        mirrorswitch::catalog::ToolCatalogState::Supported
    );
    let actionable = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "homebrew" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(actionable.len(), 2);
    assert!(
        actionable
            .iter()
            .all(|candidate| candidate.provider_id == "ustc")
    );
    assert!(actionable.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Macos]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
    }));
}
