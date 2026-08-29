#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{RubyGemsAdapter, compiled_adapter_allowlist},
    catalog::{
        CandidateEvaluation, ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod,
        Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const UPSTREAM: &str = "rubygems--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/rubygems/";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/rubygems/";
const ARTIFACT_BODY: &[u8] = b"reviewed synthetic gem payload";

fn context(
    root: &Path,
    architecture: Architecture,
    environment: ExecutionEnvironment,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
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

fn install_rubygems(root: &Path, gemrc: Option<&[u8]>, dependency_exit: i32) -> PathBuf {
    let physical_gemrc = root.join("home/developer/.config/gem/gemrc");
    if let Some(contents) = gemrc {
        write(root, "/home/developer/.config/gem/gemrc", contents);
    }
    executable(
        root,
        "/usr/bin/ruby",
        r#"#!/bin/sh
case "$1" in
  --version) printf '%s\n' 'ruby 3.4.10 (2026-06-30 revision test) [x86_64-linux]' ;;
  -rrubygems) printf '%s' '/home/developer/.config/gem/gemrc' ;;
  *) exit 70 ;;
esac
"#
        .into(),
    );
    executable(
        root,
        "/usr/bin/gem",
        format!(
            r#"#!/bin/sh
gemrc='{physical_gemrc}'
list_sources() {{
  if [ ! -f "$gemrc" ] || ! grep -q '^:sources:[[:space:]]*$' "$gemrc"; then
    printf '%s\n' 'https://rubygems.org/'
    return
  fi
  awk '
    /^:sources:[[:space:]]*$/ {{ active=1; next }}
    active && /^[[:space:]]*-[[:space:]]+/ {{
      value=$0
      sub(/^[[:space:]]*-[[:space:]]+/, "", value)
      sub(/[[:space:]]+#.*$/, "", value)
      gsub(/^"|"$/, "", value)
      gsub(/^'\''|'\''$/, "", value)
      print value
      next
    }}
    active && /^[^[:space:]#-]/ {{ exit }}
  ' "$gemrc"
}}
case "$*" in
  "--version") printf '%s\n' '3.6.9' ;;
  "environment credentials") printf '%s\n' '/home/developer/.local/share/gem/credentials' ;;
  "sources --list")
    printf '%s\n\n' '*** CURRENT SOURCES ***'
    list_sources
    ;;
  "dependency net-protocol --remote --version 0.3.0 --clear-sources --source "*)
    [ {dependency_exit} -eq 0 ] || exit {dependency_exit}
    printf '%s\n' 'Gem net-protocol-0.3.0' '  timeout (>= 0)'
    ;;
  *) exit 71 ;;
esac
"#,
            physical_gemrc = physical_gemrc.display(),
        ),
    );
    physical_gemrc
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn selection(endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "rubygems-test".into(),
        tool_id: "rubygems".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: if endpoint.contains("aliyun") {
            "aliyun"
        } else {
            "tuna"
        }
        .into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: endpoint.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: endpoint.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn private_sources_are_preserved_and_plan_is_consistent_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let original = b"---\n:sources:\n- https://build:credential@gems.corp.example/api/\n- https://rubygems.org/\n- https://backup.corp.example/gems/ # fallback\n:verbose: false\ngem: --no-document\n";
    let gemrc = install_rubygems(root, Some(original), 0);
    let adapter = RubyGemsAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("3.6.9"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Ruby 3.4.10"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("3 ordered source"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(
        current
            .sources
            .iter()
            .filter(|source| source.metadata["kind"] == ["gem-source"])
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>(),
        [
            "https://build:credential@gems.corp.example/api/",
            "https://rubygems.org/",
            "https://backup.corp.example/gems/",
        ]
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Index, EndpointRole::Artifacts]
    );
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Mirror]);

    let chosen = [selection(ALIYUN)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("- https://mirrors.aliyun.com/rubygems/"));
    assert!(rendered.contains("https://build:credential@gems.corp.example/api/"));
    assert!(rendered.contains("https://backup.corp.example/gems/ # fallback"));
    assert!(rendered.contains(":verbose: false"));
    assert!(rendered.contains("gem: --no-document"));
    assert!(!format!("{cli:?}").contains("build:credential@"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("gemrc should change")
    };
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
            .plan(&context, &updated, &chosen)
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
    assert_eq!(fs::read(gemrc).unwrap(), original);
}

#[test]
fn implicit_default_creates_only_user_sources_and_never_uses_project_scope() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let gemrc = install_rubygems(root, Some(b":verbose: false\n"), 0);
    let adapter = RubyGemsAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(TUNA)])
        .unwrap();
    assert_eq!(
        String::from_utf8(plan.changes[0].new_contents.clone()).unwrap(),
        ":verbose: false\n:sources:\n- https://mirrors.tuna.tsinghua.edu.cn/rubygems/\n"
    );
    assert_eq!(plan.changes[0].target, gemrc);
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::Project,)
            .unwrap_err()
            .to_string()
            .contains("never a project Gemfile")
    );
}

#[test]
fn overrides_ambiguous_public_sources_and_complex_yaml_are_blocked() {
    let adapter = RubyGemsAdapter;
    for (contents, environment, expected) in [
        (
            b":sources:\n- https://rubygems.org/\n".as_slice(),
            BTreeMap::from([("GEMRC".into(), "/tmp/override.gemrc".into())]),
            "GEMRC overrides",
        ),
        (
            b":sources:\n- https://rubygems.org/\n- https://mirrors.aliyun.com/rubygems/\n"
                .as_slice(),
            BTreeMap::new(),
            "multiple public sources",
        ),
        (
            b":sources: [https://rubygems.org/]\n".as_slice(),
            BTreeMap::new(),
            "complex or inline YAML",
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_rubygems(root, Some(contents), 0);
        let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
        let runtime = runtime(root, environment);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let error =
            match adapter.read_current(&context, &runtime, &detected, ConfigurationScope::User) {
                Ok(current) => adapter
                    .selection_request(&context, &detected, &current)
                    .unwrap_err(),
                Err(error) => error,
            };
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn failed_real_client_verification_restores_the_original_gemrc() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let original = b":sources:\n- https://rubygems.org/\n";
    let gemrc = install_rubygems(root, Some(original), 72);
    let adapter = RubyGemsAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(ALIYUN)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("gemrc should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(gemrc).unwrap(), original);
}

#[derive(Clone)]
struct RubyGemsProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_artifact: bool,
}

impl CandidateProber for RubyGemsProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let body = if url.ends_with(".gem") {
            if self.corrupt_artifact {
                b"corrupt".to_vec()
            } else {
                ARTIFACT_BODY.to_vec()
            }
        } else if url.ends_with(".gemspec.rz") {
            b"compressed metadata".to_vec()
        } else {
            Vec::new()
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: url
                .ends_with(".gemspec.rz")
                .then_some("application/octet-stream".into())
                .or_else(|| {
                    url.ends_with(".gem")
                        .then_some("application/octet-stream".into())
                }),
            body,
            latency_ms: 1,
        })
    }
}

fn catalog_for_synthetic_artifact() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let digest = format!("{:x}", Sha256::digest(ARTIFACT_BODY));
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "rubygems")
    {
        for probe in &mut candidate.probes {
            if probe.path.ends_with(".gem") {
                probe.sha256 = Some(digest.clone());
            }
        }
    }
    catalog
}

#[test]
fn catalog_filters_incomplete_providers_and_checks_artifact_digest_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let artifact_probes = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "rubygems")
        .flat_map(|candidate| &candidate.probes)
        .filter(|probe| probe.path.ends_with(".gem"))
        .collect::<Vec<_>>();
    assert_eq!(artifact_probes.len(), 4);
    assert!(artifact_probes.iter().all(|probe| {
        probe.sha256.as_deref()
            == Some("ba310c3d4f1cad46bb1ab20336b06669b1ff8f7c568d9cb9342b32a718547472")
    }));

    let catalog = catalog_for_synthetic_artifact();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "rubygems")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let actionable = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "rubygems" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    let mut providers = actionable
        .iter()
        .map(|candidate| candidate.provider_id.as_str())
        .collect::<Vec<_>>();
    providers.sort_unstable();
    assert_eq!(providers, ["aliyun", "nju", "tuna", "ustc"]);
    for candidate in actionable {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(candidate.endpoints.len(), 2);
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| { probe.path == "/specs.4.8.gz" && probe.method == HttpMethod::Head })
        );
        assert!(candidate.probes.iter().any(|probe| {
            probe.path.ends_with(".gemspec.rz") && probe.method == HttpMethod::Get
        }));
        assert!(candidate.probes.iter().any(|probe| {
            probe.path.ends_with(".gem")
                && probe.sha256.as_deref() == Some(&format!("{:x}", Sha256::digest(ARTIFACT_BODY)))
        }));
    }

    let adapter = RubyGemsAdapter;
    let directory = tempdir().unwrap();
    install_rubygems(
        directory.path(),
        Some(b":sources:\n- https://rubygems.org/\n"),
        0,
    );
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();

    let calls = Rc::new(RefCell::new(Vec::new()));
    let selected = MirrorSelector::with_prober(
        &catalog,
        RubyGemsProtocolProber {
            calls: calls.clone(),
            corrupt_artifact: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable);
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 12);

    let rejected = MirrorSelector::with_prober(
        &catalog,
        RubyGemsProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_artifact: true,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.repositories[0].candidates.iter().any(|candidate| {
        matches!(
            &candidate.evaluation,
            CandidateEvaluation::ProbeFailed { reason }
                if reason.contains("SHA-256")
        )
    }));
}

#[test]
fn unsupported_platform_or_version_and_missing_commands_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rubygems(root, Some(b":sources:\n- https://rubygems.org/\n"), 0);
    let adapter = RubyGemsAdapter;
    let mut windows = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    windows.os = OperatingSystem::Windows;
    let installed_runtime = runtime(root, BTreeMap::new());
    assert!(
        adapter
            .detect(&windows, &installed_runtime)
            .unwrap_err()
            .to_string()
            .contains("Linux")
    );

    let empty = tempdir().unwrap();
    let runtime = runtime(empty.path(), BTreeMap::new());
    let context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(adapter.detect(&context, &runtime).unwrap().is_none());
}
