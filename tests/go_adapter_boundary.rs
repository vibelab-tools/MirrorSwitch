#![cfg(unix)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{GoAdapter, compiled_adapter_allowlist},
    catalog::{
        CandidateEvaluation, CompositionPolicy, ConfigurationScope, DeliveryMode, Endpoint,
        EndpointRole, HttpMethod, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{
        CandidateProber, CompatibilityDimension, MirrorSelector, ProbeError, ProbeLimits,
        ProbeObservation, SelectionRequest,
    },
    transaction::ApplyOutcome,
};
use serde_json::Value;
use tempfile::tempdir;

const GO_PROXY_UPSTREAM: &str = "goproxy--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/goproxy/";
const HUAWEI: &str = "https://repo.huaweicloud.com/repository/goproxy/";
const NJU: &str = "https://repo.nju.edu.cn/go/";

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

fn native_context(root: &Path, os: OperatingSystem, architecture: Architecture) -> SystemContext {
    SystemContext {
        os,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: None,
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

fn install_go(root: &Path, version: &str, download_exit: i32) {
    let physical_env = root.join("home/developer/.config/go/env");
    executable(
        root,
        "/usr/bin/go",
        format!(
            r#"#!/bin/sh
env_file='{physical_env}'
value() {{
  key="$1"
  if [ -f "$env_file" ]; then
    found=$(sed -n "s/^${{key}}=//p" "$env_file" | tail -n 1 | tr -d '\r')
    if [ -n "$found" ]; then printf '%s' "$found"; return; fi
  fi
  case "$key" in
    GOPROXY) printf '%s' 'https://proxy.golang.org,direct' ;;
    GOSUMDB) printf '%s' 'sum.golang.org' ;;
    *) printf '%s' '' ;;
  esac
}}
case "$*" in
  "version") printf 'go version go{version} linux/amd64\n' ;;
  "env -json GOENV GO111MODULE GOPROXY GOSUMDB GOPRIVATE GONOPROXY GONOSUMDB")
    proxy=$(value GOPROXY)
    sumdb=$(value GOSUMDB)
    private=$(value GOPRIVATE)
    noproxy=$(value GONOPROXY)
    nosumdb=$(value GONOSUMDB)
    module=$(value GO111MODULE)
    printf '{{"GOENV":"/home/developer/.config/go/env","GO111MODULE":"%s","GOPROXY":"%s","GOSUMDB":"%s","GOPRIVATE":"%s","GONOPROXY":"%s","GONOSUMDB":"%s"}}\n' \
      "$module" "$proxy" "$sumdb" "$private" "$noproxy" "$nosumdb"
    ;;
  "mod download -json github.com/pkg/errors@v0.9.1")
    proxy=$(value GOPROXY)
    case "$proxy" in
      *mirrors.aliyun.com/goproxy*|*repo.huaweicloud.com/repository/goproxy*|*repo.nju.edu.cn/go*) ;;
      *) exit 71 ;;
    esac
    [ "$(value GOSUMDB)" != off ] || exit 72
    [ {download_exit} -eq 0 ] || exit {download_exit}
    printf '%s\n' '{{"Path":"github.com/pkg/errors","Version":"v0.9.1","Sum":"h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=","GoModSum":"h1:bwawxfHBFNV1fWwJd9viOWoHuK1+6w/Zk6Q0QGg9ek0="}}'
    ;;
  *) exit 73 ;;
esac
"#,
            physical_env = physical_env.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn selection(endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "go-proxy-test".into(),
        tool_id: "go".into(),
        upstream_id: GO_PROXY_UPSTREAM.into(),
        provider_id: if endpoint.contains("aliyun") {
            "aliyun"
        } else if endpoint.contains("huaweicloud") {
            "huaweicloud"
        } else {
            "nju"
        }
        .into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Index,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[derive(Clone)]
struct GoProtocolProber {
    calls: Rc<RefCell<Vec<String>>>,
}

impl CandidateProber for GoProtocolProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push(url.into());
        let body = if url.ends_with("/@v/list") {
            b"v0.9.1\n".to_vec()
        } else if url.ends_with(".info") {
            br#"{"Version":"v0.9.1"}"#.to_vec()
        } else if url.ends_with(".mod") {
            b"module github.com/pkg/errors\n".to_vec()
        } else if url.contains("/sum.golang.org/lookup/") {
            b"github.com/pkg/errors v0.9.1 h1:verified\n".to_vec()
        } else {
            Vec::new()
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body,
            latency_ms: 1,
        })
    }
}

#[test]
fn enterprise_fallback_is_preserved_and_plan_is_consistent_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_go(root, "1.27.0", 0);
    let original = b"GOFLAGS=-mod=readonly\nGONOPROXY=corp.example.com\nGONOSUMDB=corp.example.com\nGOPRIVATE=corp.example.com\nGOPROXY=https://proxy.corp.example,https://proxy.golang.org|direct\nGOSUMDB=sum.golang.org\n";
    let goenv = write(root, "/home/developer/.config/go/env", original);
    let adapter = GoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.27.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("comma and pipe"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [GO_PROXY_UPSTREAM]);
    assert_eq!(request.required_endpoint_roles, [EndpointRole::Index]);
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Proxy]);

    for incomplete in [HUAWEI, NJU] {
        assert!(
            adapter
                .plan(&context, &current, &[selection(incomplete)])
                .unwrap_err()
                .to_string()
                .contains("reviewed HTTPS GOPROXY endpoint")
        );
    }
    let chosen = [selection(ALIYUN)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!(
        "GOPROXY=https://proxy.corp.example,{}|direct",
        ALIYUN.trim_end_matches('/')
    )));
    for line in [
        "GOPRIVATE=corp.example.com",
        "GONOPROXY=corp.example.com",
        "GONOSUMDB=corp.example.com",
        "GOSUMDB=sum.golang.org",
        "GOFLAGS=-mod=readonly",
    ] {
        assert!(rendered.contains(line));
    }

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("GOENV should change")
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
    assert_eq!(fs::read(goenv).unwrap(), original);
}

#[test]
fn arm64_container_creates_goenv_from_the_effective_default_chain() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_go(root, "1.22.5", 0);
    let goenv = root.join("home/developer/.config/go/env");
    let adapter = GoAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(current.files.is_empty());
    let plan = adapter
        .plan(&context, &current, &[selection(ALIYUN)])
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(
        String::from_utf8(plan.changes[0].new_contents.clone())
            .unwrap()
            .contains("GOPROXY=https://mirrors.aliyun.com/goproxy,direct")
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("GOENV should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(goenv.exists());
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert!(!goenv.exists());
}

#[test]
fn environment_override_and_disabled_checksum_policy_block_changes() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_go(root, "1.27.0", 0);
    write(
        root,
        "/home/developer/.config/go/env",
        b"GOPROXY=https://proxy.golang.org,direct\nGOSUMDB=sum.golang.org\n",
    );
    let adapter = GoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime_value = runtime(
        root,
        BTreeMap::from([("GOPROXY".into(), "https://proxy.corp.example".into())]),
    );
    let detected = adapter.detect(&context, &runtime_value).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_value,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    let error = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap_err();
    assert!(error.to_string().contains("process environment overrides"));

    write(
        root,
        "/home/developer/.config/go/env",
        b"GOPROXY=https://proxy.golang.org,direct\nGOSUMDB=off\n",
    );
    let runtime_value = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime_value).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_value,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    let error = adapter
        .selection_request(&context, &detected, &current)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("checksum verification is disabled")
    );
}

#[test]
fn enterprise_only_and_multiple_public_proxy_chains_are_not_rewritten() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_go(root, "1.27.0", 0);
    let path = write(
        root,
        "/home/developer/.config/go/env",
        b"GOPROXY=https://proxy.corp.example,direct\nGOSUMDB=sum.golang.org\n",
    );
    let adapter = GoAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime_value = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime_value).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_value,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .selection_request(&context, &detected, &current)
            .unwrap_err()
            .to_string()
            .contains("no recognized public proxy")
    );

    let multiple =
        b"GOPROXY=https://proxy.golang.org|https://goproxy.cn,direct\nGOSUMDB=sum.golang.org\n";
    fs::write(&path, multiple).unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_value,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .selection_request(&context, &detected, &current)
            .unwrap_err()
            .to_string()
            .contains("multiple public proxy entries")
    );
    assert_eq!(fs::read(path).unwrap(), multiple);
}

#[test]
fn failed_real_module_query_restores_the_original_goenv() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_go(root, "1.27.0", 79);
    let original = b"GOPROXY=https://proxy.golang.org,direct\nGOSUMDB=sum.golang.org\n";
    let path = write(root, "/home/developer/.config/go/env", original);
    let adapter = GoAdapter;
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
        panic!("GOENV should change")
    };

    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn macos_and_windows_use_reported_goenv_and_preserve_native_line_endings() {
    for (os, architecture, newline) in [
        (OperatingSystem::Macos, Architecture::X86_64, "\n"),
        (OperatingSystem::Windows, Architecture::Arm64, "\r\n"),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_go(root, "1.27.0", 0);
        let text = format!(
            "GOPROXY=https://proxy.golang.org,direct{newline}GOSUMDB=sum.golang.org{newline}GOPRIVATE=corp.invalid.example/*{newline}GONOSUMDB=corp.invalid.example/*{newline}UNKNOWN_GO_SETTING=keep{newline}"
        );
        let original = text.into_bytes();
        let goenv = write(root, "/home/developer/.config/go/env", &original);
        let context = native_context(root, os, architecture);
        let adapter = GoAdapter;
        let mut runtime = runtime(root, BTreeMap::new());
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        assert_eq!(request.context.os, os);
        let selected = [selection(ALIYUN)];
        let plan = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
        let rendered = std::str::from_utf8(&plan.changes[0].new_contents).unwrap();
        assert!(rendered.contains("UNKNOWN_GO_SETTING=keep"));
        assert!(rendered.contains("GOPRIVATE=corp.invalid.example/*"));
        assert!(!rendered.replace(newline, "").contains('\n'));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
        else {
            panic!("native GOENV should change")
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
                .plan(&context, &updated, &selected)
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
        assert_eq!(fs::read(goenv).unwrap(), original);
    }
}

#[test]
fn catalog_keeps_three_records_but_activates_only_the_checksum_complete_candidate() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog.tools.iter().find(|tool| tool.id == "go").unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "go")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "huaweicloud", "nju"])
    );
    let complete = candidates
        .iter()
        .copied()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 1);
    assert_eq!(complete[0].provider_id, "aliyun");
    assert_eq!(complete[0].upstream_id, GO_PROXY_UPSTREAM);
    assert_eq!(complete[0].delivery_mode, DeliveryMode::Proxy);
    assert_eq!(
        complete[0].compatibility.operating_systems,
        [
            OperatingSystem::Linux,
            OperatingSystem::Macos,
            OperatingSystem::Windows
        ]
    );
    assert_eq!(complete[0].compatibility.architectures.len(), 2);
    assert_eq!(complete[0].probes.len(), 6);
    for candidate in complete {
        assert!(
            candidate
                .probes
                .iter()
                .all(|probe| probe.endpoint_role == EndpointRole::Index)
        );
        assert!(
            candidate
                .probes
                .iter()
                .all(|probe| probe.method == HttpMethod::Get)
        );
        for suffix in ["/@v/list", ".info", ".mod", ".zip"] {
            assert!(
                candidate
                    .probes
                    .iter()
                    .any(|probe| probe.path.ends_with(suffix))
            );
        }
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.path.ends_with("/sum.golang.org/supported"))
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.path.contains("/sum.golang.org/lookup/"))
        );
    }

    let incomplete = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(incomplete.len(), 2);
    assert_eq!(
        incomplete
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["huaweicloud", "nju"])
    );
    assert!(
        incomplete
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Unknown)
    );

    let calls = Rc::new(RefCell::new(Vec::new()));
    let selector = MirrorSelector::with_prober(
        &catalog,
        GoProtocolProber {
            calls: Rc::clone(&calls),
        },
        ProbeLimits::default(),
    );
    let outcome = selector
        .select_at(
            &SelectionRequest {
                tool_id: "go".into(),
                adapter_key: "go".into(),
                context: context(
                    Path::new("/"),
                    Architecture::X86_64,
                    ExecutionEnvironment::Host,
                ),
                tool_version: Some("1.27.0".into()),
                required_upstreams: vec![GO_PROXY_UPSTREAM.into()],
                repository_versions: BTreeMap::new(),
                probe_contexts: BTreeMap::new(),
                required_compatibility_evidence: vec![
                    CompatibilityDimension::OperatingSystem,
                    CompatibilityDimension::Architecture,
                    CompatibilityDimension::Environment,
                ],
                require_distribution: false,
                allowed_protocols: vec![Protocol::Https],
                required_endpoint_roles: vec![EndpointRole::Index],
                allowed_delivery_modes: vec![DeliveryMode::Proxy],
                composition_policy: CompositionPolicy::Single,
                overrides: BTreeMap::new(),
            },
            123,
        )
        .unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections.len(), 1);
    assert_eq!(outcome.selections[0].provider_id, "aliyun");
    assert_eq!(calls.borrow().len(), 6);
    assert!(
        calls
            .borrow()
            .iter()
            .all(|url| url.starts_with("https://mirrors.aliyun.com/goproxy/"))
    );
    for provider in ["huaweicloud", "nju"] {
        assert!(outcome.repositories[0].candidates.iter().any(|report| {
            report.provider_id == provider
                && matches!(report.evaluation, CandidateEvaluation::Incompatible { .. })
        }));
    }

    let inventory: Value =
        serde_json::from_str(include_str!("../catalog/provider-inventory.json")).unwrap();
    let providers = inventory["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["adapter_targets"].as_array().is_some_and(|targets| {
                targets
                    .iter()
                    .any(|target| target["tool_id"].as_str() == Some("go"))
            })
        })
        .map(|entry| entry["provider_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(providers, BTreeSet::from(["aliyun", "huaweicloud", "nju"]));
}
