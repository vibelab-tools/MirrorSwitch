#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PipAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "pypi--language-registry";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple";
const HUAWEI: &str = "https://repo.huaweicloud.com/repository/pypi/simple";
const USTC: &str = "https://mirrors.ustc.edu.cn/pypi/simple";

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

fn install_pip(root: &Path, selected: &str, query_exit: i32, environment: &str) {
    let global = root.join("etc/pip.conf");
    let user = root.join("home/developer/.config/pip/pip.conf");
    let site = root.join("opt/venv/pip.conf");
    executable(
        root,
        "/usr/bin/pip",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'pip 25.1 from /opt/venv/lib/python3.12/site-packages/pip (python 3.12)'; exit 0; fi\nif [ \"$1 $2\" = 'config debug' ]; then\n  printf 'env_var:\\n{environment}env:\\nglobal:\\n  /etc/xdg/pip/pip.conf, exists: False\\n  /etc/pip.conf, exists: True\\nsite:\\n  /opt/venv/pip.conf, exists: True\\nuser:\\n  /home/developer/.pip/pip.conf, exists: False\\n  /home/developer/.config/pip/pip.conf, exists: True\\n'\n  exit 0\nfi\nif [ \"$1 $2\" = 'config list' ]; then\n  url=$(sed -n 's/^[[:space:]]*index-url[[:space:]]*=[[:space:]]*//p' '{site}' 2>/dev/null | tail -1)\n  [ -n \"$url\" ] || url=$(sed -n 's/^[[:space:]]*index-url[[:space:]]*=[[:space:]]*//p' '{user}' 2>/dev/null | tail -1)\n  [ -n \"$url\" ] || url=$(sed -n 's/^[[:space:]]*index-url[[:space:]]*=[[:space:]]*//p' '{global}' 2>/dev/null | tail -1)\n  printf \"global.index-url='%s'\\n\" \"$url\"\n  exit 0\nfi\nif [ \"$1 $2 $3\" = 'index versions sampleproject' ]; then\n  found=1\n  for file in '{global}' '{user}' '{site}'; do [ -f \"$file\" ] && grep -q '{selected}' \"$file\" && found=0; done\n  [ $found -eq 0 ] || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  echo 'sampleproject (4.0.0)'\n  exit 0\nfi\nexit 64\n",
            global = global.display(),
            user = user.display(),
            site = site.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/home/developer")
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "pip-test".into(),
        tool_id: "pip".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Index,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_plan_preserves_extra_index_is_consistent_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pip(root, TUNA, 0, "");
    write(
        root,
        "/etc/pip.conf",
        b"[global]\nindex-url = https://pypi.org/simple\ntimeout = 30\n",
    );
    let original = b"[global]\nindex-url = https://pypi.org/simple/\nextra-index-url = https://reader:password@private.example/simple\ncache-dir = /tmp/pip-cache\n";
    let user = write(root, "/home/developer/.config/pip/pip.conf", original);
    let context = context(root, Architecture::X86_64);
    let adapter = PipAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.version.as_deref().unwrap().contains("python 3.12"));
    assert_eq!(adapter.default_scope(), ConfigurationScope::User);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("reader"));
    assert!(!serialized.contains("password"));
    assert!(current.sources.iter().any(|source| {
        source.metadata["kind"] == ["extra-index-url"]
            && source.metadata["origin_scope"] == ["user"]
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(
        request.composition_policy,
        mirrorswitch::catalog::CompositionPolicy::Single
    );

    let chosen = [selection(TUNA)];
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert!(!cli_plan.requires_elevation);
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("index-url = {TUNA}")));
    assert!(rendered.contains("extra-index-url = https://reader:password@private.example/simple"));
    assert!(!rendered.contains("trusted-host"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("pip user config should change")
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
    assert_eq!(fs::read(user).unwrap(), original);
}

#[test]
fn global_and_site_scope_paths_have_explicit_permission_plans() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pip(root, USTC, 0, "");
    write(
        root,
        "/etc/pip.conf",
        b"[global]\nindex-url = https://pypi.org/simple\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PipAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter.supported_scopes(),
        [
            ConfigurationScope::System,
            ConfigurationScope::User,
            ConfigurationScope::Site
        ]
    );

    let global = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let global_plan = adapter.plan(&context, &global, &[selection(USTC)]).unwrap();
    assert!(global_plan.requires_elevation);
    assert!(global_plan.changes[0].target.ends_with("etc/pip.conf"));

    let site = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Site)
        .unwrap();
    let site_plan = adapter.plan(&context, &site, &[selection(USTC)]).unwrap();
    assert!(!site_plan.requires_elevation);
    assert!(site_plan.changes[0].target.ends_with("opt/venv/pip.conf"));
    assert!(
        String::from_utf8(site_plan.changes[0].new_contents.clone())
            .unwrap()
            .starts_with("[global]\nindex-url")
    );
}

#[test]
fn arm64_site_query_failure_restores_the_environment_file() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pip(root, HUAWEI, 7, "");
    let original = b"[global]\nindex-url=https://pypi.org/simple\n";
    let site = write(root, "/opt/venv/pip.conf", original);
    let context = context(root, Architecture::Arm64);
    let adapter = PipAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Site)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("pip site config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(site).unwrap(), original);
}

#[test]
fn environment_credentials_command_overrides_and_tls_bypass_are_not_mutated() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pip(
        root,
        USTC,
        0,
        "  PIP_INDEX_URL='https://account:secret@private.example/simple'\\n  PIP_CONFIG_FILE='/tmp/private-pip.conf'\\n",
    );
    write(
        root,
        "/home/developer/.config/pip/pip.conf",
        b"[global]\nindex-url=https://pypi.org/simple\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PipAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("account"));
    assert!(!serialized.contains("secret"));
    let error = adapter
        .plan(&context, &current, &[selection(USTC)])
        .unwrap_err();
    assert!(error.to_string().contains("environment overrides"));

    install_pip(root, USTC, 0, "");
    write(
        root,
        "/home/developer/.config/pip/pip.conf",
        b"[global]\nindex-url=https://pypi.org/simple\ntrusted-host=mirrors.ustc.edu.cn\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let error = adapter
        .plan(&context, &current, &[selection(USTC)])
        .unwrap_err();
    assert!(error.to_string().contains("TLS verification"));

    write(
        root,
        "/home/developer/.config/pip/pip.conf",
        b"[global]\nindex-url=https://pypi.org/simple\n[install]\nindex-url=https://pypi.org/simple\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let error = adapter
        .plan(&context, &current, &[selection(USTC)])
        .unwrap_err();
    assert!(error.to_string().contains("command-specific"));
}

#[test]
fn embedded_catalog_has_six_complete_simple_api_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "pip" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert!(candidates.iter().all(|candidate| {
        candidate.upstream_id == UPSTREAM
            && matches!(
                candidate.delivery_mode,
                DeliveryMode::Mirror | DeliveryMode::Proxy
            )
            && candidate.compatibility.operating_systems == [OperatingSystem::Linux]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints[0].role == EndpointRole::Index
            && candidate.endpoints[0].protocol == Protocol::Https
            && candidate.endpoints[0].url.ends_with("/simple/")
            && candidate.probes.len() == 1
            && candidate.probes[0].method == HttpMethod::Get
            && candidate.probes[0].path == "/sampleproject/"
            && candidate.probes[0].contains.as_deref() == Some("sampleproject-")
    }));
    let incomplete = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "pip" && candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert!(
        incomplete
            .iter()
            .any(|candidate| candidate.raw_names == ["jetson-pypi"])
    );
    assert!(
        incomplete
            .iter()
            .any(|candidate| candidate.raw_names == ["pypi-packages"])
    );
}
