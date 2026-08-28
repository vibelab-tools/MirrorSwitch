#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PdmAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "pypi--language-registry";
const USTC: &str = "https://mirrors.ustc.edu.cn/pypi/simple/";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/";

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

fn install_pdm(root: &Path, selected_file: &str, selected: &str, query_exit: i32, version: &str) {
    let physical = root.join(selected_file.trim_start_matches('/'));
    executable(
        root,
        "/usr/bin/pdm",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'PDM, version {version}'; exit 0; fi\nif [ \"$1 $2\" = 'config pypi.url' ]; then\n  if grep -q '{selected}' '{physical}' 2>/dev/null; then echo '{selected}'; else echo 'https://pypi.org/simple'; fi\n  exit 0\nfi\nif [ \"$1 $2 $3\" = '--no-cache show sampleproject' ]; then\n  grep -q '{selected}' '{physical}' || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  printf 'Name: sampleproject\\nLatest version: 4.0.0\\n'\n  exit 0\nfi\nexit 64\n",
            selected = selected.trim_end_matches('/'),
            physical = physical.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/workspace")
        .with_environment(environment)
}

fn ready_project(root: &Path, pyproject: &[u8]) {
    write(root, "/workspace/pyproject.toml", pyproject);
    write(root, "/workspace/.pdm-python", b"/usr/bin/python3\n");
    write(root, "/workspace/__pypackages__/.gitignore", b"*\n");
}

fn selection(url: &str) -> MirrorSelection {
    let normalized = url.trim_end_matches('/');
    let artifacts = if normalized.contains("tuna") {
        "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages/"
    } else {
        "https://mirrors.ustc.edu.cn/pypi/packages/"
    };
    MirrorSelection {
        candidate_id: "pdm-test".into(),
        tool_id: "pdm".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: url.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: artifacts.into(),
            },
        ],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_plan_preserves_private_indexes_credentials_and_project_priority() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pdm(
        root,
        "/home/developer/.config/pdm/config.toml",
        USTC,
        0,
        "2.28.2",
    );
    write(
        root,
        "/etc/xdg/pdm/config.toml",
        b"[pypi]\nurl = \"https://pypi.org/simple\"\n",
    );
    let original_user = b"# user settings\n[pypi]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n\n[pypi.private]\nurl = \"https://reader:secret@private.example/t/path-secret/simple?token=value\"\nusername = \"reader\"\npassword = \"secret\"\ntype = \"index\"\n";
    let user = write(
        root,
        "/home/developer/.config/pdm/config.toml",
        original_user,
    );
    let pyproject = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[tool.pdm.resolution]\nrespect-source-order = true\n\n[[tool.pdm.source]]\nname = \"private\"\nurl = \"https://${PRIVATE_USER}:${PRIVATE_PASSWORD}@private.example/simple\"\ninclude_packages = [\"internal-*\"]\nexclude_packages = [\"sampleproject\"]\n";
    ready_project(root, pyproject);
    write(
        root,
        "/workspace/pdm.toml",
        b"[install]\nparallel = false\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PdmAdapter;
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("PDM, version 2.28.2"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    for secret in [
        "reader",
        "secret",
        "path-secret",
        "token=value",
        "PRIVATE_USER",
    ] {
        assert!(!serialized.contains(secret));
    }
    assert!(current.sources.iter().any(|source| {
        source.metadata["kind"] == ["respect-source-order"] && source.url == "true"
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Index, EndpointRole::Artifacts]
    );

    let chosen = [selection(USTC)];
    let mut mismatched = selection(USTC);
    mismatched.endpoints[1].url = "https://mirrors.tuna.tsinghua.edu.cn/pypi/packages/".into();
    assert!(
        adapter
            .plan(&context, &current, &[mismatched])
            .unwrap_err()
            .to_string()
            .contains("one reviewed provider")
    );
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.scope, ConfigurationScope::User);
    assert_eq!(cli.changes.len(), 1);
    assert!(
        cli.changes[0]
            .target
            .ends_with("home/developer/.config/pdm/config.toml")
    );
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("url = \"https://mirrors.ustc.edu.cn/pypi/simple\""));
    assert!(
        rendered.contains("https://reader:secret@private.example/t/path-secret/simple?token=value")
    );
    assert!(rendered.contains("username = \"reader\""));
    assert_eq!(
        fs::read(root.join("workspace/pyproject.toml")).unwrap(),
        pyproject
    );

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("PDM user config should change")
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
    adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert_eq!(fs::read(user).unwrap(), original_user);
}

#[test]
fn arm64_project_plan_preserves_source_rules_and_failure_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pdm(root, "/workspace/pyproject.toml", TUNA, 9, "2.12.4");
    write(
        root,
        "/home/developer/.config/pdm/config.toml",
        b"[pypi]\nurl = \"https://pypi.org/simple\"\n",
    );
    let original = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[tool.pdm.resolution]\nrespect-source-order = true\n\n[[tool.pdm.source]]\nname = \"private\"\nurl = \"https://${PRIVATE_TOKEN}@private.example/simple\"\ninclude_packages = [\"private-*\"]\n\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\ninclude_packages = [\"sampleproject\"]\nexclude_packages = [\"blocked-*\"]\n";
    let project = write(root, "/workspace/pyproject.toml", original);
    write(root, "/workspace/.pdm-python", b"/usr/bin/python3\n");
    write(root, "/workspace/.venv/pyvenv.cfg", b"home = /usr/bin\n");
    let context = context(root, Architecture::Arm64);
    let adapter = PdmAdapter;
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.context.architecture, Architecture::Arm64);
    let plan = adapter
        .plan(&context, &current, &[selection(TUNA)])
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        rendered.find("name = \"private\"").unwrap() < rendered.find("name = \"pypi\"").unwrap()
    );
    assert!(rendered.contains("include_packages = [\"sampleproject\"]"));
    assert!(rendered.contains("exclude_packages = [\"blocked-*\"]"));
    assert!(rendered.contains("respect-source-order = true"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("PDM project source should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(&project).unwrap(), original);

    let without_pypi = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[tool.pdm.resolution]\nrespect-source-order = true\n\n[[tool.pdm.source]]\nname = \"private\"\nurl = \"https://private.example/simple\"\ninclude_packages = [\"private-*\"]\n";
    fs::write(&project, without_pypi).unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let inserted = adapter
        .plan(&context, &current, &[selection(TUNA)])
        .unwrap();
    let inserted = String::from_utf8(inserted.changes[0].new_contents.clone()).unwrap();
    assert!(
        inserted.find("name = \"pypi\"").unwrap() < inserted.find("name = \"private\"").unwrap()
    );
    assert!(inserted.contains("include_packages = [\"private-*\"]"));
}

#[test]
fn overrides_private_defaults_credentials_tls_and_json_bypass_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pdm(
        root,
        "/home/developer/.config/pdm/config.toml",
        USTC,
        0,
        "1.15.4",
    );
    ready_project(
        root,
        b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PdmAdapter;
    let legacy_runtime = runtime(root, BTreeMap::new());
    assert!(
        adapter
            .detect(&context, &legacy_runtime)
            .unwrap_err()
            .to_string()
            .contains("2.x")
    );
    install_pdm(
        root,
        "/home/developer/.config/pdm/config.toml",
        USTC,
        0,
        "2.28.2",
    );

    write(
        root,
        "/home/developer/.config/pdm/config.toml",
        b"[pypi]\nurl = \"https://pypi.org/simple\"\n",
    );
    write(
        root,
        "/custom/pdm.toml",
        b"[pypi]\nurl = \"https://pypi.org/simple\"\n",
    );
    let custom_runtime = runtime(
        root,
        BTreeMap::from([("PDM_CONFIG_FILE".into(), "/custom/pdm.toml".into())]),
    );
    let detected = adapter.detect(&context, &custom_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &custom_runtime,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    let custom = adapter
        .plan(&context, &current, &[selection(USTC)])
        .unwrap();
    assert!(custom.changes[0].target.ends_with("custom/pdm.toml"));

    let environment_runtime = runtime(
        root,
        BTreeMap::from([(
            "PDM_PYPI_URL".into(),
            "https://private.example/simple".into(),
        )]),
    );
    let detected = adapter
        .detect(&context, &environment_runtime)
        .unwrap()
        .unwrap();
    let current = adapter
        .read_current(
            &context,
            &environment_runtime,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC)])
            .unwrap_err()
            .to_string()
            .contains("PDM_PYPI_URL")
    );

    let runtime = runtime(root, BTreeMap::new());
    write(
        root,
        "/workspace/pyproject.toml",
        b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"https://private.example/simple\"\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC)])
            .unwrap_err()
            .to_string()
            .contains("project source named pypi")
    );

    write(
        root,
        "/workspace/pyproject.toml",
        b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n",
    );
    for (config, message) in [
        (
            "[pypi]\nurl = \"https://private.example/simple\"\n",
            "private or unmapped",
        ),
        (
            "[pypi]\nurl = \"https://pypi.org/simple\"\npassword = \"secret\"\n",
            "credentials",
        ),
        (
            "[pypi]\nurl = \"https://pypi.org/simple\"\nverify_ssl = false\n",
            "TLS",
        ),
        (
            "[pypi]\nurl = \"https://pypi.org/simple\"\njson_api = true\n",
            "json_api",
        ),
    ] {
        write(
            root,
            "/home/developer/.config/pdm/config.toml",
            config.as_bytes(),
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &[selection(USTC)])
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }

    write(
        root,
        "/home/developer/.config/pdm/config.toml",
        b"[pypi]\nurl = \"https://pypi.org/simple\"\n",
    );
    write(
        root,
        "/workspace/pyproject.toml",
        b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\ntype = \"find_links\"\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC)])
            .unwrap_err()
            .to_string()
            .contains("PEP 503 index")
    );
}

#[test]
fn embedded_catalog_has_six_complete_pdm_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "pdm" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    for candidate in candidates {
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert!(matches!(
            candidate.delivery_mode,
            DeliveryMode::Mirror | DeliveryMode::Proxy
        ));
        assert!(
            candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Index)
        );
        assert!(
            candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.endpoint_role == EndpointRole::Index)
        );
        assert!(
            candidate
                .probes
                .iter()
                .any(|probe| probe.endpoint_role == EndpointRole::Artifacts)
        );
    }
    assert!(catalog.candidates.iter().any(|candidate| {
        candidate.tool_id == "pdm"
            && candidate.raw_names == ["jetson-pypi"]
            && candidate.probes.is_empty()
    }));
    assert!(catalog.candidates.iter().any(|candidate| {
        candidate.tool_id == "pdm"
            && candidate.raw_names == ["pypi-packages"]
            && candidate.probes.is_empty()
    }));
}
