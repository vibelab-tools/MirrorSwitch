#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PoetryAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "pypi--language-registry";
const USTC: &str = "https://mirrors.ustc.edu.cn/pypi/simple/";
const USTC_ARTIFACTS: &str = "https://mirrors.ustc.edu.cn/pypi/packages/";

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

fn install_poetry(root: &Path, version: &str, selected: &str, query_exit: i32, keyring: bool) {
    let project = root.join("work/project");
    let pyproject = project.join("pyproject.toml");
    fs::create_dir_all(&project).unwrap();
    executable(
        root,
        "/usr/bin/poetry",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'Poetry (version {version})'; exit 0; fi\nif [ \"$1 $2\" = 'config keyring.enabled' ]; then echo '{keyring}'; exit 0; fi\nif [ \"$1 $2\" = 'source show' ]; then\n  name=$3\n  grep -F 'url = \"{selected}\"' '{pyproject}' >/dev/null || exit 65\n  printf ' name : %s\\n url : {selected}\\n priority : primary\\n' \"$name\"\n  exit 0\nfi\nif [ \"$1 $2\" = 'debug resolve' ]; then\n  grep -F 'url = \"{selected}\"' '{pyproject}' >/dev/null || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  printf 'Resolving dependencies...\\n\\nResolution results:\\n\\npeppercorn 0.6\\nsampleproject 4.0.0\\n'\n  exit 0\nfi\nexit 64\n",
            keyring = if keyring { "true" } else { "false" },
            pyproject = pyproject.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection(index: &str, artifacts: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "poetry-test".into(),
        tool_id: "poetry".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: index.into(),
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
fn poetry_24_explicit_project_plan_preserves_private_sources_credentials_and_global_config() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_poetry(root, "2.4.1", USTC, 0, true);
    let original = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[build-system]\nrequires = [\"poetry-core>=2.0.0,<3.0.0\"]\nbuild-backend = \"poetry.core.masonry.api\"\n\n[[tool.poetry.source]]\nname = \"corp\"\nurl = \"https://packages.example/simple/\"\npriority = \"supplemental\"\n\n[[tool.poetry.source]]\nname = \"gpu\"\nurl = \"https://download.example/gpu/\"\npriority = \"explicit\"\n\n[tool.poetry.dependencies]\npython = \">=3.12,<4\"\nprivate-package = { version = \"*\", source = \"corp\" }\n";
    let pyproject = write(root, "/work/project/pyproject.toml", original);
    let global = write(
        root,
        "/home/developer/.config/pypoetry/config.toml",
        b"[repositories.publish]\nurl = \"https://upload.example/legacy/\"\n\n[certificates.corp]\ncert = \"/etc/corp-ca.pem\"\n",
    );
    let auth = write(
        root,
        "/home/developer/.config/pypoetry/auth.toml",
        b"[http-basic.corp]\nusername = \"reader\"\npassword = \"private-secret\"\n",
    );
    let local = write(
        root,
        "/work/project/poetry.toml",
        b"[virtualenvs]\nin-project = true\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PoetryAdapter;
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("project-local"))
    );
    assert_eq!(adapter.supported_scopes(), [ConfigurationScope::Project]);
    assert_eq!(adapter.default_scope(), ConfigurationScope::Project);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("reader"));
    assert!(!serialized.contains("private-secret"));
    assert!(current.sources.iter().any(|source| {
        source.metadata.get("source_name") == Some(&vec!["corp".into()])
            && source.metadata.get("priority") == Some(&vec!["supplemental".into()])
    }));
    assert!(current.sources.iter().any(|source| {
        source.metadata.get("source_name") == Some(&vec!["gpu".into()])
            && source.metadata.get("priority") == Some(&vec!["explicit".into()])
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Index, EndpointRole::Artifacts]
    );
    assert_eq!(
        request.allowed_delivery_modes,
        [DeliveryMode::Mirror, DeliveryMode::Proxy]
    );

    let chosen = [selection(USTC, USTC_ARTIFACTS)];
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert!(!cli_plan.requires_elevation);
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("name = \"mirrorswitch-pypi\""));
    assert!(rendered.contains(&format!("url = \"{USTC}\"")));
    assert!(rendered.contains("priority = \"primary\""));
    assert!(rendered.contains("source = \"corp\""));
    assert!(rendered.contains("priority = \"supplemental\""));
    assert!(rendered.contains("priority = \"explicit\""));
    let global_before = fs::read(&global).unwrap();
    let auth_before = fs::read(&auth).unwrap();
    let local_before = fs::read(&local).unwrap();

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("Poetry project should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&global).unwrap(), global_before);
    assert_eq!(fs::read(&auth).unwrap(), auth_before);
    assert_eq!(fs::read(&local).unwrap(), local_before);
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
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
    assert_eq!(fs::read(pyproject).unwrap(), original);
}

#[test]
fn poetry_18_arm64_rewrites_reviewed_primary_when_keyring_is_disabled() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_poetry(root, "1.8.5", USTC, 0, false);
    let original = b"[tool.poetry]\nname = \"probe\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = []\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n\n[[tool.poetry.source]]\nname = \"public-cache\"\nurl = \"https://pypi.org/simple/\"\npriority = \"primary\"\n\n[[tool.poetry.source]]\nname = \"private\"\nurl = \"https://packages.example/simple/\"\npriority = \"explicit\"\n";
    let pyproject = write(root, "/work/project/pyproject.toml", original);
    let context = context(root, Architecture::Arm64);
    let adapter = PoetryAdapter;
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.evidence.iter().any(|value| value.contains("1.5+")));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let chosen = [selection(USTC, USTC_ARTIFACTS)];
    let plan = adapter.plan(&context, &current, &chosen).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("name = \"public-cache\""));
    assert!(rendered.contains(&format!("url = \"{USTC}\"")));
    assert!(!rendered.contains("mirrorswitch-pypi"));
    assert!(rendered.contains("priority = \"explicit\""));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Poetry primary source should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(pyproject).unwrap(), original);
}

#[test]
fn failed_poetry_resolution_restores_the_project_file() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_poetry(root, "2.4.1", USTC, 7, true);
    let original = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n";
    let pyproject = write(root, "/work/project/pyproject.toml", original);
    let context = context(root, Architecture::Arm64);
    let adapter = PoetryAdapter;
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(USTC, USTC_ARTIFACTS)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Poetry project should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(pyproject).unwrap(), original);
}

#[test]
fn global_scope_old_priorities_private_primary_credentials_certificates_and_keyring_are_blocked() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    executable(root, "/usr/bin/pip", "#!/bin/sh\nexit 0\n".into());
    let context = context(root, Architecture::X86_64);
    let adapter = PoetryAdapter;
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new()))
            .unwrap()
            .is_none()
    );

    for version in ["1.4.2", "2.5.0", "3.0.0"] {
        install_poetry(root, version, USTC, 0, true);
        assert!(
            adapter
                .detect(&context, &runtime(root, BTreeMap::new()))
                .is_err()
        );
    }
    install_poetry(root, "2.4.1", USTC, 0, true);
    let mut no_project = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(BTreeMap::new());
    let detected = adapter.detect(&context, &no_project).unwrap().unwrap();
    assert!(
        adapter
            .read_current(
                &context,
                &no_project,
                &detected,
                ConfigurationScope::Project
            )
            .unwrap_err()
            .to_string()
            .contains("explicit project")
    );
    assert!(
        adapter
            .read_current(&context, &no_project, &detected, ConfigurationScope::User)
            .unwrap_err()
            .to_string()
            .contains("project-local")
    );
    let _ = &mut no_project;

    let base_runtime = runtime(root, BTreeMap::new());
    for (project, message) in [
        (
            "[project]\nname='probe'\nversion='0.1.0'\n[[tool.poetry.source]]\nname='old'\nurl='https://pypi.org/simple/'\npriority='secondary'\n",
            "supported priorities",
        ),
        (
            "[project]\nname='probe'\nversion='0.1.0'\n[[tool.poetry.source]]\nname='private'\nurl='https://packages.example/simple/'\npriority='primary'\n",
            "private or unmapped",
        ),
        (
            "[project]\nname='probe'\nversion='0.1.0'\n[[tool.poetry.source]]\nname='pypi'\npriority='primary'\n",
            "explicit built-in PyPI",
        ),
    ] {
        write(root, "/work/project/pyproject.toml", project.as_bytes());
        match adapter.read_current(
            &context,
            &base_runtime,
            &detected,
            ConfigurationScope::Project,
        ) {
            Err(error) => assert!(error.to_string().contains(message)),
            Ok(current) => assert!(
                adapter
                    .plan(&context, &current, &[selection(USTC, USTC_ARTIFACTS)])
                    .unwrap_err()
                    .to_string()
                    .contains(message)
            ),
        }
    }

    let base = "[project]\nname='probe'\nversion='0.1.0'\n";
    write(root, "/work/project/pyproject.toml", base.as_bytes());
    let environment_runtime = runtime(
        root,
        BTreeMap::from([(
            "POETRY_HTTP_BASIC_MIRRORSWITCH_PYPI_PASSWORD".into(),
            "environment-secret".into(),
        )]),
    );
    let current = adapter
        .read_current(
            &context,
            &environment_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("environment-secret")
    );
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC, USTC_ARTIFACTS)])
            .unwrap_err()
            .to_string()
            .contains("credentials")
    );

    let public = "[project]\nname='probe'\nversion='0.1.0'\n[[tool.poetry.source]]\nname='public-cache'\nurl='https://pypi.org/simple/'\npriority='primary'\n";
    write(root, "/work/project/pyproject.toml", public.as_bytes());
    let current = adapter
        .read_current(
            &context,
            &base_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC, USTC_ARTIFACTS)])
            .unwrap_err()
            .to_string()
            .contains("keyring")
    );

    install_poetry(root, "2.4.1", USTC, 0, false);
    write(
        root,
        "/home/developer/.config/pypoetry/auth.toml",
        b"[http-basic.public-cache]\nusername='reader'\npassword='file-secret'\n",
    );
    let no_keyring_runtime = runtime(root, BTreeMap::new());
    let current = adapter
        .read_current(
            &context,
            &no_keyring_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("file-secret")
    );
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC, USTC_ARTIFACTS)])
            .unwrap_err()
            .to_string()
            .contains("credentials")
    );

    write(root, "/home/developer/.config/pypoetry/auth.toml", b"");
    write(
        root,
        "/home/developer/.config/pypoetry/config.toml",
        b"[certificates.public-cache]\ncert=false\n",
    );
    let current = adapter
        .read_current(
            &context,
            &no_keyring_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(USTC, USTC_ARTIFACTS)])
            .unwrap_err()
            .to_string()
            .contains("certificate")
    );
}

#[test]
fn embedded_catalog_has_six_complete_poetry_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "poetry" && !candidate.probes.is_empty())
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
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Index)
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
            && candidate.probes.len() == 2
            && candidate.probes[0].method == HttpMethod::Get
            && candidate.probes[0].path == "/sampleproject/"
            && candidate.probes[1].method == HttpMethod::Get
            && candidate.probes[1]
                .path
                .ends_with("sampleproject-4.0.0-py3-none-any.whl")
    }));
}
