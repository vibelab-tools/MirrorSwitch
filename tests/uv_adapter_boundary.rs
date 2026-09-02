#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{UvAdapter, compiled_adapter_allowlist},
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

fn install_uv(root: &Path, version: &str, selected_file: &str, query_exit: i32) {
    let selected_file = root.join(selected_file.trim_start_matches('/'));
    fs::create_dir_all(root.join("work/project")).unwrap();
    executable(
        root,
        "/usr/bin/uv",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'uv {version}'; exit 0; fi\nif [ \"$1 $2\" = 'pip install' ]; then\n  grep -F 'url = \"{USTC}\"' '{selected_file}' >/dev/null || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  printf 'DEBUG Sending fresh GET request for: {USTC}sampleproject/\nResolved 2 packages\nWould install 2 packages\n + peppercorn==0.6\n + sampleproject==4.0.0\n' >&2\n  exit 0\nfi\nexit 64\n",
            selected_file = selected_file.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn native_runtime(root: &Path, home: &str, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home(home)
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection() -> MirrorSelection {
    MirrorSelection {
        candidate_id: "uv-test".into(),
        tool_id: "uv".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "ustc".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: USTC.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: USTC_ARTIFACTS.into(),
            },
        ],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_plan_overrides_system_default_and_preserves_explicit_project_sources() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_uv(root, "0.12.7", "/home/developer/.config/uv/uv.toml", 0);
    write(
        root,
        "/etc/uv/uv.toml",
        b"[[index]]\nname = \"system-public\"\nurl = \"https://pypi.org/simple/\"\ndefault = true\n",
    );
    let original_user = b"[pip]\nstrict = true\n";
    let user = write(root, "/home/developer/.config/uv/uv.toml", original_user);
    let project_contents = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = [\"private-package\"]\n\n[tool.uv.sources]\nprivate-package = { index = \"corp\" }\n\n[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://reader:secret@packages.example/simple?token=hidden\"\nexplicit = true\n";
    let project = write(root, "/work/project/pyproject.toml", project_contents);
    let adapter = UvAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("uv 0.12.7"));
    assert_eq!(adapter.default_scope(), ConfigurationScope::User);
    assert_eq!(
        adapter.supported_scopes(),
        [ConfigurationScope::User, ConfigurationScope::Project]
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    for secret in ["reader", "secret", "token=hidden"] {
        assert!(!serialized.contains(secret));
    }
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

    let chosen = [selection()];
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert_eq!(cli_plan.scope, ConfigurationScope::User);
    assert!(!cli_plan.requires_elevation);
    assert_eq!(cli_plan.changes.len(), 1);
    assert!(
        cli_plan.changes[0]
            .target
            .ends_with("home/developer/.config/uv/uv.toml")
    );
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("name = \"mirrorswitch-pypi\""));
    assert!(rendered.contains(&format!("url = \"{USTC}\"")));
    assert!(rendered.contains("default = true"));
    assert!(rendered.contains("strict = true"));
    assert_eq!(fs::read(&project).unwrap(), project_contents);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("uv user config should change")
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
    assert_eq!(fs::read(user).unwrap(), original_user);
}

#[test]
fn arm64_project_plan_overrides_user_default_and_failure_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_uv(root, "0.4.23", "/work/project/pyproject.toml", 9);
    let user_contents =
        b"[[index]]\nname = \"user-public\"\nurl = \"https://pypi.org/simple/\"\ndefault = true\n";
    let user = write(root, "/home/developer/.config/uv/uv.toml", user_contents);
    let original = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = [\"private-package\"]\n\n[tool.uv.sources]\nprivate-package = { index = \"corp\" }\n\n[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://packages.example/simple/\"\nexplicit = true\n";
    let project = write(root, "/work/project/pyproject.toml", original);
    let adapter = UvAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.context.architecture, Architecture::Arm64);
    let chosen = [selection()];
    let plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(plan.scope, ConfigurationScope::Project);
    assert!(
        plan.changes[0]
            .target
            .ends_with("work/project/pyproject.toml")
    );
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("[tool.uv.sources]"));
    assert!(rendered.contains("index = \"corp\""));
    assert!(rendered.contains("explicit = true"));
    assert!(rendered.contains(&format!("url = \"{USTC}\"")));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("uv project config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(project).unwrap(), original);
    assert_eq!(fs::read(user).unwrap(), user_contents);
}

#[test]
fn project_uv_toml_wins_and_legacy_index_url_is_rewritten_without_touching_pyproject() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_uv(root, "0.11.17", "/work/project/uv.toml", 0);
    let original = b"index-url = \"https://pypi.org/simple/\"\nindex-strategy = \"first-index\"\n";
    let project_uv = write(root, "/work/project/uv.toml", original);
    let ignored = b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\n\n[tool.uv]\nindex-strategy = \"unsafe-best-match\"\n\n[[tool.uv.index]]\nname = \"ignored-private\"\nurl = \"https://packages.example/simple/\"\ndefault = true\n";
    let pyproject = write(root, "/work/project/pyproject.toml", ignored);
    let adapter = UvAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("uv.toml"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    assert!(!current.sources.iter().any(|source| {
        source.metadata.get("source_name") == Some(&vec!["ignored-private".into()])
    }));
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    assert!(plan.changes[0].target.ends_with("work/project/uv.toml"));
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("index-url = \"{USTC}\"")));
    assert!(!rendered.contains("index = []"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("uv project config should change")
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
    assert_eq!(fs::read(project_uv).unwrap(), original);
    assert_eq!(fs::read(pyproject).unwrap(), ignored);
}

#[test]
fn versions_environment_overrides_and_unsafe_index_models_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    executable(root, "/usr/bin/pip", "#!/bin/sh\nexit 0\n".into());
    let adapter = UvAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new()))
            .unwrap()
            .is_none()
    );
    for version in ["0.4.22", "0.13.0", "1.0.0"] {
        install_uv(root, version, "/home/developer/.config/uv/uv.toml", 0);
        assert!(
            adapter
                .detect(&context, &runtime(root, BTreeMap::new()))
                .unwrap_err()
                .to_string()
                .contains("outside the reviewed")
        );
    }
    install_uv(root, "0.12.7", "/home/developer/.config/uv/uv.toml", 0);
    write(
        root,
        "/work/project/pyproject.toml",
        b"[project]\nname = \"probe\"\nversion = \"0.1.0\"\n",
    );
    let user = "/home/developer/.config/uv/uv.toml";
    write(root, user, b"");

    for (key, value) in [
        ("UV_DEFAULT_INDEX", "https://pypi.org/simple"),
        ("UV_INDEX", "https://packages.example/simple"),
        ("UV_CONFIG_FILE", "/custom/uv.toml"),
        ("UV_NO_CONFIG", "1"),
        ("UV_INDEX_STRATEGY", "unsafe-best-match"),
        ("UV_INDEX_MIRRORSWITCH_PYPI_PASSWORD", "environment-secret"),
    ] {
        let runtime = runtime(root, BTreeMap::from([(key.into(), value.into())]));
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        if key.ends_with("PASSWORD") {
            assert!(!serde_json::to_string(&current).unwrap().contains(value));
        }
        assert!(adapter.plan(&context, &current, &[selection()]).is_err());
    }

    let false_flag = runtime(
        root,
        BTreeMap::from([("UV_NO_CONFIG".into(), "false".into())]),
    );
    let detected = adapter.detect(&context, &false_flag).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &false_flag, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(adapter.plan(&context, &current, &[selection()]).is_ok());

    write(root, user, b"index-strategy = \"unsafe-best-match\"\n");
    let safe_environment = runtime(
        root,
        BTreeMap::from([("UV_INDEX_STRATEGY".into(), "first-index".into())]),
    );
    let detected = adapter
        .detect(&context, &safe_environment)
        .unwrap()
        .unwrap();
    let current = adapter
        .read_current(
            &context,
            &safe_environment,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(adapter.plan(&context, &current, &[selection()]).is_ok());

    for (config, message) in [
        (
            "[[index]]\nname = \"searchable\"\nurl = \"https://packages.example/simple\"\n",
            "searchable additional",
        ),
        (
            "[[index]]\nname = \"flat\"\nurl = \"https://packages.example/files\"\nformat = \"flat\"\n",
            "searchable additional",
        ),
        ("[pip]\nindex-url = \"https://pypi.org/simple\"\n", "uv.pip"),
        (
            "[[index]]\nname = \"private\"\nurl = \"https://packages.example/simple\"\ndefault = true\n",
            "private or unmapped",
        ),
        (
            "[[index]]\nname = \"public\"\nurl = \"https://pypi.org/simple\"\ndefault = true\nexplicit = true\n",
            "explicit",
        ),
    ] {
        write(root, user, config.as_bytes());
        let runtime = runtime(root, BTreeMap::new());
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &[selection()])
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }

    write(
        root,
        user,
        b"[[index]]\nname = \"public-cache\"\nurl = \"https://pypi.org/simple\"\ndefault = true\n",
    );
    let credential_runtime = runtime(
        root,
        BTreeMap::from([(
            "UV_INDEX_PUBLIC_CACHE_PASSWORD".into(),
            "source-secret".into(),
        )]),
    );
    let detected = adapter
        .detect(&context, &credential_runtime)
        .unwrap()
        .unwrap();
    let current = adapter
        .read_current(
            &context,
            &credential_runtime,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("source-secret")
    );
    assert!(
        adapter
            .plan(&context, &current, &[selection()])
            .unwrap_err()
            .to_string()
            .contains("credentials")
    );

    write(root, user, b"");
    write(
        root,
        "/work/project/uv.toml",
        b"[[index]]\nname = \"project-public\"\nurl = \"https://pypi.org/simple\"\ndefault = true\n",
    );
    let runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection()])
            .unwrap_err()
            .to_string()
            .contains("higher precedence")
    );

    write(
        root,
        user,
        b"[[index]]\nname = \"shared\"\nurl = \"https://pypi.org/simple\"\ndefault = true\n",
    );
    write(
        root,
        "/work/project/uv.toml",
        b"[[index]]\nname = \"shared\"\nurl = \"https://packages.example/simple\"\nexplicit = true\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection()])
            .unwrap_err()
            .to_string()
            .contains("same name")
    );
}

#[test]
fn macos_and_windows_use_native_config_roots_and_preserve_text_layout() {
    struct Case {
        os: OperatingSystem,
        architecture: Architecture,
        home: &'static str,
        system: &'static str,
        user: &'static str,
        environment: BTreeMap<String, String>,
        bom: bool,
        newline: &'static str,
    }

    let cases = [
        Case {
            os: OperatingSystem::Macos,
            architecture: Architecture::X86_64,
            home: "/Users/test",
            system: "/etc/uv/uv.toml",
            user: "/Users/test/.config/uv/uv.toml",
            environment: BTreeMap::new(),
            bom: false,
            newline: "\n",
        },
        Case {
            os: OperatingSystem::Windows,
            architecture: Architecture::Arm64,
            home: "/Users/test",
            system: "/ProgramData/uv/uv.toml",
            user: "/Users/test/AppData/Roaming/uv/uv.toml",
            environment: BTreeMap::from([
                ("APPDATA".into(), "/Users/test/AppData/Roaming".into()),
                ("ProgramData".into(), "/ProgramData".into()),
            ]),
            bom: true,
            newline: "\r\n",
        },
    ];

    for case in cases {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_uv(root, "0.12.7", case.user, 0);
        let system_contents = b"[[index]]\nname = \"system-private\"\nurl = \"https://packages.invalid.example/simple/\"\nexplicit = true\n";
        let system = write(root, case.system, system_contents);
        let project_contents = b"[project]\nname = \"native-probe\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\n\n[tool.uv.sources]\nprivate-package = { index = \"corp\" }\n\n[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://reader:secret@packages.invalid.example/simple/\"\nexplicit = true\n";
        let project = write(root, "/work/project/pyproject.toml", project_contents);
        let text = format!(
            "index-strategy = \"first-index\"{0}native-policy = \"keep\"{0}{0}[[index]]{0}name = \"public\"{0}url = \"https://pypi.org/simple/\"{0}default = true{0}",
            case.newline
        );
        let mut original = text.into_bytes();
        if case.bom {
            original.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let user = write(root, case.user, &original);
        let context = native_context(root, case.os, case.architecture);
        let adapter = UvAdapter;
        let mut runtime = native_runtime(root, case.home, case.environment);

        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert_eq!(detected.executable.as_deref(), Some(Path::new("uv")));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let selected = current
            .documents
            .iter()
            .find(|document| document.format == "uv-selected-standalone")
            .unwrap();
        assert_eq!(selected.path, PathBuf::from(case.user));
        assert!(!serde_json::to_string(&current).unwrap().contains("secret"));

        let chosen = [selection()];
        let cli = adapter.plan(&context, &current, &chosen).unwrap();
        let config = adapter.plan(&context, &current, &chosen).unwrap();
        let tui = adapter.plan(&context, &current, &chosen).unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
        assert_eq!(cli.changes[0].target, user);
        assert_eq!(
            cli.changes[0].new_contents.starts_with(&[0xef, 0xbb, 0xbf]),
            case.bom
        );
        let rendered = std::str::from_utf8(
            cli.changes[0]
                .new_contents
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&cli.changes[0].new_contents),
        )
        .unwrap();
        assert!(rendered.contains(&format!("url = \"{USTC}\"")));
        assert!(rendered.contains("native-policy = \"keep\""));
        assert!(!rendered.replace(case.newline, "").contains('\n'));

        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("native uv user configuration should change")
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
        assert_eq!(fs::read(system).unwrap(), system_contents);
        assert_eq!(fs::read(project).unwrap(), project_contents);
    }

    let directory = tempdir().unwrap();
    install_uv(
        directory.path(),
        "0.12.7",
        "/Users/test/.config/uv/uv.toml",
        0,
    );
    let mut context = native_context(
        directory.path(),
        OperatingSystem::Macos,
        Architecture::Arm64,
    );
    context.environment = ExecutionEnvironment::Container;
    let runtime = native_runtime(directory.path(), "/Users/test", BTreeMap::new());
    assert!(
        UvAdapter
            .detect(&context, &runtime)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
}

#[test]
fn embedded_catalog_has_six_complete_uv_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "uv" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert!(candidates.iter().all(|candidate| {
        candidate.upstream_id == UPSTREAM
            && matches!(
                candidate.delivery_mode,
                DeliveryMode::Mirror | DeliveryMode::Proxy
            )
            && candidate.compatibility.operating_systems
                == [
                    OperatingSystem::Linux,
                    OperatingSystem::Macos,
                    OperatingSystem::Windows,
                ]
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
