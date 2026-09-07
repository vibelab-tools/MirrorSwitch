#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PnpmAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "npm--language-registry";
const HUAWEI: &str = "https://repo.huaweicloud.com/repository/npm/";

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

fn install_pnpm(
    root: &Path,
    version: &str,
    selected: &str,
    fallback: &str,
    query_exit: i32,
    effective_override: Option<&str>,
) {
    let selected = root.join(selected.trim_start_matches('/'));
    let fallback = root.join(fallback.trim_start_matches('/'));
    let project = root.join("work/project/.npmrc");
    let workspace = root.join("work/project/pnpm-workspace.yaml");
    let project_directory = fs::canonicalize(root).unwrap().join("work/project");
    let effective_override = effective_override.unwrap_or("");
    fs::create_dir_all(&project_directory).unwrap();
    executable(
        root,
        "/usr/bin/pnpm",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nregistry() {{\n  value='https://registry.npmjs.org/'\n  for file in '{fallback}' '{selected}' '{project}'; do\n    if [ -f \"$file\" ]; then\n      found=$(sed -n 's/^[[:space:]]*registry[[:space:]]*=[[:space:]]*//p' \"$file\" | tail -1 | sed -e 's/^\"//' -e 's/\"$//' -e \"s/^'//\" -e \"s/'$//\")\n      [ -n \"$found\" ] && value=$found\n    fi\n  done\n  if [ -f '{workspace}' ]; then\n    found=$(sed -n 's/^registry:[[:space:]]*//p' '{workspace}' | tail -1 | sed -e 's/^\"//' -e 's/\"$//')\n    [ -n \"$found\" ] && value=$found\n  fi\n  [ -n '{effective_override}' ] && value='{effective_override}'\n  printf '%s\\n' \"$value\"\n}}\nif [ \"$1 $2 $3\" = 'config get registry' ]; then registry; exit 0; fi\nif [ \"$1\" = view ]; then\n  [ \"$PWD\" = '{project_directory}' ] || exit 66\n  value=$(registry)\n  [ \"${{value%/}}\" = '{mirror}' ] || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  echo '{{\"name\":\"is-number\",\"version\":\"7.0.0\",\"dist\":{{\"tarball\":\"{mirror}/is-number/-/is-number-7.0.0.tgz\"}}}}'\n  exit 0\nfi\nexit 64\n",
            mirror = HUAWEI.trim_end_matches('/'),
            fallback = fallback.display(),
            selected = selected.display(),
            project = project.display(),
            workspace = workspace.display(),
            project_directory = project_directory.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn native_runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/Users/test")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "pnpm-test".into(),
        tool_id: "pnpm".into(),
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
fn pnpm_10_user_plan_preserves_scopes_auth_store_and_project_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pnpm(
        root,
        "10.34.5",
        "/home/developer/.npmrc",
        "/home/developer/.npmrc",
        0,
        None,
    );
    let original = b"registry=\"https://registry.npmjs.org/\"\n@corp:registry=https://reader:password@packages.example/npm/\n//packages.example/npm/:_authToken=user-secret\nstore-dir=/var/tmp/pnpm-store\n";
    let user = write(root, "/home/developer/.npmrc", original);
    write(
        root,
        "/work/project/.npmrc",
        b"@team:registry=https://packages.example/team/\nstrict-peer-dependencies=false\n",
    );
    write(
        root,
        "/work/project/pnpm-workspace.yaml",
        b"packages:\n  - packages/*\nregistries:\n  '@lab': https://packages.example/lab/\nstoreDir: /var/tmp/project-store\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = PnpmAdapter;
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("npm-compatible"))
    );
    assert_eq!(adapter.supported_scopes(), [ConfigurationScope::User]);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("user-secret"));
    assert!(!serialized.contains("reader"));
    assert!(!serialized.contains("password"));
    assert!(current.sources.iter().any(|source| {
        source.metadata["kind"] == ["store-setting"] && source.metadata["origin_scope"] == ["user"]
    }));
    assert!(current.sources.iter().any(|source| {
        source.metadata["kind"] == ["scoped-registry"]
            && source.metadata["origin_scope"] == ["project"]
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Proxy]);

    let selected = [selection(HUAWEI)];
    let cli_plan = adapter.plan(&context, &current, &selected).unwrap();
    let config_plan = adapter.plan(&context, &current, &selected).unwrap();
    let tui_plan = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert!(!cli_plan.requires_elevation);
    assert!(
        cli_plan.changes[0]
            .target
            .ends_with("home/developer/.npmrc")
    );
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("registry=\"{HUAWEI}\"")));
    assert!(rendered.contains("@corp:registry=https://reader:password@packages.example/npm/"));
    assert!(rendered.contains("//packages.example/npm/:_authToken=user-secret"));
    assert!(rendered.contains("store-dir=/var/tmp/pnpm-store"));
    assert!(!format!("{cli_plan:?}").contains("user-secret"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("pnpm 10 user config should change")
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
    assert_eq!(fs::read(user).unwrap(), original);
}

#[test]
fn pnpm_11_arm64_changes_only_auth_ini_and_is_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pnpm(
        root,
        "11.24.0",
        "/home/developer/.config/pnpm/auth.ini",
        "/home/developer/.npmrc",
        0,
        None,
    );
    let original = b"registry=https://registry.npmjs.org/\n@corp:registry=https://packages.example/npm/\n//packages.example/npm/:_authToken=pnpm-secret\n";
    let auth = write(root, "/home/developer/.config/pnpm/auth.ini", original);
    let fallback = write(
        root,
        "/home/developer/.npmrc",
        b"@legacy:registry=https://packages.example/legacy/\n",
    );
    let settings = write(
        root,
        "/home/developer/.config/pnpm/config.yaml",
        b"storeDir: /var/tmp/pnpm-store\nverifyStoreIntegrity: true\n",
    );
    write(
        root,
        "/work/project/pnpm-workspace.yaml",
        b"packages:\n  - packages/*\nregistries:\n  '@team': https://packages.example/team/\n",
    );
    let context = context(root, Architecture::Arm64);
    let adapter = PnpmAdapter;
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("auth.ini"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("pnpm_config_"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(
        plan.changes[0]
            .target
            .ends_with("home/developer/.config/pnpm/auth.ini")
    );
    let fallback_before = fs::read(&fallback).unwrap();
    let settings_before = fs::read(&settings).unwrap();

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("pnpm 11 auth.ini should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&fallback).unwrap(), fallback_before);
    assert_eq!(fs::read(&settings).unwrap(), settings_before);
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &[selection(HUAWEI)])
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
    assert_eq!(fs::read(auth).unwrap(), original);
}

#[test]
fn failed_real_metadata_query_restores_pnpm_11_auth_ini() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pnpm(
        root,
        "11.24.0",
        "/home/developer/.config/pnpm/auth.ini",
        "/home/developer/.npmrc",
        7,
        None,
    );
    let original = b"registry=https://registry.npmjs.org/\n";
    let auth = write(root, "/home/developer/.config/pnpm/auth.ini", original);
    let context = context(root, Architecture::Arm64);
    let adapter = PnpmAdapter;
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("pnpm 11 auth.ini should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(auth).unwrap(), original);
}

#[test]
fn unsupported_versions_environment_project_private_tls_and_auth_are_blocked() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    executable(root, "/usr/bin/npm", "#!/bin/sh\nexit 0\n".into());
    let context = context(root, Architecture::X86_64);
    let adapter = PnpmAdapter;
    let no_pnpm = runtime(root, BTreeMap::new());
    assert!(adapter.detect(&context, &no_pnpm).unwrap().is_none());

    for version in ["9.15.9", "10.34.1", "11.21.0", "12.0.0"] {
        install_pnpm(
            root,
            version,
            "/home/developer/.npmrc",
            "/home/developer/.npmrc",
            0,
            None,
        );
        assert!(
            adapter
                .detect(&context, &runtime(root, BTreeMap::new()))
                .is_err()
        );
    }

    install_pnpm(
        root,
        "10.34.5",
        "/home/developer/.npmrc",
        "/home/developer/.npmrc",
        0,
        Some("https://private.example/npm/"),
    );
    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://registry.npmjs.org/\n",
    );
    let environment_runtime = runtime(
        root,
        BTreeMap::from([(
            "npm_config_registry".into(),
            "https://private.example/npm/".into(),
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
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("environment")
    );

    install_pnpm(
        root,
        "11.24.0",
        "/home/developer/.config/pnpm/auth.ini",
        "/home/developer/.npmrc",
        0,
        None,
    );
    write(root, "/home/developer/.config/pnpm/auth.ini", b"");
    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://private.example/npm/\n",
    );
    let runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("fallback user")
    );

    write(root, "/home/developer/.npmrc", b"");
    write(
        root,
        "/work/project/.npmrc",
        b"registry=https://registry.npmjs.org/\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("project default")
    );

    write(root, "/work/project/.npmrc", b"");
    write(
        root,
        "/work/project/pnpm-workspace.yaml",
        b"registry: https://registry.npmjs.org/\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("project default")
    );

    write(
        root,
        "/work/project/pnpm-workspace.yaml",
        b"packages:\n  - packages/*\n",
    );
    for (config, message) in [
        ("strict-ssl=false\n", "strict-ssl"),
        ("_authToken=do-not-log\n", "unscoped authentication"),
        (
            "//repo.huaweicloud.com/repository/npm/:_authToken=mirror-secret\n",
            "public pnpm mirror",
        ),
    ] {
        write(
            root,
            "/home/developer/.config/pnpm/auth.ini",
            config.as_bytes(),
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let serialized = serde_json::to_string(&current).unwrap();
        assert!(!serialized.contains("do-not-log"));
        assert!(!serialized.contains("mirror-secret"));
        assert!(
            adapter
                .plan(&context, &current, &[selection(HUAWEI)])
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
}

#[test]
fn pnpm_11_uses_native_macos_and_windows_config_directories() {
    for (os, architecture, selected, config, environment, bom, newline) in [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "/Users/test/Library/Preferences/pnpm/auth.ini",
            "/Users/test/Library/Preferences/pnpm/config.yaml",
            BTreeMap::new(),
            false,
            "\n",
        ),
        (
            OperatingSystem::Windows,
            Architecture::Arm64,
            "/Users/test/AppData/Local/pnpm/config/auth.ini",
            "/Users/test/AppData/Local/pnpm/config/config.yaml",
            BTreeMap::from([("LOCALAPPDATA".into(), "/Users/test/AppData/Local".into())]),
            true,
            "\r\n",
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_pnpm(root, "11.24.0", selected, "/Users/test/.npmrc", 0, None);
        let text = format!(
            "# native pnpm auth{newline}registry=https://registry.npmjs.org/{newline}@corp:registry=https://reader:secret@packages.invalid.example/npm/{newline}unknown-option=keep{newline}"
        );
        let mut original = text.into_bytes();
        if bom {
            original.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let auth = write(root, selected, &original);
        let fallback_contents = b"@legacy:registry=https://packages.invalid.example/legacy/\n";
        let fallback = write(root, "/Users/test/.npmrc", fallback_contents);
        let config_contents = b"storeDir: /native/pnpm-store\nverifyStoreIntegrity: true\n";
        let config_file = write(root, config, config_contents);
        write(
            root,
            "/work/project/pnpm-workspace.yaml",
            b"packages:\n  - packages/*\n",
        );
        let context = native_context(root, os, architecture);
        let adapter = PnpmAdapter;
        let mut runtime = native_runtime(root, environment);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(!serde_json::to_string(&current).unwrap().contains("secret"));
        let chosen = [selection(HUAWEI)];
        let plan = adapter.plan(&context, &current, &chosen).unwrap();
        assert_eq!(plan, adapter.plan(&context, &current, &chosen).unwrap());
        assert_eq!(plan.changes[0].target, auth);
        assert_eq!(
            plan.changes[0]
                .new_contents
                .starts_with(&[0xef, 0xbb, 0xbf]),
            bom
        );
        let rendered = std::str::from_utf8(
            plan.changes[0]
                .new_contents
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&plan.changes[0].new_contents),
        )
        .unwrap();
        assert!(rendered.contains("unknown-option=keep"));
        assert!(!rendered.replace(newline, "").contains('\n'));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
        else {
            panic!("native pnpm auth should change")
        };
        if !bom {
            assert!(
                adapter
                    .verify(&context, &mut runtime, &receipt)
                    .unwrap()
                    .valid
            );
        }
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
        assert_eq!(fs::read(auth).unwrap(), original);
        assert_eq!(fs::read(fallback).unwrap(), fallback_contents);
        assert_eq!(fs::read(config_file).unwrap(), config_contents);
    }
}

#[test]
fn embedded_catalog_requires_metadata_and_tarball_for_pnpm() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "pnpm" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 1);
    assert!(candidates.iter().all(|candidate| {
        candidate.upstream_id == UPSTREAM
            && candidate.delivery_mode == DeliveryMode::Proxy
            && candidate.compatibility.operating_systems
                == [
                    OperatingSystem::Linux,
                    OperatingSystem::Macos,
                    OperatingSystem::Windows,
                ]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints[0].role == EndpointRole::Index
            && candidate.endpoints[0].protocol == Protocol::Https
            && candidate.probes.len() == 2
            && candidate.probes[0].method == HttpMethod::Get
            && candidate.probes[0].path == "/is-number/latest"
            && candidate.probes[1].method == HttpMethod::Get
            && candidate.probes[1].path == "/is-number/-/is-number-7.0.0.tgz"
    }));
}
