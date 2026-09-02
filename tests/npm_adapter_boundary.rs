#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{NpmAdapter, compiled_adapter_allowlist},
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

fn install_clients(
    root: &Path,
    selected: &str,
    query_exit: i32,
    environment: &str,
    environment_registry: Option<&str>,
) {
    executable(
        root,
        "/usr/bin/node",
        "#!/bin/sh\n[ \"$1\" = --version ] && { echo v22.17.0; exit 0; }\nexit 64\n".into(),
    );
    let global = root.join("opt/node/etc/npmrc");
    let user = root.join("home/developer/.npmrc");
    let project = root.join("work/project/.npmrc");
    let project_directory = root.join("work/project");
    let environment_registry = environment_registry.unwrap_or("");
    executable(
        root,
        "/usr/bin/npm",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 11.4.2; exit 0; fi\nif [ \"$1 $2 $3\" = 'config get globalconfig' ]; then echo /opt/node/etc/npmrc; exit 0; fi\nif [ \"$1 $2 $3\" = 'config get userconfig' ]; then echo /home/developer/.npmrc; exit 0; fi\nif [ \"$1\" = prefix ]; then echo /work/project; exit 0; fi\nregistry() {{\n  value='https://registry.npmjs.org/'\n  for file in '{global}' '{user}' '{project}'; do\n    if [ -f \"$file\" ]; then\n      found=$(sed -n 's/^[[:space:]]*registry[[:space:]]*=[[:space:]]*//p' \"$file\" | tail -1 | sed -e 's/^\"//' -e 's/\"$//')\n      [ -n \"$found\" ] && value=$found\n    fi\n  done\n  [ -n '{environment_registry}' ] && value='{environment_registry}'\n  printf '%s\\n' \"$value\"\n}}\nif [ \"$1 $2 $3\" = 'config get registry' ]; then registry; exit 0; fi\nif [ \"$1 $2\" = 'config list' ]; then\n  printf '; \"builtin\" config from /usr/lib/node_modules/npm/npmrc\\n; \"env\" config from environment\\n{environment}'\n  exit 0\nfi\nif [ \"$1\" = view ]; then\n  [ \"$PWD\" = '{project_directory}' ] || exit 66\n  value=$(registry)\n  [ \"${{value%/}}\" = '{selected}' ] || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  echo '{{\"name\":\"is-number\",\"version\":\"7.0.0\",\"dist.tarball\":\"{selected}/is-number/-/is-number-7.0.0.tgz\"}}'\n  exit 0\nfi\nexit 64\n",
            selected = selected.trim_end_matches('/'),
            global = global.display(),
            user = user.display(),
            project = project.display(),
            project_directory = project_directory.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
}

fn native_runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/Users/test")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn install_native_clients(root: &Path, selected: &str, global_path: &str, user_path: &str) {
    executable(
        root,
        "/usr/bin/node",
        "#!/bin/sh\n[ \"$1\" = --version ] && { echo v22.17.0; exit 0; }\nexit 64\n".into(),
    );
    let global = root.join(global_path.trim_start_matches('/'));
    let user = root.join(user_path.trim_start_matches('/'));
    let project = root.join("work/project/.npmrc");
    let project_directory = root.join("work/project");
    executable(
        root,
        "/usr/bin/npm",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 11.4.2; exit 0; fi\nif [ \"$1 $2 $3\" = 'config get globalconfig' ]; then echo '{global_path}'; exit 0; fi\nif [ \"$1 $2 $3\" = 'config get userconfig' ]; then echo '{user_path}'; exit 0; fi\nif [ \"$1\" = prefix ]; then echo /work/project; exit 0; fi\nregistry() {{\n  value='https://registry.npmjs.org/'\n  for file in '{global}' '{user}' '{project}'; do\n    if [ -f \"$file\" ]; then found=$(tr -d '\\357\\273\\277' < \"$file\" | sed -n 's/^[[:space:]]*registry[[:space:]]*=[[:space:]]*//p' | tail -1 | sed -e 's/^\"//' -e 's/\"$//'); [ -n \"$found\" ] && value=$found; fi\n  done\n  printf '%s\\n' \"$value\"\n}}\nif [ \"$1 $2 $3\" = 'config get registry' ]; then registry; exit 0; fi\nif [ \"$1 $2\" = 'config list' ]; then printf '; \"env\" config from environment\\n'; exit 0; fi\nif [ \"$1\" = view ]; then [ \"$PWD\" = '{project_directory}' ] || exit 66; value=$(registry); [ \"${{value%/}}\" = '{selected}' ] || exit 65; echo '{{\"name\":\"is-number\",\"version\":\"7.0.0\",\"dist.tarball\":\"{selected}/is-number/-/is-number-7.0.0.tgz\"}}'; exit 0; fi\nexit 64\n",
            selected = selected.trim_end_matches('/'),
            global = global.display(),
            user = user.display(),
            project = project.display(),
            project_directory = project_directory.display(),
        ),
    );
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "npm-test".into(),
        tool_id: "npm".into(),
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
fn user_plan_preserves_scopes_auth_and_project_is_consistent_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, HUAWEI, 0, "", None);
    write(
        root,
        "/opt/node/etc/npmrc",
        b"registry=https://registry.npmjs.org/\nfetch-retries=3\n",
    );
    let original = b"registry=\"https://registry.npmjs.org/\"\n@corp:registry=https://reader:password@packages.example/npm/\n//packages.example/npm/:_authToken=project-secret\ncache=/var/tmp/npm-cache\n";
    let user = write(root, "/home/developer/.npmrc", original);
    write(
        root,
        "/work/project/.npmrc",
        b"@team:registry=https://packages.example/team/\nlegacy-peer-deps=true\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = NpmAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .version
            .as_deref()
            .unwrap()
            .contains("node v22.17.0")
    );
    assert_eq!(adapter.default_scope(), ConfigurationScope::User);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("project-secret"));
    assert!(!serialized.contains("reader"));
    assert!(!serialized.contains("password"));
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
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("registry=\"{HUAWEI}\"")));
    assert!(rendered.contains("@corp:registry=https://reader:password@packages.example/npm/"));
    assert!(rendered.contains("//packages.example/npm/:_authToken=project-secret"));
    assert!(!format!("{cli_plan:?}").contains("project-secret"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("npm user config should change")
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
fn global_user_and_explicit_project_scopes_have_distinct_plans() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, HUAWEI, 0, "", None);
    write(
        root,
        "/opt/node/etc/npmrc",
        b"registry=https://registry.npmjs.org/\n",
    );
    write(root, "/home/developer/.npmrc", b"fund=false\n");
    write(root, "/work/project/.npmrc", b"audit=false\n");
    let context = context(root, Architecture::X86_64);
    let adapter = NpmAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter.supported_scopes(),
        [
            ConfigurationScope::System,
            ConfigurationScope::User,
            ConfigurationScope::Project
        ]
    );

    let global = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let global_plan = adapter
        .plan(&context, &global, &[selection(HUAWEI)])
        .unwrap();
    assert!(global_plan.requires_elevation);
    assert!(
        global_plan.changes[0]
            .target
            .ends_with("opt/node/etc/npmrc")
    );

    let user = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let user_plan = adapter.plan(&context, &user, &[selection(HUAWEI)]).unwrap();
    assert!(!user_plan.requires_elevation);
    assert!(
        user_plan.changes[0]
            .target
            .ends_with("home/developer/.npmrc")
    );

    let project = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let project_plan = adapter
        .plan(&context, &project, &[selection(HUAWEI)])
        .unwrap();
    assert!(!project_plan.requires_elevation);
    assert!(
        project_plan.changes[0]
            .target
            .ends_with("work/project/.npmrc")
    );
    assert!(project_plan.changes[0].summary.contains("explicit project"));
}

#[test]
fn arm64_project_metadata_failure_restores_the_project_file() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, HUAWEI, 7, "", None);
    write(root, "/opt/node/etc/npmrc", b"fund=false\n");
    write(root, "/home/developer/.npmrc", b"audit=false\n");
    let original = b"registry=https://registry.npmjs.org/\nlegacy-peer-deps=true\n";
    let project = write(root, "/work/project/.npmrc", original);
    let context = context(root, Architecture::Arm64);
    let adapter = NpmAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("npm project config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(project).unwrap(), original);
}

#[test]
fn environment_precedence_tls_bypass_and_unsafe_auth_are_rejected_without_disclosure() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(
        root,
        HUAWEI,
        0,
        "registry = \"https://account:secret@private.example/npm/\"\\n",
        Some("https://account:secret@private.example/npm/"),
    );
    write(root, "/opt/node/etc/npmrc", b"fund=false\n");
    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://registry.npmjs.org/\n",
    );
    write(root, "/work/project/.npmrc", b"audit=false\n");
    let context = context(root, Architecture::X86_64);
    let adapter = NpmAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("account"));
    assert!(!serialized.contains("secret"));
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("environment registry override")
    );

    install_clients(root, HUAWEI, 0, "", None);
    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://registry.npmjs.org/\nstrict-ssl=false\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("strict-ssl")
    );

    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://registry.npmjs.org/\n_authToken=do-not-log-this\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("do-not-log-this")
    );
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("unscoped authentication")
    );

    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://registry.npmjs.org/\n//repo.huaweicloud.com/repository/npm/:_authToken=mirror-secret\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("public npm mirror")
    );

    write(
        root,
        "/home/developer/.npmrc",
        b"registry=https://registry.npmjs.org/\n",
    );
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
            .contains("higher precedence")
    );
}

#[test]
fn macos_and_windows_use_npm_reported_native_paths_and_preserve_layout() {
    for (os, architecture, global_path, user_path, environment, bom, newline) in [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "/usr/local/lib/node_modules/npm/npmrc",
            "/Users/test/.npmrc",
            BTreeMap::new(),
            false,
            "\n",
        ),
        (
            OperatingSystem::Windows,
            Architecture::Arm64,
            "/ProgramFiles/nodejs/node_modules/npm/npmrc",
            "/Users/test/.npmrc",
            BTreeMap::from([("APPDATA".into(), "/Users/test/AppData/Roaming".into())]),
            true,
            "\r\n",
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_native_clients(root, HUAWEI, global_path, user_path);
        let global_contents = b"registry=https://registry.npmjs.org/\nfund=false\n";
        let global = write(root, global_path, global_contents);
        write(
            root,
            "/work/project/.npmrc",
            b"@team:registry=https://packages.invalid.example/npm/\n",
        );
        let text = format!(
            "# native npm config{newline}registry=\"https://registry.npmjs.org/\"{newline}@corp:registry=https://reader:secret@packages.invalid.example/npm/{newline}unknown-option=keep{newline}"
        );
        let mut original = text.into_bytes();
        if bom {
            original.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let user = write(root, user_path, &original);
        let context = native_context(root, os, architecture);
        let adapter = NpmAdapter;
        let mut runtime = native_runtime(root, environment);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(!serde_json::to_string(&current).unwrap().contains("secret"));
        let selected = [selection(HUAWEI)];
        let plan = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
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
            panic!("native npm config should change")
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
        assert_eq!(fs::read(global).unwrap(), global_contents);
    }
}

#[test]
fn embedded_catalog_requires_metadata_and_tarball_for_the_https_complete_candidate() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "npm" && !candidate.probes.is_empty())
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
            && candidate.probes[0].expected_content_type.as_deref() == Some("application/json")
            && candidate.probes[1].path == "/is-number/-/is-number-7.0.0.tgz"
            && candidate.probes[1].expected_content_type.as_deref()
                == Some("application/octet-stream")
    }));
    let inert = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "npm" && matches!(candidate.provider_id.as_str(), "aliyun" | "nju")
        })
        .collect::<Vec<_>>();
    assert_eq!(inert.len(), 2);
    assert!(inert.iter().all(|candidate| candidate.probes.is_empty()));
    assert!(
        inert
            .iter()
            .all(|candidate| candidate.delivery_mode == DeliveryMode::Unknown)
    );
}
