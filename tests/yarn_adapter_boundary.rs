#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{YarnAdapter, compiled_adapter_allowlist},
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

fn install_yarn(
    root: &Path,
    version: &str,
    selected: &str,
    query_exit: i32,
    effective_override: Option<&str>,
) {
    let classic = version.starts_with("1.");
    let global_classic = root.join("usr/local/share/.yarnrc");
    let user_classic = root.join("home/developer/.yarnrc");
    let project_classic = root.join("work/project/.yarnrc");
    let user_berry = root.join("home/developer/.yarnrc.yml");
    let project_berry = root.join("work/project/.yarnrc.yml");
    let project_directory = root.join("work/project");
    let files = if classic {
        format!(
            "for file in '{}' '{}' '{}'; do\n    if [ -f \"$file\" ]; then found=$(awk '$1 == \"registry\" {{gsub(/\"/, \"\", $2); print $2}}' \"$file\" | tail -1); [ -n \"$found\" ] && value=$found; fi\n  done",
            global_classic.display(),
            user_classic.display(),
            project_classic.display(),
        )
    } else {
        format!(
            "for file in '{}' '{}'; do\n    if [ -f \"$file\" ]; then found=$(sed -n 's/^npmRegistryServer:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$file\" | tail -1); [ -n \"$found\" ] && value=$found; fi\n  done",
            user_berry.display(),
            project_berry.display(),
        )
    };
    let effective_override = effective_override.unwrap_or("");
    executable(
        root,
        "/usr/bin/yarn",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nregistry() {{\n  value='https://registry.yarnpkg.com/'\n  {files}\n  [ -n '{effective_override}' ] && value='{effective_override}'\n  printf '%s\\n' \"$value\"\n}}\nif [ \"$1 $2 $3\" = 'config get registry' ] || [ \"$1 $2 $3\" = 'config get npmRegistryServer' ]; then registry; exit 0; fi\nif [ \"$1 $2\" = 'config list' ]; then\n  [ -f '{global_classic}' ] && printf '{{\"type\":\"verbose\",\"data\":\"Found configuration file \\\"/usr/local/share/.yarnrc\\\".\"}}\\n'\n  [ -f '{user_classic}' ] && printf '{{\"type\":\"verbose\",\"data\":\"Found configuration file \\\"/home/developer/.yarnrc\\\".\"}}\\n'\n  [ -f '{project_classic}' ] && printf '{{\"type\":\"verbose\",\"data\":\"Found configuration file \\\"/work/project/.yarnrc\\\".\"}}\\n'\n  exit 0\nfi\nif [ \"$1\" = info ] || [ \"$1 $2\" = 'npm info' ]; then\n  [ \"$PWD\" = '{project_directory}' ] || exit 66\n  value=$(registry)\n  [ \"${{value%/}}\" = '{selected}' ] || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  if [ \"$1\" = info ]; then\n    echo '{{\"type\":\"inspect\",\"data\":{{\"name\":\"is-number\",\"version\":\"7.0.0\",\"dist\":{{\"tarball\":\"{selected}/is-number/-/is-number-7.0.0.tgz\"}}}}}}'\n  else\n    echo '{{\"name\":\"is-number\",\"version\":\"7.0.0\",\"dist\":{{\"tarball\":\"{selected}/is-number/-/is-number-7.0.0.tgz\"}}}}'\n  fi\n  exit 0\nfi\nexit 64\n",
            selected = selected.trim_end_matches('/'),
            global_classic = global_classic.display(),
            user_classic = user_classic.display(),
            project_classic = project_classic.display(),
            project_directory = project_directory.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
}

fn selection() -> MirrorSelection {
    MirrorSelection {
        candidate_id: "yarn-test".into(),
        tool_id: "yarn".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "huaweicloud".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Index,
            protocol: Protocol::Https,
            url: HUAWEI.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn classic_user_plan_preserves_project_scopes_auth_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_yarn(root, "1.22.22", HUAWEI, 0, None);
    write(root, "/work/project/package.json", b"{}\n");
    write(
        root,
        "/usr/local/share/.yarnrc",
        b"registry \"https://registry.yarnpkg.com/\"\nnetwork-timeout 600000\n",
    );
    let original =
        b"# user comment\nregistry \"https://registry.yarnpkg.com/\"\nignore-engines true\n";
    let user = write(root, "/home/developer/.yarnrc", original);
    write(
        root,
        "/work/project/.yarnrc",
        b"--install.check-files true\n",
    );
    write(
        root,
        "/work/project/.npmrc",
        b"@corp:registry=https://reader:password@packages.example/npm/\n//packages.example/npm/:_authToken=classic-secret\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = YarnAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|item| item.contains("Classic"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("classic-secret"));
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

    let selected = [selection()];
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert!(cli.changes[0].target.ends_with("home/developer/.yarnrc"));
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("registry \"{HUAWEI}\"")));
    assert!(rendered.contains("# user comment"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Classic user config should change")
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
    adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert_eq!(fs::read(user).unwrap(), original);
}

#[test]
fn berry_project_plan_preserves_plugins_scopes_and_rolls_back_on_query_failure() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_yarn(root, "4.9.2", HUAWEI, 7, None);
    write(root, "/work/project/package.json", b"{}\n");
    write(
        root,
        "/home/developer/.yarnrc.yml",
        b"npmRegistryServer: \"https://registry.yarnpkg.com/\"\n",
    );
    let original = b"yarnPath: .yarn/releases/yarn-4.9.2.cjs\nplugins:\n  - path: .yarn/plugins/example.cjs\nnpmRegistryServer: \"https://registry.yarnpkg.com/\" # keep comment\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://packages.example/npm/\"\n    npmAuthToken: berry-secret\n";
    let project = write(root, "/work/project/.yarnrc.yml", original);
    let context = context(root, Architecture::Arm64);
    let adapter = YarnAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(detected.evidence.iter().any(|item| item.contains("Berry")));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("berry-secret")
    );
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    assert!(plan.changes[0].target.ends_with("work/project/.yarnrc.yml"));
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("npmRegistryServer: \"{HUAWEI}\" # keep comment")));
    assert!(rendered.contains("yarnPath: .yarn/releases/yarn-4.9.2.cjs"));
    assert!(rendered.contains("npmAuthToken: berry-secret"));
    assert!(!rendered.contains("registry \""));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Berry project config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(project).unwrap(), original);
}

#[test]
fn berry_user_scope_is_supported_but_project_override_and_missing_context_are_explicit() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_yarn(root, "3.8.7", HUAWEI, 0, None);
    write(root, "/work/project/package.json", b"{}\n");
    let original = b"enableGlobalCache: true\n";
    let user = write(root, "/home/developer/.yarnrc.yml", original);
    write(
        root,
        "/work/project/.yarnrc.yml",
        b"nodeLinker: node-modules\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = YarnAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selected = [selection()];
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
    assert!(
        plan.changes[0]
            .target
            .ends_with("home/developer/.yarnrc.yml")
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Berry home config should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert_eq!(fs::read(user).unwrap(), original);

    write(
        root,
        "/work/project/.yarnrc.yml",
        b"npmRegistryServer: \"https://registry.yarnpkg.com/\"\n",
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selected)
            .unwrap_err()
            .to_string()
            .contains("higher precedence")
    );

    let runtime_without_project =
        OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/home/developer");
    install_yarn(root, "3.8.7", HUAWEI, 0, None);
    let detected = adapter
        .detect(&context, &runtime_without_project)
        .unwrap()
        .unwrap();
    let current = adapter
        .read_current(
            &context,
            &runtime_without_project,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selected)
            .unwrap_err()
            .to_string()
            .contains("require a project context")
    );
}

#[test]
fn generation_formats_tls_and_auth_policies_never_cross() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    write(root, "/work/project/package.json", b"{}\n");
    let context = context(root, Architecture::X86_64);
    let adapter = YarnAdapter;

    install_yarn(root, "1.22.22", HUAWEI, 0, None);
    write(
        root,
        "/home/developer/.yarnrc",
        b"registry \"https://registry.yarnpkg.com/\"\nstrict-ssl false\n",
    );
    write(
        root,
        "/work/project/.yarnrc.yml",
        b"npmRegistryServer: \"https://private.example/npm/\"\n",
    );
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection()])
            .unwrap_err()
            .to_string()
            .contains("TLS")
    );

    install_yarn(root, "4.9.2", HUAWEI, 0, None);
    write(
        root,
        "/home/developer/.yarnrc.yml",
        b"npmRegistryServer: \"https://registry.yarnpkg.com/\"\nnpmAuthToken: do-not-log\n",
    );
    write(root, "/work/project/.yarnrc.yml", b"nodeLinker: pnp\n");
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("do-not-log")
    );
    assert!(
        adapter
            .plan(&context, &current, &[selection()])
            .unwrap_err()
            .to_string()
            .contains("unscoped authentication")
    );
}

#[test]
fn embedded_catalog_has_one_complete_yarn_registry_candidate() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "yarn" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 1);
    let candidate = candidates[0];
    assert_eq!(candidate.provider_id, "huaweicloud");
    assert_eq!(candidate.upstream_id, UPSTREAM);
    assert_eq!(candidate.delivery_mode, DeliveryMode::Proxy);
    assert_eq!(
        candidate.compatibility.operating_systems,
        [OperatingSystem::Linux]
    );
    assert_eq!(
        candidate.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );
    assert_eq!(candidate.probes.len(), 2);
    assert_eq!(candidate.probes[0].method, HttpMethod::Get);
    assert_eq!(candidate.probes[0].path, "/is-number/latest");
    assert_eq!(candidate.probes[1].path, "/is-number/-/is-number-7.0.0.tgz");
    let inert = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "yarn"
                && matches!(candidate.provider_id.as_str(), "aliyun" | "nju")
        })
        .collect::<Vec<_>>();
    assert_eq!(inert.len(), 2);
    assert!(inert.iter().all(|candidate| candidate.probes.is_empty()));
}
