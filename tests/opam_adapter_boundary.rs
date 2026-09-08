#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{OpamAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const REPOSITORY_UPSTREAM: &str = "opam-repository--git-mirror";
const CACHE_UPSTREAM: &str = "opam-cache--binary-cache";
const NJU: &str = "https://mirrors.nju.edu.cn/git/opam-repository.git";
const NJU_CONFIG: &str = "git+https://mirrors.nju.edu.cn/git/opam-repository.git";
const SJTUG: &str = "https://mirror.sjtu.edu.cn/opam-cache";
const REVISION: &str = "5caa3166da37f7aafe35d10c51ed9e1e932f2ab6";
const CACHE_SHA: &str = "61f0b75950614ac5378c6ec0d822cce6463402d919d5810b736fc46522b3a73e";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: "debian".into(),
            version_id: Some("13".into()),
            version_codename: Some("trixie".into()),
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

fn install_opam(root: &Path, version: &str, query_exit: i32) {
    executable(
        root,
        "/usr/bin/opam",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nif [ \"$1 $2 $3\" = 'var root --safe' ]; then echo '/home/developer/.opam'; exit 0; fi\nif [ \"$1 $2 $3\" = 'switch show --safe' ]; then echo 'default-switch'; exit 0; fi\nif [ \"$1 $2 $3\" = 'var ocaml-version --safe' ]; then echo '5.4.0'; exit 0; fi\nif [ \"$1 $2 $3 $4\" = 'repository list --all --short' ]; then printf '%s\\n' default private; exit 0; fi\nif [ \"$1 $2\" = 'update default' ]; then\n  grep -F '{nju_config}' '{root}/home/developer/.opam/repo/repos-config' >/dev/null || exit 71\n  grep -F '{sjtug}' '{root}/home/developer/.opam/config' >/dev/null || exit 72\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  echo '[default] synchronised from mirror'\n  exit 0\nfi\nif [ \"$1 $2\" = 'source stdio.v0.16.0' ]; then [ {query_exit} -eq 0 ] || exit {query_exit}; echo 'stdio source extracted'; exit 0; fi\nexit 70\n",
            root = root.display(),
            nju_config = NJU_CONFIG,
            sjtug = SJTUG,
        ),
    );
    executable(root, "/usr/bin/git", "#!/bin/sh\nexit 0\n".into());
    executable(
        root,
        "/usr/bin/curl",
        format!(
            "#!/bin/sh\noutput=\nurl=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --output) output=$2; shift 2 ;;\n    http*) url=$1; shift ;;\n    *) shift ;;\n  esac\ndone\n[ -n \"$output\" ] && [ \"$url\" = '{sjtug}/sha256/61/{cache_sha}' ] || exit 73\nmkdir -p '{root}'\"$(dirname \"$output\")\"\nprintf '%s\\n' cache-object > '{root}'\"$output\"\n",
            root = root.display(),
            sjtug = SJTUG,
            cache_sha = CACHE_SHA,
        ),
    );
    executable(
        root,
        "/usr/bin/sha256sum",
        format!("#!/bin/sh\nprintf '%s  %s\\n' '{CACHE_SHA}' \"$1\"\n"),
    );
    for command in ["shasum", "certutil.exe"] {
        executable(
            root,
            &format!("/usr/bin/{command}"),
            format!("#!/bin/sh\nprintf '%s  fixture\\n' '{CACHE_SHA}'\n"),
        );
    }
}

fn config(archive_field: &str, custom_download: bool) -> String {
    format!(
        "opam-version: \"2.0\"\nopam-root-version: \"2.2\"\n{archive_field}repositories: \"default\"\ndownload-jobs: 3\n{}solver: \"builtin-0install\"\n",
        if custom_download {
            "download-command: [\"private-fetch\" \"%{url}%\"]\n"
        } else {
            ""
        }
    )
}

fn repositories(default: &str) -> String {
    format!(
        "opam-version: \"2.0\"\nrepositories: [\n  \"private\" {{\"https://packages.example/opam\"}} {{\"PRIVATE-FINGERPRINT\"}} {{1}}\n  \"default\" {{\"{default}\"}} {{\"OFFICIAL-FINGERPRINT\"}} {{1}}\n]\n"
    )
}

fn test_runtime(
    root: &Path,
    environment: BTreeMap<String, String>,
    project: Option<&str>,
) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selections() -> Vec<MirrorSelection> {
    vec![
        selection(REPOSITORY_UPSTREAM, "nju", NJU),
        selection(CACHE_UPSTREAM, "sjtug", SJTUG),
    ]
}

fn selection(upstream: &str, provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("opam-{provider}-test"),
        tool_id: "opam".into(),
        upstream_id: upstream.into(),
        provider_id: provider.into(),
        endpoints: [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: endpoint.into(),
        })
        .collect(),
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_plan_preserves_repository_order_anchors_project_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opam(root, "2.5.2", 0);
    let original_config = config("", false);
    let config_path = write(
        root,
        "/home/developer/.opam/config",
        original_config.as_bytes(),
    );
    let original_repos = repositories("https://opam.ocaml.org");
    let repos_path = write(
        root,
        "/home/developer/.opam/repo/repos-config",
        original_repos.as_bytes(),
    );
    let switch = b"opam-version: \"2.0\"\nsynopsis: \"local switch\"\n";
    let switch_path = write(root, "/work/project/.opam-switch/switch-config", switch);
    let lock = b"opam-version: \"2.0\"\n";
    let lock_path = write(root, "/work/project/opam.locked", lock);
    let adapter = OpamAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = test_runtime(root, BTreeMap::new(), Some("/work/project"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.5.2"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.required_upstreams,
        [REPOSITORY_UPSTREAM, CACHE_UPSTREAM]
    );
    assert_eq!(request.repository_versions[REPOSITORY_UPSTREAM], REVISION);
    let selected = selections();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config_plan = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config_plan);
    assert_eq!(config_plan, tui);
    assert_eq!(cli.changes.len(), 3);
    let repos = cli
        .changes
        .iter()
        .find(|change| change.target.ends_with("repo/repos-config"))
        .unwrap();
    let repos_text = String::from_utf8(repos.new_contents.clone()).unwrap();
    assert!(repos_text.contains(NJU_CONFIG));
    assert!(repos_text.contains("PRIVATE-FINGERPRINT"));
    assert!(repos_text.contains("OFFICIAL-FINGERPRINT"));
    assert!(repos_text.find("\"private\"").unwrap() < repos_text.find("\"default\"").unwrap());
    let global = cli
        .changes
        .iter()
        .find(|change| change.target.ends_with(".opam/config"))
        .unwrap();
    assert!(
        String::from_utf8(global.new_contents.clone())
            .unwrap()
            .contains(SJTUG)
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("opam configurations should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selected)
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
    assert_eq!(fs::read_to_string(config_path).unwrap(), original_config);
    assert_eq!(fs::read_to_string(repos_path).unwrap(), original_repos);
    assert_eq!(fs::read(switch_path).unwrap(), switch);
    assert_eq!(fs::read(lock_path).unwrap(), lock);
}

#[test]
fn macos_and_windows_use_reported_native_root_and_preserve_text_layout() {
    for (os, architecture, bom, newline) in [
        (OperatingSystem::Macos, Architecture::X86_64, false, "\n"),
        (OperatingSystem::Macos, Architecture::Arm64, true, "\n"),
        (OperatingSystem::Windows, Architecture::X86_64, true, "\r\n"),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_opam(root, "2.5.2", 0);
        let mut config_contents = config("", false).replace('\n', newline).into_bytes();
        let mut repository_contents = repositories("https://opam.ocaml.org")
            .replace('\n', newline)
            .into_bytes();
        if bom {
            config_contents.splice(..0, [0xef, 0xbb, 0xbf]);
            repository_contents.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let config_path = write(root, "/home/developer/.opam/config", &config_contents);
        let repos_path = write(
            root,
            "/home/developer/.opam/repo/repos-config",
            &repository_contents,
        );
        let project_contents = b"opam-version: \"2.0\"\n";
        let project = write(root, "/work/project/opam.locked", project_contents);
        let adapter = OpamAdapter;
        let context = native_context(root, os, architecture);
        let mut runtime = test_runtime(root, BTreeMap::new(), Some("/work/project"));
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(
            detected
                .evidence
                .iter()
                .any(|line| line.contains(&format!("{os:?}")))
        );
        assert!(
            detected
                .evidence
                .iter()
                .any(|line| line.contains("/home/developer/.opam"))
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let selected = selections();
        let cli = adapter.plan(&context, &current, &selected).unwrap();
        let config_plan = adapter.plan(&context, &current, &selected).unwrap();
        let tui = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(cli, config_plan);
        assert_eq!(config_plan, tui);
        for change in cli.changes.iter().take(2) {
            assert_eq!(change.new_contents.starts_with(&[0xef, 0xbb, 0xbf]), bom);
            if os == OperatingSystem::Windows {
                assert!(
                    change
                        .new_contents
                        .iter()
                        .enumerate()
                        .all(|(position, byte)| {
                            *byte != b'\n'
                                || position > 0 && change.new_contents[position - 1] == b'\r'
                        })
                );
            }
        }
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("opam configuration should change")
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
        assert_eq!(fs::read(config_path).unwrap(), config_contents);
        assert_eq!(fs::read(repos_path).unwrap(), repository_contents);
        assert_eq!(fs::read(project).unwrap(), project_contents);
    }
}

#[test]
fn arm64_preserves_private_archive_mirrors_and_replaces_only_official_cache() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opam(root, "2.3.0", 0);
    let archive =
        "archive-mirrors: [\"https://cache.example/private\" \"https://opam.ocaml.org/cache\"]\n";
    write(
        root,
        "/home/developer/.opam/config",
        config(archive, false).as_bytes(),
    );
    write(
        root,
        "/home/developer/.opam/repo/repos-config",
        repositories("git+https://github.com/ocaml/opam-repository.git").as_bytes(),
    );
    let adapter = OpamAdapter;
    let context = context(root, Architecture::Arm64);
    let runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let changed = plan
        .changes
        .iter()
        .find(|change| change.target.ends_with(".opam/config"))
        .unwrap();
    let text = String::from_utf8(changed.new_contents.clone()).unwrap();
    assert!(text.contains("https://cache.example/private"));
    assert!(text.contains(SJTUG));
    assert!(!text.contains("https://opam.ocaml.org/cache"));
}

#[test]
fn private_default_custom_fetch_old_version_and_mismatched_selections_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = OpamAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &test_runtime(root, BTreeMap::new(), None))
            .unwrap()
            .is_none()
    );
    install_opam(root, "2.0.10", 0);
    write(
        root,
        "/home/developer/.opam/config",
        config("", false).as_bytes(),
    );
    write(
        root,
        "/home/developer/.opam/repo/repos-config",
        repositories("https://opam.ocaml.org").as_bytes(),
    );
    assert!(
        adapter
            .detect(&context, &test_runtime(root, BTreeMap::new(), None))
            .is_err()
    );
    install_opam(root, "2.5.2", 0);
    write(
        root,
        "/home/developer/.opam/repo/repos-config",
        repositories("https://packages.example/opam").as_bytes(),
    );
    let runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(adapter.plan(&context, &current, &selections()).is_err());
    write(
        root,
        "/home/developer/.opam/repo/repos-config",
        repositories("https://opam.ocaml.org").as_bytes(),
    );
    write(
        root,
        "/home/developer/.opam/config",
        config("", true).as_bytes(),
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(adapter.plan(&context, &current, &selections()).is_err());
    write(
        root,
        "/home/developer/.opam/config",
        config("", false).as_bytes(),
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let mut mismatched = selections();
    mismatched[1].endpoints[2].url = "https://packages.example/cache".into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
}

#[test]
fn failed_repository_update_restores_both_configs() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opam(root, "2.5.2", 9);
    let original_config = config("", false);
    let config_path = write(
        root,
        "/home/developer/.opam/config",
        original_config.as_bytes(),
    );
    let original_repos = repositories("https://opam.ocaml.org");
    let repos_path = write(
        root,
        "/home/developer/.opam/repo/repos-config",
        original_repos.as_bytes(),
    );
    let adapter = OpamAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("opam files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read_to_string(config_path).unwrap(), original_config);
    assert_eq!(fs::read_to_string(repos_path).unwrap(), original_repos);
}

#[test]
fn non_native_platform_windows_arm_and_old_windows_opam_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_opam(root, "2.1.6", 0);
    write(
        root,
        "/home/developer/.opam/config",
        config("", false).as_bytes(),
    );
    write(
        root,
        "/home/developer/.opam/repo/repos-config",
        repositories("https://opam.ocaml.org").as_bytes(),
    );
    let adapter = OpamAdapter;
    let macos_container = SystemContext {
        environment: ExecutionEnvironment::Container,
        ..native_context(root, OperatingSystem::Macos, Architecture::Arm64)
    };
    assert!(
        adapter
            .detect(&macos_container, &test_runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
    let windows_arm = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    assert!(
        adapter
            .detect(&windows_arm, &test_runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("no native Windows arm64 executable")
    );
    let windows = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    assert!(
        adapter
            .detect(&windows, &test_runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("2.2+")
    );
}

#[test]
fn embedded_catalog_separates_git_repository_and_archive_cache() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "opam")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    let repository = candidates
        .iter()
        .filter(|candidate| candidate.upstream_id == REPOSITORY_UPSTREAM)
        .collect::<Vec<_>>();
    assert_eq!(repository.len(), 2);
    let complete = repository
        .iter()
        .find(|candidate| !candidate.probes.is_empty())
        .unwrap();
    assert_eq!(complete.provider_id, "nju");
    assert_eq!(complete.delivery_mode, DeliveryMode::Mirror);
    assert_eq!(
        complete.compatibility.operating_systems,
        [
            OperatingSystem::Linux,
            OperatingSystem::Macos,
            OperatingSystem::Windows,
        ]
    );
    assert_eq!(
        complete.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );
    assert_eq!(complete.compatibility.repository_versions, [REVISION]);
    assert_eq!(complete.probes.len(), 3);
    assert_eq!(
        repository
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .count(),
        1
    );
    let cache = candidates
        .iter()
        .find(|candidate| candidate.upstream_id == CACHE_UPSTREAM)
        .unwrap();
    assert_eq!(cache.provider_id, "sjtug");
    assert_eq!(cache.delivery_mode, DeliveryMode::Proxy);
    assert_eq!(
        cache.compatibility.operating_systems,
        [
            OperatingSystem::Linux,
            OperatingSystem::Macos,
            OperatingSystem::Windows,
        ]
    );
    assert_eq!(cache.probes.len(), 3);
    assert_eq!(cache.probes[0].method, HttpMethod::Head);
    assert_eq!(cache.probes[1].method, HttpMethod::Get);
    assert_eq!(cache.probes[1].sha256.as_deref(), Some(CACHE_SHA));
    assert_eq!(cache.probes[2].method, HttpMethod::Head);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "sjtug"])
    );
}
