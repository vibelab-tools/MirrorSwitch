#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{ElpaAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const GNU: &str = "gnu-elpa--language-registry";
const NONGNU: &str = "nongnu-elpa--language-registry";
const MELPA: &str = "melpa--language-registry";

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

fn install_emacs(root: &Path, version: &str, verification_exit: i32) {
    install_native_emacs(
        root,
        version,
        "gnu/linux",
        "x86_64-pc-linux-gnu",
        "/home/developer/",
        "/home/developer/.emacs.d/",
        verification_exit,
    );
}

fn install_native_emacs(
    root: &Path,
    version: &str,
    system_type: &str,
    system_configuration: &str,
    emacs_home: &str,
    user_emacs_directory: &str,
    verification_exit: i32,
) {
    executable(
        root,
        "/usr/bin/emacs",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then
  echo 'GNU Emacs {version}'
  echo 'Copyright test'
  exit 0
fi
last=
for argument in "$@"; do last=$argument; done
case "$last" in
  *MIRRORSWITCH_EMACS_HOME*)
    echo 'MIRRORSWITCH_EMACS_HOME={emacs_home}'
    echo 'MIRRORSWITCH_EMACS_DIR={user_emacs_directory}'
    echo 'MIRRORSWITCH_EMACS_SYSTEM={system_type}'
    echo 'MIRRORSWITCH_EMACS_CONFIGURATION={system_configuration}'
    exit 0
    ;;
esac
printf '%s' "$last" | grep -F 'package-refresh-contents' >/dev/null || exit 61
printf '%s' "$last" | grep -F 'mirrors.ustc.edu.cn/elpa/gnu/' >/dev/null || exit 62
printf '%s' "$last" | grep -F 'mirrors.nju.edu.cn/elpa/nongnu/' >/dev/null || exit 63
printf '%s' "$last" | grep -F 'mirrors.tuna.tsinghua.edu.cn/elpa/melpa/' >/dev/null || exit 64
[ {verification_exit} -eq 0 ] || exit {verification_exit}
echo 'MIRRORSWITCH_ELPA_VERIFY=gnu,nongnu,melpa'
"#,
        ),
    );
}

fn runtime(root: &Path, xdg: bool) -> OsRuntime {
    let environment = if xdg {
        BTreeMap::from([("XDG_CONFIG_HOME".into(), "/home/developer/.config".into())])
    } else {
        BTreeMap::new()
    };
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn native_runtime(root: &Path, project: &str) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir(project)
        .with_environment(BTreeMap::new())
}

fn selections() -> Vec<MirrorSelection> {
    [
        (GNU, "ustc", "https://mirrors.ustc.edu.cn/elpa/gnu/"),
        (NONGNU, "nju", "https://mirrors.nju.edu.cn/elpa/nongnu/"),
        (
            MELPA,
            "tuna",
            "https://mirrors.tuna.tsinghua.edu.cn/elpa/melpa/",
        ),
    ]
    .into_iter()
    .map(|(upstream, provider, url)| MirrorSelection {
        candidate_id: format!("elpa-{provider}-{upstream}"),
        tool_id: "elpa".into(),
        upstream_id: upstream.into(),
        provider_id: provider.into(),
        endpoints: [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Packages,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: url.into(),
        })
        .collect(),
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    })
    .collect()
}

#[test]
fn user_plan_preserves_custom_archives_priorities_lisp_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_emacs(root, "30.2", 0);
    let original = br#";; user configuration
(setq custom-file "~/.emacs.d/custom.el")
(setq package-archives '(("private" . "https://packages.example/elpa/")
                         ("gnu" . "https://elpa.gnu.org/packages/")))
(setq package-archive-priorities '(("private" . 100) ("gnu" . 10)))
(setq user-full-name "Developer")
"#;
    let init = write(root, "/home/developer/.emacs.d/init.el", original);
    let adapter = ElpaAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("30.2"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [GNU, NONGNU, MELPA]);
    let selected = selections();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("https://packages.example/elpa/"));
    assert!(rendered.contains("package-archive-priorities"));
    assert!(rendered.contains("user-full-name"));
    for endpoint in [
        "https://mirrors.ustc.edu.cn/elpa/gnu/",
        "https://mirrors.nju.edu.cn/elpa/nongnu/",
        "https://mirrors.tuna.tsinghua.edu.cn/elpa/melpa/",
    ] {
        assert!(rendered.contains(endpoint));
    }
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Emacs init should change")
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
    assert_eq!(fs::read(init).unwrap(), original);
}

#[test]
fn arm64_xdg_missing_init_uses_explicit_xdg_layout() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_native_emacs(
        root,
        "29.4",
        "gnu/linux",
        "aarch64-unknown-linux-gnu",
        "/home/developer/",
        "/home/developer/.config/emacs/",
        0,
    );
    let adapter = ElpaAdapter;
    let context = context(root, Architecture::Arm64);
    let runtime = runtime(root, true);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    assert!(
        plan.changes[0]
            .target
            .ends_with("home/developer/.config/emacs/init.el")
    );
    assert_eq!(
        plan,
        adapter.plan(&context, &current, &selections()).unwrap()
    );
}

#[test]
fn native_layouts_preserve_encoding_permissions_project_and_frontend_equivalence() {
    for (os, architecture, system_type, configuration, home, directory, init_name) in [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "darwin",
            "x86_64-apple-darwin24.0.0",
            "/Users/developer/",
            "/Users/developer/.config/emacs/",
            "init.el",
        ),
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            "darwin",
            "aarch64-apple-darwin24.0.0",
            "/Users/developer/",
            "/Users/developer/.emacs.d/",
            "init.el",
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            "windows-nt",
            "x86_64-w64-mingw32",
            "/home/developer/AppData/Roaming/",
            "/home/developer/AppData/Roaming/.emacs.d/",
            "_emacs",
        ),
    ] {
        let sandbox = tempdir().unwrap();
        let root = sandbox.path();
        install_native_emacs(root, "30.2", system_type, configuration, home, directory, 0);
        let init_path = if init_name == "_emacs" {
            format!("{home}{init_name}")
        } else {
            format!("{directory}{init_name}")
        };
        let original = if os == OperatingSystem::Windows {
            b"\xef\xbb\xbf;; native configuration\r\n(setq custom-file \"C:/Users/developer/private.el\")\r\n(setq package-archives '((\"private\" . \"https://build:fixture-only@packages.invalid.example/elpa/\")))\r\n(setq package-archive-priorities '((\"private\" . 100)))\r\n".as_slice()
        } else {
            b";; native configuration\n(setq custom-file \"~/.emacs.d/private.el\")\n(setq package-archives '((\"private\" . \"https://build:fixture-only@packages.invalid.example/elpa/\")))\n(setq package-archive-priorities '((\"private\" . 100)))\n".as_slice()
        };
        let init = write(root, &init_path, original);
        let mut permissions = fs::metadata(&init).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&init, permissions).unwrap();
        let project = "/home/developer/project";
        let project_file = write(
            root,
            "/home/developer/project/.dir-locals.el",
            b"((nil . ((private-token . \"project-fixture-only\"))))\n",
        );
        let context = native_context(root, os, architecture);
        let mut runtime = native_runtime(root, project);
        let adapter = ElpaAdapter;
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let evidence = detected.evidence.join("\n");
        assert!(evidence.contains(&format!("{os:?}")));
        assert!(evidence.contains(&format!("{architecture:?}")));
        assert!(evidence.contains(home.trim_end_matches('/')));
        assert!(evidence.contains(directory.trim_end_matches('/')));
        assert!(evidence.contains(project));
        assert!(!evidence.contains("fixture-only"));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let cli = adapter.plan(&context, &current, &selections()).unwrap();
        let config = adapter.plan(&context, &current, &selections()).unwrap();
        let tui = adapter.plan(&context, &current, &selections()).unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
        assert_eq!(cli.changes[0].target, init);
        let rendered = &cli.changes[0].new_contents;
        assert_eq!(
            rendered.starts_with(&[0xef, 0xbb, 0xbf]),
            os == OperatingSystem::Windows
        );
        assert_eq!(
            String::from_utf8_lossy(rendered).contains("\r\n"),
            os == OperatingSystem::Windows
        );
        assert!(String::from_utf8_lossy(rendered).contains("fixture-only"));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("native Emacs init should change")
        };
        assert!(
            adapter
                .verify(&context, &mut runtime, &receipt)
                .unwrap()
                .valid
        );
        assert_eq!(
            fs::read(&project_file).unwrap(),
            b"((nil . ((private-token . \"project-fixture-only\"))))\n"
        );
        assert_eq!(
            fs::metadata(&init).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &selections())
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
        assert_eq!(fs::read(&init).unwrap(), original);
        assert_eq!(
            fs::metadata(&init).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn ambiguous_init_old_version_malformed_markers_and_endpoint_mismatch_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = ElpaAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, false))
            .unwrap()
            .is_none()
    );
    install_emacs(root, "26.3", 0);
    assert!(
        adapter
            .detect(&context, &runtime(root, false))
            .unwrap_err()
            .to_string()
            .contains("outside reviewed")
    );
    install_emacs(root, "30.2", 0);
    write(root, "/home/developer/.emacs", b";; first\n");
    write(root, "/home/developer/.emacs.d/init.el", b";; second\n");
    assert!(adapter.detect(&context, &runtime(root, false)).is_err());
    fs::remove_file(root.join("home/developer/.emacs")).unwrap();
    write(
        root,
        "/home/developer/.emacs.d/init.el",
        b";; >>> MirrorSwitch Emacs package archives >>>\n",
    );
    assert!(adapter.detect(&context, &runtime(root, false)).is_err());
    write(root, "/home/developer/.emacs.d/init.el", b";; clean\n");
    let runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let mut bad = selections();
    bad[2].endpoints[0].url = "https://mirrors.ustc.edu.cn/elpa/gnu/".into();
    assert!(adapter.plan(&context, &current, &bad).is_err());
}

#[test]
fn failed_batch_refresh_restores_init() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_emacs(root, "30.2", 9);
    let original = b"(setq inhibit-startup-screen t)\n";
    let init = write(root, "/home/developer/.emacs.d/init.el", original);
    let adapter = ElpaAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Emacs init should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("restored: true"));
    assert_eq!(fs::read(init).unwrap(), original);
}

#[test]
fn unsupported_native_contexts_and_emulated_architectures_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_native_emacs(
        root,
        "30.2",
        "darwin",
        "x86_64-apple-darwin24.0.0",
        "/Users/developer/",
        "/Users/developer/.emacs.d/",
        0,
    );
    let adapter = ElpaAdapter;
    let runtime = native_runtime(root, "/Users/developer/project");

    let mut container = native_context(root, OperatingSystem::Macos, Architecture::X86_64);
    container.environment = ExecutionEnvironment::Container;
    assert!(
        adapter
            .detect(&container, &runtime)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );

    let windows_arm = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    assert!(
        adapter
            .detect(&windows_arm, &runtime)
            .unwrap_err()
            .to_string()
            .contains("x86_64 only")
    );

    let mac_arm = native_context(root, OperatingSystem::Macos, Architecture::Arm64);
    assert!(
        adapter
            .detect(&mac_arm, &runtime)
            .unwrap_err()
            .to_string()
            .contains("does not match Arm64")
    );
}

struct ArchiveProber;

impl CandidateProber for ArchiveProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let latency_ms = if url.contains("/gnu/") && url.contains("ustc")
            || url.contains("/nongnu/") && url.contains("nju")
            || url.contains("/melpa/") && url.contains("tuna")
        {
            1
        } else {
            4
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body: b"(a68-mode (adoc-mode (dash . [(20260221 1346)".to_vec(),
            latency_ms,
        })
    }
}

#[test]
fn catalog_splits_three_inventory_roots_into_nine_independent_archive_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "elpa")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 9);
    for upstream in [GNU, NONGNU, MELPA] {
        let archive = candidates
            .iter()
            .filter(|candidate| candidate.upstream_id == upstream)
            .collect::<Vec<_>>();
        assert_eq!(archive.len(), 3);
        assert_eq!(
            archive
                .iter()
                .map(|candidate| candidate.provider_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["nju", "tuna", "ustc"])
        );
        assert!(
            archive
                .iter()
                .all(|candidate| candidate.delivery_mode == DeliveryMode::Mirror
                    && candidate.compatibility.operating_systems
                        == [
                            OperatingSystem::Linux,
                            OperatingSystem::Macos,
                            OperatingSystem::Windows,
                        ]
                    && candidate.compatibility.architectures
                        == [Architecture::X86_64, Architecture::Arm64])
        );
    }
    assert!(
        candidates
            .iter()
            .filter(|candidate| candidate.upstream_id != MELPA)
            .all(|candidate| candidate.probes.len() == 4)
    );
    assert!(
        candidates
            .iter()
            .filter(|candidate| candidate.upstream_id == MELPA)
            .all(|candidate| candidate.probes.len() == 3)
    );

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_emacs(root, "30.2", 0);
    let adapter = ElpaAdapter;
    let context = context(root, Architecture::X86_64);
    let runtime = runtime(root, false);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let limits = ProbeLimits::default();
    assert_eq!(limits.max_bytes, 24 * 1024 * 1024);
    let selector = MirrorSelector::with_prober(&catalog, ArchiveProber, limits);
    let outcome = selector.select_at(&request, 123).unwrap();
    assert!(outcome.actionable);
    assert_eq!(
        outcome
            .selections
            .iter()
            .map(|selection| (
                selection.upstream_id.as_str(),
                selection.provider_id.as_str()
            ))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(GNU, "ustc"), (NONGNU, "nju"), (MELPA, "tuna")])
    );
}
