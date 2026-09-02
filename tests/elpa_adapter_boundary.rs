#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
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
    install_emacs(root, "29.4", 0);
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
    let selector = MirrorSelector::with_prober(
        &catalog,
        ArchiveProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 4 * 1024 * 1024,
        },
    );
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
