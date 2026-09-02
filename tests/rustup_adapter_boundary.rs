#![cfg(unix)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{RustupAdapter, compiled_adapter_allowlist},
    catalog::{
        CandidateEvaluation, ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod,
        Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const RUSTUP_UPSTREAM: &str = "rust-toolchain--release-artifacts";
const HUAWEI_DIST: &str = "https://repo.huaweicloud.com/rustup/";
const HUAWEI_UPDATE: &str = "https://repo.huaweicloud.com/rustup/rustup/";
const USTC_DIST: &str = "https://mirrors.ustc.edu.cn/rust-static/";
const USTC_UPDATE: &str = "https://mirrors.ustc.edu.cn/rust-static/rustup/";
const X64_RUSTUP_SHA: &str = "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10";
const ARM64_RUSTUP_SHA: &str = "9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792";
const X64_MAC_RUSTUP_SHA: &str = "33cf85df9142bc6d29cbc62fa5ca1d4c29622cddb55213a4c1a43c457fb9b2d7";
const ARM64_MAC_RUSTUP_SHA: &str =
    "aeb4105778ca1bd3c6b0e75768f581c656633cd51368fa61289b6a71696ac7e1";
const X64_WINDOWS_RUSTUP_SHA: &str =
    "86478e53f769379d7f0ebfa7c9aa97cb76ca92233f79aa2cc0dbee2efaac73c7";
const ARM64_WINDOWS_RUSTUP_SHA: &str =
    "3af309e6c3062aa11df0e932954f69d13b734d8a431e593812f3ecd9ff9e6ef6";

fn context(
    root: &Path,
    architecture: Architecture,
    environment: ExecutionEnvironment,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
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

fn install_rustup(root: &Path, version: &str, check_exit: i32, with_sh: bool) {
    executable(
        root,
        "/usr/bin/rustup",
        format!(
            r#"#!/bin/sh
case "$*" in
  "--version") printf '%s\n' 'rustup {version} (test 2026-08-29)' ;;
  "show home") printf '%s\n' '/home/developer/.rustup' ;;
  "show profile") printf '%s\n' 'default' ;;
  "show active-toolchain") printf '%s\n' 'stable-x86_64-unknown-linux-gnu (default)' ;;
  "component list --installed --toolchain stable-x86_64-unknown-linux-gnu")
    printf '%s\n' 'cargo-x86_64-unknown-linux-gnu' 'clippy-x86_64-unknown-linux-gnu' 'rustc-x86_64-unknown-linux-gnu'
    ;;
  "target list --installed --toolchain stable-x86_64-unknown-linux-gnu")
    printf '%s\n' 'aarch64-unknown-linux-gnu' 'x86_64-unknown-linux-gnu'
    ;;
  *) exit 73 ;;
esac
"#,
        ),
    );
    if with_sh {
        executable(
            root,
            "/usr/bin/sh",
            format!(
                r#"#!/bin/sh
command="$2"
printf '%s' "$command" | grep -Eq "export RUSTUP_DIST_SERVER='https://(repo\.huaweicloud\.com/rustup|mirrors\.ustc\.edu\.cn/rust-static)'" || exit 80
printf '%s' "$command" | grep -Eq "export RUSTUP_UPDATE_ROOT='https://(repo\.huaweicloud\.com/rustup/rustup|mirrors\.ustc\.edu\.cn/rust-static/rustup)'" || exit 81
case "$command" in
  *"rustup 'check'")
    printf '%s\n' 'stable-x86_64-unknown-linux-gnu - Up to date'
    exit {check_exit}
    ;;
  *"rustup 'show' 'profile'") printf '%s\n' 'default' ;;
  *) exit 82 ;;
esac
"#,
            ),
        );
    }
}

fn install_windows_commands(root: &Path, check_exit: i32) -> PathBuf {
    let registry = root.join("registry");
    fs::create_dir_all(&registry).unwrap();
    executable(
        root,
        "/usr/bin/reg.exe",
        format!(
            r#"#!/bin/sh
root='{registry}'
operation=$1
variable=$4
file="$root/$variable"
case "$operation" in
  query)
    [ -f "$file" ] || exit 1
    printf '%s\n' 'HKEY_CURRENT_USER\Environment' "    $variable    REG_SZ    $(cat "$file")"
    ;;
  add)
    value=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = data ]; then value=$argument; fi
      if [ "$argument" = /d ]; then previous=data; else previous=''; fi
    done
    [ -n "$value" ] || exit 2
    printf '%s' "$value" > "$file"
    ;;
  delete)
    [ -f "$file" ] || exit 1
    rm "$file"
    ;;
  *) exit 3 ;;
esac
"#,
            registry = registry.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/cmd.exe",
        format!(
            r#"#!/bin/sh
[ "$1 $2 $3" = '/D /S /C' ] || exit 4
printf '%s' "$4" | grep -q 'RUSTUP_DIST_SERVER=https://' || exit 5
printf '%s' "$4" | grep -q 'RUSTUP_UPDATE_ROOT=https://' || exit 6
case "$4" in
  *'rustup check') printf '%s\n' 'stable-aarch64-pc-windows-msvc - Up to date'; exit {check_exit} ;;
  *'rustup show profile') printf '%s\n' 'default' ;;
  *) exit 7 ;;
esac
"#,
        ),
    );
    registry
}

fn environment(shell: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("SHELL".into(), shell.into())])
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection(dist: &str, update: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "rustup-test".into(),
        tool_id: "rustup".into(),
        upstream_id: RUSTUP_UPSTREAM.into(),
        provider_id: if dist.contains("huaweicloud") {
            "huaweicloud"
        } else {
            "ustc"
        }
        .into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Releases,
                protocol: Protocol::Https,
                url: dist.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: update.into(),
            },
        ],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn posix_user_plan_preserves_state_is_consistent_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 100, true);
    write(root, "/work/project/.keep", b"");
    let original = b"# aliases\nalias ll='ls -l'\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = RustupAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment("/bin/bash"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.29.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("stable-x86_64-unknown-linux-gnu"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("profile is default"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("aarch64-unknown-linux-gnu"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [RUSTUP_UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Releases, EndpointRole::Artifacts]
    );
    assert_eq!(request.allowed_delivery_modes, [DeliveryMode::Mirror]);
    assert_eq!(request.probe_contexts[RUSTUP_UPSTREAM].len(), 2);

    let chosen = [selection(HUAWEI_DIST, HUAWEI_UPDATE)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 1);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("alias ll='ls -l'"));
    assert!(rendered.contains("export RUSTUP_DIST_SERVER='https://repo.huaweicloud.com/rustup'"));
    assert!(
        rendered.contains("export RUSTUP_UPDATE_ROOT='https://repo.huaweicloud.com/rustup/rustup'")
    );

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("rustup profile should change")
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
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn arm64_fish_uses_a_distinct_update_root_and_both_probe_targets() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 0, true);
    write(root, "/work/project/.keep", b"");
    let adapter = RustupAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let runtime = runtime(root, environment("/usr/bin/fish"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[RUSTUP_UPSTREAM]
            .iter()
            .map(|values| (values["host"].as_str(), values["rustup_sha256"].as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("aarch64-unknown-linux-gnu", ARM64_RUSTUP_SHA),
            ("x86_64-unknown-linux-gnu", X64_RUSTUP_SHA),
        ])
    );
    let plan = adapter
        .plan(&context, &current, &[selection(USTC_DIST, USTC_UPDATE)])
        .unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        rendered.contains("set -gx RUSTUP_DIST_SERVER 'https://mirrors.ustc.edu.cn/rust-static'")
    );
    assert!(
        rendered.contains(
            "set -gx RUSTUP_UPDATE_ROOT 'https://mirrors.ustc.edu.cn/rust-static/rustup'"
        )
    );
    assert!(
        plan.changes[0]
            .target
            .ends_with("home/developer/.config/fish/conf.d/mirrorswitch-rustup.fish")
    );
}

#[derive(Clone)]
struct RustupProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_update_checksum: bool,
}

impl CandidateProber for RustupProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let body = if url.ends_with("channel-rust-stable.toml") {
            b"synthetic stable manifest".to_vec()
        } else if url.ends_with("release-stable.toml") {
            b"synthetic rustup release".to_vec()
        } else if url.ends_with("rustup-init.sha256") {
            if self.corrupt_update_checksum {
                b"corrupt".to_vec()
            } else {
                format!("{X64_RUSTUP_SHA}\n{ARM64_RUSTUP_SHA}\n").into_bytes()
            }
        } else if url.ends_with("channel-rust-stable.toml.sha256") {
            b"manifest-sidecar".to_vec()
        } else {
            Vec::new()
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body,
            latency_ms: 1,
        })
    }
}

fn synthetic_catalog() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let manifest_digest = format!("{:x}", Sha256::digest(b"synthetic stable manifest"));
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "rustup")
    {
        for probe in &mut candidate.probes {
            if probe.path == "/dist/2026-08-20/channel-rust-stable.toml" {
                probe.sha256 = Some(manifest_digest.clone());
            } else if probe.path == "/dist/2026-08-20/channel-rust-stable.toml.sha256" {
                probe.contains = Some("manifest-sidecar".into());
            } else if probe.path == "/release-stable.toml" {
                probe.contains = Some("synthetic rustup release".into());
            }
        }
    }
    catalog
}

#[test]
fn catalog_requires_distribution_components_update_binary_and_checksums_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let tool = embedded
        .tools
        .iter()
        .find(|tool| tool.id == "rustup")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    let actionable = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "rustup" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(actionable.len(), 2);
    assert_eq!(
        actionable
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["huaweicloud", "ustc"])
    );
    for candidate in actionable {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(candidate.endpoints.len(), 2);
        assert_eq!(candidate.probes.len(), 8);
        assert!(candidate.probes.iter().any(|probe| {
            probe.endpoint_role == EndpointRole::Releases
                && probe.path.contains("rustc-1.98.0-{host}")
        }));
        assert!(candidate.probes.iter().any(|probe| {
            probe.endpoint_role == EndpointRole::Releases
                && probe.path.contains("rust-std-1.98.0-{host}")
        }));
        assert!(candidate.probes.iter().any(|probe| {
            probe.endpoint_role == EndpointRole::Artifacts
                && probe.path.contains("{installer}.sha256")
        }));
        assert_eq!(
            candidate.compatibility.operating_systems,
            [
                OperatingSystem::Linux,
                OperatingSystem::Macos,
                OperatingSystem::Windows,
            ]
        );
    }

    let catalog = synthetic_catalog();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let directory = tempdir().unwrap();
    install_rustup(directory.path(), "1.29.0", 0, true);
    write(directory.path(), "/work/project/.keep", b"");
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), environment("/bin/bash"));
    let adapter = RustupAdapter;
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let selected = MirrorSelector::with_prober(
        &catalog,
        RustupProtocolProber {
            calls: calls.clone(),
            corrupt_update_checksum: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable, "{selected:#?}");
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 32);

    let rejected = MirrorSelector::with_prober(
        &catalog,
        RustupProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_update_checksum: true,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.repositories[0].candidates.iter().any(|candidate| {
        matches!(
            &candidate.evaluation,
            CandidateEvaluation::ProbeFailed { reason }
                if reason.contains("metadata marker")
        )
    }));
}

#[test]
fn macos_probe_triples_and_windows_registry_transaction_are_native() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 0, true);
    write(root, "/work/project/.keep", b"");
    let adapter = RustupAdapter;
    let macos = native_context(root, OperatingSystem::Macos, Architecture::Arm64);
    let mac_runtime = runtime(root, environment("/bin/zsh"));
    let detected = adapter.detect(&macos, &mac_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&macos, &mac_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&macos, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[RUSTUP_UPSTREAM]
            .iter()
            .map(|values| {
                (
                    values["host"].as_str(),
                    values["installer"].as_str(),
                    values["rustup_sha256"].as_str(),
                )
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([("aarch64-apple-darwin", "rustup-init", ARM64_MAC_RUSTUP_SHA,)])
    );
    let macos_x64 = native_context(root, OperatingSystem::Macos, Architecture::X86_64);
    let x64_request = adapter
        .selection_request(&macos_x64, &detected, &current)
        .unwrap();
    assert_eq!(
        x64_request.probe_contexts[RUSTUP_UPSTREAM][0]["rustup_sha256"],
        X64_MAC_RUSTUP_SHA
    );

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 0, false);
    let registry = install_windows_commands(root, 0);
    fs::write(
        registry.join(DIST_VARIABLE),
        USTC_DIST.trim_end_matches('/'),
    )
    .unwrap();
    fs::write(
        registry.join(UPDATE_VARIABLE),
        USTC_UPDATE.trim_end_matches('/'),
    )
    .unwrap();
    write(root, "/work/project/.keep", b"");
    let windows = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    let environment = BTreeMap::from([(
        "LOCALAPPDATA".into(),
        "/home/developer/AppData/Local".into(),
    )]);
    let mut runtime = runtime(root, environment);
    let detected = adapter.detect(&windows, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&windows, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        current
            .documents
            .iter()
            .any(|document| document.format == "rustup-windows-recovery")
    );
    let request = adapter
        .selection_request(&windows, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[RUSTUP_UPSTREAM]
            .iter()
            .map(|values| {
                (
                    values["host"].as_str(),
                    values["installer"].as_str(),
                    values["rustup_sha256"].as_str(),
                )
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(
            "aarch64-pc-windows-msvc",
            "rustup-init.exe",
            ARM64_WINDOWS_RUSTUP_SHA,
        )])
    );
    let windows_x64 = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    let x64_request = adapter
        .selection_request(&windows_x64, &detected, &current)
        .unwrap();
    assert_eq!(
        x64_request.probe_contexts[RUSTUP_UPSTREAM][0]["rustup_sha256"],
        X64_WINDOWS_RUSTUP_SHA
    );
    let selected = [selection(HUAWEI_DIST, HUAWEI_UPDATE)];
    let plan = adapter.plan(&windows, &current, &selected).unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(!format!("{plan:?}").contains("HKCU"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&windows, &mut runtime, &plan).unwrap()
    else {
        panic!("Windows rustup environment should change")
    };
    assert_eq!(
        fs::read_to_string(registry.join(DIST_VARIABLE)).unwrap(),
        HUAWEI_DIST.trim_end_matches('/')
    );
    assert!(
        adapter
            .verify(&windows, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&windows, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let unchanged = adapter.plan(&windows, &updated, &selected).unwrap();
    assert!(unchanged.changes.is_empty());
    assert_eq!(
        adapter.apply(&windows, &mut runtime, &unchanged).unwrap(),
        ApplyOutcome::Unchanged
    );
    assert!(
        adapter
            .restore(&windows, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(
        fs::read_to_string(registry.join(DIST_VARIABLE)).unwrap(),
        USTC_DIST.trim_end_matches('/')
    );
    assert_eq!(
        fs::read_to_string(registry.join(UPDATE_VARIABLE)).unwrap(),
        USTC_UPDATE.trim_end_matches('/')
    );
    assert!(
        !root
            .join("home/developer/AppData/Local/MirrorSwitch/rustup/environment-recovery.json")
            .exists()
    );
}

#[test]
fn failed_windows_rustup_check_restores_registry_and_recovery_file() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 74, false);
    let registry = install_windows_commands(root, 74);
    write(root, "/work/project/.keep", b"");
    let context = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    let mut runtime = runtime(
        root,
        BTreeMap::from([(
            "LOCALAPPDATA".into(),
            "/home/developer/AppData/Local".into(),
        )]),
    );
    let adapter = RustupAdapter;
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI_DIST, HUAWEI_UPDATE)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Windows rustup environment should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("registry restored: true"));
    assert!(!registry.join(DIST_VARIABLE).exists());
    assert!(!registry.join(UPDATE_VARIABLE).exists());
    assert!(
        !root
            .join("home/developer/AppData/Local/MirrorSwitch/rustup/environment-recovery.json")
            .exists()
    );
}

#[test]
fn unmanaged_environment_deprecated_and_mismatched_pairs_are_blocked() {
    type PolicyCase<'a> = (&'a [u8], BTreeMap<String, String>, &'a str);
    let cases: Vec<PolicyCase<'_>> = vec![
        (
            b"export RUSTUP_DIST_SERVER='https://mirror.example/rust'\n",
            environment("/bin/bash"),
            "outside the MirrorSwitch block",
        ),
        (
            b"export RUSTUP_DIST_ROOT='https://mirror.example/dist'\n",
            environment("/bin/bash"),
            "deprecated RUSTUP_DIST_ROOT",
        ),
        (
            b"",
            BTreeMap::from([
                ("SHELL".into(), "/bin/bash".into()),
                (DIST_VARIABLE.into(), "https://mirror.example/rust".into()),
            ]),
            "process-level",
        ),
    ];
    let adapter = RustupAdapter;
    for (profile, environment, expected) in cases {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_rustup(root, "1.29.0", 0, true);
        write(root, "/work/project/.keep", b"");
        write(root, "/home/developer/.bashrc", profile);
        let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
        let runtime = runtime(root, environment);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let error = adapter
            .selection_request(&context, &detected, &current)
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }

    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 0, true);
    write(root, "/work/project/.keep", b"");
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let runtime = runtime(root, environment("/bin/bash"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let error = adapter
        .plan(&context, &current, &[selection(HUAWEI_DIST, USTC_UPDATE)])
        .unwrap_err();
    assert!(error.to_string().contains("endpoint pair"));
}

#[test]
fn failed_real_rustup_check_restores_the_original_profile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.29.0", 74, true);
    write(root, "/work/project/.keep", b"");
    let original = b"# keep me\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = RustupAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment("/bin/bash"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(HUAWEI_DIST, HUAWEI_UPDATE)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("rustup profile should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
}

#[test]
fn unsupported_version_platform_scope_and_missing_commands_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_rustup(root, "1.23.1", 0, true);
    write(root, "/work/project/.keep", b"");
    let adapter = RustupAdapter;
    let supported = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let installed = runtime(root, environment("/bin/bash"));
    assert!(
        adapter
            .detect(&supported, &installed)
            .unwrap_err()
            .to_string()
            .contains("1.24+")
    );

    let mut macos_container = supported.clone();
    macos_container.os = OperatingSystem::Macos;
    macos_container.environment = ExecutionEnvironment::Container;
    assert!(
        adapter
            .detect(&macos_container, &installed)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );

    let no_shell = tempdir().unwrap();
    install_rustup(no_shell.path(), "1.29.0", 0, false);
    let no_shell_runtime = runtime(no_shell.path(), environment("/bin/bash"));
    let no_shell_context = context(
        no_shell.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(
        adapter
            .detect(&no_shell_context, &no_shell_runtime)
            .unwrap_err()
            .to_string()
            .contains("POSIX sh")
    );

    let empty = tempdir().unwrap();
    let empty_runtime = runtime(empty.path(), environment("/bin/bash"));
    let empty_context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(
        adapter
            .detect(&empty_context, &empty_runtime)
            .unwrap()
            .is_none()
    );
}

const DIST_VARIABLE: &str = "RUSTUP_DIST_SERVER";
const UPDATE_VARIABLE: &str = "RUSTUP_UPDATE_ROOT";
