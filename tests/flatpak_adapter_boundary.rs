#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{FlatpakAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "flathub--static-files";
const SJTUG: &str = "https://mirror.sjtu.edu.cn/flathub";
const USTC: &str = "https://mirrors.ustc.edu.cn/flathub";

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

fn install_flatpak(root: &Path, selected: &str, query_exit: i32) {
    let system = root.join("var/lib/flatpak/repo/config");
    let user = root.join("home/developer/.local/share/flatpak/repo/config");
    executable(
        root,
        "/usr/bin/flatpak",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'Flatpak 1.14.10'; exit 0; fi\nif [ \"$2\" = remote-ls ]; then\n  grep -qs '{selected}' '{system}' '{user}' || exit 65\n  [ {query_exit} -eq 0 ] || exit {query_exit}\n  arch=${{3#--arch=}}\n  echo \"app/org.example.App/$arch/stable\"\n  exit 0\nfi\nexit 64\n",
            system = system.display(),
            user = user.display(),
        ),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/home/developer")
}

fn selection(url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "flatpak-test".into(),
        tool_id: "flatpak".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Artifacts,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn system_plan_preserves_remote_identity_gpg_priority_and_is_idempotent() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flatpak(root, USTC, 0);
    let original = b"[core]\nrepo_version=1\nmode=bare-user-only\n\n[remote \"flathub\"]\nurl = https://dl.flathub.org/repo/\nxa.title=Flathub\ngpg-verify=true\ngpg-verify-summary=true\nxa.prio=7\n\n[remote \"private\"]\nurl=https://packages.example/repo\ngpg-verify=false\ngpg-verify-summary=false\nxa.disable=true\nxa.prio=3\n";
    let config = write(root, "/var/lib/flatpak/repo/config", original);
    let context = context(root, Architecture::X86_64);
    let adapter = FlatpakAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("Flatpak 1.14.10"));
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::System
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let flathub = current
        .sources
        .iter()
        .find(|source| source.upstream_id.as_deref() == Some(UPSTREAM))
        .unwrap();
    assert_eq!(flathub.metadata["gpg_verify"], ["true"]);
    assert_eq!(flathub.metadata["gpg_verify_summary"], ["true"]);
    assert_eq!(flathub.metadata["priority"], ["7"]);
    assert!(
        current
            .sources
            .iter()
            .any(|source| { source.url == "https://packages.example/repo" && !source.enabled })
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[UPSTREAM][0]["flatpak_arch"],
        "x86_64"
    );

    let chosen = [selection(USTC)];
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert!(cli_plan.requires_elevation);
    assert_eq!(cli_plan.changes.len(), 1);
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("url = {USTC}")));
    assert!(rendered.contains("gpg-verify=true"));
    assert!(rendered.contains("gpg-verify-summary=true"));
    assert!(rendered.contains("xa.prio=7"));
    assert!(rendered.contains("url=https://packages.example/repo"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("Flatpak system config should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
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
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn arm64_user_scope_is_unprivileged_and_failed_query_restores_all_mapped_remotes() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flatpak(root, SJTUG, 7);
    write(
        root,
        "/var/lib/flatpak/repo/config",
        b"[core]\nrepo_version=1\n[remote \"vendor\"]\nurl=https://vendor.example/repo\ngpg-verify=true\ngpg-verify-summary=true\n",
    );
    let original = b"[core]\nrepo_version=1\n\n[remote \"flathub-user\"]\nurl=https://dl.flathub.org/repo/\ngpg-verify=true\ngpg-verify-summary=true\nxa.prio=4\n\n[remote \"flathub-disabled\"]\nurl=https://flathub.org/repo\ngpg-verify=true\ngpg-verify-summary=true\nxa.disable=true\n";
    let config = write(
        root,
        "/home/developer/.local/share/flatpak/repo/config",
        original,
    );
    let context = context(root, Architecture::Arm64);
    let adapter = FlatpakAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::User
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[UPSTREAM][0]["flatpak_arch"],
        "aarch64"
    );
    let plan = adapter
        .plan(&context, &current, &[selection(SJTUG)])
        .unwrap();
    assert!(!plan.requires_elevation);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert_eq!(rendered.matches(SJTUG).count(), 2);
    assert!(rendered.contains("xa.disable=true"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Flatpak user config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn unmapped_scope_and_disabled_gpg_policy_are_not_actionable() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flatpak(root, USTC, 0);
    write(
        root,
        "/var/lib/flatpak/repo/config",
        b"[remote \"private\"]\nurl=https://private.example/repo\ngpg-verify=true\ngpg-verify-summary=true\n",
    );
    let bad = write(
        root,
        "/home/developer/.local/share/flatpak/repo/config",
        b"[remote \"flathub\"]\nurl=https://dl.flathub.org/repo\ngpg-verify=false\ngpg-verify-summary=true\n",
    );
    let context = context(root, Architecture::X86_64);
    let adapter = FlatpakAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let error = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap_err();
    assert!(error.to_string().contains("GPG verification"));

    fs::write(
        bad,
        b"[remote \"private-user\"]\nurl=https://private.example/user\ngpg-verify=true\ngpg-verify-summary=true\n",
    )
    .unwrap();
    let error = adapter
        .default_scope_for(&context, &runtime, &detected)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no existing mapped Flathub remote")
    );
}

#[test]
fn embedded_catalog_has_two_arch_checked_flathub_proxy_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "flatpak" && candidate.delivery_mode == DeliveryMode::Proxy
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| {
        candidate.upstream_id == UPSTREAM
            && candidate.compatibility.operating_systems == [OperatingSystem::Linux]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints[0].role == EndpointRole::Artifacts
            && candidate.probes.len() == 2
            && candidate.probes[0].path == "/config"
            && candidate.probes[0].contains.as_deref() == Some("collection-id=org.flathub.Stable")
            && candidate.probes[1].path == "/summary.idx"
            && candidate.probes[1].contains.as_deref() == Some("{flatpak_arch}")
    }));
}
