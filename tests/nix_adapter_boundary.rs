#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{NixAdapter, NixMacosAdapter, compiled_adapter_allowlist},
    catalog::{
        ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const CACHE_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
const STORE_PATH: &str = "/nix/store/aasbksznz37vw5pb26wq86209q5cmza8-xgcc-15.2.0-libgcc";
const DARWIN_X86_STORE: &str = "/nix/store/4sv8vd71y21gic34irbqr4pp1xgdhqck-hello-2.12.2";
const DARWIN_ARM_STORE: &str = "/nix/store/mxawknsavjm2cfw3imi3g58497nkfiky-hello-2.12.2";

fn context(root: &Path, architecture: Architecture, distribution: &str) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: distribution.into(),
            version_id: None,
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: root.to_path_buf(),
    }
}

fn macos_context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Macos,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "macos".into(),
            version_id: Some("15.6".into()),
            version_codename: None,
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

fn install_nix(
    root: &Path,
    system: &str,
    selected: &str,
    multi_user: bool,
    ping_exit: i32,
    path_exit: i32,
) {
    if multi_user {
        write(
            root,
            "/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh",
            b"# daemon\n",
        );
    }
    let system_config = root.join("etc/nix/nix.conf");
    let user_config = root.join("home/developer/.config/nix/nix.conf");
    let json = format!(
        "{{\"substituters\":{{\"value\":%s}},\"trusted-public-keys\":{{\"value\":[\"{CACHE_KEY}\"]}},\"require-sigs\":{{\"value\":true}},\"system\":{{\"value\":\"{system}\"}},\"flake-registry\":{{\"value\":\"https://channels.nixos.org/flake-registry.json\"}}}}"
    );
    executable(
        root,
        "/usr/bin/nix",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'nix (Nix) 2.35.2'; exit 0; fi\nif [ \"$3\" = config ] && [ \"$4\" = show ]; then\n  if grep -qs '{selected}' '{system_config}' '{user_config}'; then subs='[\"{selected}\",\"https://cache.nixos.org/\",\"https://custom.example/cache\"]'; else subs='[\"https://cache.nixos.org/\",\"https://custom.example/cache\"]'; fi\n  printf '{json}\\n' \"$subs\"; exit 0\nfi\nif [ \"$3\" = store ] && [ \"$4\" = ping ]; then exit {ping_exit}; fi\nif [ \"$3\" = path-info ]; then exit {path_exit}; fi\nexit 64\n",
            system_config = system_config.display(),
            user_config = user_config.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/nix-store",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --query ]; then echo '{STORE_PATH}'; exit 0; fi\nexit 64\n"
        ),
    );
    executable(
        root,
        "/usr/bin/nix-channel",
        "#!/bin/sh\nif [ \"$1\" = --list ]; then echo 'nixpkgs https://channels.nixos.org/nixpkgs-unstable'; exit 0; fi\nexit 64\n"
            .into(),
    );
}

fn install_macos_nix(
    root: &Path,
    system: &str,
    selected: &str,
    store_path: &str,
    multi_user: bool,
) -> PathBuf {
    if multi_user {
        write(
            root,
            "/Library/LaunchDaemons/org.nixos.nix-daemon.plist",
            b"<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>org.nixos.nix-daemon</string></dict></plist>\n",
        );
    }
    let system_config = root.join("etc/nix/nix.conf");
    let user_config = root.join("Users/runner/.config/nix/nix.conf");
    let xdg_user_config = root.join("Users/runner/Library/Application Support/Nix/nix/nix.conf");
    let nix_calls = root.join("nix-calls");
    let json = format!(
        "{{\"substituters\":{{\"value\":%s}},\"trusted-public-keys\":{{\"value\":[\"{CACHE_KEY}\"]}},\"require-sigs\":{{\"value\":true}},\"system\":{{\"value\":\"{system}\"}},\"flake-registry\":{{\"value\":\"https://channels.nixos.org/flake-registry.json\"}}}}"
    );
    executable(
        root,
        "/usr/bin/nix",
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{nix_calls}'\nif [ \"$1\" = --version ]; then echo 'nix (Nix) 2.32.3'; exit 0; fi\nif [ \"$3\" = config ] && [ \"$4\" = show ]; then\n  if grep -qs '{selected}' '{system_config}' '{user_config}' '{xdg_user_config}'; then subs='[\"{selected}\",\"https://cache.nixos.org/\",\"https://custom.example/cache\"]'; else subs='[\"https://cache.nixos.org/\",\"https://custom.example/cache\"]'; fi\n  printf '{json}\\n' \"$subs\"; exit 0\nfi\nif [ \"$3\" = store ] && [ \"$4\" = ping ]; then exit 0; fi\nif [ \"$3\" = path-info ]; then exit 0; fi\nif [ \"$3\" = store ] && [ \"$4\" = ls ]; then printf '%s\\n' '{store_path}'; exit 0; fi\nexit 64\n",
            system_config = system_config.display(),
            user_config = user_config.display(),
            xdg_user_config = xdg_user_config.display(),
            nix_calls = nix_calls.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/nix-store",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --query ]; then echo '{store_path}'; exit 0; fi\nexit 64\n"
        ),
    );
    executable(
        root,
        "/usr/bin/nix-channel",
        "#!/bin/sh\nif [ \"$1\" = --list ]; then echo 'nixpkgs https://channels.nixos.org/nixpkgs-25.11-darwin'; exit 0; fi\nexit 64\n"
            .into(),
    );
    let marker = root.join("launchctl-calls");
    executable(
        root,
        "/usr/bin/launchctl",
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
            marker.display()
        ),
    );
    marker
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/home/developer")
}

fn macos_runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/Users/runner")
}

fn selection_for(tool_id: &str, url: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "nix-test".into(),
        tool_id: tool_id.into(),
        upstream_id: "nix-channels--binary-cache".into(),
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

fn selection(url: &str) -> MirrorSelection {
    selection_for("nix", url)
}

#[test]
fn single_user_plan_preserves_keys_channels_and_custom_cache_and_is_idempotent() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let selected = "https://mirrors.ustc.edu.cn/nix-channels/store";
    install_nix(root, "x86_64-linux", selected, false, 0, 0);
    let original = format!(
        "# user policy\ntrusted-public-keys = {CACHE_KEY}\nsubstituters = https://cache.nixos.org/ https://custom.example/cache # ordered\n"
    );
    let config = write(
        root,
        "/home/developer/.config/nix/nix.conf",
        original.as_bytes(),
    );
    let context = context(root, Architecture::X86_64, "debian");
    let adapter = NixAdapter;
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
    assert!(current.sources.iter().any(|source| {
        source.url == "https://channels.nixos.org/nixpkgs-unstable"
            && source.metadata["configuration_surface"] == ["channel"]
    }));
    assert!(current.sources.iter().any(|source| {
        source.url == "https://channels.nixos.org/flake-registry.json"
            && source.metadata["configuration_surface"] == ["flake-registry"]
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts["nix-channels--binary-cache"][0]["narinfo_hash"],
        "aasbksznz37vw5pb26wq86209q5cmza8"
    );

    let chosen = [selection(selected)];
    let plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(!plan.requires_elevation);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("trusted-public-keys = {CACHE_KEY}")));
    assert!(rendered.contains(&format!(
        "substituters = {selected} https://cache.nixos.org/ https://custom.example/cache # ordered"
    )));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Nix user plan should change nix.conf")
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
    assert_eq!(fs::read_to_string(config).unwrap(), original);
}

#[test]
fn multi_user_plan_moves_one_reviewed_mirror_to_base_and_failure_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let selected = "https://mirror.sjtu.edu.cn/nix-channels/store";
    install_nix(root, "x86_64-linux", selected, true, 0, 7);
    let original = b"substituters = https://custom.example/first https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store https://cache.nixos.org/\nextra-substituters = https://mirrors.nju.edu.cn/nix-channels/store https://custom.example/last\n";
    let config = write(root, "/etc/nix/nix.conf", original);
    let context = context(root, Architecture::X86_64, "ubuntu");
    let adapter = NixAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::System
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(selected)])
        .unwrap();
    assert!(plan.requires_elevation);
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!(
        "substituters = https://custom.example/first {selected} https://cache.nixos.org/"
    )));
    assert!(rendered.contains("extra-substituters = https://custom.example/last"));
    assert_eq!(rendered.matches(selected).count(), 1);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Nix system plan should change nix.conf")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn architecture_signature_policy_and_declarative_nixos_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nix(
        root,
        "aarch64-linux",
        "https://mirrors.ustc.edu.cn/nix-channels/store",
        false,
        0,
        0,
    );
    let x86_context = context(root, Architecture::X86_64, "debian");
    let adapter = NixAdapter;
    let runtime = runtime(root);
    let detected = adapter.detect(&x86_context, &runtime).unwrap().unwrap();
    let error = adapter
        .read_current(&x86_context, &runtime, &detected, ConfigurationScope::User)
        .unwrap_err();
    assert!(error.to_string().contains("aarch64-linux"));

    let arm_context = context(root, Architecture::Arm64, "debian");
    let nix_script = root.join("usr/bin/nix");
    let original_script = fs::read_to_string(&nix_script).unwrap();
    fs::write(
        &nix_script,
        original_script.replace(
            "\"require-sigs\":{\"value\":true}",
            "\"require-sigs\":{\"value\":false}",
        ),
    )
    .unwrap();
    let error = adapter
        .read_current(&arm_context, &runtime, &detected, ConfigurationScope::User)
        .unwrap_err();
    assert!(
        error.to_string().contains("require-sigs is disabled"),
        "{error}"
    );

    fs::write(
        &nix_script,
        original_script.replace(CACHE_KEY, "cache.nixos.org-1:unreviewed"),
    )
    .unwrap();
    let error = adapter
        .read_current(&arm_context, &runtime, &detected, ConfigurationScope::User)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical cache.nixos.org signing key")
    );
    fs::write(&nix_script, original_script).unwrap();

    let nixos = context(root, Architecture::Arm64, "nixos");
    let error = adapter
        .read_current(&nixos, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("nix.settings"));
}

#[test]
fn macos_multi_user_plan_reloads_launchd_and_restores_exact_state() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let selected = "https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store";
    let marker = install_macos_nix(root, "x86_64-darwin", selected, DARWIN_X86_STORE, true);
    let original = format!(
        "# daemon policy\ntrusted-public-keys = {CACHE_KEY}\nsubstituters = https://cache.nixos.org/ https://custom.example/cache # stable order\n"
    );
    let config = write(root, "/etc/nix/nix.conf", original.as_bytes());
    let context = macos_context(root, Architecture::X86_64);
    let adapter = NixMacosAdapter;
    let mut runtime = macos_runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.tool_id, "nix-macos");
    assert!(
        detected
            .evidence
            .iter()
            .any(|item| item.contains("org.nixos.nix-daemon"))
    );
    assert_eq!(
        adapter
            .default_scope_for(&context, &runtime, &detected)
            .unwrap(),
        ConfigurationScope::System
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.tool_id, "nix-macos");
    assert_eq!(request.adapter_key, "nix-macos");
    let probe = &request.probe_contexts["nix-channels--binary-cache"][0];
    assert_eq!(
        probe["darwin_probe_hash"],
        "4sv8vd71y21gic34irbqr4pp1xgdhqck"
    );
    assert_eq!(
        probe["darwin_nar_digest"],
        "8d1d176e8d926a1375badb681500497caa7b36156e0e2b75d5bd0e521a0818fa"
    );

    let choice = [selection_for("nix-macos", selected)];
    let plan = adapter.plan(&context, &current, &choice).unwrap();
    assert!(plan.requires_elevation);
    assert_eq!(
        plan.service_impact,
        mirrorswitch::plan::ServiceImpact::RestartRequired
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("macOS multi-user Nix plan should change nix.conf")
    };
    assert_eq!(
        fs::read_to_string(&marker).unwrap().trim(),
        "kickstart -k system/org.nixos.nix-daemon"
    );
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let nix_calls = fs::read_to_string(root.join("nix-calls")).unwrap();
    assert!(nix_calls.contains(&format!(
        "store ls --store {selected} --long --recursive {DARWIN_X86_STORE}"
    )));
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &choice)
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
    assert_eq!(fs::read_to_string(config).unwrap(), original);
    assert_eq!(fs::read_to_string(marker).unwrap().lines().count(), 2);
}

#[test]
fn macos_single_user_uses_xdg_config_and_arm64_darwin_probe() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let selected = "https://mirrors.nju.edu.cn/nix-channels/store";
    install_macos_nix(root, "aarch64-darwin", selected, DARWIN_ARM_STORE, false);
    let xdg = "/Users/runner/Library/Application Support/Nix";
    let original = b"substituters = https://cache.nixos.org/ https://custom.example/cache\n";
    let config = write(
        root,
        "/Users/runner/Library/Application Support/Nix/nix/nix.conf",
        original,
    );
    let context = macos_context(root, Architecture::Arm64);
    let adapter = NixMacosAdapter;
    let mut runtime = macos_runtime(root)
        .with_environment(BTreeMap::from([("XDG_CONFIG_HOME".into(), xdg.into())]));
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
    assert_eq!(
        current.documents[0].path,
        PathBuf::from("/Users/runner/Library/Application Support/Nix/nix/nix.conf")
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts["nix-channels--binary-cache"][0];
    assert_eq!(
        probe["darwin_probe_hash"],
        "mxawknsavjm2cfw3imi3g58497nkfiky"
    );
    assert_eq!(
        probe["darwin_nar_file"],
        "0mf6jiwbrgiimzjp63bbh5d73x848ynbx79ijbxhxqs42bp5nkbv.nar.xz"
    );
    let choice = [selection_for("nix-macos", selected)];
    let plan = adapter.plan(&context, &current, &choice).unwrap();
    assert!(!plan.requires_elevation);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("macOS single-user Nix plan should change nix.conf")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let nix_calls = fs::read_to_string(root.join("nix-calls")).unwrap();
    assert!(nix_calls.contains(&format!(
        "store ls --store {selected} --long --recursive {DARWIN_ARM_STORE}"
    )));
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn macos_rejects_container_conflicting_daemons_and_environment_overrides() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_macos_nix(
        root,
        "x86_64-darwin",
        "https://mirrors.nju.edu.cn/nix-channels/store",
        DARWIN_X86_STORE,
        true,
    );
    let adapter = NixMacosAdapter;
    let mut context = macos_context(root, Architecture::X86_64);
    context.environment = ExecutionEnvironment::Container;
    assert!(adapter.detect(&context, &macos_runtime(root)).is_err());

    context.environment = ExecutionEnvironment::Host;
    write(
        root,
        "/Library/LaunchDaemons/systems.determinate.nix-daemon.plist",
        b"<plist/>\n",
    );
    assert!(
        adapter
            .detect(&context, &macos_runtime(root))
            .unwrap_err()
            .to_string()
            .contains("both upstream and Determinate")
    );

    fs::remove_file(root.join("Library/LaunchDaemons/systems.determinate.nix-daemon.plist"))
        .unwrap();
    write(
        root,
        "/etc/nix/nix.conf",
        b"substituters = https://cache.nixos.org/\n",
    );
    let runtime = macos_runtime(root).with_environment(BTreeMap::from([(
        "NIX_CONFIG".into(),
        "substituters = https://private.example".into(),
    )]));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::System,)
            .unwrap_err()
            .to_string()
            .contains("NIX_CONFIG")
    );
}

#[test]
fn embedded_catalog_has_four_signed_arch_specific_cache_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "nix"
                && candidate.upstream_id == "nix-channels--binary-cache"
                && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 4);
    assert!(candidates.iter().all(|candidate| {
        candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints[0].url.ends_with("/nix-channels/store/")
            && candidate.probes.len() == 2
            && candidate.probes[0].path == "/nix-cache-info"
            && candidate.probes[0].contains.as_deref() == Some("StoreDir: /nix/store")
            && candidate.probes[1].path == "/{narinfo_hash}.narinfo"
            && candidate.probes[1].contains.as_deref() == Some("Sig: cache.nixos.org-1:")
    }));

    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "nix-macos")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(
        tool.supported_scopes,
        [ConfigurationScope::System, ConfigurationScope::User]
    );
    let darwin = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "nix-macos"
                && candidate.upstream_id == "nix-channels--binary-cache"
                && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(darwin.len(), 2);
    assert_eq!(
        darwin
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["nju", "tuna"])
    );
    assert!(darwin.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Macos]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 4
            && candidate.probes[1].path == "/{darwin_probe_hash}.narinfo"
            && candidate.probes[3].path == "/nar/{darwin_nar_file}"
    }));
}
