#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{GuixAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const CI_KEY: &str = "8D156F295D24B0D9A86FA5741A840FF2D24F60F7B6C4134814AD55625971B394";
const BORDEAUX_KEY: &str = "7D602902D3A2DBB83F8A0FB98602A754C5493B0B778C8D1DD4E0F41DE14DE34F";
const CI_UPSTREAM: &str = "guix--static-files";
const BORDEAUX_UPSTREAM: &str = "guix-bordeaux--static-files";
const CI_MIRROR: &str = "https://mirror.sjtu.edu.cn/guix";
const BORDEAUX_MIRROR: &str = "https://mirror.sjtu.edu.cn/guix-bordeaux";

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

fn install_guix(root: &Path, weather_exit: i32) {
    let drop_in = root.join("etc/systemd/system/guix-daemon.service.d/mirrorswitch.conf");
    let system_unit = root.join("etc/systemd/system/guix-daemon.service");
    executable(
        root,
        "/usr/bin/guix",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'guix (GNU Guix) 1.4.0'; exit 0; fi\nif [ \"$1\" = weather ]; then\n  grep -qs '{CI_MIRROR}' '{drop_in}' '{system_unit}' || exit 65\n  grep -qs '{BORDEAUX_MIRROR}' '{drop_in}' '{system_unit}' || exit 66\n  [ {weather_exit} -eq 0 ] || exit {weather_exit}\n  echo '100.0% substitutes available (1 out of 1)'\n  exit 0\nfi\nexit 64\n",
            drop_in = drop_in.display(),
            system_unit = system_unit.display(),
        ),
    );
    write(
        root,
        "/etc/guix/acl",
        format!("(acl (public-key (ecc (curve Ed25519) (q #{CI_KEY}#))) (public-key (ecc (curve Ed25519) (q #{BORDEAUX_KEY}#))))\n")
            .as_bytes(),
    );
}

fn runtime(root: &Path) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")]).with_home("/home/developer")
}

fn selections() -> Vec<MirrorSelection> {
    [
        (CI_UPSTREAM, CI_MIRROR),
        (BORDEAUX_UPSTREAM, BORDEAUX_MIRROR),
    ]
    .into_iter()
    .map(|(upstream, url)| MirrorSelection {
        candidate_id: format!("guix-{upstream}"),
        tool_id: "guix".into(),
        upstream_id: upstream.into(),
        provider_id: "sjtug".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Artifacts,
            protocol: Protocol::Https,
            url: url.into(),
        }],
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    })
    .collect()
}

#[test]
fn vendor_unit_plan_preserves_channels_keys_and_is_idempotent_across_front_ends() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_guix(root, 0);
    write(
        root,
        "/usr/lib/systemd/system/guix-daemon.service",
        b"[Unit]\nDescription=GNU Guix daemon\n[Service]\nExecStart=/usr/bin/guix-daemon \\\n+  --build-users-group=_guixbuild --discover=no\nEnvironment=LC_ALL=C.UTF-8\n",
    );
    let channels = write(
        root,
        "/home/developer/.config/guix/channels.scm",
        b"(list (channel (name 'guix) (url \"https://git.savannah.gnu.org/git/guix.git\")))\n",
    );
    let original_channels = fs::read(&channels).unwrap();
    let original_acl = fs::read(root.join("etc/guix/acl")).unwrap();
    let context = context(root, Architecture::X86_64, "debian");
    let adapter = GuixAdapter;
    let mut runtime = runtime(root);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("guix (GNU Guix) 1.4.0"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    assert!(current.sources.iter().any(|source| {
        source.url == "https://git.savannah.gnu.org/git/guix.git"
            && source.metadata["configuration_surface"] == ["channel"]
    }));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [CI_UPSTREAM, BORDEAUX_UPSTREAM]);
    assert_eq!(
        request.probe_contexts[CI_UPSTREAM][0]["store_hash"],
        "s5pd3rnzymliafb4la5sca63j86xs0y0"
    );

    let chosen = selections();
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert_eq!(cli_plan.changes.len(), 1);
    assert!(cli_plan.requires_elevation);
    assert_eq!(
        cli_plan.changes[0].target,
        root.join("etc/systemd/system/guix-daemon.service.d/mirrorswitch.conf")
    );
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("ExecStart=\n"));
    assert!(rendered.contains(CI_MIRROR));
    assert!(rendered.contains(BORDEAUX_MIRROR));
    assert!(rendered.contains("--build-users-group=_guixbuild"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("Guix vendor unit should create a drop-in")
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
    assert_eq!(fs::read(&channels).unwrap(), original_channels);
    assert_eq!(fs::read(root.join("etc/guix/acl")).unwrap(), original_acl);
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert!(
        !root
            .join("etc/systemd/system/guix-daemon.service.d/mirrorswitch.conf")
            .exists()
    );
}

#[test]
fn local_unit_preserves_custom_order_and_failed_weather_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_guix(root, 7);
    let original = b"[Service]\n# local policy\nExecStart=/opt/guix/bin/guix-daemon --discover=no \\\n+ --substitute-urls='https://custom.example/first https://ci.guix.gnu.org/ https://bordeaux.guix.gnu.org https://custom.example/last' --max-jobs=4\n";
    let unit = write(root, "/etc/systemd/system/guix-daemon.service", original);
    let context = context(root, Architecture::Arm64, "ubuntu");
    let adapter = GuixAdapter;
    let mut runtime = runtime(root);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::System)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(
        request.probe_contexts[BORDEAUX_UPSTREAM][0]["store_hash"],
        "s2qnbdlrwlx47h5p6rxlylny1259srmj"
    );
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!(
        "https://custom.example/first {CI_MIRROR} {BORDEAUX_MIRROR} https://custom.example/last"
    )));
    assert!(rendered.contains("--max-jobs=4"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Guix local unit should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(unit).unwrap(), original);
}

#[test]
fn declarative_system_missing_key_and_foreign_drop_in_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_guix(root, 0);
    write(
        root,
        "/usr/lib/systemd/system/guix-daemon.service",
        b"[Service]\nExecStart=/usr/bin/guix-daemon\n",
    );
    let adapter = GuixAdapter;
    let runtime = runtime(root);
    let debian = context(root, Architecture::X86_64, "debian");
    let detected = adapter.detect(&debian, &runtime).unwrap().unwrap();

    fs::write(
        root.join("etc/guix/acl"),
        format!("(acl (public-key (ecc (q #{CI_KEY}#))))\n"),
    )
    .unwrap();
    let error = adapter
        .read_current(&debian, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains(BORDEAUX_KEY));

    write(
        root,
        "/etc/guix/acl",
        format!("(acl (q #{CI_KEY}#) (q #{BORDEAUX_KEY}#))\n").as_bytes(),
    );
    write(
        root,
        "/etc/systemd/system/guix-daemon.service.d/operator.conf",
        b"[Service]\nEnvironment=KEEP=1\n",
    );
    let error = adapter
        .read_current(&debian, &runtime, &detected, ConfigurationScope::System)
        .unwrap_err();
    assert!(error.to_string().contains("operator.conf"));

    fs::remove_file(root.join("etc/systemd/system/guix-daemon.service.d/operator.conf")).unwrap();
    let guix_system = context(root, Architecture::X86_64, "guix");
    let error = adapter
        .read_current(
            &guix_system,
            &runtime,
            &detected,
            ConfigurationScope::System,
        )
        .unwrap_err();
    assert!(error.to_string().contains("guix-service-type"));
}

#[test]
fn embedded_catalog_has_two_signed_arch_specific_substitute_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "guix" && candidate.delivery_mode == DeliveryMode::Mirror
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| {
        candidate.provider_id == "sjtug"
            && candidate.compatibility.operating_systems == [OperatingSystem::Linux]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints.len() == 1
            && candidate.endpoints[0].role == EndpointRole::Artifacts
            && candidate.probes.len() == 1
            && candidate.probes[0].path == "/{store_hash}.narinfo"
            && candidate.probes[0]
                .contains
                .as_deref()
                .is_some_and(|value| value.starts_with("Signature: 1;"))
    }));
}
