#![cfg(target_os = "linux")]

use std::{
    fs,
    io::Cursor,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::AptAdapter,
    catalog::{ConfigurationScope, HttpMethod},
    catalog_update::EMBEDDED_CATALOG,
    detection::{LinuxDetectionOptions, OsRuntime, detect_linux},
    frontend::{
        ApplyToolReport, FrontendSource, RequestInput, apply_execution, load_configuration,
        normalize_request, prepare_execution,
    },
    selection::{CandidateProber, ProbeError, ProbeLimits, ProbeObservation},
    tui,
};
use tempfile::tempdir;

fn write(root: &Path, path: &str, contents: &[u8]) -> PathBuf {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn executable(root: &Path, path: &str, contents: &str) {
    let path = write(root, path, contents.as_bytes());
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn apt_report(root: &Path) -> mirrorswitch::detection::DetectionReport {
    write(
        root,
        "/etc/os-release",
        b"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n",
    );
    executable(root, "/usr/bin/apt-get", "#!/bin/sh\nexit 0\n");
    write(
        root,
        "/etc/apt/sources.list",
        b"deb [signed-by=/usr/share/keyrings/debian.gpg] http://deb.debian.org/debian bookworm main\ndeb http://security.debian.org/debian-security bookworm-security main\n",
    );
    let options = LinuxDetectionOptions {
        root: root.into(),
        home: PathBuf::from("/root"),
        project_dir: Some(PathBuf::from("/workspace")),
        executable_path: vec![PathBuf::from("/usr/bin")],
        architecture: "x86_64".into(),
        effective_uid: 0,
        container_hint: Some("docker".into()),
    };
    detect_linux(&options, &[&AptAdapter]).unwrap()
}

struct AptProber;

impl CandidateProber for AptProber {
    fn probe(
        &self,
        _method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let body = if url.ends_with("/InRelease") {
            b"-----BEGIN PGP SIGNED MESSAGE-----".to_vec()
        } else if url.contains("/binary-amd64/Release") {
            b"Architecture: amd64".to_vec()
        } else {
            return Err(ProbeError::Http(format!("unexpected probe {url}")));
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: None,
            body,
            latency_ms: if url.contains("tuna") { 1 } else { 5 },
        })
    }
}

#[test]
fn cli_configuration_and_tui_normalize_to_the_same_plan() {
    let directory = tempdir().unwrap();
    let report = apt_report(directory.path());
    let configuration_path = write(
        directory.path(),
        "/request.json",
        br#"{"version":1,"tools":[{"id":"apt","scope":"system","mirrors":{}}]}"#,
    );
    let configuration = load_configuration(&configuration_path).unwrap();
    let cli = RequestInput {
        tools: ["apt".into()].into_iter().collect(),
        scopes: [("apt".into(), ConfigurationScope::System)]
            .into_iter()
            .collect(),
        ..RequestInput::default()
    };
    let from_cli = normalize_request(&report, &cli, FrontendSource::Cli).unwrap();
    let from_configuration =
        normalize_request(&report, &configuration, FrontendSource::Configuration).unwrap();
    let mut tui_input = Cursor::new(b"\n");
    let mut tui_output = Vec::new();
    let from_tui = tui::select_tools(&report, &configuration, &mut tui_input, &mut tui_output)
        .unwrap()
        .unwrap();
    assert_eq!(from_cli.tools, from_configuration.tools);
    assert_eq!(from_configuration.tools, from_tui.tools);
    assert!(
        String::from_utf8(tui_output)
            .unwrap()
            .contains("environment=Container")
    );

    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let mut runtime = OsRuntime::new(directory.path(), vec![PathBuf::from("/usr/bin")])
        .with_home("/root")
        .with_project_dir("/workspace");
    let adapters: [&dyn Adapter; 1] = [&AptAdapter];
    let cli_plan = prepare_execution(&report, &from_cli, &catalog, &adapters, AptProber).unwrap();
    let configuration_plan =
        prepare_execution(&report, &from_configuration, &catalog, &adapters, AptProber).unwrap();
    let tui_plan = prepare_execution(&report, &from_tui, &catalog, &adapters, AptProber).unwrap();
    assert_eq!(cli_plan.tools[0].plan, configuration_plan.tools[0].plan);
    assert_eq!(configuration_plan.tools[0].plan, tui_plan.tools[0].plan);
    let mut rendered = Vec::new();
    tui::render_preview(&tui_plan.preview(), &mut rendered).unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(rendered.contains("mirror=tuna"));
    assert!(rendered.contains("elevation=true"));
    assert!(rendered.contains("old="));
    assert!(rendered.contains("new="));

    let source = directory.path().join("etc/apt/sources.list");
    let original = fs::read(&source).unwrap();
    executable(directory.path(), "/usr/bin/apt-get", "#!/bin/sh\nexit 7\n");
    let applied = apply_execution(cli_plan, &adapters, &mut runtime);
    assert!(!applied.successful);
    assert!(matches!(
        &applied.tools[0],
        ApplyToolReport::Failed { stage, recovery, .. }
            if stage == "verification" && recovery == "adapter-restore-attempted"
    ));
    assert_eq!(fs::read(source).unwrap(), original);
}

#[test]
fn configuration_version_unknown_fields_duplicates_and_unavailable_tools_are_errors() {
    let directory = tempdir().unwrap();
    let report = apt_report(directory.path());
    for (name, contents) in [
        ("version.json", r#"{"version":2}"#),
        ("unknown.json", r#"{"version":1,"unexpected":true}"#),
        (
            "duplicate.json",
            r#"{"version":1,"tools":[{"id":"apt"},{"id":"apt"}]}"#,
        ),
    ] {
        let path = write(directory.path(), name, contents.as_bytes());
        assert!(load_configuration(&path).is_err());
    }
    let unavailable = RequestInput {
        tools: ["not-installed".into()].into_iter().collect(),
        ..RequestInput::default()
    };
    assert!(
        normalize_request(&report, &unavailable, FrontendSource::Cli)
            .unwrap_err()
            .to_string()
            .contains("not detected")
    );
}

#[test]
fn binary_exposes_stable_read_only_commands_and_confirmation_gate() {
    let binary = env!("CARGO_BIN_EXE_mirrorswitch");
    let version = Command::new(binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with("mirrorswitch 0.1.0")
    );

    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for command in ["detect", "plan", "apply", "status", "restore", "tui"] {
        assert!(help.contains(command));
    }

    let status = Command::new(binary)
        .args(["status", "--offline", "--json"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let value: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["catalog"]["source"], "embedded-baseline");
    assert!(value["context"]["environment"].is_string());

    let detect = Command::new(binary)
        .args(["detect", "--offline", "--json", "--category", "system"])
        .output()
        .unwrap();
    assert!(detect.status.success());
    let value: serde_json::Value = serde_json::from_slice(&detect.stdout).unwrap();
    assert!(
        value["request"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["adapter_key"] == "apt")
    );

    let apply = Command::new(binary)
        .args(["apply", "--offline", "--json"])
        .output()
        .unwrap();
    assert_eq!(apply.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&apply.stdout).unwrap();
    assert!(value["error"].as_str().unwrap().contains("requires --yes"));

    let restore = Command::new(binary)
        .args(["restore", "not-a-transaction", "--json"])
        .output()
        .unwrap();
    assert_eq!(restore.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&restore.stdout).unwrap();
    assert!(value["error"].as_str().unwrap().contains("requires --yes"));
}
