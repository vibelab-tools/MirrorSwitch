use std::{
    cell::RefCell,
    io::Cursor,
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
};

use mirrorswitch::{
    AdapterError, Runtime,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::{ConfigurationLayout, DetectionReport, PermissionContext},
    frontend::RequestInput,
    tui,
    wsl::{discover, validate_distribution_name},
};

#[cfg(unix)]
fn success_status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

#[cfg(windows)]
fn success_status() -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

fn output(stdout: Vec<u8>) -> Output {
    Output {
        status: success_status(),
        stdout,
        stderr: Vec::new(),
    }
}

fn utf16(value: &str) -> Vec<u8> {
    std::iter::once(0xfeff)
        .chain(value.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect()
}

struct WslRuntime {
    calls: RefCell<Vec<Vec<String>>>,
    system_path_only: bool,
}

impl Runtime for WslRuntime {
    fn command_exists(&self, command: &str) -> bool {
        if self.system_path_only {
            command != "wsl.exe" && command.replace('\\', "/").ends_with("/System32/wsl.exe")
        } else {
            command == "wsl.exe"
        }
    }

    fn environment_variable(&self, name: &str) -> Option<String> {
        (self.system_path_only && name == "SystemRoot").then(|| r"C:\Windows".into())
    }

    fn read(&self, _path: &Path) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(None)
    }

    fn run(&self, program: &str, arguments: &[String]) -> Result<Output, AdapterError> {
        if self.system_path_only {
            assert!(program.replace('\\', "/").ends_with("/System32/wsl.exe"));
        } else {
            assert_eq!(program, "wsl.exe");
        }
        self.calls.borrow_mut().push(arguments.to_vec());
        if arguments == ["--list", "--quiet"] {
            return Ok(output(utf16("Ubuntu\r\nDebian\r\n")));
        }
        let name = arguments.get(1).map(String::as_str).unwrap();
        match name {
            "Ubuntu" => Ok(output(
                b"kernel=6.6.87.2-microsoft-standard-WSL2\nuid=1000\nhome=/home/ubuntu\nmirrorswitch=mirrorswitch 0.1.0\n"
                    .to_vec(),
            )),
            "Debian" => Ok(output(
                b"kernel=4.4.0-19041-Microsoft\nuid=1001\nhome=/home/debian\nmirrorswitch=\n"
                    .to_vec(),
            )),
            _ => unreachable!(),
        }
    }
}

#[test]
fn wsl_inventory_decodes_utf16_and_keeps_each_distribution_unselected() {
    let runtime = WslRuntime {
        calls: RefCell::new(Vec::new()),
        system_path_only: false,
    };

    let distributions = discover(&runtime).unwrap();

    assert_eq!(
        distributions
            .iter()
            .map(|distribution| distribution.name.as_str())
            .collect::<Vec<_>>(),
        ["Debian", "Ubuntu"]
    );
    assert_eq!(distributions[0].wsl_version, 1);
    assert_eq!(distributions[0].home, PathBuf::from("/home/debian"));
    assert!(distributions[0].mirrorswitch_version.is_none());
    assert_eq!(distributions[1].wsl_version, 2);
    assert_eq!(distributions[1].user_id, 1000);
    assert_eq!(
        distributions[1].mirrorswitch_version.as_deref(),
        Some("mirrorswitch 0.1.0")
    );
    assert!(
        distributions
            .iter()
            .all(|distribution| !distribution.selected)
    );
    assert!(runtime.calls.borrow().iter().skip(1).all(|arguments| {
        arguments[0] == "--distribution" && arguments[2..5] == ["--exec", "sh", "-c"]
    }));
}

#[test]
fn wsl_inventory_falls_back_to_the_native_system32_launcher() {
    let runtime = WslRuntime {
        calls: RefCell::new(Vec::new()),
        system_path_only: true,
    };

    let distributions = discover(&runtime).unwrap();

    assert_eq!(distributions.len(), 2);
    assert_eq!(distributions[0].name, "Debian");
    assert_eq!(distributions[1].name, "Ubuntu");
}

#[test]
fn tui_shows_wsl_as_a_separate_explicit_target_hierarchy() {
    let runtime = WslRuntime {
        calls: RefCell::new(Vec::new()),
        system_path_only: false,
    };
    let report = DetectionReport {
        context: SystemContext {
            os: OperatingSystem::Windows,
            architecture: Architecture::X86_64,
            environment: ExecutionEnvironment::Host,
            distribution: Some(Distribution {
                id: "windows".into(),
                version_id: Some("Microsoft Windows [Version 10.0.26100.1]".into()),
                version_codename: None,
                id_like: Vec::new(),
            }),
            root: PathBuf::from("/"),
        },
        container: None,
        layout: ConfigurationLayout {
            system: PathBuf::from(r"C:\ProgramData"),
            user: PathBuf::from(r"C:\Users\test\AppData\Roaming"),
            project: None,
            service_management_available: true,
        },
        permissions: PermissionContext {
            effective_uid: None,
            elevated: false,
            system_scope_requires_elevation: true,
        },
        runtimes: Vec::new(),
        related_tools: Vec::new(),
        tools: Vec::new(),
        selections: Vec::new(),
        wsl_distributions: discover(&runtime).unwrap(),
        notices: Vec::new(),
    };
    let mut output = Vec::new();

    let request = tui::select_tools(
        &report,
        &RequestInput::default(),
        &mut Cursor::new(b"\n"),
        &mut output,
    )
    .unwrap()
    .unwrap();

    assert!(request.tools.is_empty());
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("WSL distributions (not selected; rerun with --wsl NAME)"));
    assert!(output.contains("[ ] Ubuntu wsl=2 uid=1000 home=/home/ubuntu"));
    assert!(output.contains("[ ] Debian wsl=1 uid=1001 home=/home/debian"));
}

#[test]
fn unsafe_distribution_names_are_rejected_before_process_launch() {
    for name in [
        "",
        "../Ubuntu",
        "Ubuntu\\root",
        "Ubuntu\nDebian",
        "C:Ubuntu",
    ] {
        assert!(validate_distribution_name(name).is_err());
    }
    assert!(validate_distribution_name("Ubuntu-24.04 LTS").is_ok());
}

#[cfg(unix)]
#[test]
fn cli_forwards_one_explicit_distribution_without_host_detection() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let directory = tempfile::tempdir().unwrap();
    let wsl = directory.path().join("wsl.exe");
    fs::write(
        &wsl,
        b"#!/bin/sh\nif [ \"$5\" = --version ]; then echo 'mirrorswitch 0.1.0'; exit 0; fi\nprintf '{\"delegated\":true,\"distribution\":\"%s\",\"command\":\"%s\"}\\n' \"$2\" \"$5\"\nexit 3\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&wsl).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wsl, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mirrorswitch"))
        .args(["plan", "--wsl", "Ubuntu", "--json"])
        .env("PATH", directory.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "delegated": true,
            "distribution": "Ubuntu",
            "command": "plan"
        })
    );
}
