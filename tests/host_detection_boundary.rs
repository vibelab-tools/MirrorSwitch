use std::{fs, path::PathBuf};

use mirrorswitch::{
    Runtime,
    adapters::compiled_adapters,
    detection::{HostDetectionOptions, OsRuntime, detect_host},
    platform::compiled_os,
};
use tempfile::tempdir;

#[test]
fn current_host_detection_matches_the_compiled_platform() {
    let options = HostDetectionOptions::current();
    assert_eq!(options.os, compiled_os());
    assert!(options.home.is_absolute());
    assert!(options.system_config.is_absolute());
    assert!(options.user_config.is_absolute());
    assert!(options.catalog_cache.is_absolute());
    assert!(options.transaction_root.is_absolute());

    let report = detect_host(&options, &compiled_adapters()).unwrap();
    assert_eq!(report.context.os, compiled_os());
    assert_eq!(report.context.root, PathBuf::from("/"));
    assert_eq!(report.layout.system, options.system_config);
    assert_eq!(report.layout.user, options.user_config);
    assert_eq!(report.permissions.elevated, options.elevated);
    assert_eq!(
        report.permissions.system_scope_requires_elevation,
        !options.elevated
    );

    if compiled_os() != mirrorswitch::context::OperatingSystem::Linux {
        let platform = report.context.distribution.as_ref().unwrap();
        assert!(matches!(platform.id.as_str(), "macos" | "windows"));
        assert!(
            platform
                .version_id
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        );
    }
}

#[test]
fn runtime_executes_the_native_command_convention() {
    let directory = tempdir().unwrap();
    #[cfg(windows)]
    let executable = {
        fs::write(
            directory.path().join("mirrorswitch-probe"),
            b"#!/bin/sh\necho wrong-command\n",
        )
        .unwrap();
        let path = directory.path().join("mirrorswitch-probe.cmd");
        fs::write(&path, b"@echo off\r\necho native-command\r\n").unwrap();
        path
    };
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.path().join("mirrorswitch-probe");
        fs::write(&path, b"#!/bin/sh\nprintf 'native-command\\n'\n").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    };

    let runtime = OsRuntime::new("/", vec![directory.path().to_path_buf()]);
    assert!(runtime.command_exists("mirrorswitch-probe"));
    let output = runtime.run("mirrorswitch-probe", &[]).unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "native-command"
    );
    let found = runtime.find_command("mirrorswitch-probe").unwrap();
    #[cfg(windows)]
    assert_eq!(
        found.to_string_lossy().to_ascii_lowercase(),
        executable.to_string_lossy().to_ascii_lowercase()
    );
    #[cfg(unix)]
    assert_eq!(found, executable);
}
