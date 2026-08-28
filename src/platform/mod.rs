use crate::context::OperatingSystem;

/// OS for which this binary was compiled. Runtime distribution and container
/// detection are implemented separately by the Linux environment issue.
pub const fn compiled_os() -> OperatingSystem {
    #[cfg(target_os = "linux")]
    {
        OperatingSystem::Linux
    }
    #[cfg(target_os = "macos")]
    {
        OperatingSystem::Macos
    }
    #[cfg(target_os = "windows")]
    {
        OperatingSystem::Windows
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    compile_error!(
        "MirrorSwitch currently defines platform contracts for Linux, macOS, and Windows"
    );
}
