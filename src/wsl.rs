use std::{
    path::PathBuf,
    process::{Command, Output},
};

use serde::Serialize;

#[cfg(windows)]
use std::{os::windows::ffi::OsStrExt, ptr::null_mut};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, REG_SZ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryValueExW,
    },
};

use crate::{AdapterError, Runtime};

const PROBE_SCRIPT: &str = r#"printf 'kernel=%s\n' "$(uname -r)"; printf 'uid=%s\n' "$(id -u)"; printf 'home=%s\n' "$HOME"; if command -v mirrorswitch >/dev/null 2>&1; then printf 'mirrorswitch=%s\n' "$(mirrorswitch --version)"; else printf 'mirrorswitch=\n'; fi"#;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WslDistribution {
    pub name: String,
    pub wsl_version: u8,
    pub kernel: String,
    pub user_id: u32,
    pub home: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirrorswitch_version: Option<String>,
    pub selected: bool,
}

pub fn discover(runtime: &dyn Runtime) -> Result<Vec<WslDistribution>, AdapterError> {
    let Some(program) = wsl_program(runtime) else {
        return Ok(Vec::new());
    };
    let names = if let Some(names) = runtime.wsl_distribution_names()? {
        names
    } else {
        let output = runtime.run(&program, &["--list".into(), "--quiet".into()])?;
        if !output.status.success() {
            return Err(AdapterError::Runtime(format!(
                "wsl.exe --list --quiet failed with status {}",
                output.status
            )));
        }
        decode_output(if output.stdout.is_empty() {
            &output.stderr
        } else {
            &output.stdout
        })?
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
    };
    let mut distributions = Vec::new();
    for name in names {
        validate_distribution_name(&name)?;
        let output = runtime.run(
            &program,
            &[
                "--distribution".into(),
                name.clone(),
                "--exec".into(),
                "sh".into(),
                "-c".into(),
                PROBE_SCRIPT.into(),
            ],
        )?;
        if !output.status.success() {
            return Err(AdapterError::Runtime(format!(
                "WSL distribution {name} probe failed with status {}",
                output.status
            )));
        }
        distributions.push(parse_probe(&name, &decode_output(&output.stdout)?)?);
    }
    distributions.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(distributions)
}

fn wsl_program(runtime: &dyn Runtime) -> Option<String> {
    if let Some(system_root) = runtime
        .environment_variable("SystemRoot")
        .filter(|value| !value.trim().is_empty())
    {
        let candidate = PathBuf::from(system_root).join("System32").join("wsl.exe");
        return Some(candidate.display().to_string());
    }
    runtime.command_exists("wsl.exe").then(|| "wsl.exe".into())
}

#[cfg(windows)]
pub(crate) fn registered_distribution_names() -> Result<Vec<String>, AdapterError> {
    const LXSS_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Lxss";
    const DISTRIBUTION_NAME: &str = "DistributionName";

    let path = wide(LXSS_PATH);
    let mut root = null_mut();
    let result = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut root) };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(Vec::new());
    }
    win32_result(result, "open the WSL registry root")?;
    let root = RegistryKey(root);
    let mut names = Vec::new();
    let mut index = 0;
    loop {
        let mut subkey_name = [0u16; 260];
        let mut length = subkey_name.len() as u32;
        let result = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                subkey_name.as_mut_ptr(),
                &mut length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if result == ERROR_NO_MORE_ITEMS {
            break;
        }
        win32_result(result, "enumerate WSL registry entries")?;
        index += 1;

        let mut subkey = null_mut();
        let mut subkey_name = subkey_name[..length as usize].to_vec();
        subkey_name.push(0);
        let result =
            unsafe { RegOpenKeyExW(root.0, subkey_name.as_ptr(), 0, KEY_READ, &mut subkey) };
        win32_result(result, "open a WSL distribution registry entry")?;
        let subkey = RegistryKey(subkey);
        if let Some(name) = query_registry_string(subkey.0, DISTRIBUTION_NAME)? {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(windows)]
struct RegistryKey(HKEY);

#[cfg(windows)]
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

#[cfg(windows)]
fn query_registry_string(key: HKEY, name: &str) -> Result<Option<String>, AdapterError> {
    let name = wide(name);
    let mut kind = 0;
    let mut byte_length = 0;
    let result = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null_mut(),
            &mut kind,
            null_mut(),
            &mut byte_length,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    win32_result(result, "read a WSL distribution name")?;
    if kind != REG_SZ || byte_length % 2 != 0 {
        return Err(AdapterError::Runtime(
            "WSL DistributionName registry value is not a UTF-16 string".into(),
        ));
    }
    let mut value = vec![0u16; byte_length as usize / 2];
    let result = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null_mut(),
            null_mut(),
            value.as_mut_ptr().cast(),
            &mut byte_length,
        )
    };
    win32_result(result, "read a WSL distribution name")?;
    value.truncate(byte_length as usize / 2);
    while value.last() == Some(&0) {
        value.pop();
    }
    String::from_utf16(&value)
        .map(Some)
        .map_err(|_| AdapterError::Runtime("WSL DistributionName is invalid UTF-16".into()))
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

#[cfg(windows)]
fn win32_result(result: u32, action: &str) -> Result<(), AdapterError> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "could not {action}: Windows error {result}"
        )))
    }
}

pub fn run_distribution(
    distribution: &str,
    program: &str,
    arguments: &[String],
) -> Result<Output, AdapterError> {
    validate_distribution_name(distribution)?;
    if program.is_empty() || program.chars().any(char::is_control) {
        return Err(AdapterError::InvalidConfiguration(
            "WSL program name is invalid".into(),
        ));
    }
    Command::new("wsl.exe")
        .arg("--distribution")
        .arg(distribution)
        .arg("--exec")
        .arg(program)
        .args(arguments)
        .output()
        .map_err(|error| AdapterError::Runtime(format!("could not run wsl.exe: {error}")))
}

pub fn validate_distribution_name(name: &str) -> Result<(), AdapterError> {
    if name.is_empty()
        || name.len() > 128
        || name.chars().any(|character| {
            character.is_control() || matches!(character, '/' | '\\' | ':' | '"' | '\'')
        })
    {
        return Err(AdapterError::InvalidConfiguration(
            "WSL distribution name is invalid".into(),
        ));
    }
    Ok(())
}

fn parse_probe(name: &str, text: &str) -> Result<WslDistribution, AdapterError> {
    let values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    let kernel = values
        .get("kernel")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdapterError::Runtime(format!("WSL distribution {name} has no kernel")))?
        .to_string();
    let user_id = values
        .get("uid")
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AdapterError::Runtime(format!("WSL distribution {name} has no user ID")))?;
    let home = values
        .get("home")
        .filter(|value| value.starts_with('/'))
        .map(PathBuf::from)
        .ok_or_else(|| AdapterError::Runtime(format!("WSL distribution {name} has no home")))?;
    let lower_kernel = kernel.to_ascii_lowercase();
    let wsl_version =
        if lower_kernel.contains("wsl2") || lower_kernel.contains("microsoft-standard") {
            2
        } else {
            1
        };
    let mirrorswitch_version = values
        .get("mirrorswitch")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    Ok(WslDistribution {
        name: name.into(),
        wsl_version,
        kernel,
        user_id,
        home,
        mirrorswitch_version,
        selected: false,
    })
}

fn decode_output(bytes: &[u8]) -> Result<String, AdapterError> {
    if bytes.windows(2).any(|pair| pair[1] == 0) {
        if bytes.len() % 2 != 0 {
            return Err(AdapterError::Runtime(
                "wsl.exe returned malformed UTF-16 output".into(),
            ));
        }
        let values = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .skip_while(|value| *value == 0xfeff)
            .collect::<Vec<_>>();
        String::from_utf16(&values)
            .map(|value| value.trim_matches('\0').to_owned())
            .map_err(|_| AdapterError::Runtime("wsl.exe returned invalid UTF-16".into()))
    } else {
        String::from_utf8(bytes.to_vec())
            .map(|value| value.trim_matches('\0').to_owned())
            .map_err(|_| AdapterError::Runtime("wsl.exe returned invalid UTF-8".into()))
    }
}
