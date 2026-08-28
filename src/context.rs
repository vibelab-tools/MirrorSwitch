use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Operating systems understood by the shared catalog schema.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperatingSystem {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    X86_64,
    Arm64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionEnvironment {
    Host,
    Container,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Distribution {
    /// Stable machine identifier such as `debian`, `ubuntu`, or `alpine`.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_codename: Option<String>,
    #[serde(default)]
    pub id_like: Vec<String>,
}

/// Facts detected from the current machine before an adapter is selected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemContext {
    pub os: OperatingSystem,
    pub architecture: Architecture,
    pub environment: ExecutionEnvironment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<Distribution>,
    /// Root used for controlled tests or an alternate filesystem view.
    pub root: PathBuf,
}
