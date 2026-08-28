use std::{fmt, path::PathBuf};

use crate::catalog::{ConfigurationScope, Endpoint};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedTool {
    pub tool_id: String,
    pub executable: PathBuf,
    pub version: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentConfiguration {
    pub tool_id: String,
    pub scope: ConfigurationScope,
    pub sources: Vec<ConfiguredSource>,
    pub files: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredSource {
    pub upstream_id: Option<String>,
    pub url: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorSelection {
    pub tool_id: String,
    pub upstream_id: String,
    pub provider_id: String,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ChangePlan {
    pub adapter_key: String,
    pub tool_id: String,
    pub scope: ConfigurationScope,
    pub changes: Vec<PlannedFileChange>,
    pub requires_elevation: bool,
    pub service_impact: ServiceImpact,
}

impl fmt::Debug for ChangePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangePlan")
            .field("adapter_key", &self.adapter_key)
            .field("tool_id", &self.tool_id)
            .field("scope", &self.scope)
            .field("changes", &self.changes)
            .field("requires_elevation", &self.requires_elevation)
            .field("service_impact", &self.service_impact)
            .finish()
    }
}

/// Proposed bytes remain in memory for apply, but Debug output never exposes
/// them because configuration can contain private repository credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct PlannedFileChange {
    pub target: PathBuf,
    pub expected_digest: Option<String>,
    pub new_contents: Vec<u8>,
    pub summary: String,
}

impl fmt::Debug for PlannedFileChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlannedFileChange")
            .field("target", &self.target)
            .field("expected_digest", &self.expected_digest)
            .field(
                "new_contents",
                &format_args!("<redacted:{} bytes>", self.new_contents.len()),
            )
            .field("summary", &self.summary)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceImpact {
    None,
    ReloadRequired,
    RestartRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionReceipt {
    pub transaction_id: String,
    pub adapter_key: String,
    pub tool_id: String,
    pub backups: Vec<BackupRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRecord {
    pub original: PathBuf,
    pub backup: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub valid: bool,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreResult {
    pub restored: bool,
    pub summary: String,
}
