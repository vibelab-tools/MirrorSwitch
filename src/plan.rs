use std::{fmt, path::PathBuf};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::catalog::{ConfigurationScope, Endpoint};
use crate::transaction::content_digest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DetectedTool {
    pub tool_id: String,
    /// `None` is allowed when an adapter finds a valid configuration but the
    /// client is not currently callable on PATH.
    pub executable: Option<PathBuf>,
    pub version: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CurrentConfiguration {
    pub tool_id: String,
    pub scope: ConfigurationScope,
    pub sources: Vec<ConfiguredSource>,
    pub files: Vec<PathBuf>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConfiguredSource {
    pub upstream_id: Option<String>,
    pub url: String,
    pub enabled: bool,
}

impl fmt::Debug for ConfiguredSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredSource")
            .field("upstream_id", &self.upstream_id)
            .field("url", &redact_url(&self.url))
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl Serialize for ConfiguredSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConfiguredSource", 3)?;
        state.serialize_field("upstream_id", &self.upstream_id)?;
        state.serialize_field("url", &redact_url(&self.url))?;
        state.serialize_field("enabled", &self.enabled)?;
        state.end()
    }
}

fn redact_url(value: &str) -> String {
    let mut redacted = value.to_owned();
    if let Some(scheme) = redacted.find("://") {
        let authority_start = scheme + 3;
        let authority_end = redacted[authority_start..]
            .find(['/', '?', '#'])
            .map_or(redacted.len(), |offset| authority_start + offset);
        if let Some(at) = redacted[authority_start..authority_end].rfind('@') {
            redacted.replace_range(authority_start..authority_start + at, "<redacted>");
        }
    }
    if let Some(query) = redacted.find('?') {
        let fragment = redacted[query..].find('#').map(|offset| query + offset);
        match fragment {
            Some(fragment) => redacted.replace_range(query..fragment, "?<redacted>"),
            None => redacted.replace_range(query.., "?<redacted>"),
        }
    }
    if let Some(fragment) = redacted.find('#') {
        redacted.replace_range(fragment.., "#<redacted>");
    }
    redacted
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MirrorSelection {
    pub candidate_id: String,
    pub tool_id: String,
    pub upstream_id: String,
    pub provider_id: String,
    pub endpoints: Vec<Endpoint>,
    pub latency_ms: u64,
    pub selected_at_unix_ms: u64,
    pub user_override: bool,
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

impl ChangePlan {
    /// Builds a safe-to-display plan without exposing configuration contents.
    pub fn preview(&self) -> ChangePlanPreview {
        ChangePlanPreview {
            adapter_key: self.adapter_key.clone(),
            tool_id: self.tool_id.clone(),
            scope: self.scope,
            requires_elevation: self.requires_elevation,
            service_impact: self.service_impact,
            changes: self
                .changes
                .iter()
                .map(PlannedFileChange::preview)
                .collect(),
        }
    }
}

/// Proposed bytes remain in memory for apply, but Debug output never exposes
/// them because configuration can contain private repository credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct PlannedFileChange {
    pub target: PathBuf,
    /// Contents observed while planning. `None` means the file did not exist.
    pub old_contents: Option<Vec<u8>>,
    /// Unix permission bits observed while planning, when available.
    pub old_mode: Option<u32>,
    pub new_contents: Vec<u8>,
    /// Requested Unix permission bits. Existing mode is retained when omitted.
    pub new_mode: Option<u32>,
    pub summary: String,
}

impl PlannedFileChange {
    pub fn preview(&self) -> PlannedFilePreview {
        PlannedFilePreview {
            target: self.target.clone(),
            old: FileValuePreview::new(self.old_contents.as_deref(), self.old_mode),
            new: FileValuePreview::new(Some(&self.new_contents), self.new_mode.or(self.old_mode)),
            summary: self.summary.clone(),
        }
    }
}

impl fmt::Debug for PlannedFileChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlannedFileChange")
            .field("target", &self.target)
            .field(
                "old_contents",
                &self
                    .old_contents
                    .as_ref()
                    .map(|contents| format!("<redacted:{} bytes>", contents.len())),
            )
            .field("old_mode", &self.old_mode)
            .field(
                "new_contents",
                &format_args!("<redacted:{} bytes>", self.new_contents.len()),
            )
            .field("new_mode", &self.new_mode)
            .field("summary", &self.summary)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangePlanPreview {
    pub adapter_key: String,
    pub tool_id: String,
    pub scope: ConfigurationScope,
    pub requires_elevation: bool,
    pub service_impact: ServiceImpact,
    pub changes: Vec<PlannedFilePreview>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedFilePreview {
    pub target: PathBuf,
    pub old: FileValuePreview,
    pub new: FileValuePreview,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileValuePreview {
    pub exists: bool,
    pub bytes: usize,
    pub sha256: Option<String>,
    pub mode: Option<u32>,
}

impl FileValuePreview {
    fn new(contents: Option<&[u8]>, mode: Option<u32>) -> Self {
        Self {
            exists: contents.is_some(),
            bytes: contents.map_or(0, <[u8]>::len),
            sha256: contents.map(content_digest),
            mode,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceImpact {
    None,
    ReloadRequired,
    RestartRequired,
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
