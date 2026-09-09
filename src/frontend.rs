use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{ConfigurationScope, MirrorCatalog},
    context::SystemContext,
    detection::{DetectionReport, OverrideSource},
    plan::{ChangePlan, ChangePlanPreview, RestoreResult},
    selection::{CandidateProber, MirrorSelector, SelectionError, SelectionOutcome},
    transaction::{ApplyOutcome, RestoreReceipt, TransactionReceipt},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrontendSource {
    Cli,
    Configuration,
    Tui,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestInput {
    pub all: bool,
    pub tools: BTreeSet<String>,
    pub disabled_tools: BTreeSet<String>,
    pub categories: BTreeSet<String>,
    pub scopes: BTreeMap<String, ConfigurationScope>,
    pub overrides: BTreeMap<String, BTreeMap<String, String>>,
}

impl RequestInput {
    pub fn merge(&mut self, other: Self) {
        self.all |= other.all;
        self.tools.extend(other.tools);
        self.disabled_tools.extend(other.disabled_tools);
        self.categories.extend(other.categories);
        self.scopes.extend(other.scopes);
        for (tool, overrides) in other.overrides {
            self.overrides.entry(tool).or_default().extend(overrides);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NormalizedRequest {
    pub source: FrontendSource,
    pub tools: Vec<RequestedTool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestedTool {
    pub adapter_key: String,
    pub tool_id: String,
    pub scope: ConfigurationScope,
    pub overrides: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationFile {
    version: u32,
    #[serde(default)]
    all: bool,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    tools: Vec<ConfiguredTool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredTool {
    id: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    scope: Option<ConfigurationScope>,
    #[serde(default)]
    mirrors: BTreeMap<String, String>,
}

fn enabled_by_default() -> bool {
    true
}

pub fn load_configuration(path: &Path) -> Result<RequestInput, FrontendError> {
    let contents = fs::read(path).map_err(|source| FrontendError::ConfigurationIo {
        path: path.to_path_buf(),
        source,
    })?;
    let configuration: ConfigurationFile =
        serde_json::from_slice(&contents).map_err(|source| FrontendError::ConfigurationJson {
            path: path.to_path_buf(),
            source,
        })?;
    if configuration.version != 1 {
        return Err(FrontendError::ConfigurationVersion(configuration.version));
    }
    let mut input = RequestInput {
        all: configuration.all,
        categories: configuration.categories.into_iter().collect(),
        ..RequestInput::default()
    };
    for tool in configuration.tools {
        if tool.id.is_empty()
            || input.tools.contains(&tool.id)
            || input.disabled_tools.contains(&tool.id)
        {
            return Err(FrontendError::DuplicateTool(tool.id));
        }
        if tool.enabled {
            input.tools.insert(tool.id.clone());
        } else {
            input.disabled_tools.insert(tool.id.clone());
        }
        if let Some(scope) = tool.scope {
            input.scopes.insert(tool.id.clone(), scope);
        }
        if !tool.mirrors.is_empty() {
            input.overrides.insert(tool.id, tool.mirrors);
        }
    }
    Ok(input)
}

pub fn normalize_request(
    report: &DetectionReport,
    input: &RequestInput,
    source: FrontendSource,
) -> Result<NormalizedRequest, FrontendError> {
    for category in &input.categories {
        if !CATEGORY_NAMES.contains(&category.as_str()) {
            return Err(FrontendError::UnknownCategory(category.clone()));
        }
    }
    let available = report
        .selections
        .iter()
        .map(|selection| (selection.adapter_key.as_str(), selection))
        .collect::<BTreeMap<_, _>>();
    let explicit = input.all || !input.tools.is_empty() || !input.categories.is_empty();
    let mut selected = if explicit {
        BTreeSet::new()
    } else {
        report
            .selections
            .iter()
            .filter(|selection| selection.selected)
            .map(|selection| selection.adapter_key.clone())
            .collect()
    };
    if input.all {
        selected.extend(available.keys().map(|value| (*value).to_owned()));
    }
    for category in &input.categories {
        selected.extend(
            report
                .selections
                .iter()
                .filter(|selection| category_for(&selection.tool_id) == category)
                .map(|selection| selection.adapter_key.clone()),
        );
    }
    for tool in &input.tools {
        if !available.contains_key(tool.as_str()) {
            return Err(FrontendError::ToolUnavailable(tool.clone()));
        }
        selected.insert(tool.clone());
    }
    for tool in input.scopes.keys().chain(input.overrides.keys()) {
        if !available.contains_key(tool.as_str()) {
            return Err(FrontendError::ToolUnavailable(tool.clone()));
        }
    }
    for tool in &input.disabled_tools {
        selected.remove(tool);
    }

    let mut tools = Vec::new();
    for adapter_key in selected {
        let selection = available[adapter_key.as_str()];
        let scope = input
            .scopes
            .get(&adapter_key)
            .copied()
            .unwrap_or(selection.scope);
        tools.push(RequestedTool {
            adapter_key: adapter_key.clone(),
            tool_id: selection.tool_id.clone(),
            scope,
            overrides: input
                .overrides
                .get(&adapter_key)
                .cloned()
                .unwrap_or_default(),
        });
    }
    Ok(NormalizedRequest { source, tools })
}

const CATEGORY_NAMES: &[&str] = &["system", "language", "container", "infrastructure"];

pub fn category_for(tool_id: &str) -> &'static str {
    if matches!(
        tool_id,
        "apt"
            | "dnf"
            | "yum"
            | "pacman"
            | "zypper"
            | "apk"
            | "xbps"
            | "portage"
            | "nix"
            | "guix"
            | "flatpak"
            | "opkg"
    ) {
        "system"
    } else if matches!(
        tool_id,
        "containerd"
            | "docker-ce"
            | "docker-registry"
            | "podman-registry"
            | "kubernetes-images"
            | "kubernetes-packages"
    ) {
        "container"
    } else if matches!(
        tool_id,
        "ceph"
            | "elasticstack"
            | "gitlab-runner"
            | "grafana"
            | "influxdb"
            | "mariadb"
            | "mongodb"
            | "mysql"
            | "nginx"
            | "postgresql"
            | "ros"
            | "ros2"
            | "zabbix"
    ) {
        "infrastructure"
    } else {
        "language"
    }
}

pub struct PreparedExecution {
    pub context: SystemContext,
    pub source: FrontendSource,
    pub tools: Vec<PreparedTool>,
    pub skipped: Vec<SkippedTool>,
}

pub struct PreparedTool {
    pub adapter_key: String,
    pub selection: SelectionOutcome,
    pub plan: ChangePlan,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionPreview {
    pub context: SystemContext,
    pub source: FrontendSource,
    pub tools: Vec<ToolPreview>,
    pub skipped: Vec<SkippedTool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolPreview {
    pub adapter_key: String,
    pub selection: SelectionOutcome,
    pub plan: ChangePlanPreview,
}

#[derive(Clone, Debug, Serialize)]
pub struct SkippedTool {
    pub adapter_key: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<SelectionOutcome>,
}

impl PreparedExecution {
    pub fn preview(&self) -> ExecutionPreview {
        ExecutionPreview {
            context: self.context.clone(),
            source: self.source,
            tools: self
                .tools
                .iter()
                .map(|tool| ToolPreview {
                    adapter_key: tool.adapter_key.clone(),
                    selection: tool.selection.clone(),
                    plan: tool.plan.preview(),
                })
                .collect(),
            skipped: self.skipped.clone(),
        }
    }
}

pub fn prepare_execution<P: CandidateProber>(
    report: &DetectionReport,
    request: &NormalizedRequest,
    catalog: &MirrorCatalog,
    adapters: &[&dyn Adapter],
    prober: P,
) -> Result<PreparedExecution, FrontendError> {
    let selector = MirrorSelector::with_prober(catalog, prober, Default::default());
    let mut tools = Vec::new();
    let mut skipped = Vec::new();
    for requested in &request.tools {
        let adapter = adapters
            .iter()
            .find(|adapter| adapter.key() == requested.adapter_key)
            .ok_or_else(|| FrontendError::AdapterMissing(requested.adapter_key.clone()))?;
        if !adapter.supported_scopes().contains(&requested.scope) {
            return Err(FrontendError::UnsupportedScope {
                tool: requested.adapter_key.clone(),
                scope: requested.scope,
            });
        }
        let detected = report
            .tools
            .iter()
            .find(|tool| tool.adapter_key == requested.adapter_key)
            .ok_or_else(|| FrontendError::ToolUnavailable(requested.adapter_key.clone()))?;
        let current = detected
            .configurations
            .iter()
            .find(|configuration| configuration.scope == requested.scope)
            .ok_or_else(|| FrontendError::UnsupportedScope {
                tool: requested.adapter_key.clone(),
                scope: requested.scope,
            })?;
        let mut selection_request =
            adapter.selection_request(&report.context, &detected.detected, current)?;
        selection_request.overrides = requested.overrides.clone();
        let outcome = selector.select(&selection_request)?;
        if !outcome.actionable {
            skipped.push(SkippedTool {
                adapter_key: requested.adapter_key.clone(),
                reason: outcome
                    .no_change_reason
                    .clone()
                    .unwrap_or_else(|| "no compatible mirror passed verification".into()),
                selection: Some(outcome),
            });
            continue;
        }
        let plan = adapter.plan(&report.context, current, &outcome.selections)?;
        tools.push(PreparedTool {
            adapter_key: requested.adapter_key.clone(),
            selection: outcome,
            plan,
        });
    }
    Ok(PreparedExecution {
        context: report.context.clone(),
        source: request.source,
        tools,
        skipped,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplyReport {
    pub context: SystemContext,
    pub tools: Vec<ApplyToolReport>,
    pub skipped: Vec<SkippedTool>,
    pub successful: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestoreReport {
    pub adapter_key: String,
    pub receipt: RestoreReceipt,
    pub adapter: RestoreResult,
}

pub fn restore_execution(
    context: &SystemContext,
    transaction_id: &str,
    adapters: &[&dyn Adapter],
    runtime: &mut dyn Runtime,
) -> Result<RestoreReport, FrontendError> {
    let receipt = runtime.transaction_receipt(transaction_id)?;
    let [participant] = receipt.participants.as_slice() else {
        return Err(AdapterError::InvalidConfiguration(
            "explicit restore requires a transaction with exactly one adapter participant".into(),
        )
        .into());
    };
    let adapter = adapters
        .iter()
        .find(|adapter| {
            adapter.key() == participant.adapter_key && adapter.tool_id() == participant.tool_id
        })
        .ok_or_else(|| FrontendError::AdapterMissing(participant.adapter_key.clone()))?;
    let result = adapter.restore(context, runtime, &receipt)?;
    Ok(RestoreReport {
        adapter_key: participant.adapter_key.clone(),
        receipt: RestoreReceipt {
            transaction_id: receipt.transaction_id,
            restored_files: receipt.changed_files,
            verified: result.restored,
        },
        adapter: result,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ApplyToolReport {
    Applied {
        adapter_key: String,
        receipt: TransactionReceipt,
        verification: crate::plan::VerificationResult,
    },
    Unchanged {
        adapter_key: String,
    },
    Failed {
        adapter_key: String,
        stage: String,
        recovery: String,
        error: String,
    },
}

pub fn apply_execution(
    prepared: PreparedExecution,
    adapters: &[&dyn Adapter],
    runtime: &mut dyn Runtime,
) -> ApplyReport {
    let mut tools = Vec::new();
    for item in prepared.tools {
        let Some(adapter) = adapters
            .iter()
            .find(|adapter| adapter.key() == item.adapter_key)
        else {
            tools.push(ApplyToolReport::Failed {
                adapter_key: item.adapter_key,
                stage: "dispatch".into(),
                recovery: "not-applied".into(),
                error: "compiled adapter disappeared".into(),
            });
            continue;
        };
        match adapter.apply(&prepared.context, runtime, &item.plan) {
            Ok(ApplyOutcome::Unchanged) => tools.push(ApplyToolReport::Unchanged {
                adapter_key: item.adapter_key,
            }),
            Ok(ApplyOutcome::Applied(receipt)) => {
                match adapter.verify(&prepared.context, runtime, &receipt) {
                    Ok(verification) => tools.push(ApplyToolReport::Applied {
                        adapter_key: item.adapter_key,
                        receipt,
                        verification,
                    }),
                    Err(error) => tools.push(ApplyToolReport::Failed {
                        adapter_key: item.adapter_key,
                        stage: "verification".into(),
                        recovery: "adapter-restore-attempted".into(),
                        error: error.to_string(),
                    }),
                }
            }
            Err(error) => tools.push(ApplyToolReport::Failed {
                adapter_key: item.adapter_key,
                stage: "apply".into(),
                recovery: "transaction-rollback-or-no-write".into(),
                error: error.to_string(),
            }),
        }
    }
    let successful = tools
        .iter()
        .all(|item| !matches!(item, ApplyToolReport::Failed { .. }));
    ApplyReport {
        context: prepared.context,
        tools,
        skipped: prepared.skipped,
        successful,
    }
}

pub fn apply_detection_overrides(report: &mut DetectionReport, request: &NormalizedRequest) {
    let overrides = report
        .selections
        .iter()
        .map(|selection| {
            (
                selection.adapter_key.clone(),
                request
                    .tools
                    .iter()
                    .any(|tool| tool.adapter_key == selection.adapter_key),
            )
        })
        .collect();
    report.apply_overrides(
        &overrides,
        match request.source {
            FrontendSource::Tui => OverrideSource::Tui,
            FrontendSource::Cli | FrontendSource::Configuration => OverrideSource::Configuration,
        },
    );
}

#[derive(Debug, Error)]
pub enum FrontendError {
    #[error("could not read configuration {path}: {source}")]
    ConfigurationIo {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("invalid configuration {path}: {source}")]
    ConfigurationJson {
        path: std::path::PathBuf,
        source: serde_json::Error,
    },
    #[error("unsupported configuration version {0}; expected 1")]
    ConfigurationVersion(u32),
    #[error("configuration contains duplicate or empty tool {0}")]
    DuplicateTool(String),
    #[error("unknown category {0}")]
    UnknownCategory(String),
    #[error("tool {0} is not detected or operable")]
    ToolUnavailable(String),
    #[error("compiled adapter {0} is missing")]
    AdapterMissing(String),
    #[error("tool {tool} does not support scope {scope:?}")]
    UnsupportedScope {
        tool: String,
        scope: ConfigurationScope,
    },
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error(transparent)]
    Selection(#[from] SelectionError),
}
