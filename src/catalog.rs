use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::{Architecture, ExecutionEnvironment, OperatingSystem};

pub const CATALOG_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorCatalog {
    pub schema_version: u32,
    pub content_version: String,
    pub content_revision: u64,
    pub generated_at: String,
    pub providers: Vec<Provider>,
    pub upstreams: Vec<UpstreamRepository>,
    pub tools: Vec<Tool>,
    pub candidates: Vec<MirrorCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub display_name: String,
    pub catalog_source: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamRepository {
    pub id: String,
    pub family: String,
    pub display_name: String,
    pub content_kind: ContentKind,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    /// Must match an adapter compiled into the binary. Unknown keys remain
    /// cataloged but cannot become supported at runtime.
    pub adapter_key: String,
    pub display_name: String,
    pub state: ToolCatalogState,
    pub implementation_issue: String,
    pub supported_scopes: Vec<ConfigurationScope>,
    pub composition: CompositionPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorCandidate {
    pub id: String,
    pub provider_id: String,
    pub upstream_id: String,
    pub tool_id: String,
    pub catalog_state: CatalogEntryState,
    pub delivery_mode: DeliveryMode,
    pub raw_names: Vec<String>,
    pub endpoints: Vec<Endpoint>,
    pub compatibility: Compatibility,
    pub probes: Vec<ProbeSpec>,
    pub source_urls: Vec<String>,
    pub observed_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogEntryState {
    Cataloged,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolCatalogState {
    Planned,
    Supported,
}

/// Runtime evaluation is deliberately separate from catalog inventory state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CandidateEvaluation {
    AdapterUnavailable,
    Incompatible { reasons: Vec<String> },
    ProbeFailed { reason: String },
    Eligible { latency_ms: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub role: EndpointRole,
    pub protocol: Protocol,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub operating_systems: Vec<OperatingSystem>,
    pub architectures: Vec<Architecture>,
    pub environments: Vec<ExecutionEnvironment>,
    #[serde(default)]
    pub distributions: Vec<DistributionConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default)]
    pub repository_versions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionConstraint {
    pub id: String,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub codenames: Vec<String>,
}

/// Declarative HTTP probe. There is intentionally no program, script, or
/// command field in the remote schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSpec {
    pub endpoint_role: EndpointRole,
    pub method: HttpMethod,
    pub path: String,
    pub expected_status: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpMethod {
    Head,
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentKind {
    SystemPackages,
    RepositoryMetadata,
    LanguageRegistry,
    BinaryCache,
    ContainerRegistry,
    GitMirror,
    ReleaseArtifacts,
    ReleaseProxy,
    RawProxy,
    StaticFiles,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointRole {
    Metadata,
    Packages,
    Index,
    Artifacts,
    Registry,
    Git,
    Releases,
    Raw,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Https,
    Http,
    Git,
    Rsync,
    Oci,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryMode {
    Mirror,
    Proxy,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationScope {
    System,
    User,
    Site,
    Project,
    Environment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompositionPolicy {
    Single,
    OrderedFallback,
    Priority,
}

impl MirrorCatalog {
    /// Validates reference integrity and ensures only adapters compiled into
    /// the current binary can become actionable.
    pub fn validate(
        &self,
        adapter_allowlist: &HashSet<String>,
    ) -> Result<(), CatalogValidationError> {
        if self.schema_version != CATALOG_SCHEMA_VERSION {
            return Err(CatalogValidationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.content_version.is_empty()
            || self.content_revision == 0
            || self.generated_at.is_empty()
        {
            return Err(CatalogValidationError::MissingVersionMetadata);
        }

        let provider_ids = unique_ids(
            "provider",
            self.providers.iter().map(|item| item.id.as_str()),
        )?;
        let upstream_ids = unique_ids(
            "upstream",
            self.upstreams.iter().map(|item| item.id.as_str()),
        )?;
        let tool_ids = unique_ids("tool", self.tools.iter().map(|item| item.id.as_str()))?;
        unique_ids(
            "candidate",
            self.candidates.iter().map(|item| item.id.as_str()),
        )?;

        for tool in &self.tools {
            if tool.supported_scopes.is_empty()
                || tool.implementation_issue.is_empty()
                || tool.adapter_key.is_empty()
            {
                return Err(CatalogValidationError::InvalidTool(tool.id.clone()));
            }
            if tool.state == ToolCatalogState::Supported {
                if tool.id != tool.adapter_key {
                    return Err(CatalogValidationError::AdapterIdentityMismatch {
                        tool_id: tool.id.clone(),
                        adapter_key: tool.adapter_key.clone(),
                    });
                }
                if !adapter_allowlist.contains(&tool.adapter_key) {
                    return Err(CatalogValidationError::AdapterUnavailable {
                        tool_id: tool.id.clone(),
                        adapter_key: tool.adapter_key.clone(),
                    });
                }
            }
        }

        for candidate in &self.candidates {
            if !provider_ids.contains(candidate.provider_id.as_str()) {
                return Err(CatalogValidationError::UnknownReference {
                    candidate_id: candidate.id.clone(),
                    field: "provider_id",
                    value: candidate.provider_id.clone(),
                });
            }
            if !upstream_ids.contains(candidate.upstream_id.as_str()) {
                return Err(CatalogValidationError::UnknownReference {
                    candidate_id: candidate.id.clone(),
                    field: "upstream_id",
                    value: candidate.upstream_id.clone(),
                });
            }
            if !tool_ids.contains(candidate.tool_id.as_str()) {
                return Err(CatalogValidationError::UnknownReference {
                    candidate_id: candidate.id.clone(),
                    field: "tool_id",
                    value: candidate.tool_id.clone(),
                });
            }
            if candidate.endpoints.is_empty()
                || candidate.raw_names.is_empty()
                || candidate.source_urls.is_empty()
                || candidate.observed_at.is_empty()
            {
                return Err(CatalogValidationError::InvalidCandidate(
                    candidate.id.clone(),
                ));
            }
            for endpoint in &candidate.endpoints {
                let valid_protocol = match endpoint.protocol {
                    Protocol::Https => endpoint.url.starts_with("https://"),
                    Protocol::Http => endpoint.url.starts_with("http://"),
                    Protocol::Git => endpoint.url.starts_with("git://"),
                    Protocol::Rsync => endpoint.url.starts_with("rsync://"),
                    Protocol::Oci => endpoint.url.starts_with("oci://"),
                };
                if !valid_protocol {
                    return Err(CatalogValidationError::InvalidEndpoint {
                        candidate_id: candidate.id.clone(),
                        url: endpoint.url.clone(),
                    });
                }
            }
            for probe in &candidate.probes {
                if probe.path == "/"
                    || !probe.path.starts_with('/')
                    || probe.path.contains("://")
                    || probe.path.split('/').any(|segment| segment == "..")
                    || probe.expected_status.is_empty()
                    || probe
                        .expected_status
                        .iter()
                        .any(|status| !(100..=599).contains(status))
                    || probe.contains.as_ref().is_some_and(String::is_empty)
                    || (probe.method == HttpMethod::Head && probe.contains.is_some())
                    || !candidate.endpoints.iter().any(|endpoint| {
                        endpoint.role == probe.endpoint_role
                            && matches!(endpoint.protocol, Protocol::Http | Protocol::Https)
                    })
                {
                    return Err(CatalogValidationError::InvalidProbe {
                        candidate_id: candidate.id.clone(),
                        path: probe.path.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn unique_ids<'a>(
    kind: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<HashSet<&'a str>, CatalogValidationError> {
    let mut unique = HashSet::new();
    for value in values {
        if value.is_empty() || !unique.insert(value) {
            return Err(CatalogValidationError::DuplicateOrEmptyId {
                kind,
                value: value.into(),
            });
        }
    }
    Ok(unique)
}

#[derive(Debug, Error)]
pub enum CatalogValidationError {
    #[error("unsupported catalog schema version {0}")]
    UnsupportedSchema(u32),
    #[error("catalog version metadata is incomplete")]
    MissingVersionMetadata,
    #[error("{kind} identifier is empty or duplicated: {value}")]
    DuplicateOrEmptyId { kind: &'static str, value: String },
    #[error("catalog tool is invalid: {0}")]
    InvalidTool(String),
    #[error("tool {tool_id} cannot activate adapter {adapter_key}")]
    AdapterIdentityMismatch {
        tool_id: String,
        adapter_key: String,
    },
    #[error("tool {tool_id} requires adapter {adapter_key}, which is not compiled in")]
    AdapterUnavailable {
        tool_id: String,
        adapter_key: String,
    },
    #[error("candidate {candidate_id} references unknown {field} {value}")]
    UnknownReference {
        candidate_id: String,
        field: &'static str,
        value: String,
    },
    #[error("catalog candidate is incomplete: {0}")]
    InvalidCandidate(String),
    #[error("candidate {candidate_id} has an endpoint inconsistent with its protocol: {url}")]
    InvalidEndpoint { candidate_id: String, url: String },
    #[error("candidate {candidate_id} has an invalid declarative probe path: {path}")]
    InvalidProbe { candidate_id: String, path: String },
}
