use serde::{Deserialize, Serialize};

use crate::context::{Architecture, ExecutionEnvironment, OperatingSystem};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorCatalog {
    pub schema_version: u32,
    pub content_version: String,
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
    pub supported_scopes: Vec<ConfigurationScope>,
    pub composition: CompositionPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorCandidate {
    pub provider_id: String,
    pub upstream_id: String,
    pub tool_id: String,
    pub catalog_state: CatalogEntryState,
    pub endpoints: Vec<Endpoint>,
    pub compatibility: Compatibility,
    pub probes: Vec<ProbeSpec>,
    pub source_url: String,
    pub observed_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogEntryState {
    Cataloged,
    Partial,
}

/// Runtime evaluation is deliberately separate from catalog inventory state.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    LanguageRegistry,
    BinaryCache,
    ContainerRegistry,
    GitMirror,
    ReleaseArtifacts,
    StaticFiles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointRole {
    Metadata,
    Packages,
    Index,
    Artifacts,
    Registry,
    Git,
    Releases,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Https,
    Http,
    Git,
    Rsync,
    Oci,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationScope {
    System,
    User,
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
