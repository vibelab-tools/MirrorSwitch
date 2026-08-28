use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{Method, blocking::Client};
use serde::Serialize;
use thiserror::Error;

use crate::{
    catalog::{
        CandidateEvaluation, CatalogEntryState, CompositionPolicy, DeliveryMode, Endpoint,
        EndpointRole, HttpMethod, MirrorCandidate, MirrorCatalog, ProbeSpec, Protocol,
        ToolCatalogState,
    },
    context::SystemContext,
    plan::MirrorSelection,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionRequest {
    pub tool_id: String,
    pub adapter_key: String,
    pub context: SystemContext,
    pub tool_version: Option<String>,
    pub required_upstreams: Vec<String>,
    pub repository_versions: BTreeMap<String, String>,
    /// Per-upstream substitutions for declarative probe path placeholders.
    pub probe_contexts: BTreeMap<String, Vec<BTreeMap<String, String>>>,
    pub required_compatibility_evidence: Vec<CompatibilityDimension>,
    pub require_distribution: bool,
    pub allowed_protocols: Vec<Protocol>,
    pub required_endpoint_roles: Vec<EndpointRole>,
    pub allowed_delivery_modes: Vec<DeliveryMode>,
    pub composition_policy: CompositionPolicy,
    /// Per-upstream candidate IDs selected explicitly by the user.
    pub overrides: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompatibilityDimension {
    OperatingSystem,
    Architecture,
    Environment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeLimits {
    pub timeout: Duration,
    pub max_bytes: usize,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_bytes: 64 * 1024,
        }
    }
}

pub trait CandidateProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HttpCandidateProber;

impl CandidateProber for HttpCandidateProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        let client = Client::builder()
            .timeout(limits.timeout)
            .build()
            .map_err(|error| ProbeError::Http(error.to_string()))?;
        let started = Instant::now();
        let mut response = client
            .request(
                match method {
                    HttpMethod::Head => Method::HEAD,
                    HttpMethod::Get => Method::GET,
                },
                url,
            )
            .send()
            .map_err(map_reqwest_error)?;
        if method == HttpMethod::Get
            && response
                .content_length()
                .is_some_and(|length| length > limits.max_bytes as u64)
        {
            return Err(ProbeError::TooLarge {
                limit_bytes: limits.max_bytes,
            });
        }

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        if method == HttpMethod::Get {
            response
                .by_ref()
                .take(limits.max_bytes as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|error| ProbeError::Http(error.to_string()))?;
            if body.len() > limits.max_bytes {
                return Err(ProbeError::TooLarge {
                    limit_bytes: limits.max_bytes,
                });
            }
        }
        Ok(ProbeObservation {
            status,
            content_type,
            body,
            latency_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        })
    }
}

fn map_reqwest_error(error: reqwest::Error) -> ProbeError {
    if error.is_timeout() {
        ProbeError::Timeout
    } else {
        ProbeError::Http(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProbeError {
    #[error("probe timed out")]
    Timeout,
    #[error("probe response exceeds the {limit_bytes}-byte limit")]
    TooLarge { limit_bytes: usize },
    #[error("probe request failed: {0}")]
    Http(String),
}

pub struct MirrorSelector<'a, P> {
    catalog: &'a MirrorCatalog,
    prober: P,
    limits: ProbeLimits,
}

impl<'a> MirrorSelector<'a, HttpCandidateProber> {
    pub fn new(catalog: &'a MirrorCatalog) -> Self {
        Self::with_prober(catalog, HttpCandidateProber, ProbeLimits::default())
    }
}

impl<'a, P: CandidateProber> MirrorSelector<'a, P> {
    pub fn with_prober(catalog: &'a MirrorCatalog, prober: P, limits: ProbeLimits) -> Self {
        Self {
            catalog,
            prober,
            limits,
        }
    }

    pub fn select(&self, request: &SelectionRequest) -> Result<SelectionOutcome, SelectionError> {
        let measured_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.select_at(request, measured_at_unix_ms)
    }

    pub fn select_at(
        &self,
        request: &SelectionRequest,
        measured_at_unix_ms: u64,
    ) -> Result<SelectionOutcome, SelectionError> {
        validate_request(request)?;
        let tool = self
            .catalog
            .tools
            .iter()
            .find(|tool| tool.id == request.tool_id)
            .ok_or_else(|| SelectionError::UnknownTool(request.tool_id.clone()))?;
        if tool.state != ToolCatalogState::Supported {
            return Err(SelectionError::AdapterUnavailable(request.tool_id.clone()));
        }
        if tool.adapter_key != request.adapter_key {
            return Err(SelectionError::AdapterMismatch {
                tool_id: request.tool_id.clone(),
                expected: tool.adapter_key.clone(),
                actual: request.adapter_key.clone(),
            });
        }
        if tool.composition != request.composition_policy {
            return Err(SelectionError::CompositionConflict {
                tool_id: request.tool_id.clone(),
                catalog: tool.composition,
                adapter: request.composition_policy,
            });
        }

        let mut repositories = Vec::new();
        let mut provisional = Vec::new();
        for upstream_id in &request.required_upstreams {
            let candidates: Vec<_> = self
                .catalog
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.tool_id == request.tool_id && candidate.upstream_id == *upstream_id
                })
                .collect();
            let mut reports = Vec::new();
            let mut eligible = Vec::new();
            for candidate in candidates {
                let reasons = incompatibility_reasons(candidate, request);
                if !reasons.is_empty() {
                    reports.push(CandidateReport {
                        candidate_id: candidate.id.clone(),
                        provider_id: candidate.provider_id.clone(),
                        evaluation: CandidateEvaluation::Incompatible { reasons },
                    });
                    continue;
                }
                match self.probe_candidate(candidate, request) {
                    Ok(latency_ms) => {
                        reports.push(CandidateReport {
                            candidate_id: candidate.id.clone(),
                            provider_id: candidate.provider_id.clone(),
                            evaluation: CandidateEvaluation::Eligible { latency_ms },
                        });
                        eligible.push((candidate, latency_ms));
                    }
                    Err(reason) => reports.push(CandidateReport {
                        candidate_id: candidate.id.clone(),
                        provider_id: candidate.provider_id.clone(),
                        evaluation: CandidateEvaluation::ProbeFailed { reason },
                    }),
                }
            }
            eligible.sort_by(|(left, left_latency), (right, right_latency)| {
                left_latency
                    .cmp(right_latency)
                    .then_with(|| left.provider_id.cmp(&right.provider_id))
                    .then_with(|| left.id.cmp(&right.id))
            });

            let user_override = request.overrides.get(upstream_id);
            let mut selected: Vec<_> = match user_override {
                Some(candidate_id) => eligible
                    .into_iter()
                    .filter(|(candidate, _)| candidate.id == *candidate_id)
                    .take(1)
                    .collect(),
                None if request.composition_policy == CompositionPolicy::Single => {
                    eligible.into_iter().take(1).collect()
                }
                None => eligible,
            };
            let selected_ids: Vec<_> = selected
                .iter()
                .map(|(candidate, _)| candidate.id.clone())
                .collect();
            let failure_reason = if selected.is_empty() {
                Some(match user_override {
                    Some(candidate_id) => format!(
                        "user override {candidate_id} is absent, incompatible, or failed its content probe"
                    ),
                    None => "no compatible candidate passed every content probe".into(),
                })
            } else {
                None
            };
            provisional.extend(
                selected
                    .drain(..)
                    .map(|(candidate, latency_ms)| MirrorSelection {
                        candidate_id: candidate.id.clone(),
                        tool_id: request.tool_id.clone(),
                        upstream_id: upstream_id.clone(),
                        provider_id: candidate.provider_id.clone(),
                        endpoints: compatible_endpoints(candidate, request),
                        latency_ms,
                        selected_at_unix_ms: measured_at_unix_ms,
                        user_override: user_override.is_some(),
                    }),
            );
            repositories.push(RepositorySelectionReport {
                upstream_id: upstream_id.clone(),
                selected_candidate_ids: selected_ids,
                failure_reason,
                candidates: reports,
            });
        }

        let actionable = repositories
            .iter()
            .all(|repository| !repository.selected_candidate_ids.is_empty());
        let selections = if actionable { provisional } else { Vec::new() };
        Ok(SelectionOutcome {
            tool_id: request.tool_id.clone(),
            measured_at_unix_ms,
            actionable,
            no_change_reason: (!actionable).then(|| {
                "one or more required repositories have no validated mirror; no tool changes may be planned"
                    .into()
            }),
            selections,
            repositories,
        })
    }

    fn probe_candidate(
        &self,
        candidate: &MirrorCandidate,
        request: &SelectionRequest,
    ) -> Result<u64, String> {
        if candidate.probes.is_empty() {
            return Err("candidate has no repository content probe".into());
        }
        let allowed_protocols: HashSet<_> = request.allowed_protocols.iter().copied().collect();
        let mut total_latency = 0_u64;
        let empty_context = BTreeMap::new();
        let contexts = request
            .probe_contexts
            .get(&candidate.upstream_id)
            .filter(|contexts| !contexts.is_empty())
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(&empty_context));
        for context in contexts {
            for probe in &candidate.probes {
                let endpoint = candidate
                    .endpoints
                    .iter()
                    .filter(|endpoint| {
                        endpoint.role == probe.endpoint_role
                            && allowed_protocols.contains(&endpoint.protocol)
                    })
                    .min_by(|left, right| left.url.cmp(&right.url))
                    .ok_or_else(|| format!("no compatible {:?} endpoint", probe.endpoint_role))?;
                let path = expand_probe_path(&probe.path, context)?;
                let url = probe_url(endpoint, &path)?;
                let observation = self
                    .prober
                    .probe(probe.method, &url, self.limits)
                    .map_err(|error| error.to_string())?;
                validate_observation(probe, &observation)?;
                total_latency = total_latency.saturating_add(observation.latency_ms);
            }
        }
        Ok(total_latency)
    }
}

fn validate_request(request: &SelectionRequest) -> Result<(), SelectionError> {
    if request.tool_id.is_empty()
        || request.adapter_key.is_empty()
        || request.required_upstreams.is_empty()
        || request.required_compatibility_evidence.is_empty()
        || request.allowed_protocols.is_empty()
        || request.required_endpoint_roles.is_empty()
        || request.allowed_delivery_modes.is_empty()
    {
        return Err(SelectionError::InvalidRequest(
            "tool, adapter, upstreams, compatibility evidence, protocols, endpoint roles and delivery modes are required".into(),
        ));
    }
    let upstreams: HashSet<_> = request.required_upstreams.iter().collect();
    if upstreams.len() != request.required_upstreams.len() {
        return Err(SelectionError::InvalidRequest(
            "required upstream IDs must be unique".into(),
        ));
    }
    if request
        .overrides
        .keys()
        .any(|upstream| !upstreams.contains(upstream))
    {
        return Err(SelectionError::InvalidRequest(
            "every override must target a required upstream".into(),
        ));
    }
    Ok(())
}

fn incompatibility_reasons(candidate: &MirrorCandidate, request: &SelectionRequest) -> Vec<String> {
    let compatibility = &candidate.compatibility;
    let required_evidence: HashSet<_> = request
        .required_compatibility_evidence
        .iter()
        .copied()
        .collect();
    let mut reasons = Vec::new();
    if candidate.catalog_state == CatalogEntryState::Partial {
        reasons.push("catalog entry is partial".into());
    }
    if !request
        .allowed_delivery_modes
        .contains(&candidate.delivery_mode)
    {
        reasons.push(format!(
            "delivery mode {:?} is not supported by the adapter",
            candidate.delivery_mode
        ));
    }
    if compatibility.operating_systems.is_empty() {
        if required_evidence.contains(&CompatibilityDimension::OperatingSystem) {
            reasons.push("catalog has no operating-system compatibility evidence".into());
        }
    } else if !compatibility
        .operating_systems
        .contains(&request.context.os)
    {
        reasons.push("operating system does not match".into());
    }
    if compatibility.architectures.is_empty() {
        if required_evidence.contains(&CompatibilityDimension::Architecture) {
            reasons.push("catalog has no architecture compatibility evidence".into());
        }
    } else if !compatibility
        .architectures
        .contains(&request.context.architecture)
    {
        reasons.push("architecture does not match".into());
    }
    if compatibility.environments.is_empty() {
        if required_evidence.contains(&CompatibilityDimension::Environment) {
            reasons.push("catalog has no host/container compatibility evidence".into());
        }
    } else if !compatibility
        .environments
        .contains(&request.context.environment)
    {
        reasons.push("host/container environment does not match".into());
    }
    if request.require_distribution && compatibility.distributions.is_empty() {
        reasons.push("catalog has no distribution compatibility evidence".into());
    } else if !distribution_matches(candidate, request) {
        reasons.push("distribution, release, or codename does not match".into());
    }
    if compatibility
        .tool_version
        .as_ref()
        .is_some_and(|required| request.tool_version.as_ref() != Some(required))
    {
        reasons.push("tool version does not match".into());
    }
    match request.repository_versions.get(&candidate.upstream_id) {
        Some(_) if compatibility.repository_versions.is_empty() => {
            reasons.push("catalog has no repository-version compatibility evidence".into());
        }
        Some(version) if !compatibility.repository_versions.contains(version) => {
            reasons.push("repository version does not match".into());
        }
        None if !compatibility.repository_versions.is_empty() => {
            reasons.push("repository version is required but was not detected".into());
        }
        _ => {}
    }
    let allowed_protocols: HashSet<_> = request.allowed_protocols.iter().copied().collect();
    for role in &request.required_endpoint_roles {
        if !candidate.endpoints.iter().any(|endpoint| {
            endpoint.role == *role && allowed_protocols.contains(&endpoint.protocol)
        }) {
            reasons.push(format!("no compatible {role:?} endpoint"));
        }
        if !candidate
            .probes
            .iter()
            .any(|probe| probe.endpoint_role == *role)
        {
            reasons.push(format!("no repository content probe for {role:?}"));
        }
    }
    if candidate.probes.is_empty() {
        reasons.push("candidate has no repository content probe".into());
    }
    reasons
}

fn distribution_matches(candidate: &MirrorCandidate, request: &SelectionRequest) -> bool {
    if candidate.compatibility.distributions.is_empty() {
        return true;
    }
    let Some(distribution) = &request.context.distribution else {
        return false;
    };
    candidate
        .compatibility
        .distributions
        .iter()
        .any(|constraint| {
            (constraint.id == distribution.id || distribution.id_like.contains(&constraint.id))
                && (constraint.versions.is_empty()
                    || distribution
                        .version_id
                        .as_ref()
                        .is_some_and(|version| constraint.versions.contains(version)))
                && (constraint.codenames.is_empty()
                    || distribution
                        .version_codename
                        .as_ref()
                        .is_some_and(|codename| constraint.codenames.contains(codename)))
        })
}

fn compatible_endpoints(candidate: &MirrorCandidate, request: &SelectionRequest) -> Vec<Endpoint> {
    candidate
        .endpoints
        .iter()
        .filter(|endpoint| request.allowed_protocols.contains(&endpoint.protocol))
        .filter(|endpoint| request.required_endpoint_roles.contains(&endpoint.role))
        .cloned()
        .collect()
}

fn expand_probe_path(template: &str, values: &BTreeMap<String, String>) -> Result<String, String> {
    let mut expanded = String::with_capacity(template.len());
    let mut remainder = template;
    while let Some(open) = remainder.find('{') {
        let (prefix, after_open) = remainder.split_at(open);
        expanded.push_str(prefix);
        let after_open = &after_open[1..];
        let close = after_open
            .find('}')
            .ok_or_else(|| "probe path has an unterminated placeholder".to_owned())?;
        let (key, after_key) = after_open.split_at(close);
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(format!("probe path has invalid placeholder {{{key}}}"));
        }
        let value = values
            .get(key)
            .ok_or_else(|| format!("probe path requires {{{key}}}"))?;
        let safe_value = if key == "repository_path" {
            value
                .split('/')
                .filter(|segment| !segment.is_empty())
                .all(safe_probe_segment)
        } else {
            safe_probe_segment(value)
        };
        if value.is_empty() || !safe_value {
            return Err(format!(
                "probe value for {{{key}}} is not a safe path segment"
            ));
        }
        expanded.push_str(value);
        remainder = &after_key[1..];
    }
    if remainder.contains('}') {
        return Err("probe path has an unmatched closing brace".into());
    }
    expanded.push_str(remainder);
    Ok(expanded)
}

fn safe_probe_segment(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn probe_url(endpoint: &Endpoint, probe_path: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&endpoint.url)
        .map_err(|error| format!("invalid endpoint URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("content probes require HTTP or HTTPS".into());
    }
    let path = format!(
        "{}/{}",
        url.path().trim_end_matches('/'),
        probe_path.trim_start_matches('/')
    );
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.into())
}

fn validate_observation(probe: &ProbeSpec, observation: &ProbeObservation) -> Result<(), String> {
    if !probe.expected_status.contains(&observation.status) {
        return Err(format!("unexpected HTTP status {}", observation.status));
    }
    if let Some(expected) = &probe.expected_content_type {
        let actual = observation
            .content_type
            .as_deref()
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if actual.is_none_or(|actual| !actual.eq_ignore_ascii_case(expected)) {
            return Err(format!(
                "unexpected content type {}",
                actual.unwrap_or("<missing>")
            ));
        }
    }
    if let Some(expected) = &probe.contains {
        let expected = expected.as_bytes();
        if expected.is_empty() {
            return Err("repository metadata marker cannot be empty".into());
        }
        if !observation
            .body
            .windows(expected.len())
            .any(|window| window == expected)
        {
            return Err("required repository metadata marker is missing".into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectionOutcome {
    pub tool_id: String,
    pub measured_at_unix_ms: u64,
    pub actionable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_change_reason: Option<String>,
    pub selections: Vec<MirrorSelection>,
    pub repositories: Vec<RepositorySelectionReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RepositorySelectionReport {
    pub upstream_id: String,
    pub selected_candidate_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub candidates: Vec<CandidateReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CandidateReport {
    pub candidate_id: String,
    pub provider_id: String,
    pub evaluation: CandidateEvaluation,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SelectionError {
    #[error("invalid selection request: {0}")]
    InvalidRequest(String),
    #[error("unknown tool {0}")]
    UnknownTool(String),
    #[error("tool adapter is not available: {0}")]
    AdapterUnavailable(String),
    #[error("tool {tool_id} expects adapter {expected}, got {actual}")]
    AdapterMismatch {
        tool_id: String,
        expected: String,
        actual: String,
    },
    #[error("tool {tool_id} catalog policy {catalog:?} conflicts with adapter policy {adapter:?}")]
    CompositionConflict {
        tool_id: String,
        catalog: CompositionPolicy,
        adapter: CompositionPolicy,
    },
}
