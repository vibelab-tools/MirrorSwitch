use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

pub(super) const REPOSITORY_DIRECTORY: &str = "/etc/yum.repos.d";

#[derive(Clone, Copy, Debug, Default)]
pub struct DnfAdapter;

impl Adapter for DnfAdapter {
    fn key(&self) -> &'static str {
        "dnf"
    }

    fn tool_id(&self) -> &'static str {
        "dnf"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        require_supported_context(context)?;
        let files = repo_paths(runtime)?;
        let command = dnf_command(runtime);
        if command.is_none() && files.is_empty() {
            return Ok(None);
        }
        if context
            .distribution
            .as_ref()
            .is_some_and(|distribution| distribution.id == "centos")
            && !has_enabled_centos_stream_repository(context, runtime, &files)?
        {
            return Ok(None);
        }
        let mut evidence = Vec::new();
        let mut version = None;
        if let Some(command) = command {
            let output = runtime.run(command, &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "{command} --version failed with status {}",
                    output.status
                )));
            }
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or(command)
                .trim()
                .to_owned();
            evidence.push(
                if command == "dnf5" || first_line.to_ascii_lowercase().contains("dnf5") {
                    "DNF5 command and configuration semantics".into()
                } else {
                    "DNF4 command and configuration semantics".into()
                },
            );
            version = (!first_line.is_empty()).then_some(first_line);
        }
        for path in &files {
            evidence.push(format!("DNF repository configuration {}", path.display()));
        }
        Ok(Some(DetectedTool {
            tool_id: "dnf".into(),
            executable: command.map(|command| PathBuf::from("/usr/bin").join(command)),
            version,
            evidence,
        }))
    }

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        require_supported_context(context)?;
        if scope != ConfigurationScope::System {
            return Err(AdapterError::Unsupported(
                "DNF only supports system scope".into(),
            ));
        }
        let mut sources = Vec::new();
        let mut documents = Vec::new();
        for path in repo_paths(runtime)? {
            let Some(contents) = runtime.read(&path)? else {
                continue;
            };
            let text = std::str::from_utf8(&contents).map_err(|_| {
                AdapterError::InvalidConfiguration(format!(
                    "DNF repository file {} is not UTF-8",
                    path.display()
                ))
            })?;
            let sections = parse_repo_file(text, context, classify_section)?;
            sources.extend(sections.into_iter().map(configured_source));
            documents.push(ConfigurationDocument {
                path,
                format: "dnf-repo".into(),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "dnf".into(),
            scope,
            files: documents
                .iter()
                .map(|document| document.path.clone())
                .collect(),
            sources,
            documents,
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "dnf" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "DNF selection requires a system-scope DNF configuration".into(),
            ));
        }
        let mut upstreams = BTreeSet::new();
        let mut probe_contexts = BTreeMap::new();
        for source in current.sources.iter().filter(|source| source.enabled) {
            let (Some(upstream), Some(paths)) = (
                source.upstream_id.as_ref(),
                source.metadata.get("repository_path"),
            ) else {
                continue;
            };
            for path in paths {
                let expanded = expand_repo_variables(path, context)?;
                probe_contexts
                    .entry(upstream.clone())
                    .or_insert_with(Vec::new)
                    .push(BTreeMap::from([("repository_path".into(), expanded)]));
                upstreams.insert(upstream.clone());
            }
        }
        for contexts in probe_contexts.values_mut() {
            contexts.sort();
            contexts.dedup();
        }
        if upstreams.is_empty() {
            return Err(AdapterError::Unsupported(
                "no supported Fedora, Rocky, or AlmaLinux DNF repositories were detected".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "dnf".into(),
            adapter_key: "dnf".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: upstreams.into_iter().collect(),
            repository_versions: BTreeMap::new(),
            probe_contexts,
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: true,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Metadata],
            allowed_delivery_modes: vec![DeliveryMode::Mirror],
            composition_policy: CompositionPolicy::Single,
            overrides: BTreeMap::new(),
        })
    }

    fn plan(
        &self,
        context: &SystemContext,
        current: &CurrentConfiguration,
        selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "dnf" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "DNF plan requires a system-scope DNF configuration".into(),
            ));
        }
        let selected = selected_endpoints(selection, "dnf")?;
        let mut changes = Vec::new();
        for document in &current.documents {
            if document.format != "dnf-repo" {
                return Err(AdapterError::Unsupported(format!(
                    "unknown DNF document format {}",
                    document.format
                )));
            }
            let text = std::str::from_utf8(&document.contents).map_err(|_| {
                AdapterError::InvalidConfiguration("DNF repository file is not UTF-8".into())
            })?;
            let sections = parse_repo_file(text, context, classify_section)?;
            let new_contents = rewrite_repo_file(text, sections, &selected)?;
            if new_contents == document.contents {
                continue;
            }
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "replace only recognized DNF repository location fields".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "dnf".into(),
            tool_id: "dnf".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
            service_impact: ServiceImpact::None,
        })
    }

    fn apply(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        runtime.apply_plan(plan)
    }

    fn verify(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let command = dnf_command(runtime)
            .ok_or_else(|| AdapterError::Runtime("DNF command disappeared".into()))?;
        let output = runtime.run(command, &["makecache".into(), "--refresh".into()])?;
        if output.status.success() {
            return Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{command} makecache validated repository metadata and GPG policy"
                ),
            });
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
        Err(AdapterError::Verification(format!(
            "{command} makecache failed with status {}; configuration restored: {restored}",
            output.status
        )))
    }

    fn restore(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: format!(
                "restored {} DNF repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct RepoSection {
    id: String,
    enabled: bool,
    url: String,
    upstream_id: Option<String>,
    repository_path: Option<String>,
    properties: BTreeMap<String, Vec<String>>,
    location: Option<LocationField>,
}

#[derive(Clone, Debug)]
struct LocationField {
    kind: LocationKind,
    value_range: Range<usize>,
    line_range: Range<usize>,
    line: String,
    indentation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocationKind {
    BaseUrl,
    MirrorList,
    Metalink,
}

#[derive(Clone, Debug)]
struct IniField {
    key: String,
    value: String,
    value_range: Range<usize>,
    line_range: Range<usize>,
    line: String,
    indentation: String,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("DNF requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("DNF requires distribution metadata".into()))?;
    if !matches!(
        distribution.id.as_str(),
        "fedora" | "rocky" | "almalinux" | "centos"
    ) {
        return Err(AdapterError::Unsupported(format!(
            "DNF adapter has no verified rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn dnf_command(runtime: &dyn Runtime) -> Option<&'static str> {
    if runtime.command_exists("dnf5") {
        Some("dnf5")
    } else if runtime.command_exists("dnf") {
        Some("dnf")
    } else {
        None
    }
}

pub(super) fn repo_paths(runtime: &dyn Runtime) -> Result<Vec<PathBuf>, AdapterError> {
    let mut paths: Vec<_> = runtime
        .list_files(Path::new(REPOSITORY_DIRECTORY))?
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("repo"))
        .collect();
    paths.sort();
    Ok(paths)
}

pub(super) fn parse_repo_file(
    text: &str,
    context: &SystemContext,
    classifier: fn(&str, &str, &SystemContext) -> Option<(String, String)>,
) -> Result<Vec<RepoSection>, AdapterError> {
    let mut sections = Vec::new();
    let mut current_id = None;
    let mut fields = Vec::new();
    let mut offset = 0;
    for raw_line in text.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') || trimmed.len() < 3 {
                return Err(AdapterError::InvalidConfiguration(
                    "RPM repository section header is malformed".into(),
                ));
            }
            if let Some(id) = current_id.take() {
                sections.push(build_section(id, &fields, context, classifier));
                fields.clear();
            }
            current_id = Some(trimmed[1..trimmed.len() - 1].to_owned());
        } else if !trimmed.is_empty() && !trimmed.starts_with(['#', ';']) {
            if current_id.is_none() {
                return Err(AdapterError::InvalidConfiguration(
                    "RPM field appears before a repository section".into(),
                ));
            }
            let equals = line.find('=').ok_or_else(|| {
                AdapterError::InvalidConfiguration("RPM repository field has no '='".into())
            })?;
            let key = line[..equals].trim().to_ascii_lowercase();
            if key.is_empty() {
                return Err(AdapterError::InvalidConfiguration(
                    "RPM repository field name is empty".into(),
                ));
            }
            let raw_value = &line[equals + 1..];
            let leading = raw_value.len() - raw_value.trim_start().len();
            let value = raw_value.trim().to_owned();
            let value_start = offset + equals + 1 + leading;
            fields.push(IniField {
                key,
                value,
                value_range: value_start..value_start + raw_value.trim().len(),
                line_range: offset..offset + raw_line.len(),
                line: line.to_owned(),
                indentation: line[..line.len() - line.trim_start().len()].to_owned(),
            });
        }
        offset += raw_line.len();
    }
    if let Some(id) = current_id {
        sections.push(build_section(id, &fields, context, classifier));
    }
    Ok(sections)
}

fn build_section(
    id: String,
    fields: &[IniField],
    context: &SystemContext,
    classifier: fn(&str, &str, &SystemContext) -> Option<(String, String)>,
) -> RepoSection {
    let enabled = fields
        .iter()
        .rev()
        .find(|field| field.key == "enabled")
        .is_none_or(|field| {
            !matches!(
                field.value.to_ascii_lowercase().as_str(),
                "0" | "false" | "no"
            )
        });
    let location = [
        ("baseurl", LocationKind::BaseUrl),
        ("metalink", LocationKind::Metalink),
        ("mirrorlist", LocationKind::MirrorList),
    ]
    .into_iter()
    .find_map(|(key, kind)| {
        fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| LocationField {
                kind,
                value_range: field.value_range.clone(),
                line_range: field.line_range.clone(),
                line: field.line.clone(),
                indentation: field.indentation.clone(),
            })
    });
    let url = location
        .as_ref()
        .and_then(|location| {
            fields
                .iter()
                .find(|field| field.value_range == location.value_range)
        })
        .map(|field| field.value.clone())
        .unwrap_or_default();
    let (upstream_id, repository_path) = classifier(&id, &url, context)
        .map(|(upstream, path)| (Some(upstream), Some(path)))
        .unwrap_or_default();
    let mut properties = BTreeMap::new();
    for field in fields.iter().filter(|field| {
        matches!(
            field.key.as_str(),
            "autorefresh" | "priority" | "gpgcheck" | "repo_gpgcheck" | "type"
        )
    }) {
        properties
            .entry(field.key.clone())
            .or_insert_with(Vec::new)
            .push(field.value.clone());
    }
    RepoSection {
        id,
        enabled,
        url,
        upstream_id,
        repository_path,
        properties,
        location,
    }
}

fn classify_section(id: &str, url: &str, context: &SystemContext) -> Option<(String, String)> {
    if !known_repository_location(url, context.distribution.as_ref()?.id.as_str()) {
        return None;
    }
    let id = id.to_ascii_lowercase();
    match context.distribution.as_ref()?.id.as_str() {
        "fedora" => {
            let path = match id.as_str() {
                "fedora" => "releases/$releasever/Everything/$basearch/os/",
                "updates" => "updates/$releasever/Everything/$basearch/",
                "updates-testing" => "updates/testing/$releasever/Everything/$basearch/",
                _ => return None,
            };
            Some(("fedora--repository-metadata".into(), path.into()))
        }
        "rocky" => {
            enterprise_repo_path(&id).map(|path| ("rocky--repository-metadata".into(), path))
        }
        "almalinux" => {
            enterprise_repo_path(&id).map(|path| ("almalinux--repository-metadata".into(), path))
        }
        "centos" if centos_stream_location(url) => {
            let directory = match id.as_str() {
                "baseos" => "BaseOS",
                "appstream" => "AppStream",
                "crb" => "CRB",
                _ => return None,
            };
            Some((
                "centos-stream--repository-metadata".into(),
                format!("$stream/{directory}/$basearch/os/"),
            ))
        }
        _ => None,
    }
}

fn centos_stream_location(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("$stream") || lower.contains("${stream}") || lower.contains("centos-stream")
}

fn enterprise_repo_path(id: &str) -> Option<String> {
    let id = id.strip_prefix("rocky-").unwrap_or(id);
    let directory = match id {
        "baseos" => "BaseOS",
        "appstream" => "AppStream",
        "crb" | "powertools" => "CRB",
        "extras" => "extras",
        _ => return None,
    };
    Some(format!("$releasever/{directory}/$basearch/os/"))
}

fn known_repository_location(value: &str, distribution: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let provider = [
        "mirrors.aliyun.com",
        "repo.huaweicloud.com",
        "mirrors.ustc.edu.cn",
        "mirrors.tuna.tsinghua.edu.cn",
        "mirrors.nju.edu.cn",
        "mirror.sjtu.edu.cn",
    ]
    .iter()
    .any(|host| lower.contains(host));
    provider
        || match distribution {
            "fedora" => lower.contains("fedoraproject.org"),
            "rocky" => lower.contains("rockylinux.org"),
            "almalinux" => lower.contains("almalinux.org"),
            "centos" => lower.contains("centos.org"),
            _ => false,
        }
}

pub(super) fn configured_source(section: RepoSection) -> ConfiguredSource {
    let mut metadata = section.properties;
    metadata.insert("section".into(), vec![section.id]);
    if let Some(path) = section.repository_path {
        metadata.insert("repository_path".into(), vec![path]);
    }
    ConfiguredSource {
        upstream_id: section.upstream_id,
        url: section.url,
        enabled: section.enabled,
        metadata,
    }
}

pub(super) fn selected_endpoints(
    selections: &[MirrorSelection],
    tool_id: &str,
) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut selected = BTreeMap::new();
    for selection in selections {
        if selection.tool_id != tool_id {
            return Err(AdapterError::InvalidConfiguration(format!(
                "selection {} belongs to {}",
                selection.candidate_id, selection.tool_id
            )));
        }
        let endpoint = selection
            .endpoints
            .iter()
            .find(|endpoint| {
                endpoint.role == EndpointRole::Metadata && endpoint.protocol == Protocol::Https
            })
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "selection {} has no HTTPS metadata endpoint",
                    selection.candidate_id
                ))
            })?;
        if selected
            .insert(selection.upstream_id.clone(), endpoint.url.clone())
            .is_some()
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "multiple mirrors selected for {}",
                selection.upstream_id
            )));
        }
    }
    Ok(selected)
}

pub(super) fn rewrite_repo_file(
    text: &str,
    sections: Vec<RepoSection>,
    selected: &BTreeMap<String, String>,
) -> Result<Vec<u8>, AdapterError> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut replacements = Vec::new();
    for section in sections.into_iter().filter(|section| section.enabled) {
        let (Some(upstream), Some(path), Some(location)) = (
            section.upstream_id,
            section.repository_path,
            section.location,
        ) else {
            continue;
        };
        let Some(endpoint) = selected.get(&upstream) else {
            continue;
        };
        let baseurl = format!(
            "{}/{}",
            endpoint.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        match location.kind {
            LocationKind::BaseUrl => replacements.push((location.value_range, baseurl)),
            LocationKind::MirrorList | LocationKind::Metalink => replacements.push((
                location.line_range,
                format!(
                    "{}# MirrorSwitch original: {}{}{}baseurl={}{}",
                    location.indentation,
                    location.line.trim_start(),
                    newline,
                    location.indentation,
                    baseurl,
                    newline
                ),
            )),
        }
    }
    replacements.sort_by_key(|(range, _)| range.start);
    for pair in replacements.windows(2) {
        if pair[0].0.end > pair[1].0.start {
            return Err(AdapterError::InvalidConfiguration(
                "RPM repository replacement ranges overlap".into(),
            ));
        }
    }
    let mut output = text.as_bytes().to_vec();
    for (range, replacement) in replacements.into_iter().rev() {
        output.splice(range, replacement.bytes());
    }
    Ok(output)
}

pub(super) fn expand_repo_variables(
    template: &str,
    context: &SystemContext,
) -> Result<String, AdapterError> {
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("DNF requires distribution metadata".into()))?;
    let version = distribution
        .version_id
        .as_deref()
        .ok_or_else(|| AdapterError::Unsupported("DNF releasever is unavailable".into()))?;
    let releasever = if matches!(distribution.id.as_str(), "rocky" | "almalinux") {
        version.split('.').next().unwrap_or(version)
    } else {
        version
    };
    let basearch = match context.architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "aarch64",
    };
    let stream = format!("{releasever}-stream");
    let expanded = template
        .replace("${releasever}", releasever)
        .replace("$releasever", releasever)
        .replace("${basearch}", basearch)
        .replace("$basearch", basearch)
        .replace("${stream}", &stream)
        .replace("$stream", &stream);
    if expanded.contains('$')
        || expanded
            .split('/')
            .filter(|segment| !segment.is_empty())
            .any(|segment| !safe_segment(segment))
    {
        return Err(AdapterError::InvalidConfiguration(
            "DNF repository path contains unsupported variables or segments".into(),
        ));
    }
    Ok(expanded)
}

fn safe_segment(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

pub(super) fn rooted(root: &Path, logical: &Path) -> PathBuf {
    root.join(logical.strip_prefix("/").unwrap_or(logical))
}

fn has_enabled_centos_stream_repository(
    context: &SystemContext,
    runtime: &dyn Runtime,
    files: &[PathBuf],
) -> Result<bool, AdapterError> {
    for path in files {
        let Some(contents) = runtime.read(path)? else {
            continue;
        };
        let text = std::str::from_utf8(&contents).map_err(|_| {
            AdapterError::InvalidConfiguration(format!(
                "DNF repository file {} is not UTF-8",
                path.display()
            ))
        })?;
        if parse_repo_file(text, context, classify_section)?
            .iter()
            .any(|section| {
                section.enabled
                    && section.upstream_id.as_deref() == Some("centos-stream--repository-metadata")
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}
