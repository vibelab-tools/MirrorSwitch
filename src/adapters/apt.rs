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

const SOURCES_LIST: &str = "/etc/apt/sources.list";
const SOURCES_DIRECTORY: &str = "/etc/apt/sources.list.d";

#[derive(Clone, Copy, Debug, Default)]
pub struct AptAdapter;

impl Adapter for AptAdapter {
    fn key(&self) -> &'static str {
        "apt"
    }

    fn tool_id(&self) -> &'static str {
        "apt"
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
        let files = source_paths(runtime)?;
        if !runtime.command_exists("apt-get") && files.is_empty() {
            return Ok(None);
        }
        let mut evidence = Vec::new();
        if runtime.command_exists("apt-get") {
            evidence.push("apt-get is callable".into());
        }
        for path in &files {
            evidence.push(format!("APT configuration {}", path.display()));
        }
        Ok(Some(DetectedTool {
            tool_id: "apt".into(),
            executable: runtime
                .command_exists("apt-get")
                .then(|| PathBuf::from("/usr/bin/apt-get")),
            version: None,
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
                "APT only supports system scope".into(),
            ));
        }
        let mut sources = Vec::new();
        let mut documents = Vec::new();
        for path in source_paths(runtime)? {
            let Some(contents) = runtime.read(&path)? else {
                continue;
            };
            let format = source_format(&path)?;
            let parsed = parse_document(&contents, format, context)?;
            sources.extend(parsed.entries.into_iter().map(configured_source));
            documents.push(ConfigurationDocument {
                path,
                format: format.as_str().into(),
                contents,
            });
        }
        let files = documents
            .iter()
            .map(|document| document.path.clone())
            .collect();
        Ok(CurrentConfiguration {
            tool_id: "apt".into(),
            scope,
            sources,
            files,
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
        if current.tool_id != "apt" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "APT selection requires a system-scope APT configuration".into(),
            ));
        }
        let architecture = apt_architecture(context.architecture);
        let mut upstreams = BTreeSet::new();
        let mut contexts: BTreeMap<String, Vec<BTreeMap<String, String>>> = BTreeMap::new();
        for source in current.sources.iter().filter(|source| source.enabled) {
            let Some(upstream) = &source.upstream_id else {
                continue;
            };
            let suites = source.metadata.get("suites").cloned().unwrap_or_default();
            let components = source
                .metadata
                .get("components")
                .cloned()
                .unwrap_or_default();
            for suite in suites {
                for component in &components {
                    if !safe_segment(&suite) || !safe_segment(component) {
                        continue;
                    }
                    contexts
                        .entry(upstream.clone())
                        .or_default()
                        .push(BTreeMap::from([
                            ("suite".into(), suite.clone()),
                            ("component".into(), component.clone()),
                            ("architecture".into(), architecture.into()),
                        ]));
                    upstreams.insert(upstream.clone());
                }
            }
        }
        for values in contexts.values_mut() {
            values.sort();
            values.dedup();
        }
        if upstreams.is_empty() {
            return Err(AdapterError::Unsupported(
                "no supported Debian or Ubuntu APT repositories were detected".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "apt".into(),
            adapter_key: "apt".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: upstreams.into_iter().collect(),
            repository_versions: BTreeMap::new(),
            probe_contexts: contexts,
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
        if current.tool_id != "apt" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "APT plan requires a system-scope APT configuration".into(),
            ));
        }
        let selected = selected_endpoints(selection)?;
        let mut changes = Vec::new();
        for document in &current.documents {
            let format = SourceFormat::parse(&document.format)?;
            let new_contents = rewrite_document(&document.contents, format, context, &selected)?;
            if new_contents == document.contents {
                continue;
            }
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "replace only validated Debian/Ubuntu APT repository URIs".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "apt".into(),
            tool_id: "apt".into(),
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
        let output = runtime.run(
            "apt-get",
            &["update".into(), "-o".into(), "Acquire::Retries=0".into()],
        )?;
        if output.status.success() {
            return Ok(VerificationResult {
                valid: true,
                summary: "apt-get update validated repository metadata and signatures".into(),
            });
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
        Err(AdapterError::Verification(format!(
            "apt-get update failed with status {}; configuration restored: {restored}",
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
                "restored {} APT configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceFormat {
    List,
    Deb822,
}

impl SourceFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::List => "apt-list",
            Self::Deb822 => "apt-deb822",
        }
    }

    fn parse(value: &str) -> Result<Self, AdapterError> {
        match value {
            "apt-list" => Ok(Self::List),
            "apt-deb822" => Ok(Self::Deb822),
            other => Err(AdapterError::Unsupported(format!(
                "unknown APT document format {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
struct ParsedDocument {
    entries: Vec<AptEntry>,
}

#[derive(Clone, Debug)]
struct AptEntry {
    enabled: bool,
    url: String,
    upstream_id: Option<String>,
    suites: Vec<String>,
    components: Vec<String>,
    architectures: Vec<String>,
    uri_ranges: Vec<Range<usize>>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("APT requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("APT requires distribution metadata".into()))?;
    if !matches!(distribution.id.as_str(), "debian" | "ubuntu") {
        return Err(AdapterError::Unsupported(format!(
            "APT adapter has no verified rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn source_paths(runtime: &dyn Runtime) -> Result<Vec<PathBuf>, AdapterError> {
    let mut paths = Vec::new();
    if runtime.read(Path::new(SOURCES_LIST))?.is_some() {
        paths.push(PathBuf::from(SOURCES_LIST));
    }
    paths.extend(
        runtime
            .list_files(Path::new(SOURCES_DIRECTORY))?
            .into_iter()
            .filter(|path| {
                matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("list" | "sources")
                )
            }),
    );
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn source_format(path: &Path) -> Result<SourceFormat, AdapterError> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("list") | None if path == Path::new(SOURCES_LIST) => Ok(SourceFormat::List),
        Some("list") => Ok(SourceFormat::List),
        Some("sources") => Ok(SourceFormat::Deb822),
        _ => Err(AdapterError::Unsupported(format!(
            "unsupported APT source file {}",
            path.display()
        ))),
    }
}

fn parse_document(
    contents: &[u8],
    format: SourceFormat,
    context: &SystemContext,
) -> Result<ParsedDocument, AdapterError> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| AdapterError::InvalidConfiguration("APT source is not UTF-8".into()))?;
    let entries = match format {
        SourceFormat::List => parse_list(text, context)?,
        SourceFormat::Deb822 => parse_deb822(text, context)?,
    };
    Ok(ParsedDocument { entries })
}

fn parse_list(text: &str, context: &SystemContext) -> Result<Vec<AptEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    for raw_line in text.split_inclusive('\n') {
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let leading = line.len() - line.trim_start().len();
        let trimmed = &line[leading..];
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += raw_line.len();
            continue;
        }
        let content_end = trimmed.find('#').unwrap_or(trimmed.len());
        let content = &trimmed[..content_end];
        let tokens = token_spans(content);
        if tokens.is_empty() || !matches!(tokens[0].2, "deb" | "deb-src") {
            offset += raw_line.len();
            continue;
        }
        let mut uri_index = 1;
        if tokens
            .get(uri_index)
            .is_some_and(|token| token.2.starts_with('['))
        {
            while tokens
                .get(uri_index)
                .is_some_and(|token| !token.2.ends_with(']'))
            {
                uri_index += 1;
            }
            uri_index += 1;
        }
        let uri = tokens.get(uri_index).ok_or_else(|| {
            AdapterError::InvalidConfiguration("APT list entry has no URI".into())
        })?;
        let suite = tokens.get(uri_index + 1).ok_or_else(|| {
            AdapterError::InvalidConfiguration("APT list entry has no suite".into())
        })?;
        let components: Vec<_> = tokens
            .iter()
            .skip(uri_index + 2)
            .map(|token| token.2.to_owned())
            .collect();
        let architectures = list_architectures(content, context.architecture);
        let upstream_id = classifiable_upstream(uri.2, context, suite.2, &components);
        entries.push(AptEntry {
            enabled: true,
            url: uri.2.into(),
            upstream_id,
            suites: vec![suite.2.into()],
            components,
            architectures,
            uri_ranges: std::iter::once(offset + leading + uri.0..offset + leading + uri.1)
                .collect(),
        });
        offset += raw_line.len();
    }
    Ok(entries)
}

fn token_spans(value: &str) -> Vec<(usize, usize, &str)> {
    let mut result = Vec::new();
    let mut start = None;
    for (index, character) in value.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = start.take() {
                result.push((start, index, &value[start..index]));
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start) = start {
        result.push((start, value.len(), &value[start..]));
    }
    result
}

fn list_architectures(line: &str, fallback: Architecture) -> Vec<String> {
    let Some(open) = line.find('[') else {
        return vec![apt_architecture(fallback).into()];
    };
    let Some(close) = line[open + 1..].find(']').map(|close| open + 1 + close) else {
        return vec![apt_architecture(fallback).into()];
    };
    line[open + 1..close]
        .split_ascii_whitespace()
        .find_map(|option| option.strip_prefix("arch="))
        .map(|value| value.split(',').map(str::to_owned).collect())
        .unwrap_or_else(|| vec![apt_architecture(fallback).into()])
}

fn parse_deb822(text: &str, context: &SystemContext) -> Result<Vec<AptEntry>, AdapterError> {
    let mut entries = Vec::new();
    for range in paragraph_ranges(text) {
        let fields = deb822_fields(text, range.clone())?;
        let Some(types) = fields.get("types") else {
            continue;
        };
        if !types
            .value
            .split_ascii_whitespace()
            .any(|kind| matches!(kind, "deb" | "deb-src"))
        {
            continue;
        }
        let uris = fields
            .get("uris")
            .ok_or_else(|| AdapterError::InvalidConfiguration("deb822 entry has no URIs".into()))?;
        let suites = field_tokens(&fields, "suites");
        if suites.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "deb822 entry has no Suites".into(),
            ));
        }
        let components = field_tokens(&fields, "components");
        let architectures = match field_tokens(&fields, "architectures") {
            values if values.is_empty() => vec![apt_architecture(context.architecture).into()],
            values => values,
        };
        let uri_values: Vec<_> = uris.value.split_ascii_whitespace().collect();
        let classified: Vec<_> = uri_values
            .iter()
            .map(|url| classifiable_upstream(url, context, &suites[0], &components))
            .collect();
        let upstreams: BTreeSet<_> = classified.iter().flatten().cloned().collect();
        let upstream_id = (upstreams.len() == 1 && classified.iter().all(Option::is_some))
            .then(|| upstreams.into_iter().next().unwrap());
        let enabled = fields
            .get("enabled")
            .is_none_or(|field| !field.value.eq_ignore_ascii_case("no"));
        entries.push(AptEntry {
            enabled,
            url: uris.value.clone(),
            upstream_id: upstream_id.filter(|_| {
                !components.is_empty()
                    && suites.iter().all(|suite| safe_segment(suite))
                    && components.iter().all(|component| safe_segment(component))
            }),
            suites,
            components,
            architectures,
            uri_ranges: uris.token_ranges.clone(),
        });
    }
    Ok(entries)
}

#[derive(Clone, Debug)]
struct Deb822Field {
    value: String,
    token_ranges: Vec<Range<usize>>,
}

fn paragraph_ranges(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let is_blank = line.trim().is_empty();
        if is_blank {
            if start < offset {
                ranges.push(start..offset);
            }
            start = offset + line.len();
        }
        offset += line.len();
    }
    if start < text.len() {
        ranges.push(start..text.len());
    }
    ranges
}

fn deb822_fields(
    text: &str,
    paragraph: Range<usize>,
) -> Result<BTreeMap<String, Deb822Field>, AdapterError> {
    let mut starts = Vec::new();
    let mut offset = paragraph.start;
    for line in text[paragraph.clone()].split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.starts_with([' ', '\t']) || trimmed.starts_with('#') || trimmed.is_empty() {
            offset += line.len();
            continue;
        }
        let colon = trimmed
            .find(':')
            .ok_or_else(|| AdapterError::InvalidConfiguration("deb822 field has no ':'".into()))?;
        let name = trimmed[..colon].to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AdapterError::InvalidConfiguration(
                "deb822 field name is invalid".into(),
            ));
        }
        starts.push((name, offset + colon + 1, offset));
        offset += line.len();
    }
    let mut fields = BTreeMap::new();
    for (index, (name, value_start, line_start)) in starts.iter().enumerate() {
        let end = starts
            .get(index + 1)
            .map_or(paragraph.end, |(_, _, next_line)| *next_line);
        let raw = &text[*value_start..end];
        let mut tokens = Vec::new();
        let mut token_ranges = Vec::new();
        let mut raw_offset = *value_start;
        for raw_line in raw.split_inclusive('\n') {
            let line = raw_line.trim_end_matches(['\r', '\n']);
            if !line.starts_with('#') {
                for (start, end, token) in token_spans(line) {
                    tokens.push(token);
                    token_ranges.push(raw_offset + start..raw_offset + end);
                }
            }
            raw_offset += raw_line.len();
        }
        let value = tokens.join(" ");
        if fields
            .insert(
                name.clone(),
                Deb822Field {
                    value,
                    token_ranges,
                },
            )
            .is_some()
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "deb822 field {name} is duplicated near byte {line_start}"
            )));
        }
    }
    Ok(fields)
}

fn field_tokens(fields: &BTreeMap<String, Deb822Field>, name: &str) -> Vec<String> {
    fields
        .get(name)
        .map(|field| {
            field
                .value
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn configured_source(entry: AptEntry) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: entry.upstream_id,
        url: entry.url,
        enabled: entry.enabled,
        metadata: BTreeMap::from([
            ("suites".into(), entry.suites),
            ("components".into(), entry.components),
            ("architectures".into(), entry.architectures),
        ]),
    }
}

fn selected_endpoints(
    selections: &[MirrorSelection],
) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut selected = BTreeMap::new();
    for selection in selections {
        if selection.tool_id != "apt" {
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

fn rewrite_document(
    contents: &[u8],
    format: SourceFormat,
    context: &SystemContext,
    selected: &BTreeMap<String, String>,
) -> Result<Vec<u8>, AdapterError> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| AdapterError::InvalidConfiguration("APT source is not UTF-8".into()))?;
    let parsed = match format {
        SourceFormat::List => parse_list(text, context)?,
        SourceFormat::Deb822 => parse_deb822(text, context)?,
    };
    let mut replacements = Vec::new();
    for entry in parsed {
        if !entry.enabled {
            continue;
        }
        let Some(upstream) = entry.upstream_id else {
            continue;
        };
        let Some(endpoint) = selected.get(&upstream) else {
            continue;
        };
        for (index, range) in entry.uri_ranges.into_iter().enumerate() {
            let replacement = if index == 0 {
                endpoint.trim_end_matches('/').to_owned()
            } else {
                String::new()
            };
            replacements.push((range, replacement));
        }
    }
    replacements.sort_by_key(|(range, _)| range.start);
    for pair in replacements.windows(2) {
        if pair[0].0.end > pair[1].0.start {
            return Err(AdapterError::InvalidConfiguration(
                "APT source replacement ranges overlap".into(),
            ));
        }
    }
    let mut output = contents.to_vec();
    for (range, replacement) in replacements.into_iter().rev() {
        output.splice(range, replacement.bytes());
    }
    Ok(output)
}

fn classifiable_upstream(
    raw_url: &str,
    context: &SystemContext,
    suite: &str,
    components: &[String],
) -> Option<String> {
    if !safe_segment(suite)
        || components.is_empty()
        || !components.iter().all(|item| safe_segment(item))
    {
        return None;
    }
    let url = reqwest::Url::parse(raw_url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    if !known_apt_host(&host) {
        return None;
    }
    let segments: Vec<_> = url
        .path_segments()?
        .filter(|segment| !segment.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let distribution = context.distribution.as_ref()?.id.as_str();
    match distribution {
        "ubuntu" => {
            if segments.iter().any(|segment| segment == "ubuntu-ports")
                || context.architecture == Architecture::Arm64
            {
                Some("ubuntu-ports--repository-metadata".into())
            } else if segments.iter().any(|segment| segment == "ubuntu") {
                Some("ubuntu--repository-metadata".into())
            } else {
                None
            }
        }
        "debian" => {
            if segments.iter().any(|segment| segment == "debian-security")
                || host == "security.debian.org"
            {
                Some("debian-security--repository-metadata".into())
            } else if segments.iter().any(|segment| segment == "debian") {
                Some("debian--repository-metadata".into())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn known_apt_host(host: &str) -> bool {
    matches!(
        host,
        "deb.debian.org"
            | "security.debian.org"
            | "ftp.debian.org"
            | "archive.debian.org"
            | "archive.ubuntu.com"
            | "security.ubuntu.com"
            | "ports.ubuntu.com"
            | "mirrors.aliyun.com"
            | "repo.huaweicloud.com"
            | "mirrors.ustc.edu.cn"
            | "mirrors.tuna.tsinghua.edu.cn"
            | "mirrors.nju.edu.cn"
            | "mirror.sjtu.edu.cn"
    ) || host.ends_with(".archive.ubuntu.com")
        || host.ends_with(".debian.org")
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn apt_architecture(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}

fn rooted(root: &Path, logical: &Path) -> PathBuf {
    root.join(logical.strip_prefix("/").unwrap_or(logical))
}
