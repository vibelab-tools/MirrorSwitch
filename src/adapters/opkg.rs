use std::{
    cmp::Reverse,
    collections::BTreeMap,
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

const DISTFEEDS: &str = "/etc/opkg/distfeeds.conf";
const CUSTOMFEEDS: &str = "/etc/opkg/customfeeds.conf";
const OPKG_CONF: &str = "/etc/opkg.conf";
const OS_RELEASE_PATHS: &[&str] = &["/etc/os-release", "/usr/lib/os-release"];
const OPENWRT_UPSTREAM: &str = "openwrt--repository-metadata";
const IMMORTALWRT_UPSTREAM: &str = "immortalwrt--repository-metadata";

const ROOTS: &[RepositoryRoot] = &[
    RepositoryRoot::official("openwrt", "downloads.openwrt.org", ""),
    RepositoryRoot::mirror("openwrt", "mirrors.aliyun.com", "/openwrt"),
    RepositoryRoot::mirror("openwrt", "mirrors.nju.edu.cn", "/openwrt"),
    RepositoryRoot::mirror("openwrt", "mirror.sjtu.edu.cn", "/openwrt"),
    RepositoryRoot::mirror("openwrt", "mirrors.tuna.tsinghua.edu.cn", "/openwrt"),
    RepositoryRoot::mirror("openwrt", "mirrors.ustc.edu.cn", "/openwrt"),
    RepositoryRoot::official("immortalwrt", "downloads.immortalwrt.org", ""),
    RepositoryRoot::mirror("immortalwrt", "mirrors.nju.edu.cn", "/immortalwrt"),
    RepositoryRoot::mirror("immortalwrt", "mirrors.ustc.edu.cn", "/immortalwrt"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct OpkgAdapter;

impl Adapter for OpkgAdapter {
    fn key(&self) -> &'static str {
        "opkg"
    }

    fn tool_id(&self) -> &'static str {
        "opkg"
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
        if !runtime.command_exists("opkg") {
            return Ok(None);
        }
        let facts = read_system_facts(context, runtime)?;
        let output = runtime.run("opkg", &["--version".into()])?;
        if !output.status.success() {
            return Err(AdapterError::Runtime(format!(
                "opkg --version failed with status {}",
                output.status
            )));
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        Ok(Some(DetectedTool {
            tool_id: "opkg".into(),
            executable: Some(PathBuf::from("/bin/opkg")),
            version: (!version.is_empty()).then_some(version.clone()),
            evidence: vec![
                format!("opkg command {version}"),
                format!(
                    "{} {} target {}/{} package architecture {}",
                    facts.distribution,
                    facts.version,
                    facts.target,
                    facts.subtarget,
                    facts.opkg_arch
                ),
            ],
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
                "opkg only supports system scope".into(),
            ));
        }
        let facts = read_system_facts(context, runtime)?;
        let opkg_conf = required_file(runtime, OPKG_CONF)?;
        require_signature_check(&opkg_conf)?;
        let architecture_priorities = read_architecture_priorities(runtime, &facts.opkg_arch)?;
        let distfeeds = required_file(runtime, DISTFEEDS)?;
        let customfeeds = runtime.read(Path::new(CUSTOMFEEDS))?;
        let customfeeds_exists = customfeeds.is_some();
        let customfeeds = customfeeds.unwrap_or_default();
        let mut sources = configured_sources(
            utf8(Path::new(DISTFEEDS), &distfeeds)?,
            &facts,
            true,
            &architecture_priorities,
        )?;
        sources.extend(configured_sources(
            utf8(Path::new(CUSTOMFEEDS), &customfeeds)?,
            &facts,
            false,
            &architecture_priorities,
        )?);
        let mut files = vec![PathBuf::from(DISTFEEDS), PathBuf::from(OPKG_CONF)];
        if customfeeds_exists {
            files.push(PathBuf::from(CUSTOMFEEDS));
        }
        Ok(CurrentConfiguration {
            tool_id: "opkg".into(),
            scope,
            files,
            sources,
            documents: vec![
                ConfigurationDocument {
                    path: PathBuf::from(DISTFEEDS),
                    format: "opkg-distfeeds".into(),
                    contents: distfeeds,
                },
                ConfigurationDocument {
                    path: PathBuf::from(CUSTOMFEEDS),
                    format: "opkg-customfeeds-read-only".into(),
                    contents: customfeeds,
                },
                ConfigurationDocument {
                    path: PathBuf::from(OPKG_CONF),
                    format: "opkg-policy-read-only".into(),
                    contents: opkg_conf,
                },
            ],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "opkg" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "opkg selection requires a system-scope configuration".into(),
            ));
        }
        let upstream = expected_upstream(context)?;
        let mapped = current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(upstream))
            .collect::<Vec<_>>();
        if mapped.is_empty() {
            return Err(AdapterError::Unsupported(
                "no recognized opkg distribution feeds are configured".into(),
            ));
        }
        let mut contexts = mapped
            .iter()
            .map(|source| {
                Ok(BTreeMap::from([(
                    "repository_path".into(),
                    single_metadata(source, "repository_path")?.to_owned(),
                )]))
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        contexts.sort();
        contexts.dedup();
        Ok(SelectionRequest {
            tool_id: "opkg".into(),
            adapter_key: "opkg".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![upstream.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(upstream.into(), contexts)]),
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
        selections: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "opkg" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "opkg plan requires a system-scope configuration".into(),
            ));
        }
        let facts = facts_from_sources(context, &current.sources)?;
        let endpoint = selected_endpoint(selections, &facts.distribution)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "opkg-distfeeds")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("opkg distfeeds document is missing".into())
            })?;
        let text = utf8(&document.path, &document.contents)?;
        let new_contents = rewrite_distfeeds(text, &facts, endpoint)?.into_bytes();
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "replace only mapped opkg distribution feed roots while preserving feed order and policy"
                    .into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "opkg".into(),
            tool_id: "opkg".into(),
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
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let facts = read_system_facts(context, runtime)?;
            let opkg_conf = required_file(runtime, OPKG_CONF)?;
            require_signature_check(&opkg_conf)?;
            let distfeeds = required_file(runtime, DISTFEEDS)?;
            let feeds = parse_feed_lines(utf8(Path::new(DISTFEEDS), &distfeeds)?, &facts, true)?;
            let mapped = feeds
                .iter()
                .filter_map(|feed| feed.official.as_ref())
                .collect::<Vec<_>>();
            if mapped.is_empty() || mapped.iter().any(|feed| !feed.mirror) {
                return Err(AdapterError::Verification(
                    "effective opkg distribution feeds are not all on a reviewed mirror".into(),
                ));
            }
            let update = runtime.run("opkg", &["update".into()])?;
            if !update.status.success() {
                return Err(AdapterError::Verification(format!(
                    "opkg update failed with status {}",
                    update.status
                )));
            }
            let query = runtime.run("opkg", &["list".into()])?;
            if !query.status.success() || query.stdout.is_empty() {
                return Err(AdapterError::Verification(format!(
                    "opkg list returned no packages with status {}",
                    query.status
                )));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "opkg verified {} signed feeds for {} {}/{} {}",
                    mapped.len(),
                    facts.distribution,
                    facts.target,
                    facts.subtarget,
                    facts.opkg_arch
                ),
            })
        })();
        match result {
            Ok(result) => Ok(result),
            Err(error) => verification_failure(runtime, receipt, error.to_string()),
        }
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
                "restored {} opkg feed files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SystemFacts {
    distribution: String,
    version: String,
    target: String,
    subtarget: String,
    opkg_arch: String,
}

#[derive(Clone, Copy)]
struct RepositoryRoot {
    distribution: &'static str,
    host: &'static str,
    path: &'static str,
    mirror: bool,
}

impl RepositoryRoot {
    const fn official(distribution: &'static str, host: &'static str, path: &'static str) -> Self {
        Self {
            distribution,
            host,
            path,
            mirror: false,
        }
    }

    const fn mirror(distribution: &'static str, host: &'static str, path: &'static str) -> Self {
        Self {
            distribution,
            host,
            path,
            mirror: true,
        }
    }
}

#[derive(Clone, Debug)]
struct OfficialFeed {
    repository_path: String,
    mirror: bool,
}

#[derive(Clone, Debug)]
struct FeedLine {
    name: String,
    url: String,
    url_range: Range<usize>,
    order: usize,
    official: Option<OfficialFeed>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("opkg requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("opkg requires distribution metadata".into()))?;
    if !matches!(distribution.id.as_str(), "openwrt" | "immortalwrt") {
        return Err(AdapterError::Unsupported(format!(
            "opkg is extended support only for OpenWrt or ImmortalWrt, not {}",
            distribution.id
        )));
    }
    Ok(())
}

fn expected_upstream(context: &SystemContext) -> Result<&'static str, AdapterError> {
    match context.distribution.as_ref().map(|item| item.id.as_str()) {
        Some("openwrt") => Ok(OPENWRT_UPSTREAM),
        Some("immortalwrt") => Ok(IMMORTALWRT_UPSTREAM),
        _ => Err(AdapterError::Unsupported(
            "opkg has no mapped upstream for this distribution".into(),
        )),
    }
}

fn read_system_facts(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<SystemFacts, AdapterError> {
    require_supported_context(context)?;
    let mut contents = None;
    for path in OS_RELEASE_PATHS {
        if let Some(value) = runtime.read(Path::new(path))? {
            contents = Some(value);
            break;
        }
    }
    let contents = contents.ok_or_else(|| {
        AdapterError::InvalidConfiguration("OpenWrt os-release metadata is missing".into())
    })?;
    let values = parse_assignments(utf8(Path::new("/etc/os-release"), &contents)?)?;
    let distribution = required_assignment(&values, "ID")?.to_ascii_lowercase();
    let version = required_assignment(&values, "VERSION_ID")?.to_owned();
    let board = required_assignment(&values, "OPENWRT_BOARD")?;
    let opkg_arch = required_assignment(&values, "OPENWRT_ARCH")?.to_owned();
    let context_distribution = &context.distribution.as_ref().unwrap().id;
    if distribution != *context_distribution
        || context
            .distribution
            .as_ref()
            .and_then(|item| item.version_id.as_deref())
            != Some(version.as_str())
    {
        return Err(AdapterError::InvalidConfiguration(
            "opkg os-release facts disagree with detected distribution context".into(),
        ));
    }
    if !valid_version(&version) {
        return Err(AdapterError::Unsupported(format!(
            "opkg release {version} is not a stable numeric release or snapshot"
        )));
    }
    let (target, subtarget) = board.split_once('/').ok_or_else(|| {
        AdapterError::InvalidConfiguration("OPENWRT_BOARD must be target/subtarget".into())
    })?;
    if !safe_segment(target) || !safe_segment(subtarget) || !safe_segment(&opkg_arch) {
        return Err(AdapterError::InvalidConfiguration(
            "opkg target, subtarget, or package architecture is unsafe".into(),
        ));
    }
    let architecture_matches = match context.architecture {
        Architecture::X86_64 => opkg_arch == "x86_64",
        Architecture::Arm64 => opkg_arch.starts_with("aarch64_"),
    };
    if !architecture_matches {
        return Err(AdapterError::Unsupported(format!(
            "opkg package architecture {opkg_arch} does not match {:?}",
            context.architecture
        )));
    }
    Ok(SystemFacts {
        distribution,
        version,
        target: target.into(),
        subtarget: subtarget.into(),
        opkg_arch,
    })
}

fn valid_version(value: &str) -> bool {
    value.eq_ignore_ascii_case("snapshot")
        || (!value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'))
}

fn parse_assignments(text: &str) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut values = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            values.insert(key.into(), unquote(value.trim())?);
        }
    }
    Ok(values)
}

fn unquote(value: &str) -> Result<String, AdapterError> {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
    {
        return Ok(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    if value.starts_with(['"', '\'']) || value.ends_with(['"', '\'']) {
        return Err(AdapterError::InvalidConfiguration(
            "opkg os-release contains an unterminated quote".into(),
        ));
    }
    Ok(value.into())
}

fn required_assignment<'a>(
    values: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, AdapterError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("opkg os-release is missing {key}"))
        })
}

fn required_file(runtime: &dyn Runtime, path: &str) -> Result<Vec<u8>, AdapterError> {
    runtime.read(Path::new(path))?.ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("opkg configuration {path} is missing"))
    })
}

fn require_signature_check(contents: &[u8]) -> Result<(), AdapterError> {
    let text = utf8(Path::new(OPKG_CONF), contents)?;
    let enabled = text.lines().any(|line| {
        let active = line.split_once('#').map_or(line, |(active, _)| active);
        let tokens = active.split_whitespace().collect::<Vec<_>>();
        matches!(tokens.as_slice(), ["option", "check_signature"])
    });
    if !enabled {
        return Err(AdapterError::InvalidConfiguration(
            "opkg option check_signature must remain enabled".into(),
        ));
    }
    Ok(())
}

fn read_architecture_priorities(
    runtime: &dyn Runtime,
    expected: &str,
) -> Result<Vec<String>, AdapterError> {
    let output = runtime.run("opkg", &["print-architecture".into()])?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "opkg print-architecture failed with status {}",
            output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut priorities = Vec::new();
    let mut found = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3
            || fields[0] != "arch"
            || !safe_segment(fields[1])
            || fields[2].parse::<u32>().is_err()
        {
            return Err(AdapterError::InvalidConfiguration(
                "opkg returned an invalid architecture priority".into(),
            ));
        }
        found |= fields[1] == expected;
        priorities.push(format!("{}:{}", fields[1], fields[2]));
    }
    if !found {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opkg architecture priorities do not include {expected}"
        )));
    }
    Ok(priorities)
}

fn configured_sources(
    text: &str,
    facts: &SystemFacts,
    map_official: bool,
    architecture_priorities: &[String],
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    parse_feed_lines(text, facts, map_official)?
        .into_iter()
        .map(|line| {
            let upstream_id = line.official.as_ref().map(|_| upstream(facts).into());
            let mut metadata = BTreeMap::from([
                ("feed_name".into(), vec![line.name]),
                ("feed_order".into(), vec![line.order.to_string()]),
                ("distribution".into(), vec![facts.distribution.clone()]),
                ("version".into(), vec![facts.version.clone()]),
                ("target".into(), vec![facts.target.clone()]),
                ("subtarget".into(), vec![facts.subtarget.clone()]),
                ("opkg_arch".into(), vec![facts.opkg_arch.clone()]),
                (
                    "architecture_priority".into(),
                    architecture_priorities.to_vec(),
                ),
            ]);
            if let Some(official) = line.official {
                metadata.insert("repository_path".into(), vec![official.repository_path]);
            }
            Ok(ConfiguredSource {
                upstream_id,
                url: line.url,
                enabled: true,
                metadata,
            })
        })
        .collect()
}

fn parse_feed_lines(
    text: &str,
    facts: &SystemFacts,
    map_official: bool,
) -> Result<Vec<FeedLine>, AdapterError> {
    let mut feeds = Vec::new();
    let mut offset = 0;
    for (order, inclusive) in text.split_inclusive('\n').enumerate() {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let leading = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += inclusive.len();
            continue;
        }
        let Some((kind, kind_range)) = next_token(line, leading) else {
            offset += inclusive.len();
            continue;
        };
        if kind != "src/gz" {
            offset += inclusive.len();
            continue;
        }
        let name_start = skip_whitespace(line, kind_range.end);
        let (name, name_range) = next_token(line, name_start).ok_or_else(|| {
            AdapterError::InvalidConfiguration("opkg src/gz feed has no name".into())
        })?;
        let url_start = skip_whitespace(line, name_range.end);
        let (url, url_range) = next_token(line, url_start).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("opkg feed {name} has no URL"))
        })?;
        let official = if map_official {
            classify_feed(url, facts)?
        } else {
            None
        };
        feeds.push(FeedLine {
            name: name.into(),
            url: url.into(),
            url_range: offset + url_range.start..offset + url_range.end,
            order,
            official,
        });
        offset += inclusive.len();
    }
    Ok(feeds)
}

fn classify_feed(url: &str, facts: &SystemFacts) -> Result<Option<OfficialFeed>, AdapterError> {
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => parsed,
        _ => return Ok(None),
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Ok(None);
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = parsed.path().trim_end_matches('/');
    let Some(root) = ROOTS.iter().find(|root| {
        root.host == host
            && (root.path.is_empty()
                || path == root.path
                || path.starts_with(&format!("{}/", root.path)))
    }) else {
        return Ok(None);
    };
    if root.distribution != facts.distribution {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opkg feed {url} belongs to {}, not {}",
            root.distribution, facts.distribution
        )));
    }
    let repository_path = path
        .strip_prefix(root.path)
        .unwrap_or(path)
        .trim_matches('/');
    validate_repository_path(repository_path, facts)?;
    Ok(Some(OfficialFeed {
        repository_path: repository_path.into(),
        mirror: root.mirror,
    }))
}

fn validate_repository_path(path: &str, facts: &SystemFacts) -> Result<(), AdapterError> {
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| !safe_segment(segment)) {
        return Err(AdapterError::InvalidConfiguration(
            "opkg feed contains an unsafe repository path".into(),
        ));
    }
    let prefix = if facts.version.eq_ignore_ascii_case("snapshot") {
        vec!["snapshots"]
    } else {
        vec!["releases", facts.version.as_str()]
    };
    let remainder = segments.strip_prefix(prefix.as_slice()).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "opkg feed path does not match release {}",
            facts.version
        ))
    })?;
    let target_path = remainder.len() == 4
        && remainder[0] == "targets"
        && remainder[1] == facts.target
        && remainder[2] == facts.subtarget
        && remainder[3] == "packages";
    let kmods_path = remainder.len() == 5
        && remainder[0] == "targets"
        && remainder[1] == facts.target
        && remainder[2] == facts.subtarget
        && remainder[3] == "kmods";
    let packages_path =
        remainder.len() == 3 && remainder[0] == "packages" && remainder[1] == facts.opkg_arch;
    if !target_path && !kmods_path && !packages_path {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opkg feed path does not match target {}/{} and architecture {}",
            facts.target, facts.subtarget, facts.opkg_arch
        )));
    }
    Ok(())
}

fn rewrite_distfeeds(
    text: &str,
    facts: &SystemFacts,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let mut replacements = parse_feed_lines(text, facts, true)?
        .into_iter()
        .filter_map(|line| {
            line.official.map(|official| {
                (
                    line.url_range,
                    format!(
                        "{}/{}",
                        endpoint.trim_end_matches('/'),
                        official.repository_path
                    ),
                )
            })
        })
        .collect::<Vec<_>>();
    if replacements.is_empty() {
        return Err(AdapterError::Unsupported(
            "opkg has no mapped distribution feeds to rewrite".into(),
        ));
    }
    replacements.sort_by_key(|replacement| Reverse(replacement.0.start));
    let mut output = text.to_owned();
    for (range, replacement) in replacements {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn facts_from_sources(
    context: &SystemContext,
    sources: &[ConfiguredSource],
) -> Result<SystemFacts, AdapterError> {
    let upstream = expected_upstream(context)?;
    let mapped = sources
        .iter()
        .filter(|source| source.upstream_id.as_deref() == Some(upstream))
        .collect::<Vec<_>>();
    let first = mapped
        .first()
        .ok_or_else(|| AdapterError::Unsupported("opkg has no mapped distribution feeds".into()))?;
    let facts = SystemFacts {
        distribution: single_metadata(first, "distribution")?.into(),
        version: single_metadata(first, "version")?.into(),
        target: single_metadata(first, "target")?.into(),
        subtarget: single_metadata(first, "subtarget")?.into(),
        opkg_arch: single_metadata(first, "opkg_arch")?.into(),
    };
    for source in mapped {
        if single_metadata(source, "distribution")? != facts.distribution
            || single_metadata(source, "version")? != facts.version
            || single_metadata(source, "target")? != facts.target
            || single_metadata(source, "subtarget")? != facts.subtarget
            || single_metadata(source, "opkg_arch")? != facts.opkg_arch
        {
            return Err(AdapterError::InvalidConfiguration(
                "opkg feeds disagree on release, target, or architecture".into(),
            ));
        }
    }
    Ok(facts)
}

fn selected_endpoint<'a>(
    selections: &'a [MirrorSelection],
    distribution: &str,
) -> Result<&'a str, AdapterError> {
    let expected = upstream_id(distribution);
    if selections.len() != 1
        || selections[0].tool_id != "opkg"
        || selections[0].upstream_id != expected
    {
        return Err(AdapterError::InvalidConfiguration(
            "opkg plan requires exactly one distribution repository selection".into(),
        ));
    }
    let endpoint = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Metadata && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "opkg selection has no HTTPS metadata endpoint".into(),
            )
        })?;
    let normalized = endpoint.url.trim_end_matches('/');
    let reviewed = ROOTS.iter().any(|root| {
        root.mirror
            && root.distribution == distribution
            && normalized == format!("https://{}{}", root.host, root.path)
    });
    if !reviewed {
        return Err(AdapterError::InvalidConfiguration(
            "opkg selection is not a reviewed distribution mirror".into(),
        ));
    }
    Ok(normalized)
}

fn upstream(facts: &SystemFacts) -> &'static str {
    upstream_id(&facts.distribution)
}

fn upstream_id(distribution: &str) -> &'static str {
    match distribution {
        "openwrt" => OPENWRT_UPSTREAM,
        "immortalwrt" => IMMORTALWRT_UPSTREAM,
        _ => unreachable!("validated opkg distribution"),
    }
}

fn next_token(line: &str, start: usize) -> Option<(&str, Range<usize>)> {
    if start >= line.len() {
        return None;
    }
    let end = line[start..]
        .find(char::is_whitespace)
        .map_or(line.len(), |index| start + index);
    (end > start).then(|| (&line[start..end], start..end))
}

fn skip_whitespace(line: &str, start: usize) -> usize {
    start
        + line[start..]
            .find(|character: char| !character.is_whitespace())
            .unwrap_or(line.len() - start)
}

fn safe_segment(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("opkg source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opkg source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{reason}; configuration restored: {restored}"
    )))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "opkg configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
