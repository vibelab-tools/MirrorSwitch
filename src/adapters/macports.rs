use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Path, PathBuf},
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const MACPORTS_CONFIG: &str = "/opt/local/etc/macports/macports.conf";
const DEFAULT_SOURCES: &str = "/opt/local/etc/macports/sources.conf";
const DEFAULT_ARCHIVES: &str = "/opt/local/etc/macports/archive_sites.conf";
const DEFAULT_PUBKEYS: &str = "/opt/local/etc/macports/pubkeys.conf";
const DEFAULT_PUBKEY: &str = "/opt/local/share/macports/macports-pubkey.pem";
const UPSTREAM: &str = "macports--static-files";
const MANAGED_BEGIN: &str = "# BEGIN MirrorSwitch MacPorts archives";
const MANAGED_END: &str = "# END MirrorSwitch MacPorts archives";
const OFFICIAL_SOURCE: &str = "rsync://rsync.macports.org/macports/release/tarballs/ports.tar";
const OFFICIAL_ARCHIVES: &str = "https://packages.macports.org";
const MIRROR_ROOTS: &[&str] = &[
    "https://mirrors.aliyun.com/macports",
    "https://mirrors.nju.edu.cn/macports",
    "https://mirror.sjtu.edu.cn/macports",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct MacPortsAdapter;

impl Adapter for MacPortsAdapter {
    fn key(&self) -> &'static str {
        "macports"
    }

    fn tool_id(&self) -> &'static str {
        "macports"
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
        require_macos(context)?;
        let has_port = runtime.command_exists("port");
        let has_config = runtime.read(Path::new(MACPORTS_CONFIG))?.is_some();
        if !has_port && !has_config {
            return Ok(None);
        }
        if !has_port {
            return Err(AdapterError::Unsupported(
                "MacPorts configuration exists but port is not callable".into(),
            ));
        }
        let version = port_version(runtime)?;
        reviewed_version(&version)?;
        let layout = read_layout(context, runtime)?;
        Ok(Some(DetectedTool {
            tool_id: "macports".into(),
            executable: Some(PathBuf::from("port")),
            version: Some(version.clone()),
            evidence: vec![
                format!("MacPorts {version}"),
                format!(
                    "macOS {} uses Darwin {} and {}",
                    layout.macos_version,
                    layout.os_major,
                    architecture_name(context.architecture)
                ),
                format!("sources configuration is {}", layout.sources.display()),
                format!("archive configuration is {}", layout.archives.display()),
                format!("signed archive policy uses {}", layout.pubkeys.display()),
                format!(
                    "binary policy is buildfromsource={}",
                    layout.build_from_source
                ),
            ],
        }))
    }

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        require_macos(context)?;
        if scope != ConfigurationScope::System {
            return Err(AdapterError::Unsupported(
                "MacPorts sources and archive sites are system-scoped".into(),
            ));
        }
        if detected.tool_id != "macports"
            || detected.version.as_deref() != Some(&port_version(runtime)?)
        {
            return Err(AdapterError::Conflict(
                "MacPorts identity or version changed after detection".into(),
            ));
        }
        let layout = read_layout(context, runtime)?;
        let source_contents = runtime.read(&layout.sources)?.ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "MacPorts sources file {} does not exist",
                layout.sources.display()
            ))
        })?;
        let archive_contents = runtime.read(&layout.archives)?.unwrap_or_default();
        let sources_text = utf8(&layout.sources, &source_contents)?;
        let archives_text = utf8(&layout.archives, &archive_contents)?;
        let source_entries = parse_sources(sources_text, &layout.sources)?;
        let archive_entries = parse_archive_sites(archives_text, &layout.archives)?;
        validate_source_policy(&source_entries)?;
        validate_archive_policy(&archive_entries)?;

        let probe = archive_probe(layout.os_major, context.architecture)?;
        let mut sources = source_entries
            .iter()
            .enumerate()
            .map(|(position, entry)| ConfiguredSource {
                upstream_id: is_public_source(&entry.url).then(|| UPSTREAM.into()),
                url: if is_public_source(&entry.url) {
                    entry.url.clone()
                } else {
                    "redacted://custom-macports-source".into()
                },
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["ports-tree".into()]),
                    ("position".into(), vec![position.to_string()]),
                    ("flags".into(), entry.flags.clone()),
                    (
                        "macports_os_major".into(),
                        vec![layout.os_major.to_string()],
                    ),
                    ("macports_index_arch".into(), vec![probe.index_arch.into()]),
                    ("macports_archive".into(), vec![probe.archive.into()]),
                    (
                        "macports_archive_digest".into(),
                        vec![probe.archive_sha256.into()],
                    ),
                    (
                        "macports_signature_digest".into(),
                        vec![probe.signature_sha256.into()],
                    ),
                ]),
            })
            .collect::<Vec<_>>();
        sources.extend(
            archive_entries
                .iter()
                .enumerate()
                .flat_map(|(position, entry)| {
                    entry.urls.iter().map(move |url| ConfiguredSource {
                        upstream_id: is_public_archive(url).then(|| UPSTREAM.into()),
                        url: if is_public_archive(url) {
                            url.clone()
                        } else {
                            "redacted://custom-macports-archive".into()
                        },
                        enabled: true,
                        metadata: BTreeMap::from([
                            ("kind".into(), vec!["binary-archive".into()]),
                            ("name".into(), vec![entry.name.clone()]),
                            ("position".into(), vec![position.to_string()]),
                        ]),
                    })
                }),
        );
        let mut files = vec![layout.sources.clone()];
        if !archive_contents.is_empty() {
            files.push(layout.archives.clone());
        }
        Ok(CurrentConfiguration {
            tool_id: "macports".into(),
            scope,
            files,
            sources,
            documents: vec![
                ConfigurationDocument {
                    path: layout.sources,
                    format: "macports-sources".into(),
                    contents: source_contents,
                },
                ConfigurationDocument {
                    path: layout.archives,
                    format: "macports-archive-sites".into(),
                    contents: archive_contents,
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
        require_macos(context)?;
        require_current(current)?;
        let tree = current
            .sources
            .iter()
            .filter(|source| {
                metadata(source, "kind") == Some("ports-tree")
                    && source.upstream_id.as_deref() == Some(UPSTREAM)
            })
            .collect::<Vec<_>>();
        if tree.len() != 1 {
            return Err(AdapterError::Unsupported(
                "MacPorts needs exactly one public default ports tree".into(),
            ));
        }
        let context_values = BTreeMap::from([
            (
                "macports_os_major".into(),
                single_metadata(tree[0], "macports_os_major")?.into(),
            ),
            (
                "macports_index_arch".into(),
                single_metadata(tree[0], "macports_index_arch")?.into(),
            ),
            (
                "macports_archive".into(),
                single_metadata(tree[0], "macports_archive")?.into(),
            ),
            (
                "macports_archive_digest".into(),
                single_metadata(tree[0], "macports_archive_digest")?.into(),
            ),
            (
                "macports_signature_digest".into(),
                single_metadata(tree[0], "macports_signature_digest")?.into(),
            ),
        ]);
        Ok(SelectionRequest {
            tool_id: "macports".into(),
            adapter_key: "macports".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(UPSTREAM.into(), vec![context_values])]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Metadata, EndpointRole::Artifacts],
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
        require_macos(context)?;
        require_current(current)?;
        let (tree_endpoint, archive_endpoint) = selected_endpoints(selection)?;
        let source_document = current
            .documents
            .iter()
            .find(|document| document.format == "macports-sources")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("MacPorts sources document is missing".into())
            })?;
        let archive_document = current
            .documents
            .iter()
            .find(|document| document.format == "macports-archive-sites")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("MacPorts archive document is missing".into())
            })?;
        let new_sources = rewrite_sources(
            utf8(&source_document.path, &source_document.contents)?,
            &source_document.path,
            &format!("{}/ports.tar", tree_endpoint.trim_end_matches('/')),
        )?
        .into_bytes();
        let new_archives = rewrite_archive_sites(
            utf8(&archive_document.path, &archive_document.contents)?,
            &archive_document.path,
            archive_endpoint.trim_end_matches('/'),
        )?
        .into_bytes();
        let mut changes = Vec::new();
        if new_sources != source_document.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &source_document.path),
                old_contents: Some(source_document.contents.clone()),
                old_mode: None,
                new_contents: new_sources,
                new_mode: None,
                summary: "replace only the default signed MacPorts tree source".into(),
            });
        }
        if new_archives != archive_document.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &archive_document.path),
                old_contents: current
                    .files
                    .contains(&archive_document.path)
                    .then(|| archive_document.contents.clone()),
                old_mode: None,
                new_contents: new_archives,
                new_mode: None,
                summary: "prefer the paired signed MacPorts binary archive site".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "macports".into(),
            tool_id: "macports".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
            service_impact: ServiceImpact::ReloadRequired,
        })
    }

    fn apply(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        if plan.adapter_key != "macports" || plan.tool_id != "macports" {
            return Err(AdapterError::InvalidConfiguration(
                "MacPorts apply received another adapter's plan".into(),
            ));
        }
        runtime.apply_plan(plan)
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let detected = DetectedTool {
                tool_id: "macports".into(),
                executable: Some(PathBuf::from("port")),
                version: Some(port_version(runtime)?),
                evidence: Vec::new(),
            };
            let current =
                self.read_current(context, runtime, &detected, ConfigurationScope::System)?;
            let public_trees = current
                .sources
                .iter()
                .filter(|source| {
                    metadata(source, "kind") == Some("ports-tree")
                        && source.upstream_id.as_deref() == Some(UPSTREAM)
                        && is_mirror_source(&source.url)
                })
                .count();
            let public_archives = current
                .sources
                .iter()
                .filter(|source| {
                    metadata(source, "kind") == Some("binary-archive")
                        && source.upstream_id.as_deref() == Some(UPSTREAM)
                        && is_mirror_archive(&source.url)
                })
                .count();
            if public_trees != 1 || public_archives != 1 {
                return Err(AdapterError::Verification(
                    "MacPorts did not read one selected tree/archive mirror pair".into(),
                ));
            }
            for (arguments, label) in [
                (vec!["sync".into()], "port sync"),
                (
                    vec!["-q".into(), "info".into(), "zlib".into()],
                    "port info zlib",
                ),
                (
                    vec!["-q".into(), "archivefetch".into(), "zlib".into()],
                    "port archivefetch zlib",
                ),
            ] {
                command_success(runtime.run("port", &arguments)?, label)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            return verification_failure(runtime, receipt, error.to_string());
        }
        Ok(VerificationResult {
            valid: true,
            summary: "MacPorts synchronized the signed tree, read zlib metadata, and verified its binary archive"
                .into(),
        })
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
                "restored {} MacPorts configuration file(s)",
                restored.restored_files
            ),
        })
    }
}

struct Layout {
    sources: PathBuf,
    archives: PathBuf,
    pubkeys: PathBuf,
    build_from_source: String,
    macos_version: String,
    os_major: u32,
}

#[derive(Clone, Copy)]
struct ArchiveProbe {
    index_arch: &'static str,
    archive: &'static str,
    archive_sha256: &'static str,
    signature_sha256: &'static str,
}

#[derive(Clone, Debug)]
struct SourceEntry {
    url_range: Range<usize>,
    url: String,
    flags: Vec<String>,
}

#[derive(Clone, Debug)]
struct ArchiveEntry {
    name: String,
    urls_range: Option<Range<usize>>,
    urls: Vec<String>,
    fields: BTreeMap<String, String>,
}

fn require_macos(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Macos || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "MacPorts mirror configuration requires a native macOS host".into(),
        ));
    }
    Ok(())
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|value| value.parse::<u32>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u32>().ok());
    if major == Some(2) && minor.is_some_and(|minor| minor >= 8) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "MacPorts {version} is outside the reviewed 2.8+ configuration model"
        )))
    }
}

fn port_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = runtime.run("port", &["version".into()])?;
    let text = command_text(output, "port version")?;
    text.strip_prefix("Version:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Runtime("port version returned an unknown format".into()))
}

fn read_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let config_contents = runtime.read(Path::new(MACPORTS_CONFIG))?.ok_or_else(|| {
        AdapterError::Unsupported(format!("MacPorts config {MACPORTS_CONFIG} does not exist"))
    })?;
    let config = parse_key_values(
        utf8(Path::new(MACPORTS_CONFIG), &config_contents)?,
        Path::new(MACPORTS_CONFIG),
    )?;
    let prefix = config
        .get("prefix")
        .map(String::as_str)
        .unwrap_or("/opt/local");
    if prefix != "/opt/local" {
        return Err(AdapterError::Unsupported(format!(
            "MacPorts prefix {prefix} is not the reviewed /opt/local layout"
        )));
    }
    let sources = config_path(&config, "sources_conf", DEFAULT_SOURCES)?;
    let archives = config_path(&config, "archive_sites_conf", DEFAULT_ARCHIVES)?;
    let pubkeys = config_path(&config, "pubkeys_conf", DEFAULT_PUBKEYS)?;
    for path in [&sources, &archives, &pubkeys] {
        if !path.starts_with("/opt/local/etc/macports") {
            return Err(AdapterError::Unsupported(format!(
                "MacPorts configuration path {} is outside /opt/local/etc/macports",
                path.display()
            )));
        }
    }
    let build_from_source = config
        .get("buildfromsource")
        .cloned()
        .unwrap_or_else(|| "ifneeded".into());
    if !matches!(build_from_source.as_str(), "ifneeded" | "never") {
        return Err(AdapterError::Unsupported(
            "MacPorts buildfromsource=always disables binary archives".into(),
        ));
    }
    validate_pubkeys(runtime, &pubkeys)?;
    let macos_version = command_text(
        runtime.run("sw_vers", &["-productVersion".into()])?,
        "sw_vers -productVersion",
    )?;
    let kernel = command_text(runtime.run("uname", &["-r".into()])?, "uname -r")?;
    let os_major = kernel
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AdapterError::Unsupported(format!("unknown Darwin release {kernel}")))?;
    if let Some(reported) = context
        .distribution
        .as_ref()
        .and_then(|distribution| distribution.version_id.as_deref())
        .and_then(|version| version.split('.').next())
        .and_then(|value| value.parse::<u32>().ok())
        && reported >= 11
        && reported + 9 != os_major
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "macOS {reported} conflicts with Darwin {os_major}"
        )));
    }
    archive_probe(os_major, context.architecture)?;
    Ok(Layout {
        sources,
        archives,
        pubkeys,
        build_from_source,
        macos_version,
        os_major,
    })
}

fn config_path(
    config: &BTreeMap<String, String>,
    key: &str,
    default: &str,
) -> Result<PathBuf, AdapterError> {
    let path = PathBuf::from(config.get(key).map(String::as_str).unwrap_or(default));
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "MacPorts {key} must be absolute"
        )))
    }
}

fn validate_pubkeys(runtime: &dyn Runtime, path: &Path) -> Result<(), AdapterError> {
    let contents = runtime.read(path)?.ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "MacPorts pubkeys file {} does not exist",
            path.display()
        ))
    })?;
    let text = utf8(path, &contents)?;
    let keys = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if !keys.contains(&DEFAULT_PUBKEY) || runtime.read(Path::new(DEFAULT_PUBKEY))?.is_none() {
        return Err(AdapterError::Unsupported(
            "MacPorts official archive verification key is missing".into(),
        ));
    }
    Ok(())
}

fn parse_key_values(text: &str, path: &Path) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or("").trim();
        if active.is_empty() {
            continue;
        }
        let mut fields = active.split_whitespace();
        let key = fields.next().unwrap();
        let value = fields.collect::<Vec<_>>().join(" ");
        if value.is_empty() {
            continue;
        }
        if values.insert(key.into(), value).is_some() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} contains duplicate {key} settings",
                path.display()
            )));
        }
    }
    Ok(values)
}

fn parse_sources(text: &str, path: &Path) -> Result<Vec<SourceEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let active_end = line.find('#').unwrap_or(line.len());
        let active = &line[..active_end];
        let trimmed = active.trim();
        if trimmed.is_empty() {
            offset += inclusive.len();
            continue;
        }
        let (url, flags) = match trimmed.split_once(char::is_whitespace) {
            Some((url, rest)) => (url, parse_source_flags(rest, path)?),
            None => (trimmed, Vec::new()),
        };
        if !url.contains("://") {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} contains an invalid source URI",
                path.display()
            )));
        }
        let leading = active.find(url).unwrap();
        entries.push(SourceEntry {
            url_range: offset + leading..offset + leading + url.len(),
            url: url.into(),
            flags,
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn parse_source_flags(value: &str, path: &Path) -> Result<Vec<String>, AdapterError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "{} contains malformed source flags",
                path.display()
            ))
        })?;
    let flags = inner
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if flags
        .iter()
        .any(|flag| !matches!(flag.as_str(), "default" | "nosync"))
    {
        return Err(AdapterError::Unsupported(
            "MacPorts source contains an unknown flag".into(),
        ));
    }
    Ok(flags)
}

fn validate_source_policy(entries: &[SourceEntry]) -> Result<(), AdapterError> {
    let default = entries
        .iter()
        .filter(|entry| entry.flags.iter().any(|flag| flag == "default"))
        .collect::<Vec<_>>();
    if default.len() != 1 || !is_public_source(&default[0].url) {
        return Err(AdapterError::Unsupported(
            "MacPorts needs exactly one reviewed public [default] ports tree".into(),
        ));
    }
    if default[0].flags.iter().any(|flag| flag == "nosync") {
        return Err(AdapterError::Unsupported(
            "MacPorts default source is marked nosync".into(),
        ));
    }
    Ok(())
}

fn rewrite_sources(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    let entries = parse_sources(text, path)?;
    validate_source_policy(&entries)?;
    let default = entries
        .iter()
        .find(|entry| entry.flags.iter().any(|flag| flag == "default"))
        .unwrap();
    let mut output = text.to_owned();
    output.replace_range(default.url_range.clone(), endpoint);
    Ok(output)
}

fn parse_archive_sites(text: &str, path: &Path) -> Result<Vec<ArchiveEntry>, AdapterError> {
    let mut entries = Vec::new();
    let mut current: Option<ArchiveEntry> = None;
    let mut offset = 0;
    managed_range(text, path)?;
    for inclusive in text.split_inclusive('\n') {
        let line_start = offset;
        offset += inclusive.len();
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let active = line.split('#').next().unwrap_or("");
        let trimmed = active.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let key = fields.next().unwrap();
        let value = fields.collect::<Vec<_>>().join(" ");
        if key == "name" {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            if value.is_empty() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "{} contains an archive site without a name",
                    path.display()
                )));
            }
            current = Some(ArchiveEntry {
                name: value,
                urls_range: None,
                urls: Vec::new(),
                fields: BTreeMap::new(),
            });
            continue;
        }
        let Some(entry) = current.as_mut() else {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} contains archive fields before a name",
                path.display()
            )));
        };
        if entry.fields.insert(key.into(), value.clone()).is_some() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} archive {} contains duplicate {key}",
                path.display(),
                entry.name
            )));
        }
        if key == "urls" {
            entry.urls = value.split_whitespace().map(str::to_owned).collect();
            let value_start = active.find(value.as_str()).unwrap();
            entry.urls_range =
                Some(line_start + value_start..line_start + value_start + value.len());
        }
    }
    if let Some(entry) = current {
        entries.push(entry);
    }
    Ok(entries)
}

fn validate_archive_policy(entries: &[ArchiveEntry]) -> Result<(), AdapterError> {
    let defaults = entries
        .iter()
        .filter(|entry| entry.name == "macports_archives")
        .collect::<Vec<_>>();
    if defaults.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "archive_sites.conf contains multiple macports_archives entries".into(),
        ));
    }
    if let Some(entry) = defaults.first() {
        if entry
            .fields
            .get("type")
            .is_some_and(|value| value != "tbz2")
            || entry
                .fields
                .get("prefix")
                .is_some_and(|value| value != "/opt/local")
            || entry.urls.iter().any(|url| !is_public_archive(url))
        {
            return Err(AdapterError::Unsupported(
                "custom macports_archives policy must be preserved unchanged".into(),
            ));
        }
    }
    Ok(())
}

fn rewrite_archive_sites(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    let range = managed_range(text, path)?;
    let entries = parse_archive_sites(text, path)?;
    validate_archive_policy(&entries)?;
    if let Some(entry) = entries
        .iter()
        .find(|entry| entry.name == "macports_archives")
    {
        let range = entry.urls_range.clone().ok_or_else(|| {
            AdapterError::Unsupported("macports_archives entry has no URLs".into())
        })?;
        let mut output = text.to_owned();
        output.replace_range(range, endpoint);
        return Ok(output);
    }
    let mut output = match range {
        Some(range) => format!("{}{}", &text[..range.start], &text[range.end..]),
        None => text.to_owned(),
    };
    while output.ends_with("\n\n") {
        output.pop();
    }
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    if !output.is_empty() {
        output.push('\n');
    }
    output.push_str(MANAGED_BEGIN);
    output.push('\n');
    output.push_str("name macports_archives\n");
    output.push_str(&format!("urls {endpoint}\n"));
    output.push_str(MANAGED_END);
    output.push('\n');
    Ok(output)
}

fn managed_range(text: &str, path: &Path) -> Result<Option<Range<usize>>, AdapterError> {
    let begins = text.match_indices(MANAGED_BEGIN).collect::<Vec<_>>();
    let ends = text.match_indices(MANAGED_END).collect::<Vec<_>>();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([(begin, _)], [(end, _)]) if begin < end => {
            let end = text[*end..]
                .find('\n')
                .map_or(text.len(), |offset| end + offset + 1);
            Ok(Some(*begin..end))
        }
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "{} has malformed MirrorSwitch MacPorts markers",
            path.display()
        ))),
    }
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "macports"
        && current.scope == ConfigurationScope::System
        && current.documents.len() == 2
    {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "MacPorts requires one sources and one archive-sites document".into(),
        ))
    }
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<(&str, &str), AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "macports" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "MacPorts plan requires exactly one paired mirror selection".into(),
        ));
    }
    let metadata = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Metadata && endpoint.protocol == Protocol::Https
        })
        .map(|endpoint| endpoint.url.as_str());
    let artifacts = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .map(|endpoint| endpoint.url.as_str());
    let (Some(metadata), Some(artifacts)) = (metadata, artifacts) else {
        return Err(AdapterError::InvalidConfiguration(
            "MacPorts selection lacks paired HTTPS tree and archive endpoints".into(),
        ));
    };
    if !is_mirror_source(&format!("{}/ports.tar", metadata.trim_end_matches('/')))
        || !is_mirror_archive(artifacts)
        || provider_root(metadata) != provider_root(artifacts)
    {
        return Err(AdapterError::InvalidConfiguration(
            "MacPorts selection is not a reviewed same-provider mirror pair".into(),
        ));
    }
    Ok((metadata, artifacts))
}

fn archive_probe(os_major: u32, architecture: Architecture) -> Result<ArchiveProbe, AdapterError> {
    match (os_major, architecture) {
        (23, Architecture::Arm64) => Ok(ArchiveProbe {
            index_arch: "arm",
            archive: "zlib-1.3.2_0.darwin_23.arm64.tbz2",
            archive_sha256: "8ab2dcf0e4a1a7cc8fd186a63d55774961eb1e55788858669825ab193d871a59",
            signature_sha256: "0c3a166eac3a9afd7ce79723770c6d9b8c4b747b1b7c33b998fa1f270073f07a",
        }),
        (23, Architecture::X86_64) => Ok(ArchiveProbe {
            index_arch: "i386",
            archive: "zlib-1.3.2_0.darwin_23.x86_64.tbz2",
            archive_sha256: "f540f2e51f02a2f2f476a3088a310e99fe4031e5e26c9fa2e55119e0bfa46b2e",
            signature_sha256: "faa6c60f465a297949c6c90ba487e48582b718435b04361ffe21a150701c4f97",
        }),
        (24, Architecture::Arm64) => Ok(ArchiveProbe {
            index_arch: "arm",
            archive: "zlib-1.3.2_0.darwin_24.arm64.tbz2",
            archive_sha256: "6df2d10ff4522a67610b49d872ba19342c92793a31b874c314c912a3bd452072",
            signature_sha256: "fe14a22df118d2f89bb9e80b3a16be17957e61ce8500e630278affad09703c76",
        }),
        (24, Architecture::X86_64) => Ok(ArchiveProbe {
            index_arch: "i386",
            archive: "zlib-1.3.2_0.darwin_24.x86_64.tbz2",
            archive_sha256: "5dae3b165cbe87f3d77e7e380159b26f2e69867fd0d1458dee5799f1bbdd2327",
            signature_sha256: "9d9ad96fd82afde5c908e15231e942cfb5d44500d23086d7885f5ab9ce52f1fa",
        }),
        (25, Architecture::Arm64) => Ok(ArchiveProbe {
            index_arch: "arm",
            archive: "zlib-1.3.2_0.darwin_25.arm64.tbz2",
            archive_sha256: "486450a6cb032db02f2c2ae577bf5c3c9bc7743af12a9bc6d8fc503fc16fa2c6",
            signature_sha256: "4ad55d05fe27c83a15531c7aead8ed62da8867bb59892188223498c58373715f",
        }),
        _ => Err(AdapterError::Unsupported(format!(
            "MacPorts mirror evidence does not cover Darwin {os_major} {}",
            architecture_name(architecture)
        ))),
    }
}

fn is_public_source(url: &str) -> bool {
    normalize_url(url) == normalize_url(OFFICIAL_SOURCE) || is_mirror_source(url)
}

fn is_mirror_source(url: &str) -> bool {
    MIRROR_ROOTS.iter().any(|root| {
        normalize_url(url) == normalize_url(&format!("{root}/release/tarballs/ports.tar"))
    })
}

fn is_public_archive(url: &str) -> bool {
    normalize_url(url) == normalize_url(OFFICIAL_ARCHIVES) || is_mirror_archive(url)
}

fn is_mirror_archive(url: &str) -> bool {
    MIRROR_ROOTS
        .iter()
        .any(|root| normalize_url(url) == normalize_url(&format!("{root}/packages")))
}

fn provider_root(url: &str) -> Option<&'static str> {
    MIRROR_ROOTS
        .iter()
        .copied()
        .find(|root| normalize_url(url).starts_with(&normalize_url(root)))
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn architecture_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "arm64",
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("MacPorts source is missing {key}"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "MacPorts source has ambiguous {key}"
        )));
    }
    Ok(&values[0])
}

fn command_text(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    command_success(output.clone(), label)?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 output")))
}

fn command_success(output: std::process::Output, label: &str) -> Result<(), AdapterError> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = stderr
            .split_whitespace()
            .chain(stdout.split_whitespace())
            .map(|token| {
                if token.contains("://") {
                    "<url>".to_owned()
                } else {
                    token.to_owned()
                }
            })
            .take(80)
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(512)
            .collect::<String>();
        Err(AdapterError::Runtime(format!(
            "{label} failed with status {}{}",
            output.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )))
    }
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
            "MacPorts configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.into()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
