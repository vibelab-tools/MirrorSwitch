use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Range,
    path::{Component, Path, PathBuf},
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

const PACMAN_CONFIG: &str = "/etc/pacman.conf";

#[derive(Clone, Copy, Debug, Default)]
pub struct PacmanAdapter;

impl Adapter for PacmanAdapter {
    fn key(&self) -> &'static str {
        "pacman"
    }

    fn tool_id(&self) -> &'static str {
        "pacman"
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
        let has_command = runtime.command_exists("pacman");
        let has_config = runtime.read(Path::new(PACMAN_CONFIG))?.is_some();
        if !has_command && !has_config {
            return Ok(None);
        }
        let mut evidence = Vec::new();
        let mut version = None;
        if has_command {
            let output = runtime.run("pacman", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "pacman --version failed with status {}",
                    output.status
                )));
            }
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("pacman")
                .trim()
                .to_owned();
            version = Some(first_line.clone());
            evidence.push(format!("Pacman command {first_line}"));
        }
        if has_config {
            evidence.push(format!("Pacman configuration {PACMAN_CONFIG}"));
        }
        Ok(Some(DetectedTool {
            tool_id: "pacman".into(),
            executable: has_command.then(|| PathBuf::from("/usr/bin/pacman")),
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
                "Pacman only supports system scope".into(),
            ));
        }
        let main_path = PathBuf::from(PACMAN_CONFIG);
        let main_contents = runtime.read(&main_path)?.ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("{PACMAN_CONFIG} is missing"))
        })?;
        let main_text = utf8_document(&main_path, &main_contents)?;
        let main = parse_document(&main_path, main_text, context, None)?;

        let mut documents = BTreeMap::from([(
            main_path.clone(),
            ConfigurationDocument {
                path: main_path.clone(),
                format: "pacman-conf".into(),
                contents: main_contents,
            },
        )]);
        let mut sources = sources_from_servers(&main_path, &main.servers, context)?;
        let mut queue = VecDeque::from(main.includes);
        let mut visited = BTreeSet::new();
        let mut owners: BTreeMap<PathBuf, String> = BTreeMap::new();

        while let Some(include) = queue.pop_front() {
            let path = resolve_include(&include.source_file, &include.path)?;
            let visit_key = (
                path.clone(),
                include.upstream_id.clone(),
                include.section.clone(),
            );
            if !visited.insert(visit_key) {
                continue;
            }
            if let Some(existing) = owners.insert(path.clone(), include.upstream_id.clone())
                && existing != include.upstream_id
            {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Pacman include {} is shared by incompatible repositories",
                    path.display()
                )));
            }
            let contents = if let Some(document) = documents.get(&path) {
                document.contents.clone()
            } else {
                let contents = runtime.read(&path)?.ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Pacman include {} is missing",
                        path.display()
                    ))
                })?;
                documents.insert(
                    path.clone(),
                    ConfigurationDocument {
                        path: path.clone(),
                        format: "pacman-mirrorlist".into(),
                        contents: contents.clone(),
                    },
                );
                contents
            };
            let text = utf8_document(&path, &contents)?;
            let binding = RepositoryBinding {
                upstream_id: include.upstream_id,
                section: include.section,
            };
            let parsed = parse_document(&path, text, context, Some(&binding))?;
            sources.extend(sources_from_servers(&path, &parsed.servers, context)?);
            queue.extend(parsed.includes);
        }

        let documents = documents.into_values().collect::<Vec<_>>();
        Ok(CurrentConfiguration {
            tool_id: "pacman".into(),
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
        if current.tool_id != "pacman" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Pacman selection requires a system-scope Pacman configuration".into(),
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
                probe_contexts
                    .entry(upstream.clone())
                    .or_insert_with(Vec::new)
                    .push(BTreeMap::from([(
                        "repository_path".into(),
                        expand_architecture(path, context)?,
                    )]));
                upstreams.insert(upstream.clone());
            }
        }
        for contexts in probe_contexts.values_mut() {
            contexts.sort();
            contexts.dedup();
        }
        if upstreams.is_empty() {
            return Err(AdapterError::Unsupported(
                "no supported Pacman repository servers were detected".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "pacman".into(),
            adapter_key: "pacman".into(),
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
        if current.tool_id != "pacman" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Pacman plan requires a system-scope Pacman configuration".into(),
            ));
        }
        let selected = selected_endpoints(selection)?;
        let mut file_upstreams: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
        for source in &current.sources {
            let (Some(upstream), Some(files)) =
                (source.upstream_id.as_ref(), source.metadata.get("file"))
            else {
                continue;
            };
            for file in files {
                file_upstreams
                    .entry(PathBuf::from(file))
                    .or_default()
                    .insert(upstream.clone());
            }
        }

        let mut changes = Vec::new();
        for document in &current.documents {
            let text = utf8_document(&document.path, &document.contents)?;
            let forced = if document.format == "pacman-conf" {
                None
            } else if document.format == "pacman-mirrorlist" {
                let upstreams = file_upstreams.get(&document.path).ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Pacman include {} has no repository owner",
                        document.path.display()
                    ))
                })?;
                if upstreams.len() != 1 {
                    return Err(AdapterError::InvalidConfiguration(format!(
                        "Pacman include {} has multiple repository owners",
                        document.path.display()
                    )));
                }
                Some(RepositoryBinding {
                    upstream_id: upstreams.iter().next().unwrap().clone(),
                    section: "include".into(),
                })
            } else {
                return Err(AdapterError::Unsupported(format!(
                    "unknown Pacman document format {}",
                    document.format
                )));
            };
            let parsed = parse_document(&document.path, text, context, forced.as_ref())?;
            let new_contents = rewrite_servers(text, parsed.servers, &selected)?;
            if new_contents == document.contents {
                continue;
            }
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "replace only selected Pacman repository server lists".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "pacman".into(),
            tool_id: "pacman".into(),
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
        let output = runtime.run("pacman", &["-Syy".into(), "--noconfirm".into()])?;
        if output.status.success() {
            return Ok(VerificationResult {
                valid: true,
                summary: "pacman -Syy validated repository databases and SigLevel policy".into(),
            });
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
        Err(AdapterError::Verification(format!(
            "pacman -Syy failed with status {}; configuration restored: {restored}",
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
                "restored {} Pacman configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct RepositoryBinding {
    upstream_id: String,
    section: String,
}

#[derive(Clone, Debug)]
struct IncludeDirective {
    source_file: PathBuf,
    path: String,
    upstream_id: String,
    section: String,
}

#[derive(Clone, Debug)]
struct ServerLine {
    upstream_id: String,
    section: String,
    url: String,
    line: String,
    indentation: String,
    line_range: Range<usize>,
    included: bool,
}

#[derive(Default)]
struct ParsedDocument {
    includes: Vec<IncludeDirective>,
    servers: Vec<ServerLine>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("Pacman requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("Pacman requires distribution metadata".into()))?;
    let supported = matches!(
        (distribution.id.as_str(), context.architecture),
        ("arch", Architecture::X86_64) | ("archarm", Architecture::Arm64)
    );
    if !supported {
        return Err(AdapterError::Unsupported(format!(
            "Pacman has no verified repository model for {} on {:?}",
            distribution.id, context.architecture
        )));
    }
    Ok(())
}

fn parse_document(
    file: &Path,
    text: &str,
    context: &SystemContext,
    forced: Option<&RepositoryBinding>,
) -> Result<ParsedDocument, AdapterError> {
    let mut parsed = ParsedDocument::default();
    let mut section = None;
    let mut offset = 0;
    for raw_line in text.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[#") {
            if !trimmed.ends_with(']') || trimmed.len() < 3 {
                return Err(AdapterError::InvalidConfiguration(
                    "Pacman repository section header is malformed".into(),
                ));
            }
            section = Some(trimmed[1..trimmed.len() - 1].to_ascii_lowercase());
            offset += raw_line.len();
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += raw_line.len();
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            offset += raw_line.len();
            continue;
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim();
        let binding = forced.cloned().or_else(|| {
            section
                .as_deref()
                .and_then(|section| classify_section(section, context))
        });
        let Some(binding) = binding else {
            offset += raw_line.len();
            continue;
        };
        match key.as_str() {
            "include" => parsed.includes.push(IncludeDirective {
                source_file: file.to_path_buf(),
                path: value.into(),
                upstream_id: binding.upstream_id,
                section: binding.section,
            }),
            "server" => parsed.servers.push(ServerLine {
                upstream_id: binding.upstream_id,
                section: binding.section,
                url: value.into(),
                line: line.into(),
                indentation: line[..line.len() - line.trim_start().len()].into(),
                line_range: offset..offset + raw_line.len(),
                included: forced.is_some(),
            }),
            _ => {}
        }
        offset += raw_line.len();
    }
    Ok(parsed)
}

fn classify_section(section: &str, context: &SystemContext) -> Option<RepositoryBinding> {
    if section == "archlinuxcn" {
        return Some(RepositoryBinding {
            upstream_id: "archlinuxcn--repository-metadata".into(),
            section: section.into(),
        });
    }
    if section == "blackarch" && context.architecture == Architecture::X86_64 {
        return Some(RepositoryBinding {
            upstream_id: "blackarch--repository-metadata".into(),
            section: section.into(),
        });
    }
    const OFFICIAL: &[&str] = &[
        "core",
        "extra",
        "multilib",
        "community",
        "core-testing",
        "extra-testing",
        "multilib-testing",
        "alarm",
        "aur",
    ];
    if !OFFICIAL.contains(&section) {
        return None;
    }
    let distribution = context.distribution.as_ref()?.id.as_str();
    let upstream = match distribution {
        "arch" if !matches!(section, "alarm" | "aur") => "archlinux--repository-metadata",
        "archarm" if section != "multilib" && section != "multilib-testing" => {
            "archlinuxarm--repository-metadata"
        }
        _ => return None,
    };
    Some(RepositoryBinding {
        upstream_id: upstream.into(),
        section: section.into(),
    })
}

fn sources_from_servers(
    file: &Path,
    servers: &[ServerLine],
    context: &SystemContext,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    servers
        .iter()
        .map(|server| {
            let repository_path =
                repository_database_path(&server.upstream_id, &server.section, context)?;
            Ok(ConfiguredSource {
                upstream_id: Some(server.upstream_id.clone()),
                url: server.url.clone(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("file".into(), vec![file.display().to_string()]),
                    ("section".into(), vec![server.section.clone()]),
                    ("repository_path".into(), vec![repository_path]),
                ]),
            })
        })
        .collect()
}

fn repository_database_path(
    upstream: &str,
    section: &str,
    _context: &SystemContext,
) -> Result<String, AdapterError> {
    match upstream {
        "archlinux--repository-metadata" => Ok(format!("{section}/os/$arch/{section}.db")),
        "archlinuxarm--repository-metadata" => Ok(format!("$arch/{section}/{section}.db")),
        "archlinuxcn--repository-metadata" => Ok("$arch/archlinuxcn.db".into()),
        "blackarch--repository-metadata" => Ok("blackarch/os/$arch/blackarch.db".into()),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "unknown Pacman upstream {upstream}"
        ))),
    }
}

fn resolve_include(source_file: &Path, value: &str) -> Result<PathBuf, AdapterError> {
    if value.is_empty() || value.contains(['*', '?', '[', ']']) || value.contains('$') {
        return Err(AdapterError::Unsupported(format!(
            "Pacman Include pattern {value:?} is not a single safe file"
        )));
    }
    let value = Path::new(value);
    let path = if value.is_absolute() {
        value.to_path_buf()
    } else {
        source_file
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .join(value)
    };
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Pacman Include {} is not a normalized path",
            path.display()
        )));
    }
    Ok(path)
}

fn selected_endpoints(
    selections: &[MirrorSelection],
) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut selected = BTreeMap::new();
    for selection in selections {
        if selection.tool_id != "pacman" {
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

fn rewrite_servers(
    text: &str,
    servers: Vec<ServerLine>,
    selected: &BTreeMap<String, String>,
) -> Result<Vec<u8>, AdapterError> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut groups: BTreeMap<(String, String), Vec<ServerLine>> = BTreeMap::new();
    for server in servers {
        let section_key = if server.included {
            "include".into()
        } else {
            server.section.clone()
        };
        groups
            .entry((server.upstream_id.clone(), section_key))
            .or_default()
            .push(server);
    }
    let mut replacements = Vec::new();
    for ((upstream, _), mut group) in groups {
        let Some(endpoint) = selected.get(&upstream) else {
            continue;
        };
        group.sort_by_key(|server| server.line_range.start);
        let desired = desired_server(&upstream, endpoint)?;
        if group.len() == 1 && group[0].url == desired {
            continue;
        }
        for (index, server) in group.into_iter().enumerate() {
            let mut replacement = format!(
                "{}# MirrorSwitch original: {}{}",
                server.indentation,
                server.line.trim_start(),
                newline
            );
            if index == 0 {
                replacement.push_str(&format!(
                    "{}Server = {}{}",
                    server.indentation, desired, newline
                ));
            }
            replacements.push((server.line_range, replacement));
        }
    }
    replacements.sort_by_key(|(range, _)| range.start);
    for pair in replacements.windows(2) {
        if pair[0].0.end > pair[1].0.start {
            return Err(AdapterError::InvalidConfiguration(
                "Pacman server replacement ranges overlap".into(),
            ));
        }
    }
    let mut output = text.as_bytes().to_vec();
    for (range, replacement) in replacements.into_iter().rev() {
        output.splice(range, replacement.bytes());
    }
    Ok(output)
}

fn desired_server(upstream: &str, endpoint: &str) -> Result<String, AdapterError> {
    let suffix = match upstream {
        "archlinux--repository-metadata" | "blackarch--repository-metadata" => "$repo/os/$arch",
        "archlinuxarm--repository-metadata" => "$arch/$repo",
        "archlinuxcn--repository-metadata" => "$arch",
        _ => {
            return Err(AdapterError::InvalidConfiguration(format!(
                "unknown Pacman upstream {upstream}"
            )));
        }
    };
    Ok(format!("{}/{}", endpoint.trim_end_matches('/'), suffix))
}

fn expand_architecture(template: &str, context: &SystemContext) -> Result<String, AdapterError> {
    let architecture = match context.architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "aarch64",
    };
    let expanded = template
        .replace("${arch}", architecture)
        .replace("$arch", architecture);
    if expanded.contains('$')
        || expanded
            .split('/')
            .filter(|segment| !segment.is_empty())
            .any(|segment| {
                matches!(segment, "." | "..")
                    || !segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
                    })
            })
    {
        return Err(AdapterError::InvalidConfiguration(
            "Pacman repository path contains unsupported variables or segments".into(),
        ));
    }
    Ok(expanded)
}

fn utf8_document<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Pacman configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn rooted(root: &Path, logical: &Path) -> PathBuf {
    root.join(logical.strip_prefix("/").unwrap_or(logical))
}
