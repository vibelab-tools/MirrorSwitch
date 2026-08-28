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

const MAKE_CONF: &str = "/etc/portage/make.conf";
const REPOS_CONF: &str = "/etc/portage/repos.conf";
const DEFAULT_REPOS_CONF: &str = "/usr/share/portage/config/repos.conf";
const GENERATED_REPO_CONF: &str = "/etc/portage/repos.conf/gentoo.conf";
const DISTFILES_UPSTREAM: &str = "gentoo--repository-metadata";
const PORTAGE_SYNC_UPSTREAM: &str = "gentoo-portage--repository-metadata";

#[derive(Clone, Copy, Debug, Default)]
pub struct PortageAdapter;

impl Adapter for PortageAdapter {
    fn key(&self) -> &'static str {
        "portage"
    }

    fn tool_id(&self) -> &'static str {
        "portage"
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
        let has_command = runtime.command_exists("emerge");
        let has_configuration = runtime.read(Path::new(MAKE_CONF))?.is_some()
            || !repository_documents(runtime)?.is_empty();
        if !has_command && !has_configuration {
            return Ok(None);
        }

        let mut evidence = Vec::new();
        let mut version = None;
        if has_command {
            let output = runtime.run("emerge", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "emerge --version failed with status {}",
                    output.status
                )));
            }
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("Portage")
                .trim()
                .to_owned();
            version = (!first_line.is_empty()).then_some(first_line.clone());
            evidence.push(format!("Portage command {first_line}"));
        }
        if runtime.read(Path::new(MAKE_CONF))?.is_some() {
            evidence.push(format!("Portage configuration {MAKE_CONF}"));
        }
        evidence.push(format!(
            "Gentoo profile architecture {}",
            portage_architecture(context.architecture)
        ));

        Ok(Some(DetectedTool {
            tool_id: "portage".into(),
            executable: has_command.then(|| PathBuf::from("/usr/bin/emerge")),
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
                "Portage only supports system scope".into(),
            ));
        }

        let profile = profile_metadata(context, runtime)?;
        let make_contents = runtime.read(Path::new(MAKE_CONF))?;
        let make_bytes = make_contents.clone().unwrap_or_default();
        let make_text = utf8(MAKE_CONF, &make_bytes)?;
        let mirrors = parse_mirror_assignment(make_text)?;
        let mut sources = if let Some(assignment) = mirrors {
            if assignment.urls.is_empty() {
                vec![distfiles_source("", &profile)]
            } else {
                assignment
                    .urls
                    .iter()
                    .map(|url| distfiles_source(url, &profile))
                    .collect()
            }
        } else {
            vec![distfiles_source("", &profile)]
        };
        let mut documents = vec![ConfigurationDocument {
            path: PathBuf::from(MAKE_CONF),
            format: if make_contents.is_some() {
                "portage-make".into()
            } else {
                "portage-make-missing".into()
            },
            contents: make_bytes,
        }];

        let repository_documents = repository_documents(runtime)?;
        let parsed = repository_documents
            .iter()
            .map(|document| {
                Ok((
                    document,
                    parse_repositories(utf8(
                        &document.path.to_string_lossy(),
                        &document.contents,
                    )?)?,
                ))
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        let main_repo = main_repository(parsed.iter().map(|(_, repositories)| repositories))?;
        for (_, repositories) in &parsed {
            for section in &repositories.sections {
                let Some(sync_uri) = section.value("sync-uri") else {
                    continue;
                };
                let sync_type = section.value("sync-type").unwrap_or("");
                let is_main = section.name == main_repo;
                let upstream_id = (is_main
                    && sync_type.eq_ignore_ascii_case("rsync")
                    && known_gentoo_sync(sync_uri))
                .then(|| PORTAGE_SYNC_UPSTREAM.into());
                let mut metadata = profile.clone();
                metadata.insert("repository".into(), vec![section.name.clone()]);
                metadata.insert("sync_type".into(), vec![sync_type.into()]);
                metadata.insert("main_repository".into(), vec![is_main.to_string()]);
                for key in [
                    "location",
                    "auto-sync",
                    "sync-openpgp-key-path",
                    "sync-openpgp-keyserver",
                    "sync-openpgp-key-package",
                    "sync-rsync-verify-metamanifest",
                ] {
                    if let Some(value) = section.value(key) {
                        metadata.insert(key.replace('-', "_"), vec![value.into()]);
                    }
                }
                sources.push(ConfiguredSource {
                    upstream_id,
                    url: sync_uri.into(),
                    enabled: true,
                    metadata,
                });
            }
        }
        documents.extend(repository_documents);

        Ok(CurrentConfiguration {
            tool_id: "portage".into(),
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
        if current.tool_id != "portage" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Portage selection requires a system-scope configuration".into(),
            ));
        }
        let mut upstreams = current
            .sources
            .iter()
            .filter(|source| source.enabled)
            .filter_map(|source| source.upstream_id.clone())
            .collect::<BTreeSet<_>>();
        upstreams.insert(DISTFILES_UPSTREAM.into());
        let architecture = portage_architecture(context.architecture).to_owned();
        let mut probe_contexts = BTreeMap::from([(
            DISTFILES_UPSTREAM.into(),
            vec![BTreeMap::from([
                ("gentoo_arch".into(), architecture.clone()),
                ("stage3_arch".into(), architecture.clone()),
            ])],
        )]);
        if upstreams.contains(PORTAGE_SYNC_UPSTREAM) {
            probe_contexts.insert(
                PORTAGE_SYNC_UPSTREAM.into(),
                vec![BTreeMap::from([("gentoo_arch".into(), architecture)])],
            );
        }
        Ok(SelectionRequest {
            tool_id: "portage".into(),
            adapter_key: "portage".into(),
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
            allowed_protocols: vec![Protocol::Https, Protocol::Rsync],
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
        if current.tool_id != "portage" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Portage plan requires a system-scope configuration".into(),
            ));
        }
        let distfiles = selected_endpoint(selection, DISTFILES_UPSTREAM, Protocol::Https)?;
        let sync = selection
            .iter()
            .any(|item| item.upstream_id == PORTAGE_SYNC_UPSTREAM)
            .then(|| selected_endpoint(selection, PORTAGE_SYNC_UPSTREAM, Protocol::Rsync))
            .transpose()?;
        let parsed_repositories = current
            .documents
            .iter()
            .filter(|document| document.format.contains("repos"))
            .map(|document| {
                Ok((
                    document,
                    parse_repositories(utf8(
                        &document.path.to_string_lossy(),
                        &document.contents,
                    )?)?,
                ))
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        let main_repo = main_repository(
            parsed_repositories
                .iter()
                .map(|(_, repositories)| repositories),
        )?;

        let mut changes = Vec::new();
        for document in &current.documents {
            let (target, old_contents, new_contents, summary) = match document.format.as_str() {
                "portage-make" | "portage-make-missing" => {
                    let text = utf8(&document.path.to_string_lossy(), &document.contents)?;
                    let rewritten = rewrite_mirrors(text, distfiles)?;
                    (
                        document.path.clone(),
                        (document.format == "portage-make").then(|| document.contents.clone()),
                        rewritten.into_bytes(),
                        "set the selected Gentoo distfiles mirror",
                    )
                }
                "portage-repos" | "portage-default-repos" => {
                    let Some(sync) = sync else {
                        continue;
                    };
                    let text = utf8(&document.path.to_string_lossy(), &document.contents)?;
                    let repositories = parse_repositories(text)?;
                    let rewritten = rewrite_main_sync(text, &repositories, &main_repo, sync)?;
                    let (target, old_contents) = if document.format == "portage-default-repos" {
                        (PathBuf::from(GENERATED_REPO_CONF), None)
                    } else {
                        (document.path.clone(), Some(document.contents.clone()))
                    };
                    (
                        target,
                        old_contents,
                        rewritten.into_bytes(),
                        "replace only the Gentoo main repository rsync URI",
                    )
                }
                other => {
                    return Err(AdapterError::Unsupported(format!(
                        "unknown Portage document format {other}"
                    )));
                }
            };
            if old_contents.as_deref() == Some(new_contents.as_slice()) {
                continue;
            }
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &target),
                old_contents,
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: summary.into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "portage".into(),
            tool_id: "portage".into(),
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
        let emerge = runtime.run("emerge", &["--info".into()])?;
        if !emerge.status.success() {
            return verification_failure(
                runtime,
                receipt,
                format!("emerge --info failed with status {}", emerge.status),
            );
        }

        let repository_documents = repository_documents(runtime)?;
        let parsed = repository_documents
            .iter()
            .map(|document| {
                parse_repositories(utf8(&document.path.to_string_lossy(), &document.contents)?)
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        let main_repo = main_repository(parsed.iter())?;
        for repositories in parsed {
            let Some(section) = repositories
                .sections
                .iter()
                .find(|section| section.name == main_repo)
            else {
                continue;
            };
            let (Some(sync_type), Some(sync_uri)) =
                (section.value("sync-type"), section.value("sync-uri"))
            else {
                continue;
            };
            if !sync_type.eq_ignore_ascii_case("rsync") || !known_gentoo_sync(sync_uri) {
                continue;
            }
            let target = format!("{}/profiles/repo_name", sync_uri.trim_end_matches('/'));
            let output = runtime.run(
                "rsync",
                &[
                    "--list-only".into(),
                    "--contimeout=5".into(),
                    "--timeout=15".into(),
                    target,
                ],
            )?;
            if !output.status.success() {
                return verification_failure(
                    runtime,
                    receipt,
                    format!(
                        "read-only rsync repository check failed with status {}",
                        output.status
                    ),
                );
            }
            break;
        }
        Ok(VerificationResult {
            valid: true,
            summary: "emerge parsed Portage configuration and the selected rsync repository passed a read-only metadata check".into(),
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
                "restored {} Portage configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct MirrorAssignment {
    value_range: Range<usize>,
    urls: Vec<String>,
}

#[derive(Clone, Debug)]
struct RepoField {
    key: String,
    value: String,
    value_range: Range<usize>,
}

#[derive(Clone, Debug)]
struct RepoSection {
    name: String,
    fields: Vec<RepoField>,
}

impl RepoSection {
    fn value(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .rev()
            .find(|field| field.key == key)
            .map(|field| field.value.as_str())
    }
}

#[derive(Clone, Debug)]
struct Repositories {
    sections: Vec<RepoSection>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("Portage requires Linux".into()));
    }
    let distribution = context.distribution.as_ref().ok_or_else(|| {
        AdapterError::Unsupported("Portage requires distribution metadata".into())
    })?;
    if distribution.id != "gentoo" && !distribution.id_like.iter().any(|id| id == "gentoo") {
        return Err(AdapterError::Unsupported(format!(
            "Portage adapter has no verified configuration rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn portage_architecture(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "amd64",
        Architecture::Arm64 => "arm64",
    }
}

fn profile_metadata(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<BTreeMap<String, Vec<String>>, AdapterError> {
    let mut metadata = BTreeMap::from([(
        "profile_architecture".into(),
        vec![portage_architecture(context.architecture).into()],
    )]);
    if let Some(contents) = runtime.read(Path::new("/etc/portage/make.profile/parent"))? {
        let parent = utf8("/etc/portage/make.profile/parent", &contents)?.trim();
        if !parent.is_empty() {
            metadata.insert("profile_parent".into(), vec![parent.into()]);
        }
    }
    Ok(metadata)
}

fn distfiles_source(url: &str, profile: &BTreeMap<String, Vec<String>>) -> ConfiguredSource {
    let mut metadata = profile.clone();
    metadata.insert("variable".into(), vec!["GENTOO_MIRRORS".into()]);
    ConfiguredSource {
        upstream_id: Some(DISTFILES_UPSTREAM.into()),
        url: url.into(),
        enabled: true,
        metadata,
    }
}

fn repository_documents(runtime: &dyn Runtime) -> Result<Vec<ConfigurationDocument>, AdapterError> {
    let mut documents = Vec::new();
    match runtime.list_files(Path::new(REPOS_CONF)) {
        Ok(paths) => {
            for path in paths.into_iter().filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("conf")
            }) {
                if let Some(contents) = runtime.read(&path)? {
                    documents.push(ConfigurationDocument {
                        path,
                        format: "portage-repos".into(),
                        contents,
                    });
                }
            }
        }
        Err(AdapterError::Runtime(_)) => {
            if let Some(contents) = runtime.read(Path::new(REPOS_CONF))? {
                documents.push(ConfigurationDocument {
                    path: PathBuf::from(REPOS_CONF),
                    format: "portage-repos".into(),
                    contents,
                });
            }
        }
        Err(error) => return Err(error),
    }
    documents.sort_by(|left, right| left.path.cmp(&right.path));
    if documents.is_empty()
        && let Some(contents) = runtime.read(Path::new(DEFAULT_REPOS_CONF))?
    {
        documents.push(ConfigurationDocument {
            path: PathBuf::from(DEFAULT_REPOS_CONF),
            format: "portage-default-repos".into(),
            contents,
        });
    }
    Ok(documents)
}

fn parse_mirror_assignment(text: &str) -> Result<Option<MirrorAssignment>, AdapterError> {
    let mut found = None;
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let leading = line.len() - line.trim_start().len();
        let mut rest = &line[leading..];
        let mut consumed = leading;
        if rest.starts_with('#') || rest.is_empty() {
            offset += inclusive.len();
            continue;
        }
        if let Some(after) = rest.strip_prefix("export")
            && after.starts_with(char::is_whitespace)
        {
            let whitespace = after.len() - after.trim_start().len();
            consumed += "export".len() + whitespace;
            rest = after.trim_start();
        }
        let Some(after_name) = rest.strip_prefix("GENTOO_MIRRORS") else {
            offset += inclusive.len();
            continue;
        };
        if !after_name.is_empty()
            && !after_name.starts_with(char::is_whitespace)
            && !after_name.starts_with('=')
        {
            offset += inclusive.len();
            continue;
        }
        consumed += "GENTOO_MIRRORS".len();
        let whitespace = after_name.len() - after_name.trim_start().len();
        consumed += whitespace;
        let after_name = after_name.trim_start();
        let Some(after_equals) = after_name.strip_prefix('=') else {
            return Err(AdapterError::InvalidConfiguration(
                "GENTOO_MIRRORS assignment is missing '='".into(),
            ));
        };
        consumed += 1;
        let whitespace = after_equals.len() - after_equals.trim_start().len();
        consumed += whitespace;
        let value = after_equals.trim_start();
        if value.ends_with('\\') {
            return Err(AdapterError::Unsupported(
                "multiline GENTOO_MIRRORS assignments are not supported".into(),
            ));
        }
        let (value_length, raw) = shell_value(value)?;
        let value_range = offset + consumed..offset + consumed + value_length;
        let assignment = MirrorAssignment {
            value_range,
            urls: raw.split_whitespace().map(str::to_owned).collect(),
        };
        if found.replace(assignment).is_some() {
            return Err(AdapterError::InvalidConfiguration(
                "multiple active GENTOO_MIRRORS assignments are ambiguous".into(),
            ));
        }
        offset += inclusive.len();
    }
    Ok(found)
}

fn shell_value(value: &str) -> Result<(usize, &str), AdapterError> {
    let Some(first) = value.chars().next() else {
        return Ok((0, ""));
    };
    if matches!(first, '\'' | '"') {
        let mut escaped = false;
        for (index, character) in value[first.len_utf8()..].char_indices() {
            if first == '"' && character == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if character == first && !escaped {
                let end = first.len_utf8() + index;
                return Ok((end + character.len_utf8(), &value[first.len_utf8()..end]));
            }
            escaped = false;
        }
        return Err(AdapterError::InvalidConfiguration(
            "GENTOO_MIRRORS has an unterminated quote".into(),
        ));
    }
    let end = value
        .char_indices()
        .find_map(|(index, character)| {
            (character == '#'
                && (index == 0
                    || value[..index]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)))
            .then_some(index)
        })
        .unwrap_or(value.len());
    let trimmed = value[..end].trim_end();
    Ok((trimmed.len(), trimmed))
}

fn rewrite_mirrors(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let rendered = format!("\"{}\"", endpoint.trim_end_matches('/'));
    let Some(assignment) = parse_mirror_assignment(text)? else {
        let mut output = text.to_owned();
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str("GENTOO_MIRRORS=");
        output.push_str(&rendered);
        output.push('\n');
        return Ok(output);
    };
    let mut output = text.to_owned();
    output.replace_range(assignment.value_range, &rendered);
    Ok(output)
}

fn parse_repositories(text: &str) -> Result<Repositories, AdapterError> {
    let mut sections = Vec::new();
    let mut current: Option<RepoSection> = None;
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            let name = trimmed[1..trimmed.len() - 1].trim();
            if name.is_empty() {
                return Err(AdapterError::InvalidConfiguration(
                    "Portage repository section name is empty".into(),
                ));
            }
            current = Some(RepoSection {
                name: name.into(),
                fields: Vec::new(),
            });
            offset += inclusive.len();
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            offset += inclusive.len();
            continue;
        }
        let Some(section) = current.as_mut() else {
            offset += inclusive.len();
            continue;
        };
        let Some(equals) = line.find('=') else {
            offset += inclusive.len();
            continue;
        };
        let key = line[..equals].trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "Portage repository field name is empty".into(),
            ));
        }
        let value_part = &line[equals + 1..];
        let leading = value_part.len() - value_part.trim_start().len();
        let value_start = offset + equals + 1 + leading;
        let value = value_part.trim();
        section.fields.push(RepoField {
            key,
            value: value.into(),
            value_range: value_start..value_start + value.len(),
        });
        offset += inclusive.len();
    }
    if let Some(section) = current {
        sections.push(section);
    }
    Ok(Repositories { sections })
}

fn main_repository<'a>(
    repositories: impl Iterator<Item = &'a Repositories>,
) -> Result<String, AdapterError> {
    let values = repositories
        .flat_map(|repositories| repositories.sections.iter())
        .filter(|section| section.name.eq_ignore_ascii_case("DEFAULT"))
        .filter_map(|section| section.value("main-repo"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if values.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "repos.conf declares conflicting main-repo values".into(),
        ));
    }
    Ok(values.into_iter().next().unwrap_or_else(|| "gentoo".into()))
}

fn rewrite_main_sync(
    text: &str,
    repositories: &Repositories,
    main_repo: &str,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let mut ranges = repositories
        .sections
        .iter()
        .filter(|section| section.name == main_repo)
        .filter(|section| {
            section
                .value("sync-type")
                .is_some_and(|value| value.eq_ignore_ascii_case("rsync"))
        })
        .filter(|section| section.value("sync-uri").is_some_and(known_gentoo_sync))
        .flat_map(|section| {
            section
                .fields
                .iter()
                .filter(|field| field.key == "sync-uri")
                .map(|field| field.value_range.clone())
        })
        .collect::<Vec<_>>();
    if ranges.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Gentoo main repository has multiple sync-uri values".into(),
        ));
    }
    let Some(range) = ranges.pop() else {
        return Ok(text.into());
    };
    let mut output = text.to_owned();
    output.replace_range(range, endpoint.trim_end_matches('/'));
    Ok(output)
}

fn known_gentoo_sync(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("rsync://")
        && lower.contains("gentoo-portage")
        && [
            "gentoo.org",
            "mirrors.aliyun.com",
            "mirrors.nju.edu.cn",
            "mirrors.tuna.tsinghua.edu.cn",
            "mirrors.ustc.edu.cn",
        ]
        .iter()
        .any(|host| lower.contains(host))
}

fn selected_endpoint<'a>(
    selections: &'a [MirrorSelection],
    upstream: &str,
    protocol: Protocol,
) -> Result<&'a str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "portage" && selection.upstream_id == upstream)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Portage plan requires exactly one selection for {upstream}"
        )));
    }
    let endpoint = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| endpoint.role == EndpointRole::Metadata && endpoint.protocol == protocol)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Portage selection for {upstream} has no {protocol:?} metadata endpoint"
            ))
        })?;
    let prefix = match protocol {
        Protocol::Https => "https://",
        Protocol::Rsync => "rsync://",
        _ => unreachable!("Portage requests only HTTPS or rsync endpoints"),
    };
    if !endpoint.url.starts_with(prefix)
        || endpoint.url.chars().any(|character| {
            !character.is_ascii_alphanumeric()
                && !matches!(character, ':' | '/' | '.' | '_' | '-' | '~' | '+' | '%')
        })
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Portage selection for {upstream} has an unsafe configuration URL"
        )));
    }
    Ok(&endpoint.url)
}

fn verification_failure(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<VerificationResult, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{reason}; configuration restored: {restored}"
    )))
}

fn utf8<'a>(path: &str, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!("Portage configuration {path} is not UTF-8"))
    })
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
