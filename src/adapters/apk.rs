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

const REPOSITORIES: &str = "/etc/apk/repositories";
const ALPINE_UPSTREAM: &str = "alpine--repository-metadata";

#[derive(Clone, Copy, Debug, Default)]
pub struct ApkAdapter;

impl Adapter for ApkAdapter {
    fn key(&self) -> &'static str {
        "apk"
    }

    fn tool_id(&self) -> &'static str {
        "apk"
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
        let has_command = runtime.command_exists("apk");
        let has_configuration = runtime.read(Path::new(REPOSITORIES))?.is_some();
        if !has_command && !has_configuration {
            return Ok(None);
        }
        let mut evidence = has_configuration
            .then(|| format!("APK repository configuration {REPOSITORIES}"))
            .into_iter()
            .collect::<Vec<_>>();
        let mut version = None;
        if has_command {
            let output = runtime.run("apk", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "apk --version failed with status {}",
                    output.status
                )));
            }
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("apk-tools")
                .trim()
                .to_owned();
            version = (!first_line.is_empty()).then_some(first_line.clone());
            evidence.insert(0, format!("APK command {first_line}"));
        }
        Ok(Some(DetectedTool {
            tool_id: "apk".into(),
            executable: has_command.then(|| PathBuf::from("/sbin/apk")),
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
                "APK only supports system scope".into(),
            ));
        }
        let contents = runtime.read(Path::new(REPOSITORIES))?.ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "APK configuration {REPOSITORIES} is missing"
            ))
        })?;
        let text = std::str::from_utf8(&contents).map_err(|_| {
            AdapterError::InvalidConfiguration("APK repositories file is not UTF-8".into())
        })?;
        let architecture = apk_architecture(context.architecture);
        let sources = parse_repositories(text)?
            .into_iter()
            .map(|line| {
                let mut metadata =
                    BTreeMap::from([("architecture".into(), vec![architecture.into()])]);
                if let Some(tag) = line.tag {
                    metadata.insert("tag".into(), vec![tag]);
                }
                let upstream_id = line.official.as_ref().map(|official| {
                    metadata.insert("branch".into(), vec![official.branch.clone()]);
                    metadata.insert("repository".into(), vec![official.repository.clone()]);
                    ALPINE_UPSTREAM.into()
                });
                ConfiguredSource {
                    upstream_id,
                    url: line.url,
                    enabled: true,
                    metadata,
                }
            })
            .collect();
        Ok(CurrentConfiguration {
            tool_id: "apk".into(),
            scope,
            files: vec![PathBuf::from(REPOSITORIES)],
            sources,
            documents: vec![ConfigurationDocument {
                path: PathBuf::from(REPOSITORIES),
                format: "apk-repositories".into(),
                contents,
            }],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "apk" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "APK selection requires a system-scope configuration".into(),
            ));
        }
        let architecture = apk_architecture(context.architecture).to_owned();
        let mut contexts = current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(ALPINE_UPSTREAM))
            .map(|source| {
                Ok(BTreeMap::from([
                    (
                        "branch".into(),
                        single_metadata(source, "branch")?.to_owned(),
                    ),
                    (
                        "repository".into(),
                        single_metadata(source, "repository")?.to_owned(),
                    ),
                    ("architecture".into(), architecture.clone()),
                ]))
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        contexts.sort();
        contexts.dedup();
        if contexts.is_empty() {
            return Err(AdapterError::Unsupported(
                "no recognized Alpine repositories are configured".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "apk".into(),
            adapter_key: "apk".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![ALPINE_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(ALPINE_UPSTREAM.into(), contexts)]),
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
        if current.tool_id != "apk" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "APK plan requires a system-scope configuration".into(),
            ));
        }
        let endpoint = selected_endpoint(selection)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "apk-repositories")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("APK repository document is missing".into())
            })?;
        let text = std::str::from_utf8(&document.contents).map_err(|_| {
            AdapterError::InvalidConfiguration("APK repositories file is not UTF-8".into())
        })?;
        let new_contents = rewrite_repositories(text, endpoint)?.into_bytes();
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "replace only recognized Alpine repository mirror roots".into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "apk".into(),
            tool_id: "apk".into(),
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
        let output = runtime.run("apk", &["update".into(), "--no-progress".into()])?;
        if output.status.success() {
            return Ok(VerificationResult {
                valid: true,
                summary: "apk update validated signed repository indexes".into(),
            });
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
        Err(AdapterError::Verification(format!(
            "apk update failed with status {}; configuration restored: {restored}",
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
                "restored {} APK repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct OfficialRepository {
    branch: String,
    repository: String,
}

#[derive(Clone, Debug)]
struct RepositoryLine {
    url: String,
    url_range: Range<usize>,
    tag: Option<String>,
    official: Option<OfficialRepository>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("APK requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("APK requires distribution metadata".into()))?;
    if distribution.id != "alpine" && !distribution.id_like.iter().any(|id| id == "alpine") {
        return Err(AdapterError::Unsupported(format!(
            "APK adapter has no verified configuration rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn apk_architecture(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "aarch64",
    }
}

fn parse_repositories(text: &str) -> Result<Vec<RepositoryLine>, AdapterError> {
    let mut repositories = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let leading = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += inclusive.len();
            continue;
        }
        let (first, first_range) = next_token(line, leading).ok_or_else(|| {
            AdapterError::InvalidConfiguration("APK repository entry is empty".into())
        })?;
        let (tag, url, range) = if first.starts_with('@') {
            let next_start = skip_whitespace(line, first_range.end);
            let (url, range) = next_token(line, next_start).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "APK repository tag {first} has no repository URL"
                ))
            })?;
            (Some(first.to_owned()), url, range)
        } else {
            (None, first, first_range)
        };
        let remainder = line[range.end..].trim();
        let official = (remainder.is_empty() || remainder.starts_with('#'))
            .then(|| classify_official(url))
            .flatten();
        repositories.push(RepositoryLine {
            url: url.into(),
            url_range: offset + range.start..offset + range.end,
            tag,
            official,
        });
        offset += inclusive.len();
    }
    Ok(repositories)
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

fn classify_official(url: &str) -> Option<OfficialRepository> {
    let (scheme, remainder) = url.split_once("://")?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let (authority, path) = remainder.split_once('/')?;
    if authority.contains(['@', ':'])
        || ![
            "dl-cdn.alpinelinux.org",
            "mirrors.aliyun.com",
            "repo.huaweicloud.com",
            "mirrors.nju.edu.cn",
            "mirror.sjtu.edu.cn",
            "mirrors.tuna.tsinghua.edu.cn",
            "mirrors.ustc.edu.cn",
        ]
        .contains(&authority.to_ascii_lowercase().as_str())
    {
        return None;
    }
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    if segments.len() != 3 || segments[0] != "alpine" {
        return None;
    }
    let branch = segments[1];
    let valid_branch = matches!(branch, "edge" | "latest-stable")
        || branch.strip_prefix('v').is_some_and(|version| {
            !version.is_empty()
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        });
    if !valid_branch || !matches!(segments[2], "main" | "community" | "testing") {
        return None;
    }
    Some(OfficialRepository {
        branch: branch.into(),
        repository: segments[2].into(),
    })
}

fn rewrite_repositories(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let repositories = parse_repositories(text)?;
    let mut replacements = repositories
        .into_iter()
        .filter_map(|line| {
            line.official.map(|official| {
                (
                    line.url_range,
                    format!(
                        "{}/{}/{}",
                        endpoint.trim_end_matches('/'),
                        official.branch,
                        official.repository
                    ),
                )
            })
        })
        .collect::<Vec<_>>();
    replacements.sort_by_key(|replacement| Reverse(replacement.0.start));
    let mut output = text.to_owned();
    for (range, replacement) in replacements {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "apk" && selection.upstream_id == ALPINE_UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "APK plan requires exactly one Alpine repository selection".into(),
        ));
    }
    let endpoint = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Metadata && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "APK selection has no HTTPS metadata endpoint".into(),
            )
        })?;
    if !endpoint.url.starts_with("https://")
        || endpoint.url.chars().any(|character| {
            !character.is_ascii_alphanumeric()
                && !matches!(character, ':' | '/' | '.' | '_' | '-' | '~' | '+' | '%')
        })
    {
        return Err(AdapterError::InvalidConfiguration(
            "APK selection has an unsafe configuration URL".into(),
        ));
    }
    Ok(&endpoint.url)
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("APK source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "APK source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
