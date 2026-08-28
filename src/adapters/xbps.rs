use std::{
    cmp::Reverse,
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

const SYSTEM_CONFIG: &str = "/usr/share/xbps.d";
const USER_CONFIG: &str = "/etc/xbps.d";
const VOID_UPSTREAM: &str = "void--repository-metadata";

#[derive(Clone, Copy, Debug, Default)]
pub struct XbpsAdapter;

impl Adapter for XbpsAdapter {
    fn key(&self) -> &'static str {
        "xbps"
    }

    fn tool_id(&self) -> &'static str {
        "xbps"
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
        let has_command = runtime.command_exists("xbps-install");
        let documents = effective_documents(runtime)?;
        if !has_command && documents.is_empty() {
            return Ok(None);
        }
        let mut evidence = documents
            .iter()
            .map(|document| format!("XBPS repository configuration {}", document.path.display()))
            .collect::<Vec<_>>();
        let mut version = None;
        if has_command {
            let output = runtime.run("xbps-install", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "xbps-install --version failed with status {}",
                    output.status
                )));
            }
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("XBPS")
                .trim()
                .to_owned();
            version = (!first_line.is_empty()).then_some(first_line.clone());
            evidence.insert(0, format!("XBPS command {first_line}"));
        }
        if runtime.command_exists("xbps-uhelper") {
            evidence.push(format!(
                "XBPS target architecture {}",
                detect_variant(context, runtime)?.xbps_arch
            ));
        }
        Ok(Some(DetectedTool {
            tool_id: "xbps".into(),
            executable: has_command.then(|| PathBuf::from("/usr/bin/xbps-install")),
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
                "XBPS only supports system scope".into(),
            ));
        }
        let variant = detect_variant(context, runtime)?;
        let documents = effective_documents(runtime)?;
        if documents.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "no effective XBPS repository configuration was found".into(),
            ));
        }
        let mut sources = Vec::new();
        for document in &documents {
            let text = utf8(&document.path, &document.contents)?;
            for repository in parse_repositories(text)? {
                let classification = classify_repository(&repository.url, &variant);
                if classification == RepositoryClassification::MismatchedOfficial {
                    return Err(AdapterError::InvalidConfiguration(format!(
                        "XBPS repository {} does not match target {}",
                        repository.url, variant.xbps_arch
                    )));
                }
                let repository_path = match classification {
                    RepositoryClassification::Official(path) => Some(path),
                    RepositoryClassification::Custom => None,
                    RepositoryClassification::MismatchedOfficial => unreachable!(),
                };
                let mut metadata = BTreeMap::from([
                    (
                        "configuration_file".into(),
                        vec![document.path.display().to_string()],
                    ),
                    ("xbps_arch".into(), vec![variant.xbps_arch.clone()]),
                    ("libc".into(), vec![variant.libc.into()]),
                    (
                        "configuration_origin".into(),
                        vec![if document.format == "xbps-user" {
                            "system-override".into()
                        } else {
                            "package-default".into()
                        }],
                    ),
                ]);
                if let Some(path) = &repository_path {
                    metadata.insert("repository_path".into(), vec![path.clone()]);
                }
                sources.push(ConfiguredSource {
                    upstream_id: repository_path.map(|_| VOID_UPSTREAM.into()),
                    url: repository.url,
                    enabled: true,
                    metadata,
                });
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "xbps".into(),
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
        if current.tool_id != "xbps" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "XBPS selection requires a system-scope configuration".into(),
            ));
        }
        let mut contexts = current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(VOID_UPSTREAM))
            .map(|source| {
                Ok(BTreeMap::from([
                    (
                        "repository_path".into(),
                        single_metadata(source, "repository_path")?.to_owned(),
                    ),
                    (
                        "xbps_arch".into(),
                        single_metadata(source, "xbps_arch")?.to_owned(),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        contexts.sort();
        contexts.dedup();
        if contexts.is_empty() {
            return Err(AdapterError::Unsupported(
                "no recognized Void repositories are configured".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "xbps".into(),
            adapter_key: "xbps".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![VOID_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(VOID_UPSTREAM.into(), contexts)]),
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
        if current.tool_id != "xbps" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "XBPS plan requires a system-scope configuration".into(),
            ));
        }
        let endpoint = selected_endpoint(selection)?;
        let variant = variant_from_current(context, current)?;
        let mut changes = Vec::new();
        for document in &current.documents {
            if !matches!(document.format.as_str(), "xbps-user" | "xbps-system") {
                return Err(AdapterError::Unsupported(format!(
                    "unknown XBPS document format {}",
                    document.format
                )));
            }
            let text = utf8(&document.path, &document.contents)?;
            let new_contents = rewrite_repositories(text, endpoint, &variant)?.into_bytes();
            if new_contents == document.contents {
                continue;
            }
            let (target, old_contents) = if document.format == "xbps-system" {
                let file_name = document.path.file_name().ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "XBPS system configuration has no file name".into(),
                    )
                })?;
                (PathBuf::from(USER_CONFIG).join(file_name), None)
            } else {
                (document.path.clone(), Some(document.contents.clone()))
            };
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &target),
                old_contents,
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "replace only recognized Void repository mirror roots".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "xbps".into(),
            tool_id: "xbps".into(),
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
        for (program, arguments) in [
            ("xbps-install", vec!["-S".into()]),
            ("xbps-query", vec!["-L".into()]),
        ] {
            let output = runtime.run(program, &arguments)?;
            if !output.status.success() {
                let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
                return Err(AdapterError::Verification(format!(
                    "{program} repository verification failed with status {}; configuration restored: {restored}",
                    output.status
                )));
            }
        }
        Ok(VerificationResult {
            valid: true,
            summary: "XBPS refreshed signed indexes and listed effective repositories".into(),
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
                "restored {} XBPS configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XbpsVariant {
    xbps_arch: String,
    libc: &'static str,
    repository_base: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RepositoryClassification {
    Official(String),
    MismatchedOfficial,
    Custom,
}

#[derive(Clone, Debug)]
struct RepositoryLine {
    url: String,
    value_range: Range<usize>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("XBPS requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("XBPS requires distribution metadata".into()))?;
    if distribution.id != "void" && !distribution.id_like.iter().any(|id| id == "void") {
        return Err(AdapterError::Unsupported(format!(
            "XBPS adapter has no verified configuration rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn detect_variant(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<XbpsVariant, AdapterError> {
    if !runtime.command_exists("xbps-uhelper") {
        return Err(AdapterError::Unsupported(
            "xbps-uhelper is required to detect architecture and libc".into(),
        ));
    }
    let output = runtime.run("xbps-uhelper", &["arch".into()])?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "xbps-uhelper arch failed with status {}",
            output.status
        )));
    }
    let xbps_arch = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let (architecture, libc, repository_base) = match xbps_arch.as_str() {
        "x86_64" => (Architecture::X86_64, "glibc", "current"),
        "x86_64-musl" => (Architecture::X86_64, "musl", "current/musl"),
        "aarch64" => (Architecture::Arm64, "glibc", "current/aarch64"),
        "aarch64-musl" => (Architecture::Arm64, "musl", "current/aarch64"),
        _ => {
            return Err(AdapterError::Unsupported(format!(
                "XBPS architecture {xbps_arch} is outside the v0.1 support matrix"
            )));
        }
    };
    if architecture != context.architecture {
        return Err(AdapterError::InvalidConfiguration(format!(
            "system architecture {:?} conflicts with XBPS architecture {xbps_arch}",
            context.architecture
        )));
    }
    Ok(XbpsVariant {
        xbps_arch,
        libc,
        repository_base,
    })
}

fn variant_from_current(
    context: &SystemContext,
    current: &CurrentConfiguration,
) -> Result<XbpsVariant, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter_map(|source| source.metadata.get("xbps_arch"))
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "XBPS sources do not agree on one target architecture".into(),
        ));
    }
    let xbps_arch = values.into_iter().next().unwrap();
    let (architecture, libc, repository_base) = match xbps_arch.as_str() {
        "x86_64" => (Architecture::X86_64, "glibc", "current"),
        "x86_64-musl" => (Architecture::X86_64, "musl", "current/musl"),
        "aarch64" => (Architecture::Arm64, "glibc", "current/aarch64"),
        "aarch64-musl" => (Architecture::Arm64, "musl", "current/aarch64"),
        _ => unreachable!("read_current accepts only supported XBPS architectures"),
    };
    if architecture != context.architecture {
        return Err(AdapterError::InvalidConfiguration(
            "XBPS plan architecture does not match the system".into(),
        ));
    }
    Ok(XbpsVariant {
        xbps_arch,
        libc,
        repository_base,
    })
}

fn effective_documents(runtime: &dyn Runtime) -> Result<Vec<ConfigurationDocument>, AdapterError> {
    let mut documents = BTreeMap::<String, ConfigurationDocument>::new();
    for (directory, format) in [(SYSTEM_CONFIG, "xbps-system"), (USER_CONFIG, "xbps-user")] {
        for path in runtime.list_files(Path::new(directory))? {
            if path.extension().and_then(|extension| extension.to_str()) != Some("conf") {
                continue;
            }
            let Some(contents) = runtime.read(&path)? else {
                continue;
            };
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            documents.insert(
                file_name.into(),
                ConfigurationDocument {
                    path,
                    format: format.into(),
                    contents,
                },
            );
        }
    }
    Ok(documents.into_values().collect())
}

fn parse_repositories(text: &str) -> Result<Vec<RepositoryLine>, AdapterError> {
    let mut repositories = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += inclusive.len();
            continue;
        }
        let Some(equals) = line.find('=') else {
            offset += inclusive.len();
            continue;
        };
        if line[..equals].trim() != "repository" {
            offset += inclusive.len();
            continue;
        }
        let value_part = &line[equals + 1..];
        let leading = value_part.len() - value_part.trim_start().len();
        let value_start = offset + equals + 1 + leading;
        let value = value_part.trim();
        if value.is_empty() || value.contains(char::is_whitespace) {
            return Err(AdapterError::InvalidConfiguration(
                "XBPS repository URL must be one non-empty token".into(),
            ));
        }
        repositories.push(RepositoryLine {
            url: value.into(),
            value_range: value_start..value_start + value.len(),
        });
        offset += inclusive.len();
    }
    Ok(repositories)
}

fn classify_repository(url: &str, variant: &XbpsVariant) -> RepositoryClassification {
    let Some((scheme, remainder)) = url.split_once("://") else {
        return RepositoryClassification::Custom;
    };
    if !matches!(scheme, "http" | "https") {
        return RepositoryClassification::Custom;
    }
    let (authority, path) = remainder.split_once('/').unwrap_or((remainder, ""));
    let authority = authority.to_ascii_lowercase();
    let provider = [
        "repo-default.voidlinux.org",
        "repo-fastly.voidlinux.org",
        "mirrors.nju.edu.cn",
        "mirror.sjtu.edu.cn",
        "mirrors.tuna.tsinghua.edu.cn",
    ]
    .contains(&authority.as_str());
    if !provider || authority.contains(['@', ':']) {
        return RepositoryClassification::Custom;
    }
    let mut path = path.trim_matches('/');
    if path.starts_with("voidlinux/") {
        path = &path["voidlinux/".len()..];
    }
    if !path.starts_with("current") {
        return RepositoryClassification::Custom;
    }
    let allowed_suffixes: &[&str] = if variant.xbps_arch == "x86_64" {
        &["", "nonfree", "debug", "multilib", "multilib/nonfree"]
    } else {
        &["", "nonfree", "debug"]
    };
    let Some(suffix) = path.strip_prefix(variant.repository_base) else {
        return RepositoryClassification::MismatchedOfficial;
    };
    let suffix = suffix.trim_start_matches('/');
    if !allowed_suffixes.contains(&suffix) {
        return RepositoryClassification::MismatchedOfficial;
    }
    RepositoryClassification::Official(path.into())
}

fn rewrite_repositories(
    text: &str,
    endpoint: &str,
    variant: &XbpsVariant,
) -> Result<String, AdapterError> {
    let mut replacements = Vec::new();
    for repository in parse_repositories(text)? {
        match classify_repository(&repository.url, variant) {
            RepositoryClassification::Official(path) => replacements.push((
                repository.value_range,
                format!("{}/{}", endpoint.trim_end_matches('/'), path),
            )),
            RepositoryClassification::MismatchedOfficial => {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "XBPS repository {} does not match target {}",
                    repository.url, variant.xbps_arch
                )));
            }
            RepositoryClassification::Custom => {}
        }
    }
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
        .filter(|selection| selection.tool_id == "xbps" && selection.upstream_id == VOID_UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "XBPS plan requires exactly one Void repository selection".into(),
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
                "XBPS selection has no HTTPS metadata endpoint".into(),
            )
        })?;
    if !endpoint.url.starts_with("https://")
        || endpoint.url.chars().any(|character| {
            !character.is_ascii_alphanumeric()
                && !matches!(character, ':' | '/' | '.' | '_' | '-' | '~' | '+' | '%')
        })
    {
        return Err(AdapterError::InvalidConfiguration(
            "XBPS selection has an unsafe configuration URL".into(),
        ));
    }
    Ok(&endpoint.url)
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("XBPS source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "XBPS source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "XBPS configuration {} is not UTF-8",
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
