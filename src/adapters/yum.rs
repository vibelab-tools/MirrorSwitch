use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, CurrentConfiguration, DetectedTool, MirrorSelection,
        PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

use super::dnf::{
    configured_source, parse_repo_file, repo_paths, rewrite_repo_file, rooted, selected_endpoints,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct YumAdapter;

impl Adapter for YumAdapter {
    fn key(&self) -> &'static str {
        "yum"
    }

    fn tool_id(&self) -> &'static str {
        "yum"
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
        require_linux_centos(context)?;
        if !runtime.command_exists("yum") {
            return Ok(None);
        }
        let output = runtime.run("yum", &["--version".into()])?;
        if !output.status.success() {
            return Err(AdapterError::Runtime(format!(
                "yum --version failed with status {}",
                output.status
            )));
        }
        let first_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        let major = version_major(&first_line).ok_or_else(|| {
            AdapterError::Unsupported("could not identify the YUM implementation version".into())
        })?;
        if major >= 4 {
            return Ok(None);
        }
        require_supported_context(context)?;
        if major != 3 {
            return Err(AdapterError::Unsupported(format!(
                "YUM {first_line} has no verified legacy configuration rules"
            )));
        }
        Ok(Some(DetectedTool {
            tool_id: "yum".into(),
            executable: Some("/usr/bin/yum".into()),
            version: Some(first_line.clone()),
            evidence: vec![format!("legacy YUM 3 implementation {first_line}")],
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
                "YUM only supports system scope".into(),
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
                    "YUM repository file {} is not UTF-8",
                    path.display()
                ))
            })?;
            let sections = parse_repo_file(text, context, classify_section)?;
            sources.extend(sections.into_iter().map(configured_source));
            documents.push(ConfigurationDocument {
                path,
                format: "yum-repo".into(),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "yum".into(),
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
        if current.tool_id != "yum" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "YUM selection requires a system-scope YUM configuration".into(),
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
                        expand_repository_path(path, context)?,
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
                "no supported CentOS Linux YUM repositories were detected".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "yum".into(),
            adapter_key: "yum".into(),
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
        if current.tool_id != "yum" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "YUM plan requires a system-scope YUM configuration".into(),
            ));
        }
        let selected = selected_endpoints(selection, "yum")?;
        let mut changes = Vec::new();
        for document in &current.documents {
            if document.format != "yum-repo" {
                return Err(AdapterError::Unsupported(format!(
                    "unknown YUM document format {}",
                    document.format
                )));
            }
            let text = std::str::from_utf8(&document.contents).map_err(|_| {
                AdapterError::InvalidConfiguration("YUM repository file is not UTF-8".into())
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
                summary: "replace only recognized legacy YUM repository locations".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "yum".into(),
            tool_id: "yum".into(),
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
        let clean = runtime.run("yum", &["clean".into(), "expire-cache".into()])?;
        if !clean.status.success() {
            return verification_failure(runtime, receipt, "yum clean expire-cache", clean.status);
        }
        let refresh = runtime.run("yum", &["makecache".into()])?;
        if !refresh.status.success() {
            return verification_failure(runtime, receipt, "yum makecache", refresh.status);
        }
        Ok(VerificationResult {
            valid: true,
            summary: "yum makecache validated repository metadata and GPG policy".into(),
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
                "restored {} YUM repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    require_linux_centos(context)?;
    let major = release_major(context)?;
    if !matches!(major, "6" | "7") {
        return Err(AdapterError::Unsupported(format!(
            "CentOS Linux {major} is not a verified legacy YUM release"
        )));
    }
    if context.architecture == Architecture::Arm64 && major != "7" {
        return Err(AdapterError::Unsupported(format!(
            "CentOS Linux {major} has no verified aarch64 YUM archive"
        )));
    }
    Ok(())
}

fn require_linux_centos(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("YUM requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("YUM requires distribution metadata".into()))?;
    if distribution.id != "centos" {
        return Err(AdapterError::Unsupported(format!(
            "legacy YUM adapter has no verified rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn classify_section(id: &str, url: &str, context: &SystemContext) -> Option<(String, String)> {
    if !known_centos_location(url) {
        return None;
    }
    let repository = match id.to_ascii_lowercase().as_str() {
        "base" => "os",
        "updates" => "updates",
        "extras" => "extras",
        _ => return None,
    };
    let (upstream, release) = match context.architecture {
        Architecture::X86_64 => (
            "centos-vault--repository-metadata",
            archive_release(release_major(context).ok()?)?,
        ),
        Architecture::Arm64 => ("centos-altarch--repository-metadata", "7"),
    };
    Some((
        upstream.into(),
        format!("{release}/{repository}/$basearch/"),
    ))
}

fn known_centos_location(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "mirrorlist.centos.org",
        "mirror.centos.org",
        "vault.centos.org",
        "mirrors.aliyun.com",
        "repo.huaweicloud.com",
        "mirrors.ustc.edu.cn",
        "mirrors.tuna.tsinghua.edu.cn",
        "mirrors.nju.edu.cn",
        "mirror.sjtu.edu.cn",
    ]
    .iter()
    .any(|host| lower.contains(host))
        && !lower.contains("epel")
        && !lower.contains("centos-stream")
}

fn release_major(context: &SystemContext) -> Result<&str, AdapterError> {
    let version = context
        .distribution
        .as_ref()
        .and_then(|distribution| distribution.version_id.as_deref())
        .ok_or_else(|| AdapterError::Unsupported("YUM releasever is unavailable".into()))?;
    Ok(version.split('.').next().unwrap_or(version))
}

fn archive_release(major: &str) -> Option<&'static str> {
    match major {
        "6" => Some("6.10"),
        "7" => Some("7.9.2009"),
        _ => None,
    }
}

fn expand_repository_path(template: &str, context: &SystemContext) -> Result<String, AdapterError> {
    let basearch = match context.architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "aarch64",
    };
    let expanded = template
        .replace("${basearch}", basearch)
        .replace("$basearch", basearch);
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
            "YUM repository path contains unsupported variables or segments".into(),
        ));
    }
    Ok(expanded)
}

fn version_major(version: &str) -> Option<u64> {
    version
        .split_whitespace()
        .find_map(|token| token.split('.').next()?.parse().ok())
}

fn verification_failure(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    command: &str,
    status: std::process::ExitStatus,
) -> Result<VerificationResult, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{command} failed with status {status}; configuration restored: {restored}"
    )))
}
