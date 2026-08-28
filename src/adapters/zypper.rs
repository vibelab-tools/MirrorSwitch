use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, CurrentConfiguration, DetectedTool, MirrorSelection,
        PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

use super::dnf::{
    configured_source, expand_repo_variables, parse_repo_file, rewrite_repo_file, rooted,
    selected_endpoints,
};

const REPOSITORY_DIRECTORY: &str = "/etc/zypp/repos.d";

#[derive(Clone, Copy, Debug, Default)]
pub struct ZypperAdapter;

impl Adapter for ZypperAdapter {
    fn key(&self) -> &'static str {
        "zypper"
    }

    fn tool_id(&self) -> &'static str {
        "zypper"
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
        let has_command = runtime.command_exists("zypper");
        if !has_command && files.is_empty() {
            return Ok(None);
        }
        let mut evidence = files
            .iter()
            .map(|path| format!("Zypper repository configuration {}", path.display()))
            .collect::<Vec<_>>();
        let mut version = None;
        if has_command {
            let output = runtime.run("zypper", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "zypper --version failed with status {}",
                    output.status
                )));
            }
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("zypper")
                .trim()
                .to_owned();
            version = (!first_line.is_empty()).then_some(first_line.clone());
            evidence.insert(0, format!("Zypper command {first_line}"));
        }
        Ok(Some(DetectedTool {
            tool_id: "zypper".into(),
            executable: has_command.then(|| PathBuf::from("/usr/bin/zypper")),
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
                "Zypper only supports system scope".into(),
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
                    "Zypper repository file {} is not UTF-8",
                    path.display()
                ))
            })?;
            let sections = parse_repo_file(text, context, classify_section)?;
            sources.extend(sections.into_iter().map(configured_source));
            documents.push(ConfigurationDocument {
                path,
                format: "zypper-repo".into(),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "zypper".into(),
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
        if current.tool_id != "zypper" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Zypper selection requires a system-scope configuration".into(),
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
                        expand_repo_variables(path, context)?,
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
                "no supported openSUSE or Packman repositories were detected".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "zypper".into(),
            adapter_key: "zypper".into(),
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
        if current.tool_id != "zypper" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Zypper plan requires a system-scope configuration".into(),
            ));
        }
        let selected = selected_endpoints(selection, "zypper")?;
        let mut changes = Vec::new();
        for document in &current.documents {
            if document.format != "zypper-repo" {
                return Err(AdapterError::Unsupported(format!(
                    "unknown Zypper document format {}",
                    document.format
                )));
            }
            let text = std::str::from_utf8(&document.contents).map_err(|_| {
                AdapterError::InvalidConfiguration("Zypper repository file is not UTF-8".into())
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
                summary: "replace only recognized Zypper repository base URLs".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "zypper".into(),
            tool_id: "zypper".into(),
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
            "zypper",
            &[
                "--non-interactive".into(),
                "refresh".into(),
                "--force".into(),
            ],
        )?;
        if output.status.success() {
            return Ok(VerificationResult {
                valid: true,
                summary: "zypper refresh validated repository metadata and GPG policy".into(),
            });
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
        Err(AdapterError::Verification(format!(
            "zypper refresh failed with status {}; configuration restored: {restored}",
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
                "restored {} Zypper repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported("Zypper requires Linux".into()));
    }
    let distribution = context
        .distribution
        .as_ref()
        .ok_or_else(|| AdapterError::Unsupported("Zypper requires distribution metadata".into()))?;
    if !matches!(
        distribution.id.as_str(),
        "opensuse-leap" | "opensuse-tumbleweed"
    ) {
        return Err(AdapterError::Unsupported(format!(
            "Zypper adapter has no verified repository rules for {}",
            distribution.id
        )));
    }
    Ok(())
}

fn repo_paths(runtime: &dyn Runtime) -> Result<Vec<PathBuf>, AdapterError> {
    let mut paths = runtime
        .list_files(Path::new(REPOSITORY_DIRECTORY))?
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("repo"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn classify_section(id: &str, url: &str, context: &SystemContext) -> Option<(String, String)> {
    let lower = url.to_ascii_lowercase();
    if lower.contains("packman") {
        let path = match context.distribution.as_ref()?.id.as_str() {
            "opensuse-leap" => "suse/openSUSE_Leap_$releasever/",
            "opensuse-tumbleweed" => "suse/openSUSE_Tumbleweed/",
            _ => return None,
        };
        return Some(("packman--repository-metadata".into(), path.into()));
    }
    if !known_opensuse_location(&lower) {
        return None;
    }
    match context.distribution.as_ref()?.id.as_str() {
        "opensuse-leap" => classify_leap(id),
        "opensuse-tumbleweed" => classify_tumbleweed(id, &lower),
        _ => None,
    }
}

fn classify_leap(id: &str) -> Option<(String, String)> {
    let path = match id.to_ascii_lowercase().as_str() {
        "repo-oss" => "distribution/leap/$releasever/repo/oss/",
        "repo-non-oss" => "distribution/leap/$releasever/repo/non-oss/",
        "repo-update" => "leap/$releasever/oss/",
        "repo-update-non-oss" => "leap/$releasever/non-oss/",
        "repo-backports-update" => "leap/$releasever/backports/",
        "repo-sle-update" => "leap/$releasever/sle/",
        _ => return None,
    };
    let upstream = if path.starts_with("distribution/") {
        "opensuse--repository-metadata"
    } else {
        "opensuse-update--repository-metadata"
    };
    Some((upstream.into(), path.into()))
}

fn classify_tumbleweed(id: &str, url: &str) -> Option<(String, String)> {
    let repository = match id.to_ascii_lowercase().as_str() {
        "repo-oss" => "oss",
        "repo-non-oss" => "non-oss",
        "repo-update" => {
            return Some((
                "opensuse-update--repository-metadata".into(),
                "tumbleweed/".into(),
            ));
        }
        _ => return None,
    };
    if url.contains("/ports/") {
        Some((
            "opensuse-ports--repository-metadata".into(),
            format!("aarch64/tumbleweed/repo/{repository}/"),
        ))
    } else {
        Some((
            "opensuse-tumbleweed--repository-metadata".into(),
            format!("tumbleweed/repo/{repository}/"),
        ))
    }
}

fn known_opensuse_location(value: &str) -> bool {
    [
        "download.opensuse.org",
        "mirrors.aliyun.com",
        "repo.huaweicloud.com",
        "mirrors.ustc.edu.cn",
        "mirrors.tuna.tsinghua.edu.cn",
        "mirrors.nju.edu.cn",
        "mirror.sjtu.edu.cn",
    ]
    .iter()
    .any(|host| value.contains(host))
}
