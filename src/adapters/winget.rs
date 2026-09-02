use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

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

const UPSTREAM: &str = "winget-source--static-files";
const SOURCE_TYPE: &str = "Microsoft.PreIndexed.Package";
const OFFICIAL_ARGUMENT: &str = "https://cdn.winget.microsoft.com/cache";
const USTC_ARGUMENT: &str = "https://mirrors.ustc.edu.cn/winget-source";
const NJU_ARGUMENT: &str = "https://mirrors.nju.edu.cn/winget-source";
const MANIFEST_ID: &str = "9849";
const X64_INSTALLER_HASH: &str = "A6FC67FEDAF9128A3309A1E2EBB8B986AECCF70122EE46D2CB4849E423F0C627";
const ARM64_INSTALLER_HASH: &str =
    "083B5377392BC57CF27052B6D20A2D927770683BCA844632901FF38B4B7B0AC7";

#[derive(Clone, Copy, Debug, Default)]
pub struct WinGetAdapter;

impl Adapter for WinGetAdapter {
    fn key(&self) -> &'static str {
        "winget"
    }
    fn tool_id(&self) -> &'static str {
        "winget"
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
        require_windows(context)?;
        if !runtime.command_exists("winget") {
            return Ok(None);
        }
        let version = winget_version(runtime)?;
        let features = version_features(&version)?;
        let sources = export_sources(runtime)?;
        let winget = community_source(&sources)?;
        Ok(Some(DetectedTool {
            tool_id: "winget".into(),
            executable: Some(PathBuf::from("winget")),
            version: Some(version.clone()),
            evidence: vec![
                format!("WinGet {version}"),
                format!("winget source type is {}", winget.source_type),
                format!(
                    "{} enabled sources; msstore and custom sources remain read-only",
                    sources.len()
                ),
                format!(
                    "source protocol uses {}",
                    if features.trusted_flag {
                        "WinGet 1.8+ trusted-source mode"
                    } else {
                        "WinGet 1.6/1.7 compatibility mode"
                    }
                ),
                "source agreement commands are never auto-accepted".into(),
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
        require_windows(context)?;
        if scope != ConfigurationScope::System {
            return Err(AdapterError::Unsupported(
                "WinGet source replacement requires system scope".into(),
            ));
        }
        let version = winget_version(runtime)?;
        if detected.tool_id != "winget" || detected.version.as_deref() != Some(&version) {
            return Err(AdapterError::Conflict(
                "WinGet identity or version changed after detection".into(),
            ));
        }
        let features = version_features(&version)?;
        let sources = export_sources(runtime)?;
        let winget = community_source(&sources)?;
        validate_source_features(winget, features)?;
        let state_path = state_path(runtime)?;
        let state_contents = runtime.read(&state_path)?;
        let configured = sources
            .into_iter()
            .enumerate()
            .map(|(position, source)| {
                let community = source.name.eq_ignore_ascii_case("winget");
                let mut metadata = if community {
                    current_source_metadata(&source, context, &version)
                } else {
                    BTreeMap::from([
                        (
                            "kind".into(),
                            vec![
                                if source.name.eq_ignore_ascii_case("msstore") {
                                    "msstore-read-only"
                                } else {
                                    "custom-read-only"
                                }
                                .into(),
                            ],
                        ),
                        ("name".into(), vec![source.name.clone()]),
                        ("source_type".into(), vec![source.source_type.clone()]),
                    ])
                };
                metadata.insert("position".into(), vec![position.to_string()]);
                ConfiguredSource {
                    upstream_id: community.then(|| UPSTREAM.into()),
                    url: if community || source.name.eq_ignore_ascii_case("msstore") {
                        source.argument.clone()
                    } else {
                        "redacted://custom-winget-source".into()
                    },
                    enabled: true,
                    metadata,
                }
            })
            .collect();
        Ok(CurrentConfiguration {
            tool_id: "winget".into(),
            scope,
            files: state_contents
                .is_some()
                .then(|| state_path.clone())
                .into_iter()
                .collect(),
            sources: configured,
            documents: vec![ConfigurationDocument {
                path: state_path,
                format: "winget-command-state".into(),
                contents: state_contents.unwrap_or_default(),
            }],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_windows(context)?;
        require_current(current)?;
        let source = current
            .sources
            .iter()
            .find(|source| source.upstream_id.as_deref() == Some(UPSTREAM))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "WinGet community source metadata is missing".into(),
                )
            })?;
        let values = BTreeMap::from([
            (
                "winget_arch".into(),
                single_metadata(source, "winget_arch")?.into(),
            ),
            (
                "winget_manifest_id".into(),
                single_metadata(source, "winget_manifest_id")?.into(),
            ),
            (
                "winget_installer_hash".into(),
                single_metadata(source, "winget_installer_hash")?.into(),
            ),
        ]);
        Ok(SelectionRequest {
            tool_id: "winget".into(),
            adapter_key: "winget".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(UPSTREAM.into(), vec![values])]),
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
        require_windows(context)?;
        require_current(current)?;
        let endpoint = selected_endpoint(selection)?;
        let current_sources = current_sources(current)?;
        let original = community_source(&current_sources)?.clone();
        if normalize_url(&original.argument) == normalize_url(endpoint) {
            return Ok(ChangePlan {
                adapter_key: "winget".into(),
                tool_id: "winget".into(),
                scope: ConfigurationScope::System,
                changes: Vec::new(),
                requires_elevation: true,
                service_impact: ServiceImpact::None,
            });
        }
        let document = &current.documents[0];
        if !document.contents.is_empty() {
            return Err(AdapterError::Conflict("a previous WinGet recovery state is still active; restore it before changing sources".into()));
        }
        let state = RecoveryState {
            schema_version: 1,
            winget_version: version_from_current(current)?,
            original,
            selected_argument: endpoint.into(),
        };
        let contents = serde_json::to_vec_pretty(&state).map_err(|error| {
            AdapterError::Runtime(format!(
                "could not serialize WinGet recovery state: {error}"
            ))
        })?;
        Ok(ChangePlan {
            adapter_key: "winget".into(),
            tool_id: "winget".into(),
            scope: ConfigurationScope::System,
            changes: vec![PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current.files.contains(&document.path).then(Vec::new),
                old_mode: None,
                new_contents: contents,
                new_mode: None,
                summary: "record private WinGet source recovery state before command mutation"
                    .into(),
            }],
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
        if plan.adapter_key != "winget" || plan.tool_id != "winget" || plan.changes.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(
                "WinGet apply requires one recovery-state plan".into(),
            ));
        }
        let state: RecoveryState =
            serde_json::from_slice(&plan.changes[0].new_contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "WinGet recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        let outcome = runtime.apply_plan(plan)?;
        let ApplyOutcome::Applied(receipt) = &outcome else {
            return Ok(outcome);
        };
        if let Err(error) = replace_source(
            runtime,
            &state.selected_argument,
            &state.winget_version,
            &state.original,
        ) {
            let source_restored = restore_source(runtime, &state).is_ok();
            let transaction_restored =
                source_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
            return Err(AdapterError::Runtime(format!(
                "WinGet source replacement failed: {error}; source restored: {source_restored}; recovery file restored: {transaction_restored}"
            )));
        }
        Ok(outcome)
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let state = read_recovery_state(runtime, receipt)?;
        let result = verify_source(context, runtime, &state);
        if let Err(error) = result {
            let source_restored = restore_source(runtime, &state).is_ok();
            let transaction_restored =
                source_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
            return Err(AdapterError::Verification(format!(
                "{error}; source restored: {source_restored}; recovery file restored: {transaction_restored}"
            )));
        }
        Ok(VerificationResult { valid: true, summary: "WinGet updated and searched the mirrored source, then downloaded the architecture-specific jq installer with hash verification".into() })
    }

    fn restore(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        let state = read_recovery_state(runtime, receipt)?;
        restore_source(runtime, &state)?;
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: "restored the previous WinGet community source and recovery file".into(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SourceDetails {
    name: String,
    #[serde(rename = "Type")]
    source_type: String,
    #[serde(rename = "Arg")]
    argument: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    identifier: String,
    #[serde(default)]
    trust_level: Vec<String>,
    #[serde(default)]
    explicit: Option<bool>,
    #[serde(default)]
    priority: Option<u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryState {
    schema_version: u32,
    winget_version: String,
    original: SourceDetails,
    selected_argument: String,
}

impl RecoveryState {
    fn validate(&self) -> Result<(), AdapterError> {
        version_features(&self.winget_version)?;
        if self.schema_version != 1
            || !self.original.name.eq_ignore_ascii_case("winget")
            || self.original.source_type != SOURCE_TYPE
            || !is_public_argument(&self.original.argument)
            || !is_mirror_argument(&self.selected_argument)
        {
            return Err(AdapterError::InvalidConfiguration(
                "WinGet recovery state has an unsafe source identity".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct VersionFeatures {
    trusted_flag: bool,
    source_edit: bool,
}

fn require_windows(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Windows || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "WinGet adapter requires a native Windows host".into(),
        ));
    }
    if let Some(version) = context
        .distribution
        .as_ref()
        .and_then(|distribution| distribution.version_id.as_deref())
    {
        let numbers = version
            .split(|character: char| !character.is_ascii_digit())
            .filter(|value| !value.is_empty())
            .filter_map(|value| value.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if numbers.len() < 3 || numbers[0] != 10 || numbers[1] != 0 || numbers[2] < 17_763 {
            return Err(AdapterError::Unsupported(format!(
                "WinGet requires Windows 10 1809 / build 17763 or later, observed {version}"
            )));
        }
        if context.architecture == Architecture::Arm64 && numbers[2] < 22_000 {
            return Err(AdapterError::Unsupported(
                "native WinGet ARM64 support requires Windows 11".into(),
            ));
        }
    }
    Ok(())
}

fn winget_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let text = command_text(
        runtime.run("winget", &["--version".into()])?,
        "winget --version",
    )?;
    let value = text.trim().trim_start_matches('v');
    version_features(value)?;
    Ok(value.into())
}

fn version_features(version: &str) -> Result<VersionFeatures, AdapterError> {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|value| value.parse::<u32>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u32>().ok());
    match (major, minor) {
        (Some(1), Some(minor)) if minor >= 6 => Ok(VersionFeatures {
            trusted_flag: minor >= 8,
            source_edit: minor >= 12,
        }),
        _ => Err(AdapterError::Unsupported(format!(
            "WinGet {version} is outside the reviewed 1.6+ source model"
        ))),
    }
}

fn export_sources(runtime: &dyn Runtime) -> Result<Vec<SourceDetails>, AdapterError> {
    let text = command_text(
        runtime.run(
            "winget",
            &[
                "source".into(),
                "export".into(),
                "--disable-interactivity".into(),
            ],
        )?,
        "winget source export",
    )?;
    let mut sources = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
    {
        sources.push(serde_json::from_str(line).map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "WinGet source export returned invalid JSON: {error}"
            ))
        })?);
    }
    if sources.is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "WinGet source export returned no sources".into(),
        ));
    }
    Ok(sources)
}

fn community_source(sources: &[SourceDetails]) -> Result<&SourceDetails, AdapterError> {
    let matches = sources
        .iter()
        .filter(|source| source.name.eq_ignore_ascii_case("winget"))
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0].source_type != SOURCE_TYPE
        || !is_public_argument(&matches[0].argument)
    {
        return Err(AdapterError::Unsupported(
            "WinGet needs one reviewed Microsoft.PreIndexed.Package community source".into(),
        ));
    }
    Ok(matches[0])
}

fn validate_source_features(
    source: &SourceDetails,
    features: VersionFeatures,
) -> Result<(), AdapterError> {
    if !features.source_edit
        && (source.priority.is_some() || source.explicit.is_some_and(|value| value))
    {
        return Err(AdapterError::Unsupported(
            "this WinGet version cannot preserve source priority/explicit state".into(),
        ));
    }
    Ok(())
}

fn state_path(runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    runtime
        .environment_variable("LOCALAPPDATA")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join("MirrorSwitch").join("winget-source-state.json"))
        .ok_or_else(|| {
            AdapterError::Unsupported("WinGet recovery requires an absolute LOCALAPPDATA".into())
        })
}

fn current_sources(current: &CurrentConfiguration) -> Result<Vec<SourceDetails>, AdapterError> {
    let mut sources = Vec::new();
    for source in &current.sources {
        let name = single_metadata(source, "name")?.to_owned();
        let source_type = single_metadata(source, "source_type")?.to_owned();
        if name.eq_ignore_ascii_case("winget") {
            sources.push(SourceDetails {
                name,
                source_type,
                argument: source.url.clone(),
                data: single_metadata(source, "data")?.to_owned(),
                identifier: single_metadata(source, "identifier")?.to_owned(),
                trust_level: source
                    .metadata
                    .get("trust_level")
                    .cloned()
                    .unwrap_or_default(),
                explicit: optional_metadata(source, "explicit")
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| {
                        AdapterError::InvalidConfiguration(
                            "WinGet explicit metadata is invalid".into(),
                        )
                    })?,
                priority: optional_metadata(source, "priority")
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| {
                        AdapterError::InvalidConfiguration(
                            "WinGet priority metadata is invalid".into(),
                        )
                    })?,
            });
        }
    }
    if sources.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "WinGet current state has no community source".into(),
        ));
    }
    Ok(sources)
}

fn version_from_current(current: &CurrentConfiguration) -> Result<String, AdapterError> {
    current
        .sources
        .iter()
        .find(|source| source.upstream_id.as_deref() == Some(UPSTREAM))
        .and_then(|source| source.metadata.get("winget_version"))
        .and_then(|values| values.first())
        .cloned()
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("WinGet current state has no version".into())
        })
}

fn replace_source(
    runtime: &dyn Runtime,
    argument: &str,
    version: &str,
    original: &SourceDetails,
) -> Result<(), AdapterError> {
    remove_community(runtime)?;
    add_source(runtime, argument, version, original, true)
}

fn restore_source(runtime: &dyn Runtime, state: &RecoveryState) -> Result<(), AdapterError> {
    let _ = remove_community(runtime);
    add_source(
        runtime,
        &state.original.argument,
        &state.winget_version,
        &state.original,
        false,
    )
}

fn remove_community(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    command_success(
        runtime.run(
            "winget",
            &[
                "source".into(),
                "remove".into(),
                "--name".into(),
                "winget".into(),
                "--disable-interactivity".into(),
            ],
        )?,
        "winget source remove",
    )
}

fn add_source(
    runtime: &dyn Runtime,
    argument: &str,
    version: &str,
    policy: &SourceDetails,
    selected_mirror: bool,
) -> Result<(), AdapterError> {
    let features = version_features(version)?;
    let mut arguments = vec![
        "source".into(),
        "add".into(),
        "--name".into(),
        "winget".into(),
        "--arg".into(),
        argument.into(),
        "--type".into(),
        SOURCE_TYPE.into(),
    ];
    if features.trusted_flag
        && (selected_mirror
            || policy
                .trust_level
                .iter()
                .any(|value| value.eq_ignore_ascii_case("trusted")))
    {
        arguments.extend(["--trust-level".into(), "trusted".into()]);
    }
    arguments.push("--disable-interactivity".into());
    command_success(runtime.run("winget", &arguments)?, "winget source add")?;
    if features.source_edit && (policy.priority.is_some() || policy.explicit.is_some()) {
        let mut edit = vec![
            "source".into(),
            "edit".into(),
            "--name".into(),
            "winget".into(),
        ];
        if let Some(priority) = policy.priority {
            edit.extend(["--priority".into(), priority.to_string()]);
        }
        if let Some(explicit) = policy.explicit {
            edit.extend(["--explicit".into(), explicit.to_string()]);
        }
        edit.push("--disable-interactivity".into());
        command_success(runtime.run("winget", &edit)?, "winget source edit")?;
    }
    Ok(())
}

fn verify_source(
    context: &SystemContext,
    runtime: &dyn Runtime,
    state: &RecoveryState,
) -> Result<(), AdapterError> {
    let sources = export_sources(runtime)?;
    let source = community_source(&sources)?;
    if normalize_url(&source.argument) != normalize_url(&state.selected_argument) {
        return Err(AdapterError::Verification(
            "WinGet did not read the selected source argument".into(),
        ));
    }
    command_success(
        runtime.run(
            "winget",
            &[
                "source".into(),
                "update".into(),
                "--name".into(),
                "winget".into(),
                "--disable-interactivity".into(),
            ],
        )?,
        "winget source update",
    )?;
    command_success(
        runtime.run(
            "winget",
            &[
                "search".into(),
                "--id".into(),
                "jqlang.jq".into(),
                "--exact".into(),
                "--source".into(),
                "winget".into(),
                "--disable-interactivity".into(),
            ],
        )?,
        "winget search jqlang.jq",
    )?;
    let state_path = state_path(runtime)?;
    let directory = state_path
        .parent()
        .unwrap()
        .join("winget-download-verification");
    let powershell = powershell(runtime)?;
    powershell_directory(runtime, powershell, &directory, true)?;
    let download = runtime.run(
        "winget",
        &[
            "download".into(),
            "--id".into(),
            "jqlang.jq".into(),
            "--exact".into(),
            "--source".into(),
            "winget".into(),
            "--architecture".into(),
            winget_architecture(context.architecture).into(),
            "--download-directory".into(),
            directory.display().to_string(),
            "--disable-interactivity".into(),
        ],
    );
    let result = download.and_then(|output| command_success(output, "winget download jqlang.jq"));
    let cleanup = powershell_directory(runtime, powershell, &directory, false);
    result?;
    cleanup?;
    Ok(())
}

fn powershell(runtime: &dyn Runtime) -> Result<&'static str, AdapterError> {
    if runtime.command_exists("powershell") {
        Ok("powershell")
    } else if runtime.command_exists("pwsh") {
        Ok("pwsh")
    } else {
        Err(AdapterError::Unsupported(
            "WinGet verification requires PowerShell".into(),
        ))
    }
}

fn powershell_directory(
    runtime: &dyn Runtime,
    powershell: &str,
    path: &Path,
    create: bool,
) -> Result<(), AdapterError> {
    let script = if create {
        format!(
            "New-Item -ItemType Directory -Force -LiteralPath '{}' | Out-Null",
            path.display().to_string().replace('\'', "''")
        )
    } else {
        format!(
            "Remove-Item -Recurse -Force -LiteralPath '{}' -ErrorAction SilentlyContinue",
            path.display().to_string().replace('\'', "''")
        )
    };
    command_success(
        runtime.run(
            powershell,
            &[
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script,
            ],
        )?,
        "PowerShell WinGet verification directory",
    )
}

fn read_recovery_state(
    runtime: &dyn Runtime,
    receipt: &TransactionReceipt,
) -> Result<RecoveryState, AdapterError> {
    if receipt.participants.len() != 1
        || receipt.participants[0].adapter_key != "winget"
        || receipt.participants[0].tool_id != "winget"
        || receipt.changed_targets.len() != 1
    {
        return Err(AdapterError::InvalidConfiguration(
            "WinGet receipt does not identify one recovery state".into(),
        ));
    }
    let contents = runtime
        .read(&receipt.changed_targets[0])?
        .ok_or_else(|| AdapterError::Runtime("WinGet recovery state is missing".into()))?;
    let state: RecoveryState = serde_json::from_slice(&contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("WinGet recovery state is invalid: {error}"))
    })?;
    state.validate()?;
    Ok(state)
}

fn current_source_metadata(
    source: &SourceDetails,
    context: &SystemContext,
    version: &str,
) -> BTreeMap<String, Vec<String>> {
    let mut metadata = BTreeMap::from([
        ("kind".into(), vec!["community".into()]),
        ("name".into(), vec![source.name.clone()]),
        ("source_type".into(), vec![source.source_type.clone()]),
        ("data".into(), vec![source.data.clone()]),
        ("identifier".into(), vec![source.identifier.clone()]),
        ("trust_level".into(), source.trust_level.clone()),
        ("winget_version".into(), vec![version.into()]),
        (
            "winget_arch".into(),
            vec![winget_architecture(context.architecture).into()],
        ),
        ("winget_manifest_id".into(), vec![MANIFEST_ID.into()]),
        (
            "winget_installer_hash".into(),
            vec![installer_hash(context.architecture).into()],
        ),
    ]);
    if let Some(explicit) = source.explicit {
        metadata.insert("explicit".into(), vec![explicit.to_string()]);
    }
    if let Some(priority) = source.priority {
        metadata.insert("priority".into(), vec![priority.to_string()]);
    }
    metadata
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "winget" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "WinGet plan requires exactly one source selection".into(),
        ));
    }
    let metadata = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Metadata && endpoint.protocol == Protocol::Https
        })
        .map(|endpoint| endpoint.url.trim_end_matches('/'));
    let artifacts = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .map(|endpoint| endpoint.url.trim_end_matches('/'));
    let (Some(metadata), Some(artifacts)) = (metadata, artifacts) else {
        return Err(AdapterError::InvalidConfiguration(
            "WinGet selection lacks metadata and artifact endpoints".into(),
        ));
    };
    if normalize_url(metadata) != normalize_url(artifacts) || !is_mirror_argument(metadata) {
        return Err(AdapterError::InvalidConfiguration(
            "WinGet selection is not a reviewed single-provider source".into(),
        ));
    }
    Ok(metadata)
}

fn is_public_argument(value: &str) -> bool {
    normalize_url(value) == normalize_url(OFFICIAL_ARGUMENT) || is_mirror_argument(value)
}
fn is_mirror_argument(value: &str) -> bool {
    [USTC_ARGUMENT, NJU_ARGUMENT]
        .iter()
        .any(|candidate| normalize_url(value) == normalize_url(candidate))
}
fn normalize_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}
fn winget_architecture(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x64",
        Architecture::Arm64 => "arm64",
    }
}
fn installer_hash(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => X64_INSTALLER_HASH,
        Architecture::Arm64 => ARM64_INSTALLER_HASH,
    }
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "winget"
        && current.scope == ConfigurationScope::System
        && current.documents.len() == 1
    {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "WinGet requires one command-state recovery document".into(),
        ))
    }
}
fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("WinGet source is missing {key}"))
    })?;
    if values.len() == 1 {
        Ok(&values[0])
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "WinGet source has ambiguous {key}"
        )))
    }
}
fn optional_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| (values.len() == 1).then(|| values[0].as_str()))
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
        Err(AdapterError::Runtime(format!(
            "{label} failed with status {}",
            output.status
        )))
    }
}
fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.into()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
