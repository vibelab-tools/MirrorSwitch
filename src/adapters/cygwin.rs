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

const UPSTREAM: &str = "cygwin--static-files";
const HUAWEI: &str = "https://repo.huaweicloud.com/cygwin";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/sourceware/cygwin";
const OFFICIAL: &str = "https://mirrors.kernel.org/sourceware/cygwin";

#[derive(Clone, Copy, Debug, Default)]
pub struct CygwinAdapter;

impl Adapter for CygwinAdapter {
    fn key(&self) -> &'static str {
        "cygwin"
    }
    fn tool_id(&self) -> &'static str {
        "cygwin"
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
        let layout = layout(runtime)?;
        let has_state = runtime.read(&layout.setup_rc)?.is_some();
        let setup = layout.setup.display().to_string();
        let has_setup = runtime.command_exists(&setup);
        if !has_state && !has_setup {
            return Ok(None);
        }
        if !has_state || !has_setup {
            return Err(AdapterError::Unsupported(
                "Cygwin requires both setup.rc and setup-x86_64.exe".into(),
            ));
        }
        let version = setup_version(runtime, &setup)?;
        let state = parse_setup_rc(
            utf8(&layout.setup_rc, &runtime.read(&layout.setup_rc)?.unwrap())?,
            &layout.setup_rc,
        )?;
        Ok(Some(DetectedTool {
            tool_id: "cygwin".into(),
            executable: Some(layout.setup),
            version: Some(version.clone()),
            evidence: vec![
                format!("Cygwin setup {version}"),
                format!("Cygwin root is {}", layout.root.display()),
                format!(
                    "Cygwin local package directory is {}",
                    state.last_cache.display()
                ),
                "Cygwin setup and repository architecture are x86_64 only".into(),
                "installed package selection and Cygwin configuration remain read-only".into(),
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
                "Cygwin setup state is installation-scoped".into(),
            ));
        }
        let layout = layout(runtime)?;
        let setup = layout.setup.display().to_string();
        if detected.tool_id != "cygwin"
            || detected.version.as_deref() != Some(&setup_version(runtime, &setup)?)
        {
            return Err(AdapterError::Conflict(
                "Cygwin setup identity or version changed after detection".into(),
            ));
        }
        let contents = runtime.read(&layout.setup_rc)?.ok_or_else(|| {
            AdapterError::InvalidConfiguration("Cygwin setup.rc disappeared".into())
        })?;
        let state = parse_setup_rc(utf8(&layout.setup_rc, &contents)?, &layout.setup_rc)?;
        if !is_public_mirror(&state.last_mirror) {
            return Err(AdapterError::Unsupported(
                "Cygwin last-mirror is custom and must be preserved".into(),
            ));
        }
        Ok(CurrentConfiguration {
            tool_id: "cygwin".into(),
            scope,
            files: vec![layout.setup_rc.clone()],
            sources: vec![ConfiguredSource {
                upstream_id: Some(UPSTREAM.into()),
                url: state.last_mirror,
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["setup-repository".into()]),
                    ("root".into(), vec![layout.root.display().to_string()]),
                    (
                        "local_package_dir".into(),
                        vec![state.last_cache.display().to_string()],
                    ),
                    ("setup".into(), vec![layout.setup.display().to_string()]),
                ]),
            }],
            documents: vec![ConfigurationDocument {
                path: layout.setup_rc,
                format: "cygwin-setup-rc".into(),
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
        require_windows(context)?;
        require_current(current)?;
        Ok(SelectionRequest {
            tool_id: "cygwin".into(),
            adapter_key: "cygwin".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
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
        let document = &current.documents[0];
        let rendered = rewrite_last_mirror(
            utf8(&document.path, &document.contents)?,
            &document.path,
            endpoint,
        )?
        .into_bytes();
        let changes = (rendered != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: "change only Cygwin setup.rc last-mirror".into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "cygwin".into(),
            tool_id: "cygwin".into(),
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
        if plan.adapter_key != "cygwin" || plan.tool_id != "cygwin" {
            return Err(AdapterError::InvalidConfiguration(
                "Cygwin apply received another adapter's plan".into(),
            ));
        }
        runtime.apply_plan(plan)
    }

    fn verify(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let layout = layout(runtime)?;
            let contents = runtime
                .read(&layout.setup_rc)?
                .ok_or_else(|| AdapterError::Verification("Cygwin setup.rc disappeared".into()))?;
            let state = parse_setup_rc(utf8(&layout.setup_rc, &contents)?, &layout.setup_rc)?;
            if !is_mirror(&state.last_mirror) {
                return Err(AdapterError::Verification(
                    "Cygwin did not read the selected mirror".into(),
                ));
            }
            let setup = layout.setup.display().to_string();
            command_success(
                runtime.run(
                    &setup,
                    &[
                        "--quiet-mode".into(),
                        "--wait".into(),
                        "--download".into(),
                        "--no-admin".into(),
                        "--no-shortcuts".into(),
                        "--no-desktop".into(),
                        "--no-startmenu".into(),
                        "--root".into(),
                        layout.root.display().to_string(),
                        "--local-package-dir".into(),
                        state.last_cache.display().to_string(),
                        "--site".into(),
                        state.last_mirror.clone(),
                        "--packages".into(),
                        "dash".into(),
                    ],
                )?,
                "Cygwin setup signed dash download",
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
            return Err(AdapterError::Verification(format!(
                "{error}; configuration restored: {restored}"
            )));
        }
        Ok(VerificationResult {
            valid: true,
            summary:
                "Cygwin setup downloaded dash through signed x86_64 metadata without installing it"
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
            summary: "restored the previous Cygwin setup mirror".into(),
        })
    }
}

struct Layout {
    root: PathBuf,
    setup: PathBuf,
    setup_rc: PathBuf,
}
struct SetupState {
    last_mirror: String,
    last_cache: PathBuf,
    mirror_range: Range<usize>,
}

fn require_windows(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Windows || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Cygwin setup adapter requires a native Windows host".into(),
        ));
    }
    if context.architecture != Architecture::X86_64 {
        return Err(AdapterError::Unsupported(
            "Cygwin setup has no native Windows ARM64 repository".into(),
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
        if numbers.len() < 3 || numbers[0] != 10 || numbers[1] != 0 {
            return Err(AdapterError::Unsupported(format!(
                "Cygwin requires Windows 10 or 11, observed {version}"
            )));
        }
    }
    Ok(())
}

fn layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let root = runtime
        .environment_variable("CYGWIN_ROOT")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_root);
    if !root.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "CYGWIN_ROOT must be absolute".into(),
        ));
    }
    let setup = match runtime
        .environment_variable("CYGWIN_SETUP")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
    {
        Some(path) => path,
        None => runtime
            .home_dir()
            .ok_or_else(|| {
                AdapterError::Unsupported("Cygwin setup discovery requires USERPROFILE".into())
            })?
            .join("Downloads")
            .join("setup-x86_64.exe"),
    };
    if !setup.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "CYGWIN_SETUP must be absolute".into(),
        ));
    }
    Ok(Layout {
        setup_rc: root.join("etc").join("setup").join("setup.rc"),
        root,
        setup,
    })
}

fn default_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\cygwin64")
    } else {
        PathBuf::from("/cygwin64")
    }
}

fn setup_version(runtime: &dyn Runtime, setup: &str) -> Result<String, AdapterError> {
    let text = command_text(
        runtime.run(setup, &["--version".into()])?,
        "setup-x86_64 --version",
    )?;
    text.lines()
        .find(|line| line.chars().any(|character| character.is_ascii_digit()))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Runtime("Cygwin setup version output is unknown".into()))
}

fn parse_setup_rc(text: &str, path: &Path) -> Result<SetupState, AdapterError> {
    let mut mirror = None;
    let mut cache = None;
    let lines = line_ranges(text);
    for (index, (_, line)) in lines.iter().enumerate() {
        let key = line.trim();
        if !matches!(key, "last-mirror" | "last-cache") {
            continue;
        }
        let Some((range, value_line)) = lines.get(index + 1) else {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} has no value after {key}",
                path.display()
            )));
        };
        let value = value_line.trim();
        if value.is_empty() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} has an empty {key}",
                path.display()
            )));
        }
        let leading = value_line.find(value).unwrap();
        let value_range = range.start + leading..range.start + leading + value.len();
        if key == "last-mirror" {
            if mirror.replace((value.to_owned(), value_range)).is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "Cygwin setup.rc has duplicate last-mirror".into(),
                ));
            }
        } else if cache.replace(PathBuf::from(value)).is_some() {
            return Err(AdapterError::InvalidConfiguration(
                "Cygwin setup.rc has duplicate last-cache".into(),
            ));
        }
    }
    let (last_mirror, mirror_range) = mirror.ok_or_else(|| {
        AdapterError::InvalidConfiguration("Cygwin setup.rc has no last-mirror".into())
    })?;
    let last_cache = cache.ok_or_else(|| {
        AdapterError::InvalidConfiguration("Cygwin setup.rc has no last-cache".into())
    })?;
    if !last_cache.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "Cygwin last-cache must be absolute".into(),
        ));
    }
    Ok(SetupState {
        last_mirror,
        last_cache,
        mirror_range,
    })
}

fn line_ranges(text: &str) -> Vec<(Range<usize>, &str)> {
    let mut offset = 0;
    let mut lines = Vec::new();
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        lines.push((offset..offset + inclusive.len(), line));
        offset += inclusive.len();
    }
    if text.is_empty() { Vec::new() } else { lines }
}

fn rewrite_last_mirror(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    let state = parse_setup_rc(text, path)?;
    if !is_public_mirror(&state.last_mirror) {
        return Err(AdapterError::Unsupported(
            "custom Cygwin last-mirror must be preserved".into(),
        ));
    }
    let mut output = text.to_owned();
    output.replace_range(state.mirror_range, endpoint);
    Ok(output)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "cygwin" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Cygwin plan requires exactly one repository selection".into(),
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
            "Cygwin selection lacks metadata and package endpoints".into(),
        ));
    };
    if normalize_url(metadata) != normalize_url(artifacts) || !is_mirror(metadata) {
        return Err(AdapterError::InvalidConfiguration(
            "Cygwin selection is not a reviewed same-provider repository".into(),
        ));
    }
    Ok(metadata)
}

fn is_public_mirror(value: &str) -> bool {
    normalize_url(value) == normalize_url(OFFICIAL) || is_mirror(value)
}
fn is_mirror(value: &str) -> bool {
    [HUAWEI, TUNA]
        .iter()
        .any(|candidate| normalize_url(value) == normalize_url(candidate))
}
fn normalize_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}
fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "cygwin"
        && current.scope == ConfigurationScope::System
        && current.documents.len() == 1
    {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "Cygwin requires one setup.rc document".into(),
        ))
    }
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
fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Cygwin configuration {} is not UTF-8",
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
