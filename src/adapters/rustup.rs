use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Component, Path, PathBuf},
    process::Output,
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

const RUSTUP_UPSTREAM: &str = "rust-toolchain--release-artifacts";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch rustup mirrors >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch rustup mirrors <<<";
const DIST_VARIABLE: &str = "RUSTUP_DIST_SERVER";
const UPDATE_VARIABLE: &str = "RUSTUP_UPDATE_ROOT";
const DEPRECATED_VARIABLE: &str = "RUSTUP_DIST_ROOT";
const MIRROR_PAIRS: &[(&str, &str)] = &[
    (
        "https://repo.huaweicloud.com/rustup",
        "https://repo.huaweicloud.com/rustup/rustup",
    ),
    (
        "https://mirrors.ustc.edu.cn/rust-static",
        "https://mirrors.ustc.edu.cn/rust-static/rustup",
    ),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct RustupAdapter;

impl Adapter for RustupAdapter {
    fn key(&self) -> &'static str {
        "rustup"
    }

    fn tool_id(&self) -> &'static str {
        "rustup"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::User
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        require_linux(context)?;
        if !runtime.command_exists("rustup") {
            return Ok(None);
        }
        if !runtime.command_exists("sh") {
            return Err(AdapterError::Unsupported(
                "rustup verification requires a POSIX sh".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        let snapshot = tool_snapshot(runtime)?;
        let toolchain = snapshot
            .active_toolchain
            .as_deref()
            .unwrap_or("none installed");
        let components = display_list(&snapshot.components);
        let targets = display_list(&snapshot.targets);
        Ok(Some(DetectedTool {
            tool_id: "rustup".into(),
            executable: Some(PathBuf::from("rustup")),
            version: Some(snapshot.version.clone()),
            evidence: vec![
                format!("rustup {}", snapshot.version),
                format!("rustup home is {}", snapshot.rustup_home.display()),
                format!("active toolchain is {toolchain}"),
                format!("default installation profile is {}", snapshot.profile),
                format!("installed components are {components}"),
                format!("installed targets are {targets}"),
                format!(
                    "selected {} environment file is {}",
                    layout.shell.name(),
                    layout.profile.display()
                ),
                format!(
                    "{DIST_VARIABLE} is {}",
                    environment_state(runtime, DIST_VARIABLE)
                ),
                format!(
                    "{UPDATE_VARIABLE} is {}",
                    environment_state(runtime, UPDATE_VARIABLE)
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
        require_linux(context)?;
        require_scope(scope)?;
        if detected.tool_id != "rustup" {
            return Err(AdapterError::InvalidConfiguration(
                "rustup read received another tool's detection result".into(),
            ));
        }
        let version = tool_version(&run_rustup(runtime, &["--version"], "rustup --version")?)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "rustup version changed after detection".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        let observed = runtime.read(&layout.profile)?;
        let exists = observed.is_some();
        let contents = observed.unwrap_or_default();
        let text = utf8(&layout.profile, &contents)?;
        let parsed = parse_profile(text, &layout.profile, layout.shell)?;
        let mut sources = parsed.sources;
        sources.push(shell_source(&layout.profile, layout.shell));
        for variable in [DIST_VARIABLE, UPDATE_VARIABLE, DEPRECATED_VARIABLE] {
            if let Some(value) = runtime
                .environment_variable(variable)
                .filter(|value| !value.is_empty())
            {
                sources.push(configured_source(
                    &value,
                    if variable == DEPRECATED_VARIABLE {
                        "deprecated-environment-override"
                    } else {
                        "environment-override"
                    },
                    variable,
                    Path::new(":env:"),
                    layout.shell,
                ));
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "rustup".into(),
            scope,
            files: exists
                .then_some(layout.profile.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path: layout.profile,
                format: "rustup-selected-shell-profile".into(),
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
        require_linux(context)?;
        require_current(current)?;
        reviewed_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("rustup version is missing".into())
        })?)?;
        validate_policy(current)?;
        Ok(SelectionRequest {
            tool_id: "rustup".into(),
            adapter_key: "rustup".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![RUSTUP_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(RUSTUP_UPSTREAM.into(), rustup_probe_contexts())]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Releases, EndpointRole::Artifacts],
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let (dist, update) = selected_pair(selections)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "rustup-selected-shell-profile")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "selected rustup shell profile is missing".into(),
                )
            })?;
        let shell = shell_from_sources(current)?;
        let old = utf8(&document.path, &document.contents)?;
        let new_contents = rewrite_profile(old, dist, update, &document.path, shell)?.into_bytes();
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current
                    .files
                    .contains(&document.path)
                    .then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "set one managed rustup distribution/update pair in {}; preserve toolchains, profile, components, targets and unrelated shell policy",
                    document.path.display()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "rustup".into(),
            tool_id: "rustup".into(),
            scope: ConfigurationScope::User,
            changes,
            requires_elevation: false,
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
            let layout = config_layout(context, runtime)?;
            let target = rooted(&context.root, &layout.profile);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "rustup transaction receipt does not contain the selected profile".into(),
                ));
            }
            let contents = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("selected rustup profile disappeared".into())
            })?;
            let text = utf8(&layout.profile, &contents)?;
            let parsed = parse_profile(text, &layout.profile, layout.shell)?;
            if parsed.unmanaged || parsed.deprecated {
                return Err(AdapterError::Verification(
                    "rustup profile gained a conflicting mirror assignment".into(),
                ));
            }
            let (dist, update) = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed rustup mirror block disappeared".into())
            })?;
            if !reviewed_pair(&dist, &update) {
                return Err(AdapterError::Verification(
                    "managed rustup block contains an unreviewed endpoint pair".into(),
                ));
            }
            if rewrite_profile(text, &dist, &update, &layout.profile, layout.shell)? != text {
                return Err(AdapterError::Verification(
                    "managed rustup mirror block is not canonical".into(),
                ));
            }
            let check = run_with_mirrors(runtime, &dist, &update, &["check"])?;
            if !matches!(check.status.code(), Some(0 | 100)) {
                return Err(AdapterError::Verification(format!(
                    "rustup check failed with status {}",
                    check.status
                )));
            }
            if combined_output(&check).trim().is_empty() {
                return Err(AdapterError::Verification(
                    "rustup check returned no toolchain or update evidence".into(),
                ));
            }
            let profile = run_with_mirrors(runtime, &dist, &update, &["show", "profile"])?;
            if !profile.status.success() {
                return Err(AdapterError::Verification(format!(
                    "rustup show profile failed with status {}",
                    profile.status
                )));
            }
            let profile = stdout(&profile, "rustup show profile")?;
            if !matches!(profile.as_str(), "minimal" | "default" | "complete") {
                return Err(AdapterError::Verification(
                    "rustup show profile returned an unrecognized value".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "rustup check validated toolchain distribution {dist} and update root {update} with profile {profile}"
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
                "restored {} rustup shell profile file(s)",
                restored.restored_files
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellKind {
    Posix,
    Fish,
}

impl ShellKind {
    fn name(self) -> &'static str {
        match self {
            Self::Posix => "POSIX shell",
            Self::Fish => "fish",
        }
    }
}

#[derive(Debug)]
struct Layout {
    shell: ShellKind,
    profile: PathBuf,
}

#[derive(Debug)]
struct ToolSnapshot {
    version: String,
    rustup_home: PathBuf,
    profile: String,
    active_toolchain: Option<String>,
    components: Vec<String>,
    targets: Vec<String>,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<(String, String)>,
    unmanaged: bool,
    deprecated: bool,
    sources: Vec<ConfiguredSource>,
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("rustup requires a detected user home".into()))?;
    validate_path(&home, "home")?;
    let shell_name = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_owned))
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "rustup requires SHELL to select a persistent environment file".into(),
            )
        })?;
    let shell = match shell_name.as_str() {
        "bash" | "zsh" | "sh" | "dash" | "ash" | "ksh" => ShellKind::Posix,
        "fish" => ShellKind::Fish,
        _ => {
            return Err(AdapterError::Unsupported(format!(
                "rustup shell {shell_name} is outside the reviewed shell set"
            )));
        }
    };
    let profile = selected_profile(context, runtime, &home, &shell_name, shell)?;
    Ok(Layout { shell, profile })
}

fn selected_profile(
    context: &SystemContext,
    runtime: &dyn Runtime,
    home: &Path,
    shell_name: &str,
    shell: ShellKind,
) -> Result<PathBuf, AdapterError> {
    if let Some(value) = runtime
        .environment_variable("PROFILE")
        .filter(|value| !value.is_empty())
    {
        if value == "/dev/null" {
            return Err(AdapterError::Unsupported(
                "PROFILE=/dev/null explicitly disables shell-profile changes".into(),
            ));
        }
        let path = PathBuf::from(value);
        validate_user_profile(&path, home)?;
        return Ok(path);
    }
    if context.environment == ExecutionEnvironment::Container
        && shell_name == "bash"
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(value);
        validate_user_profile(&path, home)?;
        return Ok(path);
    }
    let path = match (shell_name, shell) {
        ("bash", _) => home.join(".bashrc"),
        ("zsh", _) => {
            if let Some(value) = runtime
                .environment_variable("ZDOTDIR")
                .filter(|value| !value.is_empty())
            {
                PathBuf::from(value).join(".zshrc")
            } else {
                home.join(".zshrc")
            }
        }
        (_, ShellKind::Fish) => home.join(".config/fish/conf.d/mirrorswitch-rustup.fish"),
        _ => home.join(".profile"),
    };
    validate_user_profile(&path, home)?;
    Ok(path)
}

fn tool_snapshot(runtime: &dyn Runtime) -> Result<ToolSnapshot, AdapterError> {
    let version = tool_version(&run_rustup(runtime, &["--version"], "rustup --version")?)?;
    let rustup_home = PathBuf::from(stdout(
        &run_rustup(runtime, &["show", "home"], "rustup show home")?,
        "rustup show home",
    )?);
    validate_path(&rustup_home, "home")?;
    let profile = stdout(
        &run_rustup(runtime, &["show", "profile"], "rustup show profile")?,
        "rustup show profile",
    )?;
    if !matches!(profile.as_str(), "minimal" | "default" | "complete") {
        return Err(AdapterError::Unsupported(format!(
            "rustup profile {profile} is unrecognized"
        )));
    }
    let active_output = invoke_rustup(runtime, &["show", "active-toolchain"])?;
    let active_toolchain = if active_output.status.success() {
        let active = stdout(&active_output, "rustup show active-toolchain")?
            .split_whitespace()
            .next()
            .map(str::to_owned)
            .ok_or_else(|| {
                AdapterError::Unsupported("rustup active toolchain output is empty".into())
            })?;
        validate_toolchain_name(&active)?;
        Some(active)
    } else if combined_output(&active_output)
        .to_ascii_lowercase()
        .contains("no active toolchain")
    {
        None
    } else {
        return Err(AdapterError::Runtime(format!(
            "rustup show active-toolchain failed with status {}",
            active_output.status
        )));
    };
    let (components, targets) = if let Some(toolchain) = &active_toolchain {
        (
            list_installed(runtime, "component", toolchain)?,
            list_installed(runtime, "target", toolchain)?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(ToolSnapshot {
        version,
        rustup_home,
        profile,
        active_toolchain,
        components,
        targets,
    })
}

fn list_installed(
    runtime: &dyn Runtime,
    kind: &str,
    toolchain: &str,
) -> Result<Vec<String>, AdapterError> {
    let output = run_rustup(
        runtime,
        &[kind, "list", "--installed", "--toolchain", toolchain],
        &format!("rustup {kind} list --installed"),
    )?;
    let mut values = stdout(&output, &format!("rustup {kind} list --installed"))?
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    Ok(values)
}

fn tool_version(output: &Output) -> Result<String, AdapterError> {
    let text = stdout(output, "rustup --version")?;
    let mut fields = text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some("rustup")).then(|| fields.map(str::to_owned).collect::<Vec<_>>())
    });
    let version = fields
        .as_mut()
        .and_then(|fields| fields.first().cloned())
        .ok_or_else(|| AdapterError::Unsupported("rustup version output is unrecognized".into()))?;
    reviewed_version(&version)?;
    Ok(version)
}

fn reviewed_version(value: &str) -> Result<(), AdapterError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(AdapterError::Unsupported(format!(
            "rustup version {value} is unrecognized"
        )));
    }
    let major = parts[0].parse::<u64>().ok();
    let minor = parts[1].parse::<u64>().ok();
    if major != Some(1) || minor.is_none_or(|minor| minor < 24) {
        return Err(AdapterError::Unsupported(format!(
            "rustup {value} is outside the reviewed 1.24+ environment model"
        )));
    }
    Ok(())
}

fn validate_toolchain_name(value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(AdapterError::Unsupported(format!(
            "rustup toolchain name {value} is unrecognized"
        )));
    }
    Ok(())
}

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(", ")
    }
}

fn rustup_probe_contexts() -> Vec<BTreeMap<String, String>> {
    [
        (
            "x86_64-unknown-linux-gnu",
            "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10",
        ),
        (
            "aarch64-unknown-linux-gnu",
            "9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792",
        ),
    ]
    .into_iter()
    .map(|(host, rustup_sha256)| {
        BTreeMap::from([
            ("host".into(), host.into()),
            ("rustup_sha256".into(), rustup_sha256.into()),
        ])
    })
    .collect()
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let managed = range
        .as_ref()
        .map(|range| managed_values(&text[range.clone()], path, shell))
        .transpose()?;
    let mut unmanaged = false;
    let mut deprecated = false;
    let mut sources = managed
        .iter()
        .flat_map(|(dist, update)| {
            [
                configured_source(dist, "managed-shell-profile", DIST_VARIABLE, path, shell),
                configured_source(
                    update,
                    "managed-shell-profile",
                    UPDATE_VARIABLE,
                    path,
                    shell,
                ),
            ]
        })
        .collect::<Vec<_>>();
    for (start, line) in line_spans(text) {
        if range.as_ref().is_some_and(|range| range.contains(&start)) {
            continue;
        }
        if let Some((variable, value)) = assignment(line.trim(), shell)? {
            if variable == DEPRECATED_VARIABLE {
                deprecated = true;
                sources.push(configured_source(
                    value,
                    "deprecated-shell-profile",
                    variable,
                    path,
                    shell,
                ));
            } else {
                unmanaged = true;
                sources.push(configured_source(
                    value,
                    "unmanaged-shell-profile",
                    variable,
                    path,
                    shell,
                ));
            }
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged,
        deprecated,
        sources,
    })
}

fn managed_values(
    block: &str,
    path: &Path,
    shell: ShellKind,
) -> Result<(String, String), AdapterError> {
    let mut values = BTreeMap::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || matches!(line, MANAGED_BEGIN | MANAGED_END) {
            continue;
        }
        if let Some((variable, value)) = assignment(line, shell)? {
            if variable == DEPRECATED_VARIABLE || values.insert(variable, value).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "managed rustup block in {} has duplicate or deprecated assignments",
                    path.display()
                )));
            }
        } else {
            return Err(AdapterError::InvalidConfiguration(format!(
                "managed rustup block in {} contains unexpected content",
                path.display()
            )));
        }
    }
    if values.len() != 2 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed rustup block in {} must assign both rustup mirror variables",
            path.display()
        )));
    }
    let dist = values.remove(DIST_VARIABLE).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "managed rustup block in {} is missing {DIST_VARIABLE}",
            path.display()
        ))
    })?;
    let update = values.remove(UPDATE_VARIABLE).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "managed rustup block in {} is missing {UPDATE_VARIABLE}",
            path.display()
        ))
    })?;
    Ok((dist.into(), update.into()))
}

fn assignment(line: &str, shell: ShellKind) -> Result<Option<(&str, &str)>, AdapterError> {
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let parsed = match shell {
        ShellKind::Posix => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            line.split_once('=')
                .map(|(key, value)| (key.trim(), value.trim()))
        }
        ShellKind::Fish => {
            let Some(rest) = line.strip_prefix("set ") else {
                if contains_variable(line) {
                    return Err(complex_assignment());
                }
                return Ok(None);
            };
            let mut fields = rest.split_whitespace();
            let (Some(flags), Some(variable), Some(value)) =
                (fields.next(), fields.next(), fields.next())
            else {
                if contains_variable(line) {
                    return Err(complex_assignment());
                }
                return Ok(None);
            };
            if fields.next().is_some() || !flags.contains('x') {
                if contains_variable(line) {
                    return Err(complex_assignment());
                }
                return Ok(None);
            }
            Some((variable, value))
        }
    };
    let Some((variable, raw)) = parsed else {
        if contains_variable(line) {
            return Err(complex_assignment());
        }
        return Ok(None);
    };
    if !matches!(
        variable,
        DIST_VARIABLE | UPDATE_VARIABLE | DEPRECATED_VARIABLE
    ) {
        if contains_variable(line) {
            return Err(complex_assignment());
        }
        return Ok(None);
    }
    Ok(Some((variable, literal_value(raw)?)))
}

fn contains_variable(line: &str) -> bool {
    [DIST_VARIABLE, UPDATE_VARIABLE, DEPRECATED_VARIABLE]
        .iter()
        .any(|variable| line.contains(variable))
}

fn complex_assignment() -> AdapterError {
    AdapterError::InvalidConfiguration(
        "rustup mirror assignment is not a supported literal shell assignment".into(),
    )
}

fn literal_value(raw: &str) -> Result<&str, AdapterError> {
    let single_quoted = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double_quoted = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    let value = if single_quoted || double_quoted {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.is_empty()
        || value.contains([';', '`', '$', '\n', '\r'])
        || (single_quoted && value.contains('\''))
        || (double_quoted && value.contains('"'))
        || (!single_quoted
            && !double_quoted
            && raw
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '\'' | '"')))
    {
        return Err(complex_assignment());
    }
    Ok(value)
}

fn managed_range(text: &str, path: &Path) -> Result<Option<Range<usize>>, AdapterError> {
    let begins = line_spans(text)
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == MANAGED_BEGIN)
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let ends = line_spans(text)
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == MANAGED_END)
        .map(|(start, line)| start + line.len())
        .collect::<Vec<_>>();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([begin], [end]) if begin < end => Ok(Some(*begin..*end)),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "rustup managed markers in {} are missing, duplicated, or out of order",
            path.display()
        ))),
    }
}

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
}

fn rewrite_profile(
    text: &str,
    dist: &str,
    update: &str,
    path: &Path,
    shell: ShellKind,
) -> Result<String, AdapterError> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(dist, update, newline, shell);
    if let Some(range) = managed_range(text, path)? {
        return Ok(format!(
            "{}{}{}",
            &text[..range.start],
            block,
            &text[range.end..]
        ));
    }
    let mut result = text.to_owned();
    if !result.is_empty() {
        if !result.ends_with('\n') {
            result.push_str(newline);
        }
        if !result.ends_with(&format!("{newline}{newline}")) {
            result.push_str(newline);
        }
    }
    result.push_str(&block);
    Ok(result)
}

fn render_managed(dist: &str, update: &str, newline: &str, shell: ShellKind) -> String {
    let assignments = match shell {
        ShellKind::Posix => {
            format!("export {DIST_VARIABLE}='{dist}'{newline}export {UPDATE_VARIABLE}='{update}'")
        }
        ShellKind::Fish => {
            format!("set -gx {DIST_VARIABLE} '{dist}'{newline}set -gx {UPDATE_VARIABLE} '{update}'")
        }
    };
    format!("{MANAGED_BEGIN}{newline}{assignments}{newline}{MANAGED_END}{newline}")
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    let managed = managed_pair_from_sources(current)?;
    let mut environment = BTreeMap::new();
    for source in &current.sources {
        match metadata(source, "kind") {
            Some("unmanaged-shell-profile") => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected shell profile assigns rustup mirrors outside the MirrorSwitch block"
                        .into(),
                ));
            }
            Some("deprecated-shell-profile" | "deprecated-environment-override") => {
                return Err(AdapterError::Unsupported(
                    "deprecated RUSTUP_DIST_ROOT is configured and must not be combined with RUSTUP_DIST_SERVER"
                        .into(),
                ));
            }
            Some("environment-override") => {
                let variable = metadata(source, "variable").ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "rustup environment source has no variable identity".into(),
                    )
                })?;
                environment.insert(variable, source.url.as_str());
            }
            _ => {}
        }
    }
    if !environment.is_empty() {
        let Some((dist, update)) = managed else {
            return Err(AdapterError::Unsupported(
                "process-level rustup mirror variables override persistent configuration".into(),
            ));
        };
        if environment.len() != 2
            || environment.get(DIST_VARIABLE).copied() != Some(dist.as_str())
            || environment.get(UPDATE_VARIABLE).copied() != Some(update.as_str())
        {
            return Err(AdapterError::Unsupported(
                "process-level rustup mirror variables conflict with the managed profile".into(),
            ));
        }
    }
    Ok(())
}

fn managed_pair_from_sources(
    current: &CurrentConfiguration,
) -> Result<Option<(String, String)>, AdapterError> {
    let mut values = BTreeMap::new();
    for source in current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind") == Some("managed-shell-profile"))
    {
        let variable = metadata(source, "variable").ok_or_else(|| {
            AdapterError::InvalidConfiguration("managed rustup source has no variable".into())
        })?;
        if values.insert(variable, source.url.clone()).is_some() {
            return Err(AdapterError::InvalidConfiguration(
                "managed rustup source is duplicated".into(),
            ));
        }
    }
    match values.len() {
        0 => Ok(None),
        2 => Ok(Some((
            values.remove(DIST_VARIABLE).ok_or_else(|| {
                AdapterError::InvalidConfiguration("managed rustup dist server is missing".into())
            })?,
            values.remove(UPDATE_VARIABLE).ok_or_else(|| {
                AdapterError::InvalidConfiguration("managed rustup update root is missing".into())
            })?,
        ))),
        _ => Err(AdapterError::InvalidConfiguration(
            "managed rustup source pair is incomplete".into(),
        )),
    }
}

fn shell_from_sources(current: &CurrentConfiguration) -> Result<ShellKind, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter_map(|source| metadata(source, "shell"))
        .collect::<Vec<_>>();
    let value = values.first().copied().unwrap_or("posix");
    if values.iter().any(|other| *other != value) {
        return Err(AdapterError::InvalidConfiguration(
            "rustup shell evidence is inconsistent".into(),
        ));
    }
    match value {
        "posix" => Ok(ShellKind::Posix),
        "fish" => Ok(ShellKind::Fish),
        _ => Err(AdapterError::InvalidConfiguration(
            "rustup shell evidence is unrecognized".into(),
        )),
    }
}

fn selected_pair(selections: &[MirrorSelection]) -> Result<(&str, &str), AdapterError> {
    let selected = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "rustup" && selection.upstream_id == RUSTUP_UPSTREAM
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "rustup requires exactly one complete mirror selection".into(),
        ));
    }
    let releases = selected[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Releases && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    let updates = selected[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    if releases.len() != 1
        || updates.len() != 1
        || !reviewed_pair(&releases[0].url, &updates[0].url)
    {
        return Err(AdapterError::InvalidConfiguration(
            "rustup selection lacks one reviewed distribution/update endpoint pair".into(),
        ));
    }
    Ok((
        releases[0].url.trim_end_matches('/'),
        updates[0].url.trim_end_matches('/'),
    ))
}

fn reviewed_pair(dist: &str, update: &str) -> bool {
    let Some(dist) = normalized_base(dist) else {
        return false;
    };
    let Some(update) = normalized_base(update) else {
        return false;
    };
    MIRROR_PAIRS.contains(&(dist.as_str(), update.as_str()))
}

fn normalized_base(value: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(value).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(value.trim_end_matches('/').to_ascii_lowercase())
}

fn configured_source(
    url: &str,
    kind: &str,
    variable: &str,
    path: &Path,
    shell: ShellKind,
) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(RUSTUP_UPSTREAM.into()),
        url: url.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("variable".into(), vec![variable.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            (
                "shell".into(),
                vec![
                    match shell {
                        ShellKind::Posix => "posix",
                        ShellKind::Fish => "fish",
                    }
                    .into(),
                ],
            ),
        ]),
    }
}

fn shell_source(path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: shell.name().into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["shell-evidence".into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            (
                "shell".into(),
                vec![
                    match shell {
                        ShellKind::Posix => "posix",
                        ShellKind::Fish => "fish",
                    }
                    .into(),
                ],
            ),
        ]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn run_rustup(
    runtime: &dyn Runtime,
    arguments: &[&str],
    operation: &str,
) -> Result<Output, AdapterError> {
    let output = invoke_rustup(runtime, arguments)?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    Ok(output)
}

fn invoke_rustup(runtime: &dyn Runtime, arguments: &[&str]) -> Result<Output, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    match runtime.project_dir() {
        Some(directory) => runtime.run_in(&directory, "rustup", &arguments),
        None => runtime.run("rustup", &arguments),
    }
}

fn run_with_mirrors(
    runtime: &dyn Runtime,
    dist: &str,
    update: &str,
    arguments: &[&str],
) -> Result<Output, AdapterError> {
    if !reviewed_pair(dist, update) {
        return Err(AdapterError::Verification(
            "rustup verification received an unreviewed endpoint pair".into(),
        ));
    }
    let mut command = format!(
        "export {DIST_VARIABLE}={}; export {UPDATE_VARIABLE}={}; rustup",
        shell_quote(dist),
        shell_quote(update)
    );
    for argument in arguments {
        command.push(' ');
        command.push_str(&shell_quote(argument));
    }
    let arguments = vec!["-c".into(), command];
    match runtime.project_dir() {
        Some(directory) => runtime.run_in(&directory, "sh", &arguments),
        None => runtime.run("sh", &arguments),
    }
}

fn stdout(output: &Output, operation: &str) -> Result<String, AdapterError> {
    String::from_utf8(output.stdout.clone())
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 stdout")))
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn environment_state(runtime: &dyn Runtime, variable: &str) -> &'static str {
    if runtime
        .environment_variable(variable)
        .is_some_and(|value| !value.is_empty())
    {
        "set"
    } else {
        "unset"
    }
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "rustup v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "rustup v0.1 writes only one selected user environment file".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "rustup" {
        return Err(AdapterError::InvalidConfiguration(
            "rustup operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn validate_user_profile(path: &Path, home: &Path) -> Result<(), AdapterError> {
    validate_path(path, "shell profile")?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "selected rustup environment file {} is outside the user home",
            path.display()
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "rustup reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "rustup environment file {} is not UTF-8",
            path.display()
        ))
    })
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

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
