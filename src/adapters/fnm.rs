use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
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

const NODE_UPSTREAM: &str = "nodejs--release-artifacts";
const REVIEWED_NODE_VERSION: &str = "v24.1.0";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch fnm mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch fnm mirror <<<";
const NODE_MIRRORS: &[&str] = &[
    "https://mirrors.aliyun.com/nodejs-release",
    "https://repo.huaweicloud.com/nodejs",
    "https://mirrors.nju.edu.cn/nodejs-release",
    "https://mirrors.tuna.tsinghua.edu.cn/nodejs-release",
    "https://mirrors.ustc.edu.cn/node",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct FnmAdapter;

impl Adapter for FnmAdapter {
    fn key(&self) -> &'static str {
        "fnm"
    }

    fn tool_id(&self) -> &'static str {
        "fnm"
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
        require_supported_context(context)?;
        if !runtime.command_exists("fnm") {
            return Ok(None);
        }
        let layout = config_layout(context, runtime)?;
        let version_output = run_fnm(runtime, &["--version"])?;
        let version = fnm_version(&version_output)?;
        reviewed_version(&version)?;
        let remote_help = run_fnm(runtime, &["list-remote", "--help"])?;
        require_remote_protocol(&remote_help)?;
        let (_, current_output) = invoke_fnm(runtime, &["current"])?;
        let current = observed_current(&current_output);
        let (_, installed_output) = invoke_fnm(runtime, &["list"])?;
        let installed = installed_versions(&installed_output);
        let installed_summary = if installed.is_empty() {
            "none".into()
        } else {
            installed.into_iter().collect::<Vec<_>>().join(", ")
        };
        Ok(Some(DetectedTool {
            tool_id: "fnm".into(),
            executable: Some(PathBuf::from("fnm")),
            version: Some(version.clone()),
            evidence: vec![
                format!("fnm {version}"),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                format!("selected user home is {}", layout.home.display()),
                format!("active shell is {}", layout.shell.name()),
                format!("native shell executable is {}", layout.shell_executable),
                format!(
                    "selected shell initialization is {}",
                    layout.profile.display()
                ),
                runtime.project_dir().map_or_else(
                    || "no project directory was selected".into(),
                    |path| format!("project directory {} remains read-only", path.display()),
                ),
                format!("current Node.js selection is {current}"),
                format!("installed Node.js versions are {installed_summary}"),
                "list-remote supports filter, latest, mirror and architecture controls".into(),
                format!(
                    "FNM_NODE_DIST_MIRROR is {}",
                    environment_state(runtime, "FNM_NODE_DIST_MIRROR")
                ),
                format!("FNM_DIR is {}", environment_state(runtime, "FNM_DIR")),
                format!("FNM_ARCH is {}", environment_state(runtime, "FNM_ARCH")),
            ],
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
        if scope != ConfigurationScope::User {
            return Err(AdapterError::Unsupported(
                "fnm only supports one selected user shell initialization file".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        let observed = runtime.read(&layout.profile)?;
        let exists = observed.is_some();
        let contents = observed.unwrap_or_default();
        let text = utf8(&layout.profile, &contents)?;
        let parsed = parse_profile(text, &layout.profile, layout.shell)?;
        let mut sources = parsed.sources;
        if let Some(value) = runtime
            .environment_variable("FNM_NODE_DIST_MIRROR")
            .filter(|value| !value.is_empty())
        {
            sources.push(configured_source(
                value,
                "environment-override",
                Path::new(":env:"),
                layout.shell,
            ));
        }
        Ok(CurrentConfiguration {
            tool_id: "fnm".into(),
            scope,
            files: exists
                .then_some(layout.profile.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path: layout.profile,
                format: format!("fnm-selected-{}-profile", layout.shell.name()),
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
        require_current(current)?;
        let target = detected
            .evidence
            .iter()
            .find_map(|line| line.strip_prefix("current Node.js selection is "))
            .and_then(normalized_node_version)
            .unwrap_or_else(|| REVIEWED_NODE_VERSION.into());
        Ok(SelectionRequest {
            tool_id: "fnm".into(),
            adapter_key: "fnm".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![NODE_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                NODE_UPSTREAM.into(),
                release_probe_contexts(context, &target)?,
            )]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Releases],
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
        require_supported_context(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("fnm-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected fnm shell profile is missing".into())
            })?;
        let shell = shell_from_format(&document.format)?;
        let old = utf8(&document.path, &document.contents)?;
        let mut new_contents = rewrite_profile(old, endpoint, &document.path, shell)?.into_bytes();
        if document.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            new_contents.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let changes = if new_contents == document.contents {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current
                    .files
                    .contains(&document.path)
                    .then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "add or retarget one managed FNM_NODE_DIST_MIRROR assignment in the explicitly selected {} user profile while preserving fnm initialization and unrelated shell policy",
                    shell.name()
                ),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "fnm".into(),
            tool_id: "fnm".into(),
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
                    "fnm transaction receipt does not contain the selected shell profile".into(),
                ));
            }
            let contents = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("selected fnm shell profile disappeared".into())
            })?;
            let text = utf8(&layout.profile, &contents)?;
            let parsed = parse_profile(text, &layout.profile, layout.shell)?;
            if parsed.unmanaged || parsed.command_override {
                return Err(AdapterError::Verification(
                    "fnm shell profile gained conflicting mirror policy".into(),
                ));
            }
            let endpoint = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed fnm mirror block disappeared".into())
            })?;
            if !is_reviewed(&endpoint) {
                return Err(AdapterError::Verification(
                    "managed fnm mirror block contains an unreviewed endpoint".into(),
                ));
            }
            let expected = rewrite_profile(text, &endpoint, &layout.profile, layout.shell)?;
            if expected != text {
                return Err(AdapterError::Verification(
                    "managed fnm mirror block is not canonical".into(),
                ));
            }
            let output = run_fnm(
                runtime,
                &[
                    "list-remote",
                    "--filter",
                    REVIEWED_NODE_VERSION,
                    "--latest",
                    "--node-dist-mirror",
                    &endpoint,
                    "--arch",
                    fnm_architecture(context)?,
                ],
            )?;
            if !output
                .split_whitespace()
                .filter_map(normalized_node_version)
                .any(|version| version == REVIEWED_NODE_VERSION)
            {
                return Err(AdapterError::Verification(format!(
                    "fnm did not return {REVIEWED_NODE_VERSION} from the selected mirror"
                )));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "fnm list-remote resolved {REVIEWED_NODE_VERSION} from {endpoint}"
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
                "restored {} fnm shell profile file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellKind {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

impl ShellKind {
    fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
        }
    }
}

#[derive(Debug)]
struct Layout {
    home: PathBuf,
    shell: ShellKind,
    shell_executable: String,
    profile: PathBuf,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<String>,
    unmanaged: bool,
    command_override: bool,
    sources: Vec<ConfiguredSource>,
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("fnm requires a detected user home".into()))?;
    validate_path(&home, "home")?;
    let (shell, shell_executable) = if context.os == OperatingSystem::Windows {
        let executable = if runtime.command_exists("pwsh") {
            "pwsh"
        } else if runtime.command_exists("powershell") {
            "powershell"
        } else {
            return Err(AdapterError::Unsupported(
                "fnm on Windows requires PowerShell or PowerShell 7 for profile discovery".into(),
            ));
        };
        (ShellKind::PowerShell, executable.into())
    } else {
        let executable = runtime.environment_variable("SHELL").ok_or_else(|| {
            AdapterError::Unsupported(
                "fnm requires SHELL to select bash, zsh, or fish initialization".into(),
            )
        })?;
        let shell = Path::new(&executable)
            .file_name()
            .and_then(|name| name.to_str().and_then(parse_shell))
            .ok_or_else(|| {
                AdapterError::Unsupported(
                    "fnm requires SHELL to select bash, zsh, or fish initialization".into(),
                )
            })?;
        (shell, executable)
    };
    let profile = selected_profile(context, runtime, &home, shell, &shell_executable)?;
    Ok(Layout {
        home,
        shell,
        shell_executable,
        profile,
    })
}

fn parse_shell(value: &str) -> Option<ShellKind> {
    match value {
        "bash" => Some(ShellKind::Bash),
        "zsh" => Some(ShellKind::Zsh),
        "fish" => Some(ShellKind::Fish),
        _ => None,
    }
}

fn selected_profile(
    context: &SystemContext,
    runtime: &dyn Runtime,
    home: &Path,
    shell: ShellKind,
    shell_executable: &str,
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
        && shell == ShellKind::Bash
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(value);
        validate_user_profile(&path, home)?;
        return Ok(path);
    }
    let path = match shell {
        ShellKind::Bash => home.join(".bashrc"),
        ShellKind::Zsh => {
            if let Some(value) = runtime
                .environment_variable("ZDOTDIR")
                .filter(|value| !value.is_empty())
            {
                let directory = PathBuf::from(value);
                validate_user_profile(&directory.join(".zshrc"), home)?;
                directory.join(".zshrc")
            } else {
                home.join(".zshrc")
            }
        }
        ShellKind::Fish => home.join(".config/fish/conf.d/fnm.fish"),
        ShellKind::PowerShell => powershell_profile(runtime, shell_executable)?,
    };
    validate_user_profile(&path, home)?;
    let contents = runtime.read(&path)?.ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "{} does not exist; set PROFILE to select a persistent fnm environment explicitly",
            path.display()
        ))
    })?;
    let text = utf8(&path, &contents)?;
    if !text.lines().any(is_fnm_loader_line) {
        return Err(AdapterError::Unsupported(format!(
            "{} does not initialize fnm; set PROFILE to select another persistent environment",
            path.display()
        )));
    }
    Ok(path)
}

fn powershell_profile(
    runtime: &dyn Runtime,
    shell_executable: &str,
) -> Result<PathBuf, AdapterError> {
    let output = runtime.run(
        shell_executable,
        &[
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            "[Console]::Out.Write($PROFILE.CurrentUserCurrentHost)".into(),
        ],
    )?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{shell_executable} profile discovery failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        AdapterError::Runtime("PowerShell returned a non-UTF-8 profile path".into())
    })?;
    let profile = PathBuf::from(stdout.trim());
    if profile.as_os_str().is_empty() {
        return Err(AdapterError::Unsupported(
            "PowerShell did not report CurrentUserCurrentHost profile".into(),
        ));
    }
    Ok(profile)
}

fn is_fnm_loader_line(line: &str) -> bool {
    let line = line.trim();
    !line.starts_with('#') && line.to_ascii_lowercase().contains("fnm env")
}

fn run_fnm(runtime: &dyn Runtime, arguments: &[&str]) -> Result<String, AdapterError> {
    let (status, stdout) = invoke_fnm(runtime, arguments)?;
    if !status.success() {
        return Err(AdapterError::Runtime(format!(
            "fnm {} failed with status {status}",
            arguments.join(" ")
        )));
    }
    Ok(stdout)
}

fn invoke_fnm(
    runtime: &dyn Runtime,
    arguments: &[&str],
) -> Result<(std::process::ExitStatus, String), AdapterError> {
    let output = runtime.run(
        "fnm",
        &arguments
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("fnm returned non-UTF-8 stdout".into()))?;
    Ok((output.status, stdout.trim().to_owned()))
}

fn fnm_version(output: &str) -> Result<String, AdapterError> {
    output
        .split_whitespace()
        .find(|token| {
            token
                .chars()
                .next()
                .is_some_and(|value| value.is_ascii_digit())
        })
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("fnm version output is unrecognized".into()))
}

fn reviewed_version(value: &str) -> Result<(), AdapterError> {
    let major = value
        .split('.')
        .next()
        .and_then(|part| part.parse::<u64>().ok());
    if major != Some(1)
        || value
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(AdapterError::Unsupported(format!(
            "fnm {value} is outside the reviewed 1.x command model"
        )));
    }
    Ok(())
}

fn require_remote_protocol(help: &str) -> Result<(), AdapterError> {
    let missing = ["--filter", "--latest", "--node-dist-mirror", "--arch"]
        .into_iter()
        .filter(|flag| !help.contains(flag))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "fnm list-remote lacks required protocol controls: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn observed_current(output: &str) -> String {
    output
        .split_whitespace()
        .find_map(normalized_node_version)
        .unwrap_or_else(|| "none".into())
}

fn installed_versions(output: &str) -> BTreeSet<String> {
    output
        .split_whitespace()
        .filter_map(normalized_node_version)
        .collect()
}

fn normalized_node_version(value: &str) -> Option<String> {
    let version = value.trim_matches(|character: char| matches!(character, '*' | '-' | '>'));
    let version = version.strip_prefix('v').unwrap_or(version);
    let parts = version.split('.').collect::<Vec<_>>();
    (parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())))
    .then(|| format!("v{version}"))
}

fn release_probe_contexts(
    context: &SystemContext,
    version: &str,
) -> Result<Vec<BTreeMap<String, String>>, AdapterError> {
    let architecture = fnm_architecture(context)?;
    let suffix = match context.os {
        OperatingSystem::Linux => format!("linux-{architecture}.tar.xz"),
        OperatingSystem::Macos => format!("darwin-{architecture}.tar.gz"),
        OperatingSystem::Windows => format!("win-{architecture}.zip"),
    };
    Ok(vec![BTreeMap::from([
        ("version".into(), version.into()),
        (
            "artifact_filename".into(),
            format!("node-{version}-{suffix}"),
        ),
    ])])
}

fn fnm_architecture(context: &SystemContext) -> Result<&'static str, AdapterError> {
    match (context.os, context.architecture) {
        (OperatingSystem::Windows, Architecture::Arm64) => Err(AdapterError::Unsupported(
            "fnm on Windows arm64 is unavailable because fnm 1.39.0 publishes one x64 Windows binary"
                .into(),
        )),
        (_, Architecture::X86_64) => Ok("x64"),
        (_, Architecture::Arm64) => Ok("arm64"),
    }
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let managed = range
        .as_ref()
        .map(|range| managed_value(&text[range.clone()], path, shell))
        .transpose()?;
    let mut unmanaged = false;
    let mut command_override = false;
    let mut sources = managed
        .iter()
        .map(|endpoint| configured_source(endpoint.clone(), "managed-shell-profile", path, shell))
        .collect::<Vec<_>>();
    for (start, line) in line_spans(text) {
        if range.as_ref().is_some_and(|range| range.contains(&start)) {
            continue;
        }
        let active = line.trim();
        if active.is_empty() || active.starts_with('#') {
            continue;
        }
        if active.contains("fnm") && active.contains("--node-dist-mirror") {
            command_override = true;
            sources.push(policy_source("command-override", path, shell));
        }
        if let Some(value) = assignment(active, shell)? {
            unmanaged = true;
            sources.push(configured_source(
                value.into(),
                "unmanaged-shell-profile",
                path,
                shell,
            ));
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged,
        command_override,
        sources,
    })
}

fn managed_value(block: &str, path: &Path, shell: ShellKind) -> Result<String, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| assignment(line.trim(), shell).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed fnm block in {} must assign FNM_NODE_DIST_MIRROR exactly once",
            path.display()
        )));
    }
    Ok(values[0].to_owned())
}

fn assignment(line: &str, shell: ShellKind) -> Result<Option<&str>, AdapterError> {
    let raw = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            if key.trim() != "FNM_NODE_DIST_MIRROR" {
                return Ok(None);
            }
            value.trim()
        }
        ShellKind::Fish => {
            let Some(rest) = line.strip_prefix("set ") else {
                return Ok(None);
            };
            let mut fields = rest.split_whitespace();
            let Some(flags) = fields.next() else {
                return Ok(None);
            };
            let Some(key) = fields.next() else {
                return Ok(None);
            };
            let Some(value) = fields.next() else {
                return Ok(None);
            };
            if !flags.contains('x') || key != "FNM_NODE_DIST_MIRROR" {
                return Ok(None);
            }
            if fields.next().is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "fish FNM_NODE_DIST_MIRROR assignment is not a literal value".into(),
                ));
            }
            value
        }
        ShellKind::PowerShell => {
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            if !key.trim().eq_ignore_ascii_case("$env:FNM_NODE_DIST_MIRROR") {
                return Ok(None);
            }
            value.trim()
        }
    };
    literal_value(raw).map(Some)
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
        return Err(AdapterError::InvalidConfiguration(
            "FNM_NODE_DIST_MIRROR assignment is not a literal value".into(),
        ));
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
            "fnm managed markers in {} are missing, duplicated, or out of order",
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
    endpoint: &str,
    path: &Path,
    shell: ShellKind,
) -> Result<String, AdapterError> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(endpoint, newline, shell);
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

fn render_managed(endpoint: &str, newline: &str, shell: ShellKind) -> String {
    let assignment = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            format!("export FNM_NODE_DIST_MIRROR='{endpoint}'")
        }
        ShellKind::Fish => format!("set -gx FNM_NODE_DIST_MIRROR '{endpoint}'"),
        ShellKind::PowerShell => format!("$env:FNM_NODE_DIST_MIRROR = '{endpoint}'"),
    };
    format!("{MANAGED_BEGIN}{newline}{assignment}{newline}{MANAGED_END}{newline}")
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = source
            .metadata
            .get("kind")
            .and_then(|values| values.first())
            .map(String::as_str);
        match kind {
            Some("unmanaged-shell-profile") => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected shell profile already assigns FNM_NODE_DIST_MIRROR outside the MirrorSwitch block"
                        .into(),
                ));
            }
            Some("command-override") => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected shell profile passes an explicit --node-dist-mirror to fnm".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let selected = selections
        .iter()
        .filter(|selection| selection.tool_id == "fnm" && selection.upstream_id == NODE_UPSTREAM)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "fnm requires exactly one Node.js release selection".into(),
        ));
    }
    let endpoints = selected[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Releases && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    if endpoints.len() != 1 || !is_reviewed(&endpoints[0].url) {
        return Err(AdapterError::InvalidConfiguration(
            "fnm selection has no single reviewed Node.js release endpoint".into(),
        ));
    }
    Ok(endpoints[0].url.trim_end_matches('/'))
}

fn is_reviewed(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| NODE_MIRRORS.contains(&value.as_str()))
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

fn configured_source(url: String, kind: &str, path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(NODE_UPSTREAM.into()),
        url,
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("shell".into(), vec![shell.name().into()]),
        ]),
    }
}

fn policy_source(kind: &str, path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("shell".into(), vec![shell.name().into()]),
        ]),
    }
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [
        ShellKind::Bash,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::PowerShell,
    ]
    .into_iter()
    .find(|shell| format == format!("fnm-selected-{}-profile", shell.name()))
    .ok_or_else(|| AdapterError::InvalidConfiguration("unknown fnm profile format".into()))
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

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "fnm on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "fnm on Windows arm64 is unavailable because fnm 1.39.0 publishes one x64 Windows binary"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "fnm requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "fnm" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "fnm plan requires one selected user shell profile".into(),
        ));
    }
    Ok(())
}

fn validate_user_profile(path: &Path, home: &Path) -> Result<(), AdapterError> {
    validate_path(path, "shell profile")?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "selected fnm shell profile {} is outside the user home",
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
            "fnm reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "fnm shell profile {} is not UTF-8",
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
