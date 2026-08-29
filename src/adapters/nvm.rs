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
const IOJS_UPSTREAM: &str = "iojs--release-artifacts";
const REVIEWED_NODE_VERSION: &str = "v24.1.0";
const REVIEWED_IOJS_VERSION: &str = "v3.3.1";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch nvm mirrors >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch nvm mirrors <<<";
const NODE_MIRRORS: &[&str] = &[
    "https://mirrors.aliyun.com/nodejs-release",
    "https://repo.huaweicloud.com/nodejs",
    "https://mirrors.nju.edu.cn/nodejs-release",
    "https://mirrors.tuna.tsinghua.edu.cn/nodejs-release",
    "https://mirrors.ustc.edu.cn/node",
];
const IOJS_MIRRORS: &[&str] = &["https://repo.huaweicloud.com/iojs"];

#[derive(Clone, Copy, Debug, Default)]
pub struct NvmAdapter;

impl Adapter for NvmAdapter {
    fn key(&self) -> &'static str {
        "nvm"
    }

    fn tool_id(&self) -> &'static str {
        "nvm"
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
        let Some(layout) = config_layout(context, runtime)? else {
            return Ok(None);
        };
        let version = run_nvm(runtime, &layout, None, &["--version"])?;
        validate_nvm_version(&version)?;
        let (_, current_output) = invoke_nvm(runtime, &layout, None, &["current"])?;
        let current = observed_current(&current_output);
        let (_, installed_output) = invoke_nvm(runtime, &layout, None, &["ls", "--no-colors"])?;
        let installed = installed_versions(&installed_output);
        let installed_summary = if installed.is_empty() {
            "none".into()
        } else {
            installed.into_iter().collect::<Vec<_>>().join(", ")
        };
        let installation = if runtime.read(&layout.nvm_dir.join(".git/HEAD"))?.is_some() {
            "git checkout"
        } else {
            "script or source checkout"
        };
        Ok(Some(DetectedTool {
            tool_id: "nvm".into(),
            executable: Some(layout.nvm_script.clone()),
            version: Some(version.clone()),
            evidence: vec![
                format!("nvm {version} from {installation}"),
                format!("active shell is {}", layout.shell),
                format!(
                    "selected shell initialization is {}",
                    layout.profile.display()
                ),
                format!("current Node.js/io.js selection is {current}"),
                format!("installed Node.js/io.js versions are {installed_summary}"),
                format!(
                    "NVM_NODEJS_ORG_MIRROR is {}",
                    environment_state(runtime, "NVM_NODEJS_ORG_MIRROR")
                ),
                format!(
                    "NVM_IOJS_ORG_MIRROR is {}",
                    environment_state(runtime, "NVM_IOJS_ORG_MIRROR")
                ),
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
        require_linux(context)?;
        if scope != ConfigurationScope::User {
            return Err(AdapterError::Unsupported(
                "nvm only supports the selected user's shell initialization file".into(),
            ));
        }
        let layout = config_layout(context, runtime)?.ok_or_else(|| {
            AdapterError::Unsupported("nvm installation is no longer available".into())
        })?;
        let observed = runtime.read(&layout.profile)?;
        let exists = observed.is_some();
        let contents = observed.unwrap_or_default();
        let text = utf8(&layout.profile, &contents)?;
        let parsed = parse_profile(text, &layout.profile)?;
        let mut sources = parsed.sources;
        for variable in ["NVM_NODEJS_ORG_MIRROR", "NVM_IOJS_ORG_MIRROR"] {
            if let Some(value) = runtime
                .environment_variable(variable)
                .filter(|value| !value.is_empty())
            {
                sources.push(configured_source(
                    upstream_for_variable(variable),
                    value,
                    "environment-override",
                    Path::new(":env:"),
                ));
            }
        }
        if runtime
            .environment_variable("NVM_AUTH_HEADER")
            .is_some_and(|value| !value.is_empty())
        {
            sources.push(policy_source("authorization-header", Path::new(":env:")));
        }
        Ok(CurrentConfiguration {
            tool_id: "nvm".into(),
            scope,
            files: exists
                .then_some(layout.profile.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path: layout.profile,
                format: "nvm-selected-shell-profile".into(),
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
        let target = detected
            .evidence
            .iter()
            .find_map(|line| line.strip_prefix("current Node.js/io.js selection is "))
            .filter(|value| valid_node_version(value))
            .unwrap_or(REVIEWED_NODE_VERSION)
            .to_owned();
        Ok(SelectionRequest {
            tool_id: "nvm".into(),
            adapter_key: "nvm".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![NODE_UPSTREAM.into(), IOJS_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([
                (
                    NODE_UPSTREAM.into(),
                    release_probe_contexts("node", &target),
                ),
                (
                    IOJS_UPSTREAM.into(),
                    release_probe_contexts("iojs", REVIEWED_IOJS_VERSION),
                ),
            ]),
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let node = selected_endpoint(selections, NODE_UPSTREAM, NODE_MIRRORS)?;
        let iojs = selected_endpoint(selections, IOJS_UPSTREAM, IOJS_MIRRORS)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "nvm-selected-shell-profile")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected nvm shell profile is missing".into())
            })?;
        let old = utf8(&document.path, &document.contents)?;
        let new_contents = rewrite_profile(old, node, iojs, &document.path)?.into_bytes();
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
                summary: "add or retarget one managed Node.js/io.js mirror block in the explicitly selected user shell profile while preserving nvm initialization and unrelated shell policy".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "nvm".into(),
            tool_id: "nvm".into(),
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
            let layout = config_layout(context, runtime)?
                .ok_or_else(|| AdapterError::Verification("nvm installation disappeared".into()))?;
            let target = rooted(&context.root, &layout.profile);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "nvm transaction receipt does not contain the selected shell profile".into(),
                ));
            }
            let contents = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("selected nvm shell profile disappeared".into())
            })?;
            let text = utf8(&layout.profile, &contents)?;
            let parsed = parse_profile(text, &layout.profile)?;
            if parsed.unmanaged_mirror || parsed.authorization_header {
                return Err(AdapterError::Verification(
                    "nvm shell profile gained conflicting mirror or authorization policy".into(),
                ));
            }
            let (node, iojs) = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed nvm mirror block disappeared".into())
            })?;
            if !is_reviewed(&node, NODE_MIRRORS) || !is_reviewed(&iojs, IOJS_MIRRORS) {
                return Err(AdapterError::Verification(
                    "managed nvm mirror block contains an unreviewed endpoint".into(),
                ));
            }
            let expected = rewrite_profile(text, &node, &iojs, &layout.profile)?;
            if expected != text {
                return Err(AdapterError::Verification(
                    "managed nvm mirror block is not canonical".into(),
                ));
            }
            let node_output = run_nvm(
                runtime,
                &layout,
                Some((&node, &iojs)),
                &["ls-remote", "--no-colors", REVIEWED_NODE_VERSION],
            )?;
            if !node_output
                .lines()
                .any(|line| line.trim() == REVIEWED_NODE_VERSION)
            {
                return Err(AdapterError::Verification(format!(
                    "nvm did not return {REVIEWED_NODE_VERSION} from the selected Node.js mirror"
                )));
            }
            let iojs_output = run_nvm(
                runtime,
                &layout,
                Some((&node, &iojs)),
                &["ls-remote", "--no-colors", "iojs"],
            )?;
            let expected_iojs = format!("iojs-{REVIEWED_IOJS_VERSION}");
            if !iojs_output.lines().any(|line| line.trim() == expected_iojs) {
                return Err(AdapterError::Verification(format!(
                    "nvm did not return {expected_iojs} from the selected io.js mirror"
                )));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "nvm ls-remote resolved {REVIEWED_NODE_VERSION} from {node} and {expected_iojs} from {iojs}"
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
        let restored = runtime
            .restore_transaction(&receipt.transaction_id)
            .map_err(|error| AdapterError::Runtime(error.to_string()))?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: format!(
                "restored {} nvm shell profile file(s)",
                restored.restored_files
            ),
        })
    }
}

#[derive(Debug)]
struct Layout {
    shell: String,
    nvm_dir: PathBuf,
    nvm_script: PathBuf,
    profile: PathBuf,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<(String, String)>,
    unmanaged_mirror: bool,
    authorization_header: bool,
    sources: Vec<ConfiguredSource>,
}

fn config_layout(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<Option<Layout>, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("nvm requires a detected user home".into()))?;
    validate_path(&home, "home")?;
    let nvm_dir = if let Some(value) = runtime
        .environment_variable("NVM_DIR")
        .filter(|value| !value.is_empty())
    {
        PathBuf::from(value.trim_end_matches('/'))
    } else if let Some(value) = runtime
        .environment_variable("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
    {
        PathBuf::from(value).join("nvm")
    } else {
        home.join(".nvm")
    };
    validate_path(&nvm_dir, "NVM_DIR")?;
    let nvm_script = nvm_dir.join("nvm.sh");
    let Some(script) = runtime.read(&nvm_script)? else {
        return Ok(None);
    };
    if script.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "nvm script {} is empty",
            nvm_script.display()
        )));
    }
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_owned))
        .ok_or_else(|| AdapterError::Unsupported("nvm requires an explicit SHELL".into()))?;
    if !matches!(
        shell.as_str(),
        "bash" | "zsh" | "sh" | "dash" | "ash" | "ksh"
    ) {
        return Err(AdapterError::Unsupported(format!(
            "nvm shell {shell} is outside the reviewed POSIX shell set"
        )));
    }
    if !runtime.command_exists(&shell) {
        return Err(AdapterError::Unsupported(format!(
            "selected nvm shell {shell} is not callable"
        )));
    }
    let profile = selected_profile(context, runtime, &home, &shell)?;
    Ok(Some(Layout {
        shell,
        nvm_dir,
        nvm_script,
        profile,
    }))
}

fn selected_profile(
    context: &SystemContext,
    runtime: &dyn Runtime,
    home: &Path,
    shell: &str,
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
        && shell == "bash"
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(value);
        validate_user_profile(&path, home)?;
        return Ok(path);
    }
    let names: &[&str] = match shell {
        "bash" => &[".bashrc", ".bash_profile", ".profile"],
        "zsh" => &[".zshrc", ".zprofile", ".profile"],
        "ksh" => &[".kshrc", ".profile"],
        "sh" | "dash" | "ash" => &[".profile"],
        _ => unreachable!("reviewed shell"),
    };
    let mut matches = Vec::new();
    for name in names {
        let path = home.join(name);
        if let Some(contents) = runtime.read(&path)? {
            let text = utf8(&path, &contents)?;
            if text.lines().any(is_nvm_loader_line) {
                matches.push(path);
            }
        }
    }
    match matches.as_slice() {
        [profile] => Ok(profile.clone()),
        [] => Err(AdapterError::Unsupported(format!(
            "no {shell} profile that loads nvm was found; set PROFILE to select one explicitly"
        ))),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "multiple {shell} profiles load nvm; set PROFILE to select exactly one"
        ))),
    }
}

fn is_nvm_loader_line(line: &str) -> bool {
    let line = line.trim();
    !line.starts_with('#') && line.contains("nvm.sh")
}

fn run_nvm(
    runtime: &dyn Runtime,
    layout: &Layout,
    mirrors: Option<(&str, &str)>,
    arguments: &[&str],
) -> Result<String, AdapterError> {
    let (status, stdout) = invoke_nvm(runtime, layout, mirrors, arguments)?;
    if !status.success() {
        return Err(AdapterError::Runtime(format!(
            "nvm {} failed with status {status}",
            arguments.join(" ")
        )));
    }
    Ok(stdout)
}

fn invoke_nvm(
    runtime: &dyn Runtime,
    layout: &Layout,
    mirrors: Option<(&str, &str)>,
    arguments: &[&str],
) -> Result<(std::process::ExitStatus, String), AdapterError> {
    let mut command = format!(
        "export NVM_DIR={}; unset NVM_AUTH_HEADER; ",
        shell_quote(&layout.nvm_dir.display().to_string())
    );
    if let Some((node, iojs)) = mirrors {
        command.push_str(&format!(
            "export NVM_NODEJS_ORG_MIRROR={}; export NVM_IOJS_ORG_MIRROR={}; ",
            shell_quote(node),
            shell_quote(iojs)
        ));
    }
    command.push_str(&format!(
        ". {}; nvm",
        shell_quote(&layout.nvm_script.display().to_string())
    ));
    for argument in arguments {
        command.push(' ');
        command.push_str(&shell_quote(argument));
    }
    let output = runtime.run(&layout.shell, &["-c".into(), command])?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("nvm returned non-UTF-8 stdout".into()))?;
    Ok((output.status, stdout.trim().to_owned()))
}

fn observed_current(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .find(|value| {
            valid_node_version(value)
                || valid_iojs_version(value)
                || matches!(*value, "none" | "system")
        })
        .unwrap_or("unavailable")
        .to_owned()
}

fn installed_versions(output: &str) -> BTreeSet<String> {
    output
        .split_whitespace()
        .map(|value| value.trim_matches(|character: char| matches!(character, '*' | '-' | '>')))
        .filter(|value| valid_node_version(value) || valid_iojs_version(value))
        .map(str::to_owned)
        .collect()
}

fn validate_nvm_version(value: &str) -> Result<(), AdapterError> {
    let mut parts = value.split('.');
    if value.is_empty()
        || parts.clone().count() < 2
        || parts.any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(AdapterError::Unsupported(format!(
            "unrecognized nvm version {value}"
        )));
    }
    Ok(())
}

fn valid_node_version(value: &str) -> bool {
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_iojs_version(value: &str) -> bool {
    value.strip_prefix("iojs-").is_some_and(valid_node_version)
}

fn release_probe_contexts(prefix: &str, version: &str) -> Vec<BTreeMap<String, String>> {
    [Architecture::X86_64, Architecture::Arm64]
        .into_iter()
        .map(|architecture| {
            BTreeMap::from([
                ("artifact_prefix".into(), prefix.into()),
                ("version".into(), version.into()),
                (
                    "architecture".into(),
                    match architecture {
                        Architecture::X86_64 => "x64",
                        Architecture::Arm64 => "arm64",
                    }
                    .into(),
                ),
            ])
        })
        .collect()
}

fn parse_profile(text: &str, path: &Path) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let mut unmanaged_mirror = false;
    let mut authorization_header = false;
    let mut sources = Vec::new();
    let managed = if let Some(range) = &range {
        let mut values = BTreeMap::new();
        for line in text[range.clone()].lines() {
            if let Some((key, value)) = assignment(line)? {
                if values.insert(key.to_owned(), value.to_owned()).is_some() {
                    return Err(AdapterError::InvalidConfiguration(format!(
                        "managed nvm block in {} assigns {key} more than once",
                        path.display()
                    )));
                }
            }
        }
        let node = values.remove("NVM_NODEJS_ORG_MIRROR").ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "managed nvm block in {} is missing NVM_NODEJS_ORG_MIRROR",
                path.display()
            ))
        })?;
        let iojs = values.remove("NVM_IOJS_ORG_MIRROR").ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "managed nvm block in {} is missing NVM_IOJS_ORG_MIRROR",
                path.display()
            ))
        })?;
        if !values.is_empty() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "managed nvm block in {} contains unexpected assignments",
                path.display()
            )));
        }
        sources.push(configured_source(
            NODE_UPSTREAM,
            node.clone(),
            "managed-shell-profile",
            path,
        ));
        sources.push(configured_source(
            IOJS_UPSTREAM,
            iojs.clone(),
            "managed-shell-profile",
            path,
        ));
        Some((node, iojs))
    } else {
        None
    };
    for (start, line) in line_spans(text) {
        if range.as_ref().is_some_and(|range| range.contains(&start)) {
            continue;
        }
        if let Some((key, value)) = assignment(line)? {
            match key {
                "NVM_NODEJS_ORG_MIRROR" | "NVM_IOJS_ORG_MIRROR" => {
                    unmanaged_mirror = true;
                    sources.push(configured_source(
                        upstream_for_variable(key),
                        value.into(),
                        "unmanaged-shell-profile",
                        path,
                    ));
                }
                "NVM_AUTH_HEADER" => {
                    authorization_header = true;
                    sources.push(policy_source("authorization-header", path));
                }
                _ => {}
            }
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged_mirror,
        authorization_header,
        sources,
    })
}

fn assignment(line: &str) -> Result<Option<(&str, &str)>, AdapterError> {
    let mut line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if let Some(rest) = line.strip_prefix("export ") {
        line = rest.trim_start();
    }
    let Some((key, raw)) = line.split_once('=') else {
        return Ok(None);
    };
    let key = key.trim();
    if !matches!(
        key,
        "NVM_NODEJS_ORG_MIRROR" | "NVM_IOJS_ORG_MIRROR" | "NVM_AUTH_HEADER"
    ) {
        return Ok(None);
    }
    let raw = raw.trim();
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
        return Err(AdapterError::InvalidConfiguration(format!(
            "nvm shell assignment for {key} is not a literal value"
        )));
    }
    Ok(Some((key, value)))
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
            "nvm managed markers in {} are missing, duplicated, or out of order",
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
    node: &str,
    iojs: &str,
    path: &Path,
) -> Result<String, AdapterError> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(node, iojs, newline);
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

fn render_managed(node: &str, iojs: &str, newline: &str) -> String {
    format!(
        "{MANAGED_BEGIN}{newline}export NVM_NODEJS_ORG_MIRROR='{node}'{newline}export NVM_IOJS_ORG_MIRROR='{iojs}'{newline}{MANAGED_END}{newline}"
    )
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
                    "selected shell profile already assigns nvm mirror variables outside the MirrorSwitch block"
                        .into(),
                ));
            }
            Some("authorization-header") => {
                return Err(AdapterError::InvalidConfiguration(
                    "NVM_AUTH_HEADER is configured; refusing to redirect that credential to a public mirror"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn selected_endpoint<'a>(
    selections: &'a [MirrorSelection],
    upstream: &str,
    allowlist: &[&str],
) -> Result<&'a str, AdapterError> {
    let selected = selections
        .iter()
        .filter(|selection| selection.tool_id == "nvm" && selection.upstream_id == upstream)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "nvm requires exactly one selection for {upstream}"
        )));
    }
    let endpoints = selected[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Releases && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    if endpoints.len() != 1 || !is_reviewed(&endpoints[0].url, allowlist) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "nvm selection for {upstream} has no single reviewed release endpoint"
        )));
    }
    Ok(endpoints[0].url.trim_end_matches('/'))
}

fn is_reviewed(value: &str, allowlist: &[&str]) -> bool {
    normalized_base(value).is_some_and(|value| allowlist.contains(&value.as_str()))
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

fn configured_source(upstream: &str, url: String, kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(upstream.into()),
        url,
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn policy_source(kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn upstream_for_variable(variable: &str) -> &'static str {
    match variable {
        "NVM_NODEJS_ORG_MIRROR" => NODE_UPSTREAM,
        "NVM_IOJS_ORG_MIRROR" => IOJS_UPSTREAM,
        _ => unreachable!("reviewed nvm mirror variable"),
    }
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
            "nvm v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "nvm" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "nvm plan requires the selected user shell profile".into(),
        ));
    }
    Ok(())
}

fn validate_user_profile(path: &Path, home: &Path) -> Result<(), AdapterError> {
    validate_path(path, "shell profile")?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "selected nvm shell profile {} is outside the user home",
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
            "nvm reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "nvm shell profile {} is not UTF-8",
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
