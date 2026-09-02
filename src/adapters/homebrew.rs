use std::{
    collections::{BTreeMap, BTreeSet},
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

const GIT_UPSTREAM: &str = "homebrew--git-mirror";
const BOTTLES_UPSTREAM: &str = "homebrew-bottles--binary-cache";
const GIT_ENDPOINT: &str = "https://mirrors.ustc.edu.cn/brew.git";
const OFFICIAL_GIT_ENDPOINT: &str = "https://github.com/Homebrew/brew";
const BOTTLES_ENDPOINT: &str = "https://mirrors.ustc.edu.cn/homebrew-bottles";
const API_ENDPOINT: &str = "https://mirrors.ustc.edu.cn/homebrew-bottles/api";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch Homebrew mirrors >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch Homebrew mirrors <<<";
const VARIABLES: &[&str] = &[
    "HOMEBREW_BREW_GIT_REMOTE",
    "HOMEBREW_API_DOMAIN",
    "HOMEBREW_ARTIFACT_DOMAIN",
    "HOMEBREW_BOTTLE_DOMAIN",
    "HOMEBREW_NO_INSTALL_FROM_API",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct HomebrewAdapter;

impl Adapter for HomebrewAdapter {
    fn key(&self) -> &'static str {
        "homebrew"
    }

    fn tool_id(&self) -> &'static str {
        "homebrew"
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
        require_macos(context)?;
        if !runtime.command_exists("brew") {
            return Ok(None);
        }
        let version = homebrew_version(&run(runtime, "brew", &["--version"])?)?;
        reviewed_version(&version)?;
        let prefix = one_line(&run(runtime, "brew", &["--prefix"])?, "brew --prefix")?;
        require_prefix(context.architecture, &prefix)?;
        let repository = one_line(
            &run(runtime, "brew", &["--repository"])?,
            "brew --repository",
        )?;
        let layout = profile_layout(runtime)?;
        let git_remote = if runtime.command_exists("git") {
            run_in(
                runtime,
                Path::new(&repository),
                "git",
                &["remote", "get-url", "origin"],
            )
            .ok()
            .and_then(|value| value.lines().next().map(str::to_owned))
            .unwrap_or_else(|| "unavailable".into())
        } else {
            "git-unavailable".into()
        };
        let git_remote_state = if normalize_url(&git_remote) == normalize_url(OFFICIAL_GIT_ENDPOINT)
        {
            "official"
        } else if normalize_url(&git_remote) == normalize_url(GIT_ENDPOINT) {
            "reviewed-mirror"
        } else {
            "custom-or-unavailable"
        };
        Ok(Some(DetectedTool {
            tool_id: "homebrew".into(),
            executable: Some(PathBuf::from("brew")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Homebrew {version}"),
                format!("prefix is {prefix}"),
                format!("brew repository is {repository}"),
                format!("brew repository origin is {git_remote_state}"),
                format!("persistent shell profile is {}", layout.profile.display()),
                format!("shell is {}", layout.shell.name()),
                environment_evidence(runtime, "HOMEBREW_BREW_GIT_REMOTE"),
                environment_evidence(runtime, "HOMEBREW_API_DOMAIN"),
                environment_evidence(runtime, "HOMEBREW_ARTIFACT_DOMAIN"),
                environment_evidence(runtime, "HOMEBREW_BOTTLE_DOMAIN"),
                environment_evidence(runtime, "HOMEBREW_NO_INSTALL_FROM_API"),
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
        require_macos(context)?;
        if scope != ConfigurationScope::User {
            return Err(AdapterError::Unsupported(
                "Homebrew mirror persistence supports only the owning user profile".into(),
            ));
        }
        let layout = profile_layout(runtime)?;
        let repository = one_line(
            &run(runtime, "brew", &["--repository"])?,
            "brew --repository",
        )?;
        let git_config = PathBuf::from(repository).join(".git/config");
        let git_contents = runtime.read(&git_config)?.ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "Homebrew Git configuration {} is missing",
                git_config.display()
            ))
        })?;
        let git_origin = git_origin(utf8(&git_config, &git_contents)?, &git_config)?;
        let observed = runtime.read(&layout.profile)?;
        let exists = observed.is_some();
        let contents = observed.unwrap_or_default();
        let text = utf8(&layout.profile, &contents)?;
        let parsed = parse_profile(text, &layout.profile, layout.shell)?;
        let mut sources = parsed.sources;
        for variable in VARIABLES {
            if let Some(value) = runtime
                .environment_variable(variable)
                .filter(|value| !value.trim().is_empty())
            {
                sources.push(configured_source(
                    Some(variable),
                    &value,
                    "environment-override",
                    Path::new(":env:"),
                ));
            }
        }
        sources.push(configured_source(
            Some("HOMEBREW_BREW_GIT_REMOTE"),
            &git_origin,
            "brew-git-origin",
            &git_config,
        ));
        let mut files = exists
            .then_some(layout.profile.clone())
            .into_iter()
            .collect::<Vec<_>>();
        files.push(git_config.clone());
        Ok(CurrentConfiguration {
            tool_id: "homebrew".into(),
            scope,
            files,
            sources,
            documents: vec![
                ConfigurationDocument {
                    path: layout.profile,
                    format: format!("homebrew-{}-profile", layout.shell.name()),
                    contents,
                },
                ConfigurationDocument {
                    path: git_config,
                    format: "homebrew-git-config".into(),
                    contents: git_contents,
                },
            ],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_macos(context)?;
        require_current(current)?;
        let version = detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Homebrew version is missing".into())
        })?;
        reviewed_version(version)?;
        let major = version.split('.').next().unwrap_or(version).to_owned();
        if current.sources.iter().any(|source| {
            source.metadata.get("variable").is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value == "HOMEBREW_NO_INSTALL_FROM_API")
            })
        }) {
            return Err(AdapterError::Unsupported(
                "HOMEBREW_NO_INSTALL_FROM_API requires core/cask Git surfaces that have no complete six-provider candidate".into(),
            ));
        }
        let (tag, digest) = bottle_fixture(context.architecture);
        Ok(SelectionRequest {
            tool_id: "homebrew".into(),
            adapter_key: "homebrew".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![GIT_UPSTREAM.into(), BOTTLES_UPSTREAM.into()],
            repository_versions: BTreeMap::from([
                (GIT_UPSTREAM.into(), major.clone()),
                (BOTTLES_UPSTREAM.into(), major),
            ]),
            probe_contexts: BTreeMap::from([(
                BOTTLES_UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("homebrew_bottle_tag".into(), tag.into()),
                    ("homebrew_bottle_sha".into(), digest.into()),
                ])],
            )]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Artifacts],
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
        require_macos(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let git = selected_endpoint(selections, GIT_UPSTREAM, EndpointRole::Git)?;
        let bottles = selected_endpoint(selections, BOTTLES_UPSTREAM, EndpointRole::Artifacts)?;
        let providers = selections
            .iter()
            .map(|selection| selection.provider_id.as_str())
            .collect::<BTreeSet<_>>();
        if providers.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(
                "Homebrew Git, API and bottle surfaces must come from one validated provider"
                    .into(),
            ));
        }
        let git = reviewed_url(&git, GIT_ENDPOINT)?;
        let bottles = reviewed_url(&bottles, BOTTLES_ENDPOINT)?;
        let api = format!("{bottles}/api");
        let document = current
            .documents
            .iter()
            .find(|document| {
                document.format.starts_with("homebrew-") && document.format.ends_with("-profile")
            })
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Homebrew profile document is missing".into())
            })?;
        let shell = shell_from_format(&document.format)?;
        let old = utf8(&document.path, &document.contents)?;
        let new_contents =
            rewrite_profile(old, &document.path, shell, &git, &api, &bottles)?.into_bytes();
        let mut changes = Vec::new();
        if new_contents != document.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current
                    .files
                    .contains(&document.path)
                    .then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "set one managed Homebrew Brew Git, signed API and OCI artifact block while preserving unrelated shell and tap policy".into(),
            });
        }
        let git_document = current
            .documents
            .iter()
            .find(|document| document.format == "homebrew-git-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Homebrew Git config document is missing".into())
            })?;
        let git_text = utf8(&git_document.path, &git_document.contents)?;
        let git_contents = rewrite_git_origin(git_text, &git_document.path, &git)?.into_bytes();
        if git_contents != git_document.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &git_document.path),
                old_contents: Some(git_document.contents.clone()),
                old_mode: None,
                new_contents: git_contents,
                new_mode: None,
                summary: "retarget only the Homebrew/brew origin while preserving other Git remotes and settings".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "homebrew".into(),
            tool_id: "homebrew".into(),
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
            let layout = profile_layout(runtime)?;
            let target = rooted(&context.root, &layout.profile);
            let repository = one_line(
                &run(runtime, "brew", &["--repository"])?,
                "brew --repository",
            )?;
            let git_config = rooted(
                &context.root,
                &PathBuf::from(&repository).join(".git/config"),
            );
            if !receipt.changed_targets.contains(&target)
                || !receipt.changed_targets.contains(&git_config)
            {
                return Err(AdapterError::Verification(
                    "Homebrew receipt does not contain both profile and Brew Git config".into(),
                ));
            }
            let contents = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("Homebrew shell profile disappeared".into())
            })?;
            let parsed = parse_profile(
                utf8(&layout.profile, &contents)?,
                &layout.profile,
                layout.shell,
            )?;
            if parsed.unmanaged {
                return Err(AdapterError::Verification(
                    "Homebrew profile gained an unmanaged mirror assignment".into(),
                ));
            }
            require_managed_values(&parsed.managed)?;
            let origin = run_in(
                runtime,
                Path::new(&repository),
                "git",
                &["remote", "get-url", "origin"],
            )?;
            if origin.trim() != GIT_ENDPOINT {
                return Err(AdapterError::Verification(
                    "Homebrew/brew origin does not match the selected mirror".into(),
                ));
            }
            let (tag, _) = bottle_fixture(context.architecture);
            let environment = [
                format!("HOMEBREW_BREW_GIT_REMOTE={GIT_ENDPOINT}"),
                format!("HOMEBREW_API_DOMAIN={API_ENDPOINT}"),
                format!("HOMEBREW_ARTIFACT_DOMAIN={BOTTLES_ENDPOINT}"),
            ];
            run_brew_with_environment(runtime, &environment, &["config"])?;
            let info =
                run_brew_with_environment(runtime, &environment, &["info", "--json=v2", "jq"])?;
            if !info.contains("jq") {
                return Err(AdapterError::Verification(
                    "brew info did not resolve the fixed jq formula".into(),
                ));
            }
            run_brew_with_environment(runtime, &environment, &["update", "--quiet"])?;
            run_brew_with_environment(
                runtime,
                &environment,
                &["fetch", "--force", &format!("--bottle-tag={tag}"), "jq"],
            )?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Homebrew update/info/fetch validated USTC Brew Git, signed API and {tag} bottle"
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
                "restored {} Homebrew shell profile file(s)",
                restored.restored_files
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

impl ShellKind {
    fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

struct Layout {
    shell: ShellKind,
    profile: PathBuf,
}

struct ParsedProfile {
    managed: BTreeMap<String, String>,
    unmanaged: bool,
    sources: Vec<ConfiguredSource>,
}

fn require_macos(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Macos || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Homebrew mirror configuration requires a native macOS host".into(),
        ));
    }
    Ok(())
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    let major = version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AdapterError::Unsupported(format!("unknown Homebrew version {version}")))?;
    if matches!(major, 4 | 5) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "Homebrew {version} is outside the reviewed 4.x/5.x API-mode range"
        )))
    }
}

fn require_prefix(architecture: Architecture, prefix: &str) -> Result<(), AdapterError> {
    let expected = match architecture {
        Architecture::X86_64 => "/usr/local",
        Architecture::Arm64 => "/opt/homebrew",
    };
    if prefix == expected {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "Homebrew prefix {prefix} is not the reviewed {expected} prefix"
        )))
    }
}

fn profile_layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Homebrew requires a user home".into()))?;
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| {
            Path::new(&value)
                .file_name()?
                .to_str()
                .and_then(parse_shell)
        })
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "Homebrew persistence requires a bash, zsh, or fish SHELL".into(),
            )
        })?;
    let profile = if let Some(value) = runtime
        .environment_variable("PROFILE")
        .filter(|value| !value.trim().is_empty())
    {
        PathBuf::from(value)
    } else {
        match shell {
            ShellKind::Bash => home.join(".bash_profile"),
            ShellKind::Zsh => home.join(".zprofile"),
            ShellKind::Fish => home.join(".config/fish/conf.d/mirrorswitch-homebrew.fish"),
        }
    };
    if !profile.is_absolute() || !profile.starts_with(&home) {
        return Err(AdapterError::Unsupported(format!(
            "Homebrew profile {} is outside the detected user home",
            profile.display()
        )));
    }
    Ok(Layout { shell, profile })
}

fn parse_shell(value: &str) -> Option<ShellKind> {
    match value {
        "bash" => Some(ShellKind::Bash),
        "zsh" => Some(ShellKind::Zsh),
        "fish" => Some(ShellKind::Fish),
        _ => None,
    }
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let mut managed = BTreeMap::new();
    let mut unmanaged = false;
    let mut sources = Vec::new();
    for (start, line) in line_spans(text) {
        let active = line.trim();
        if active.is_empty() || active.starts_with('#') {
            continue;
        }
        for variable in VARIABLES {
            if let Some(value) = assignment(active, shell, variable) {
                let inside = range.as_ref().is_some_and(|range| range.contains(&start));
                if inside {
                    if managed.insert((*variable).into(), value.into()).is_some() {
                        return Err(AdapterError::InvalidConfiguration(format!(
                            "{} contains duplicate {variable} assignments",
                            path.display()
                        )));
                    }
                } else {
                    unmanaged = true;
                }
                sources.push(configured_source(
                    Some(variable),
                    value,
                    if inside {
                        "managed-profile"
                    } else {
                        "unmanaged-profile"
                    },
                    path,
                ));
            }
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged,
        sources,
    })
}

fn git_origin(text: &str, path: &Path) -> Result<String, AdapterError> {
    let mut in_origin = false;
    let mut origin = None;
    for line in text.lines() {
        let active = line.trim();
        if active.starts_with('[') {
            in_origin = active.eq_ignore_ascii_case("[remote \"origin\"]");
            continue;
        }
        if in_origin
            && let Some((key, value)) = active.split_once('=')
            && key.trim().eq_ignore_ascii_case("url")
            && origin.replace(value.trim().to_owned()).is_some()
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} contains duplicate Homebrew origin URLs",
                path.display()
            )));
        }
    }
    origin.ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "{} does not contain a Homebrew origin remote",
            path.display()
        ))
    })
}

fn rewrite_git_origin(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    git_origin(text, path)?;
    let mut in_origin = false;
    let mut replaced = false;
    let mut output = String::with_capacity(text.len() + endpoint.len());
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        let ending = &line[content.len()..];
        let active = content.trim();
        if active.starts_with('[') {
            in_origin = active.eq_ignore_ascii_case("[remote \"origin\"]");
        }
        if in_origin
            && let Some((key, _)) = active.split_once('=')
            && key.trim().eq_ignore_ascii_case("url")
        {
            let indent = &content[..content.len() - content.trim_start().len()];
            output.push_str(indent);
            output.push_str("url = ");
            output.push_str(endpoint);
            output.push_str(ending);
            replaced = true;
        } else {
            output.push_str(line);
        }
    }
    if replaced {
        Ok(output)
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "{} Homebrew origin could not be rewritten",
            path.display()
        )))
    }
}

fn assignment<'a>(line: &'a str, shell: ShellKind, variable: &str) -> Option<&'a str> {
    let value = match shell {
        ShellKind::Bash | ShellKind::Zsh => line
            .strip_prefix("export ")
            .unwrap_or(line)
            .strip_prefix(variable)?
            .strip_prefix('=')?,
        ShellKind::Fish => line
            .strip_prefix("set -gx ")?
            .strip_prefix(variable)?
            .trim_start(),
    };
    Some(value.trim().trim_matches(['\'', '"']))
}

fn managed_range(text: &str, path: &Path) -> Result<Option<Range<usize>>, AdapterError> {
    let begins = text.match_indices(MANAGED_BEGIN).collect::<Vec<_>>();
    let ends = text.match_indices(MANAGED_END).collect::<Vec<_>>();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([(begin, _)], [(end, _)]) if begin < end => {
            let end = text[*end..]
                .find('\n')
                .map_or(text.len(), |offset| end + offset + 1);
            Ok(Some(*begin..end))
        }
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "{} has malformed or duplicate MirrorSwitch Homebrew markers",
            path.display()
        ))),
    }
}

fn rewrite_profile(
    text: &str,
    path: &Path,
    shell: ShellKind,
    git: &str,
    api: &str,
    artifacts: &str,
) -> Result<String, AdapterError> {
    let range = managed_range(text, path)?;
    let mut base = match range {
        Some(range) => format!("{}{}", &text[..range.start], &text[range.end..]),
        None => text.to_owned(),
    };
    while base.ends_with("\n\n") {
        base.pop();
    }
    if !base.is_empty() && !base.ends_with('\n') {
        base.push('\n');
    }
    if !base.is_empty() {
        base.push('\n');
    }
    base.push_str(MANAGED_BEGIN);
    base.push('\n');
    for (variable, value) in [
        ("HOMEBREW_BREW_GIT_REMOTE", git),
        ("HOMEBREW_API_DOMAIN", api),
        ("HOMEBREW_ARTIFACT_DOMAIN", artifacts),
    ] {
        match shell {
            ShellKind::Bash | ShellKind::Zsh => {
                base.push_str(&format!("export {variable}=\"{value}\"\n"));
            }
            ShellKind::Fish => {
                base.push_str(&format!("set -gx {variable} \"{value}\"\n"));
            }
        }
    }
    base.push_str(MANAGED_END);
    base.push('\n');
    Ok(base)
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = source
            .metadata
            .get("kind")
            .and_then(|values| values.first())
            .map(String::as_str)
            .unwrap_or("unknown");
        if kind == "managed-profile" {
            continue;
        }
        let variable = source
            .metadata
            .get("variable")
            .and_then(|values| values.first())
            .map(String::as_str)
            .unwrap_or("unknown");
        let expected = match variable {
            "HOMEBREW_BREW_GIT_REMOTE" => Some(GIT_ENDPOINT),
            "HOMEBREW_API_DOMAIN" => Some(API_ENDPOINT),
            "HOMEBREW_ARTIFACT_DOMAIN" => Some(BOTTLES_ENDPOINT),
            _ => None,
        };
        if kind == "brew-git-origin"
            && [OFFICIAL_GIT_ENDPOINT, GIT_ENDPOINT]
                .iter()
                .any(|endpoint| normalize_url(&source.url) == normalize_url(endpoint))
        {
            continue;
        }
        if kind == "environment-override"
            && expected
                .is_some_and(|expected| normalize_url(&source.url).as_deref() == Some(expected))
        {
            continue;
        }
        return Err(AdapterError::Unsupported(format!(
            "Homebrew {variable} is already controlled by {kind}; preserve it instead of overriding"
        )));
    }
    Ok(())
}

fn require_managed_values(values: &BTreeMap<String, String>) -> Result<(), AdapterError> {
    let expected = [
        ("HOMEBREW_BREW_GIT_REMOTE", GIT_ENDPOINT),
        ("HOMEBREW_API_DOMAIN", API_ENDPOINT),
        ("HOMEBREW_ARTIFACT_DOMAIN", BOTTLES_ENDPOINT),
    ];
    if values.len() == expected.len()
        && expected
            .iter()
            .all(|(key, expected)| values.get(*key).is_some_and(|value| value == expected))
        && !values.contains_key("HOMEBREW_BOTTLE_DOMAIN")
    {
        Ok(())
    } else {
        Err(AdapterError::Verification(
            "Homebrew managed block is incomplete or not in current API/OCI mode".into(),
        ))
    }
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "homebrew" && current.scope == ConfigurationScope::User {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "Homebrew adapter received another tool or scope".into(),
        ))
    }
}

fn selected_endpoint(
    selections: &[MirrorSelection],
    upstream: &str,
    role: EndpointRole,
) -> Result<String, AdapterError> {
    let selection = selections
        .iter()
        .find(|selection| selection.upstream_id == upstream)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("missing {upstream} selection"))
        })?;
    selection
        .endpoints
        .iter()
        .find(|endpoint| endpoint.role == role)
        .or_else(|| {
            selection
                .endpoints
                .iter()
                .find(|endpoint| endpoint.role == EndpointRole::Artifacts)
        })
        .map(|endpoint| endpoint.url.clone())
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("{upstream} endpoint is missing"))
        })
}

fn reviewed_url(value: &str, expected: &str) -> Result<String, AdapterError> {
    let normalized = normalize_url(value).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Homebrew endpoint is not safe HTTPS".into())
    })?;
    if normalized == expected.to_ascii_lowercase() {
        Ok(expected.into())
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "Homebrew endpoint {value} is not the reviewed USTC surface"
        )))
    }
}

fn normalize_url(value: &str) -> Option<String> {
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

fn bottle_fixture(architecture: Architecture) -> (&'static str, &'static str) {
    match architecture {
        Architecture::X86_64 => (
            "sonoma",
            "af9ddba2379910ceed96961891002b1c8c133f6f3f290ccb3d7c7d877dd4e9e9",
        ),
        Architecture::Arm64 => (
            "arm64_sequoia",
            "ef70e236f58a8a781436ee400f9bdf847ad7d12e75115871fb6a94b9214a1a41",
        ),
    }
}

fn run(runtime: &dyn Runtime, program: &str, arguments: &[&str]) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|value| (*value).into())
        .collect::<Vec<_>>();
    let output = runtime.run(program, &arguments)?;
    if !output.status.success() {
        return Err(AdapterError::Verification(format!(
            "{program} failed with status {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_in(
    runtime: &dyn Runtime,
    directory: &Path,
    program: &str,
    arguments: &[&str],
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|value| (*value).into())
        .collect::<Vec<_>>();
    let output = runtime.run_in(directory, program, &arguments)?;
    if !output.status.success() {
        return Err(AdapterError::Verification(format!(
            "{program} failed with status {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_brew_with_environment(
    runtime: &dyn Runtime,
    environment: &[String],
    arguments: &[&str],
) -> Result<String, AdapterError> {
    let mut command = environment.to_vec();
    command.push("brew".into());
    command.extend(arguments.iter().map(|value| (*value).into()));
    run(
        runtime,
        "env",
        &command.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

fn homebrew_version(output: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Homebrew "))
        .and_then(|value| value.split_whitespace().next())
        .filter(|value| value.split('.').count() >= 2)
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("could not parse Homebrew version".into()))
}

fn one_line(output: &str, command: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("{command} returned no value")))
}

fn environment_evidence(runtime: &dyn Runtime, name: &str) -> String {
    format!(
        "{name} is {}",
        if runtime
            .environment_variable(name)
            .is_some_and(|value| !value.trim().is_empty())
        {
            "set"
        } else {
            "unset"
        }
    )
}

fn configured_source(
    variable: Option<&str>,
    value: &str,
    kind: &str,
    path: &Path,
) -> ConfiguredSource {
    let upstream = match variable {
        Some("HOMEBREW_BREW_GIT_REMOTE") => Some(GIT_UPSTREAM.into()),
        Some("HOMEBREW_API_DOMAIN" | "HOMEBREW_ARTIFACT_DOMAIN" | "HOMEBREW_BOTTLE_DOMAIN") => {
            Some(BOTTLES_UPSTREAM.into())
        }
        _ => None,
    };
    let mut metadata = BTreeMap::from([
        ("kind".into(), vec![kind.into()]),
        ("config_path".into(), vec![path.display().to_string()]),
    ]);
    if let Some(variable) = variable {
        metadata.insert("variable".into(), vec![variable.into()]);
    }
    ConfiguredSource {
        upstream_id: upstream,
        url: value.into(),
        enabled: true,
        metadata,
    }
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish]
        .into_iter()
        .find(|shell| format == format!("homebrew-{}-profile", shell.name()))
        .ok_or_else(|| AdapterError::InvalidConfiguration("unknown Homebrew profile format".into()))
}

fn line_spans(text: &str) -> Vec<(usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n')
        .map(|line| {
            let start = offset;
            offset += line.len();
            (start, line.trim_end_matches(['\r', '\n']))
        })
        .collect()
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents)
        .map_err(|_| AdapterError::InvalidConfiguration(format!("{} is not UTF-8", path.display())))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
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
