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

const PUB_UPSTREAM: &str = "dart-pub--language-registry";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub";
const SJTUG: &str = "https://mirror.sjtu.edu.cn/dart-pub";
const REVIEWED_HOSTS: &[&str] = &[TUNA, SJTUG];
const OFFICIAL_HOSTS: &[&str] = &["https://pub.dev", "https://pub.dartlang.org"];
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch Dart Pub mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch Dart Pub mirror <<<";
const VERIFY_MARKER: &str = "# Managed by MirrorSwitch: Dart Pub verification project v1";

#[derive(Clone, Copy, Debug, Default)]
pub struct DartPubAdapter;

impl Adapter for DartPubAdapter {
    fn key(&self) -> &'static str {
        "dart-pub"
    }

    fn tool_id(&self) -> &'static str {
        "dart-pub"
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
        if !runtime.command_exists("dart") {
            return Ok(None);
        }
        if !runtime.command_exists("env") {
            return Err(AdapterError::Unsupported(
                "Dart Pub verification requires the standard env command".into(),
            ));
        }
        let version_output = run_dart(runtime, None, &["--version"], "dart --version")?;
        let version = dart_version(&version_output)?;
        reviewed_version(&version)?;
        let pub_help = run_dart(runtime, None, &["pub", "--help"], "dart pub --help")?;
        require_pub_protocol(&pub_help)?;
        let layout = config_layout(context, runtime)?;
        let project = inspect_project(runtime)?;
        let token_files = token_file_count(runtime, &layout.token_dir)?;
        Ok(Some(DetectedTool {
            tool_id: "dart-pub".into(),
            executable: Some(PathBuf::from("dart")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Dart SDK {version}"),
                architecture_evidence(&version_output),
                "dart pub exposes get and deps commands".into(),
                format!("selected shell is {}", layout.shell.name()),
                format!("selected profile is {}", layout.profile.display()),
                format!(
                    "PUB_HOSTED_URL is {}",
                    environment_state(runtime, "PUB_HOSTED_URL")
                ),
                format!("PUB_CACHE is {}", environment_state(runtime, "PUB_CACHE")),
                format!(
                    "FLUTTER_STORAGE_BASE_URL is {} (not managed)",
                    environment_state(runtime, "FLUTTER_STORAGE_BASE_URL")
                ),
                format!("project hosted declaration(s): {}", project.hosted),
                format!("project publish target(s): {}", project.publish_targets),
                format!("project lock hosted source(s): {}", project.lock_hosted),
                format!("Pub token store file(s): {token_files} (contents not read)"),
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
        if detected.tool_id != "dart-pub" {
            return Err(AdapterError::InvalidConfiguration(
                "Dart Pub read received another tool's detection result".into(),
            ));
        }
        let output = run_dart(runtime, None, &["--version"], "dart --version")?;
        let version = dart_version(&output)?;
        reviewed_version(&version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Dart SDK version changed after detection".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        let profile_contents = runtime.read(&layout.profile)?;
        let profile_exists = profile_contents.is_some();
        let profile_contents = profile_contents.unwrap_or_default();
        let profile_text = utf8(&layout.profile, &profile_contents)?;
        let parsed = parse_profile(profile_text, &layout.profile, layout.shell)?;
        let mut sources = profile_sources(&parsed, &layout.profile, layout.shell);
        sources.push(snapshot_source("dart-version", &version));
        if let Some(cache) = runtime
            .environment_variable("PUB_CACHE")
            .filter(|value| !value.trim().is_empty())
        {
            sources.push(snapshot_source(
                "pub-cache-configured",
                &safe_path_snapshot(&cache),
            ));
        }
        if let Some(value) = runtime
            .environment_variable("PUB_HOSTED_URL")
            .filter(|value| !value.trim().is_empty())
        {
            let represented = parsed
                .managed
                .as_deref()
                .into_iter()
                .chain(parsed.unmanaged.iter().map(|item| item.value.as_str()))
                .any(|profile_value| same_base(profile_value, &value));
            if !represented {
                sources.push(policy_source(
                    "environment-override",
                    Path::new(":env:"),
                    layout.shell,
                ));
            }
        }
        if token_file_count(runtime, &layout.token_dir)? > 0 {
            sources.push(policy_source(
                "credentials-detected",
                &layout.token_dir,
                layout.shell,
            ));
        }

        let mut files = profile_exists
            .then_some(layout.profile.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let mut documents = vec![ConfigurationDocument {
            path: layout.profile.clone(),
            format: format!("dart-pub-selected-{}-profile", layout.shell.name()),
            contents: profile_contents,
        }];
        for (path, format) in project_paths(runtime)? {
            let Some(contents) = runtime.read(&path)? else {
                continue;
            };
            files.push(path.clone());
            let text = utf8(&path, &contents)?;
            sources.extend(project_sources(text, &path, format));
            documents.push(ConfigurationDocument {
                path,
                format: format.into(),
                contents,
            });
        }
        let fixture = runtime.read(&layout.verification_pubspec)?;
        let fixture_exists = fixture.is_some();
        let fixture = fixture.unwrap_or_default();
        if fixture_exists {
            files.push(layout.verification_pubspec.clone());
            if utf8(&layout.verification_pubspec, &fixture)? != render_verification_pubspec() {
                sources.push(policy_source(
                    "verification-conflict",
                    &layout.verification_pubspec,
                    layout.shell,
                ));
            }
        }
        documents.push(ConfigurationDocument {
            path: layout.verification_pubspec,
            format: "dart-pub-verification-pubspec".into(),
            contents: fixture,
        });
        Ok(CurrentConfiguration {
            tool_id: "dart-pub".into(),
            scope,
            files,
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
        require_linux(context)?;
        require_current(current)?;
        reviewed_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Dart SDK version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "dart-pub".into(),
            adapter_key: "dart-pub".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![PUB_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![
                EndpointRole::Index,
                EndpointRole::Metadata,
                EndpointRole::Artifacts,
            ],
            allowed_delivery_modes: vec![DeliveryMode::Proxy],
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
        let endpoint = selected_hosted_endpoint(selections)?;
        let profile = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("dart-pub-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "selected Dart Pub shell profile is missing".into(),
                )
            })?;
        let shell = shell_from_format(&profile.format)?;
        let profile_text = utf8(&profile.path, &profile.contents)?;
        let rendered = rewrite_profile(profile_text, &profile.path, shell, &endpoint)?.into_bytes();
        let fixture = find_document(current, "dart-pub-verification-pubspec")?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            profile,
            rendered,
            "add or retarget one managed PUB_HOSTED_URL assignment while preserving unrelated shell policy",
            &mut changes,
        );
        add_change(
            context,
            current,
            fixture,
            render_verification_pubspec().into_bytes(),
            "create an isolated Dart Pub dependency fixture",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "dart-pub".into(),
            tool_id: "dart-pub".into(),
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
            let known = [
                rooted(&context.root, &layout.profile),
                rooted(&context.root, &layout.verification_pubspec),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Dart Pub transaction receipt contains no known target".into(),
                ));
            }
            let profile = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("Dart Pub shell profile disappeared".into())
            })?;
            let parsed = parse_profile(
                utf8(&layout.profile, &profile)?,
                &layout.profile,
                layout.shell,
            )?;
            if parsed.dynamic || !parsed.unmanaged.is_empty() {
                return Err(AdapterError::Verification(
                    "Dart Pub shell profile gained conflicting PUB_HOSTED_URL policy".into(),
                ));
            }
            let endpoint = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed PUB_HOSTED_URL is missing".into())
            })?;
            if !is_reviewed(&endpoint) {
                return Err(AdapterError::Verification(
                    "managed PUB_HOSTED_URL is not reviewed".into(),
                ));
            }
            let pubspec = runtime.read(&layout.verification_pubspec)?.ok_or_else(|| {
                AdapterError::Verification("Dart Pub verification pubspec disappeared".into())
            })?;
            if utf8(&layout.verification_pubspec, &pubspec)? != render_verification_pubspec() {
                return Err(AdapterError::Verification(
                    "Dart Pub verification pubspec is not canonical".into(),
                ));
            }
            run_verification(runtime, &layout, &endpoint, &["pub", "get"])?;
            let deps = run_verification(
                runtime,
                &layout,
                &endpoint,
                &["pub", "deps", "--style=compact"],
            )?;
            if !deps.contains("retry 3.1.2") {
                return Err(AdapterError::Verification(
                    "Dart Pub dependency query did not resolve retry 3.1.2".into(),
                ));
            }
            let lock = runtime.read(&layout.verification_lock)?.ok_or_else(|| {
                AdapterError::Verification("Dart Pub verification lockfile was not created".into())
            })?;
            let lock = utf8(&layout.verification_lock, &lock)?;
            if !lock.contains("retry:")
                || !lock.contains("version: \"3.1.2\"")
                || !lock.contains(endpoint.trim_end_matches('/'))
            {
                return Err(AdapterError::Verification(
                    "Dart Pub lockfile does not bind retry 3.1.2 to the selected hosted URL".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Dart Pub resolved retry 3.1.2 through {endpoint} with an isolated cache"
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
                "restored {} Dart Pub configuration files from {}",
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

#[derive(Debug)]
struct Layout {
    shell: ShellKind,
    profile: PathBuf,
    token_dir: PathBuf,
    verification_root: PathBuf,
    verification_pubspec: PathBuf,
    verification_lock: PathBuf,
    verification_cache: PathBuf,
}

#[derive(Clone, Debug)]
struct Assignment {
    range: Range<usize>,
    value: String,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<String>,
    unmanaged: Vec<Assignment>,
    dynamic: bool,
}

#[derive(Default)]
struct ProjectObservation {
    hosted: usize,
    publish_targets: usize,
    lock_hosted: usize,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Dart Pub v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Dart Pub adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "dart-pub" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Dart Pub operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Dart Pub requires a user home".into()))?;
    validate_path(&home, "home")?;
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().and_then(parse_shell))
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "Dart Pub requires SHELL to select bash, zsh, or fish initialization".into(),
            )
        })?;
    let profile = selected_profile(context, runtime, &home, shell)?;
    let token_dir = match runtime
        .environment_variable("XDG_CONFIG_HOME")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => {
            let path = PathBuf::from(value);
            validate_path(&path, "XDG_CONFIG_HOME")?;
            path.join("dart")
        }
        None => home.join(".config/dart"),
    };
    let verification_root = home.join(".mirrorswitch/verification/dart-pub");
    Ok(Layout {
        shell,
        profile,
        token_dir,
        verification_pubspec: verification_root.join("pubspec.yaml"),
        verification_lock: verification_root.join("pubspec.lock"),
        verification_cache: verification_root.join("cache"),
        verification_root,
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
) -> Result<PathBuf, AdapterError> {
    if let Some(value) = runtime
        .environment_variable("PROFILE")
        .filter(|value| !value.trim().is_empty())
    {
        if value == "/dev/null" {
            return Err(AdapterError::Unsupported(
                "PROFILE=/dev/null disables persistent Dart Pub configuration".into(),
            ));
        }
        let path = PathBuf::from(value);
        validate_user_path(&path, home, "shell profile")?;
        return Ok(path);
    }
    if context.environment == ExecutionEnvironment::Container
        && shell == ShellKind::Bash
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.trim().is_empty())
    {
        let path = PathBuf::from(value);
        validate_user_path(&path, home, "BASH_ENV")?;
        return Ok(path);
    }
    let path = match shell {
        ShellKind::Bash => home.join(".bashrc"),
        ShellKind::Zsh => match runtime
            .environment_variable("ZDOTDIR")
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) => {
                let path = PathBuf::from(value).join(".zshrc");
                validate_user_path(&path, home, "ZDOTDIR profile")?;
                path
            }
            None => home.join(".zshrc"),
        },
        ShellKind::Fish => home.join(".config/fish/conf.d/mirrorswitch-dart-pub.fish"),
    };
    validate_user_path(&path, home, "shell profile")?;
    Ok(path)
}

fn project_paths(runtime: &dyn Runtime) -> Result<Vec<(PathBuf, &'static str)>, AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(Vec::new());
    };
    validate_path(&project, "project")?;
    Ok(vec![
        (project.join("pubspec.yaml"), "dart-pub-project-pubspec"),
        (project.join("pubspec.lock"), "dart-pub-project-lock"),
    ])
}

fn inspect_project(runtime: &dyn Runtime) -> Result<ProjectObservation, AdapterError> {
    let mut observation = ProjectObservation::default();
    for (path, format) in project_paths(runtime)? {
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        let text = utf8(&path, &contents)?;
        if format == "dart-pub-project-pubspec" {
            observation.hosted += text.matches("hosted:").count();
            observation.publish_targets += text
                .lines()
                .filter(|line| active_yaml_line(line).starts_with("publish_to:"))
                .count();
        } else {
            observation.lock_hosted += text
                .lines()
                .filter(|line| active_yaml_line(line) == "source: hosted")
                .count();
        }
    }
    Ok(observation)
}

fn token_file_count(runtime: &dyn Runtime, directory: &Path) -> Result<usize, AdapterError> {
    Ok(runtime
        .list_files(directory)?
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "pub-tokens.json" || name == "pub-credentials.json")
        })
        .count())
}

fn project_sources(text: &str, path: &Path, format: &str) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if format == "dart-pub-project-pubspec" {
        for line in text.lines().map(active_yaml_line) {
            if line.starts_with("hosted:") {
                sources.push(project_source("project-hosted-preserved", path));
            } else if line.starts_with("publish_to:") {
                sources.push(project_source("publish-target-preserved", path));
            } else if line.starts_with("git:")
                || line.starts_with("path:")
                || line.starts_with("sdk:")
            {
                sources.push(project_source("non-hosted-source-preserved", path));
            }
        }
    } else {
        for line in text.lines().map(active_yaml_line) {
            if line == "source: hosted" {
                sources.push(project_source("project-lock-preserved", path));
            }
        }
    }
    sources
}

fn active_yaml_line(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim()
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let managed_range = managed_range(text, path)?;
    let managed = managed_range
        .as_ref()
        .map(|range| managed_value(&text[range.clone()], path, shell))
        .transpose()?;
    let mut unmanaged = Vec::new();
    let mut dynamic = false;
    for (start, line) in line_spans(text) {
        if managed_range
            .as_ref()
            .is_some_and(|range| range.contains(&start))
        {
            continue;
        }
        let active = line.trim();
        if active.is_empty() || active.starts_with('#') || !active.contains("PUB_HOSTED_URL") {
            continue;
        }
        match assignment(active, shell)? {
            Some(value) => unmanaged.push(Assignment {
                range: start..start + line.len(),
                value: value.into(),
            }),
            None => dynamic = true,
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged,
        dynamic,
    })
}

fn managed_value(block: &str, path: &Path, shell: ShellKind) -> Result<String, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| assignment(line.trim(), shell).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed Dart Pub block in {} must assign PUB_HOSTED_URL exactly once",
            path.display()
        )));
    }
    let value = values[0];
    if !is_reviewed(value) {
        return Err(AdapterError::Unsupported(
            "managed PUB_HOSTED_URL is bound to an unreviewed endpoint".into(),
        ));
    }
    Ok(value.into())
}

fn assignment(line: &str, shell: ShellKind) -> Result<Option<&str>, AdapterError> {
    let raw = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            if key.trim() != "PUB_HOSTED_URL" {
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
            if !flags.contains('x') || key != "PUB_HOSTED_URL" {
                return Ok(None);
            }
            if fields.next().is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "fish PUB_HOSTED_URL assignment is not a literal value".into(),
                ));
            }
            value
        }
    };
    literal_value(raw).map(Some)
}

fn literal_value(raw: &str) -> Result<&str, AdapterError> {
    let single = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    let value = if single || double {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.is_empty()
        || value.contains([';', '`', '$', '\n', '\r'])
        || (single && value.contains('\''))
        || (double && value.contains('"'))
        || (!single
            && !double
            && raw
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '\'' | '"')))
    {
        return Err(AdapterError::InvalidConfiguration(
            "PUB_HOSTED_URL assignment is not a literal value".into(),
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
            "Dart Pub managed markers in {} are missing, duplicated, or out of order",
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

fn profile_sources(parsed: &ParsedProfile, path: &Path, shell: ShellKind) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(value) = &parsed.managed {
        sources.push(configured_source(
            value,
            "managed-shell-profile",
            path,
            shell,
        ));
    }
    for assignment in &parsed.unmanaged {
        let kind = if is_public(&assignment.value) {
            "adoptable-shell-profile"
        } else {
            "private-shell-profile"
        };
        sources.push(if kind == "adoptable-shell-profile" {
            configured_source(&assignment.value, kind, path, shell)
        } else {
            policy_source(kind, path, shell)
        });
    }
    if parsed.unmanaged.len() + usize::from(parsed.managed.is_some()) > 1 {
        sources.push(policy_source("duplicate-shell-profile", path, shell));
    }
    if parsed.dynamic {
        sources.push(policy_source("dynamic-shell-profile", path, shell));
    }
    sources
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        match kind {
            "private-shell-profile" => {
                return Err(AdapterError::Unsupported(
                    "existing PUB_HOSTED_URL points to a private, authenticated, or unreviewed repository"
                        .into(),
                ));
            }
            "duplicate-shell-profile" => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected shell profile assigns PUB_HOSTED_URL more than once".into(),
                ));
            }
            "dynamic-shell-profile" => {
                return Err(AdapterError::Unsupported(
                    "selected shell profile computes PUB_HOSTED_URL dynamically".into(),
                ));
            }
            "environment-override" => {
                return Err(AdapterError::Unsupported(
                    "current PUB_HOSTED_URL is not represented by the selected persistent profile"
                        .into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Dart Pub verification target contains data not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_profile(
    text: &str,
    path: &Path,
    shell: ShellKind,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let parsed = parse_profile(text, path, shell)?;
    if parsed.dynamic || parsed.unmanaged.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Dart Pub profile cannot be rewritten safely".into(),
        ));
    }
    if parsed
        .unmanaged
        .iter()
        .any(|assignment| !is_public(&assignment.value))
    {
        return Err(AdapterError::Unsupported(
            "private or unreviewed PUB_HOSTED_URL cannot be replaced".into(),
        ));
    }
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
    if let Some(assignment) = parsed.unmanaged.first() {
        return Ok(format!(
            "{}{}{}",
            &text[..assignment.range.start],
            block,
            &text[assignment.range.end..]
        ));
    }
    let mut output = text.to_owned();
    if !output.is_empty() {
        if !output.ends_with('\n') {
            output.push_str(newline);
        }
        if !output.ends_with(&format!("{newline}{newline}")) {
            output.push_str(newline);
        }
    }
    output.push_str(&block);
    Ok(output)
}

fn render_managed(endpoint: &str, newline: &str, shell: ShellKind) -> String {
    let assignment = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            format!("export PUB_HOSTED_URL='{endpoint}'")
        }
        ShellKind::Fish => format!("set -gx PUB_HOSTED_URL '{endpoint}'"),
    };
    format!("{MANAGED_BEGIN}{newline}{assignment}{newline}{MANAGED_END}{newline}")
}

fn render_verification_pubspec() -> String {
    format!(
        "{VERIFY_MARKER}\nname: mirrorswitch_dart_pub_verification\npublish_to: none\nenvironment:\n  sdk: '>=2.12.0 <4.0.0'\ndependencies:\n  retry: 3.1.2\n"
    )
}

fn selected_hosted_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "dart-pub" && selection.upstream_id == PUB_UPSTREAM
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Dart Pub requires exactly one registry selection".into(),
        ));
    }
    let selection = matches[0];
    let role_url = |role| -> Result<String, AdapterError> {
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if endpoints.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Dart Pub selection requires one HTTPS {role:?} endpoint"
            )));
        }
        normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Dart Pub {role:?} endpoint is unsafe"))
        })
    };
    let index = role_url(EndpointRole::Index)?;
    let metadata = role_url(EndpointRole::Metadata)?;
    let artifacts = role_url(EndpointRole::Artifacts)?;
    if index != metadata {
        return Err(AdapterError::InvalidConfiguration(
            "Dart Pub index and metadata endpoints must share the reviewed hosted URL".into(),
        ));
    }
    let (provider, expected_artifacts) = match index.as_str() {
        TUNA => (
            "tuna",
            "https://mirrors.tuna.tsinghua.edu.cn/dart-pub/packages",
        ),
        SJTUG => (
            "sjtug",
            "https://storage.flutter-io.cn/dartlang-pub-exported-api/latest/api/archives",
        ),
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Dart Pub hosted endpoint is not reviewed".into(),
            ));
        }
    };
    if selection.provider_id != provider || artifacts != expected_artifacts {
        return Err(AdapterError::InvalidConfiguration(
            "Dart Pub provider, hosted endpoint, and archive endpoint do not match".into(),
        ));
    }
    Ok(index)
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

fn same_base(left: &str, right: &str) -> bool {
    normalized_base(left).is_some_and(|left| normalized_base(right).as_deref() == Some(&left))
}

fn is_reviewed(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| REVIEWED_HOSTS.contains(&value.as_str()))
}

fn is_public(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| {
        REVIEWED_HOSTS.contains(&value.as_str()) || OFFICIAL_HOSTS.contains(&value.as_str())
    })
}

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<&'a ConfigurationDocument, AdapterError> {
    let matches = current
        .documents
        .iter()
        .filter(|document| document.format == format)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Dart Pub current configuration must contain exactly one {format} document"
        )));
    }
    Ok(matches[0])
}

fn add_change(
    context: &SystemContext,
    current: &CurrentConfiguration,
    document: &ConfigurationDocument,
    new_contents: Vec<u8>,
    summary: &str,
    changes: &mut Vec<PlannedFileChange>,
) {
    if document.contents == new_contents {
        return;
    }
    changes.push(PlannedFileChange {
        target: rooted(&context.root, &document.path),
        old_contents: current
            .files
            .contains(&document.path)
            .then(|| document.contents.clone()),
        old_mode: None,
        new_contents,
        new_mode: None,
        summary: summary.into(),
    });
}

fn run_verification(
    runtime: &dyn Runtime,
    layout: &Layout,
    endpoint: &str,
    arguments: &[&str],
) -> Result<String, AdapterError> {
    let cache = layout.verification_cache.to_str().ok_or_else(|| {
        AdapterError::Verification("Dart Pub verification cache path is not UTF-8".into())
    })?;
    let mut command = vec![
        format!("PUB_HOSTED_URL={endpoint}"),
        format!("PUB_CACHE={cache}"),
        "DART_SUPPRESS_ANALYTICS=1".into(),
        "dart".into(),
    ];
    command.extend(arguments.iter().map(|argument| (*argument).into()));
    let output = runtime.run_in(&layout.verification_root, "env", &command)?;
    command_output(output, "Dart Pub dependency verification")
}

fn run_dart(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = match directory {
        Some(directory) => runtime.run_in(directory, "dart", &arguments)?,
        None => runtime.run("dart", &arguments)?,
    };
    command_output(output, label)
}

fn command_output(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{label} failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stdout")))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stderr")))?;
    Ok(format!("{stdout}\n{stderr}").trim().into())
}

fn dart_version(output: &str) -> Result<String, AdapterError> {
    output
        .split_whitespace()
        .skip_while(|token| *token != "version:")
        .nth(1)
        .filter(|value| valid_version(value))
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("Dart SDK version output is unrecognized".into()))
}

fn valid_version(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
        && value.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    let mut parts = version.split(['.', '-']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    if !matches!((major, minor), (Some(2), Some(12..)) | (Some(3), Some(_))) {
        return Err(AdapterError::Unsupported(format!(
            "Dart SDK {version} is outside the reviewed 2.12 through 3.x Pub model"
        )));
    }
    Ok(())
}

fn require_pub_protocol(help: &str) -> Result<(), AdapterError> {
    let missing = ["get", "deps"]
        .into_iter()
        .filter(|command| {
            !help
                .lines()
                .any(|line| line.trim_start().starts_with(command))
        })
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "dart pub lacks required commands: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn architecture_evidence(output: &str) -> String {
    output
        .split_once(" on ")
        .map(|(_, architecture)| format!("Dart runtime architecture is {}", architecture.trim()))
        .unwrap_or_else(|| "Dart runtime architecture was not reported".into())
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish]
        .into_iter()
        .find(|shell| format == format!("dart-pub-selected-{}-profile", shell.name()))
        .ok_or_else(|| AdapterError::InvalidConfiguration("unknown Dart Pub profile format".into()))
}

fn configured_source(value: &str, kind: &str, path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(PUB_UPSTREAM.into()),
        url: normalized_base(value).unwrap_or_else(|| "<preserved>".into()),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("shell".into(), vec![shell.name().into()]),
        ]),
    }
}

fn project_source(kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
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

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("dart-pub-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Dart Pub source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Dart Pub source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn environment_state(runtime: &dyn Runtime, variable: &str) -> &'static str {
    if runtime
        .environment_variable(variable)
        .is_some_and(|value| !value.trim().is_empty())
    {
        "set"
    } else {
        "unset"
    }
}

fn safe_path_snapshot(value: &str) -> String {
    let path = Path::new(value);
    if path.is_absolute()
        && !path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        path.display().to_string()
    } else {
        "configured".into()
    }
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "Dart Pub {kind} {} is outside the user home",
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
            "Dart Pub reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Dart Pub configuration {} is not UTF-8",
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
