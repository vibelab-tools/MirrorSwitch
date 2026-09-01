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

const UPSTREAM: &str = "python-releases--release-artifacts";
const PYTHON_VERSION: &str = "3.14.7";
const ARCHIVE: &str = "Python-3.14.7.tar.xz";
const ARCHIVE_SHA256: &str = "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81";
const DEFINITION_URL: &str = "https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tar.xz";
const RELEASE_IDENTITY: &str =
    "3.14.7/3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81";
const HUAWEI: &str = "https://repo.huaweicloud.com/python";
const NJU: &str = "https://mirrors.nju.edu.cn/python";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/python";
const OFFICIAL_MIRRORS: &[&str] = &[
    "https://pyenv.github.io/pythons",
    "https://www.python.org/ftp/python",
];
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch python-build mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch python-build mirror <<<";
const MIRROR_ENV: &str = "PYTHON_BUILD_MIRROR_URL";
const SKIP_CHECKSUM_ENV: &str = "PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM";
const POLICY_ENVIRONMENTS: &[&str] = &[
    "PYTHON_BUILD_SKIP_MIRROR",
    "PYTHON_BUILD_ROOT",
    "PYTHON_BUILD_DEFINITIONS",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct PyenvAdapter;

impl Adapter for PyenvAdapter {
    fn key(&self) -> &'static str {
        "pyenv"
    }

    fn tool_id(&self) -> &'static str {
        "pyenv"
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
        if !runtime.command_exists("pyenv") {
            return Ok(None);
        }
        for command in ["env", "curl", "sha256sum"] {
            if !runtime.command_exists(command) {
                return Err(AdapterError::Unsupported(format!(
                    "pyenv mirror verification requires {command}"
                )));
            }
        }
        reject_custom_definition_environment(runtime)?;
        let snapshot = inspect_pyenv(runtime, None)?;
        let layout = config_layout(context, runtime)?;
        let profile = runtime.read(&layout.profile)?.unwrap_or_default();
        let init_count = utf8(&layout.profile, &profile)?
            .lines()
            .filter(|line| {
                let line = line.split('#').next().unwrap_or_default();
                line.contains("pyenv init")
            })
            .count();
        Ok(Some(DetectedTool {
            tool_id: "pyenv".into(),
            executable: Some(PathBuf::from("pyenv")),
            version: Some(snapshot.pyenv_version.clone()),
            evidence: vec![
                format!("pyenv {}", snapshot.pyenv_version),
                format!("python-build {}", snapshot.python_build_version),
                format!("pyenv root is {}", snapshot.root.display()),
                format!("python-build definition includes CPython {PYTHON_VERSION}"),
                format!("definition archive checksum is {ARCHIVE_SHA256}"),
                format!("selected shell is {}", layout.shell.name()),
                format!("selected profile is {}", layout.profile.display()),
                format!("existing active pyenv init line(s): {init_count} (preserved)"),
                format!(
                    "PYTHON_BUILD_MIRROR_URL is {}",
                    environment_state(runtime, MIRROR_ENV)
                ),
                format!(
                    "PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM is {}",
                    environment_state(runtime, SKIP_CHECKSUM_ENV)
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
        if detected.tool_id != "pyenv" {
            return Err(AdapterError::InvalidConfiguration(
                "pyenv read received another tool's detection result".into(),
            ));
        }
        let snapshot = inspect_pyenv(runtime, None)?;
        if detected.version.as_deref() != Some(snapshot.pyenv_version.as_str()) {
            return Err(AdapterError::Conflict(
                "pyenv version changed after detection".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        let profile = runtime.read(&layout.profile)?;
        let profile_exists = profile.is_some();
        let profile = profile.unwrap_or_default();
        let parsed = parse_profile(
            utf8(&layout.profile, &profile)?,
            &layout.profile,
            layout.shell,
        )?;
        let mut sources = profile_sources(&parsed, &layout.profile, layout.shell);
        sources.push(snapshot_source("pyenv-version", &snapshot.pyenv_version));
        sources.push(snapshot_source(
            "python-build-version",
            &snapshot.python_build_version,
        ));
        sources.push(snapshot_source("release-identity", RELEASE_IDENTITY));
        if POLICY_ENVIRONMENTS.iter().any(|name| {
            runtime
                .environment_variable(name)
                .is_some_and(|value| !value.trim().is_empty())
        }) {
            sources.push(policy_source(
                "custom-definition-or-skip-environment",
                Path::new(":env:"),
                layout.shell,
            ));
        }
        for (name, key) in [
            (MIRROR_ENV, ManagedKey::Mirror),
            (SKIP_CHECKSUM_ENV, ManagedKey::SkipChecksum),
        ] {
            if let Some(value) = runtime
                .environment_variable(name)
                .filter(|value| !value.trim().is_empty())
                && !parsed
                    .value_for(key)
                    .into_iter()
                    .chain(
                        parsed
                            .unmanaged
                            .iter()
                            .filter(|assignment| assignment.key == key)
                            .map(|assignment| assignment.value.as_str()),
                    )
                    .any(|profile| profile.trim_end_matches('/') == value.trim_end_matches('/'))
            {
                sources.push(policy_source(
                    "process-environment-override",
                    Path::new(":env:"),
                    layout.shell,
                ));
            }
        }

        let mut files = profile_exists
            .then_some(layout.profile.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let mut documents = vec![ConfigurationDocument {
            path: layout.profile,
            format: format!("pyenv-selected-{}-profile", layout.shell.name()),
            contents: profile,
        }];
        let manifest = runtime.read(&layout.verification_manifest)?;
        let manifest_exists = manifest.is_some();
        let manifest = manifest.unwrap_or_default();
        if manifest_exists {
            files.push(layout.verification_manifest.clone());
            if utf8(&layout.verification_manifest, &manifest)? != render_manifest() {
                sources.push(policy_source(
                    "verification-conflict",
                    &layout.verification_manifest,
                    layout.shell,
                ));
            }
        }
        documents.push(ConfigurationDocument {
            path: layout.verification_manifest,
            format: "pyenv-verification-manifest".into(),
            contents: manifest,
        });
        Ok(CurrentConfiguration {
            tool_id: "pyenv".into(),
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
        review_pyenv_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("pyenv version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "pyenv".into(),
            adapter_key: "pyenv".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::from([(UPSTREAM.into(), RELEASE_IDENTITY.into())]),
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
        let endpoint = selected_endpoint(selections)?;
        let profile = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("pyenv-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected pyenv profile is missing".into())
            })?;
        let shell = shell_from_format(&profile.format)?;
        let manifest = find_document(current, "pyenv-verification-manifest")?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            profile,
            rewrite_profile(
                utf8(&profile.path, &profile.contents)?,
                &profile.path,
                shell,
                &endpoint,
            )?
            .into_bytes(),
            "add or retarget python-build mirror variables while preserving pyenv initialization",
            &mut changes,
        );
        add_change(
            context,
            current,
            manifest,
            render_manifest().into_bytes(),
            "create a fixed python-build definition and archive verification manifest",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "pyenv".into(),
            tool_id: "pyenv".into(),
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
                rooted(&context.root, &layout.verification_manifest),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "pyenv transaction receipt contains no known target".into(),
                ));
            }
            let profile = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("pyenv shell profile disappeared".into())
            })?;
            let parsed = parse_profile(
                utf8(&layout.profile, &profile)?,
                &layout.profile,
                layout.shell,
            )?;
            if parsed.dynamic || !parsed.unmanaged.is_empty() || parsed.policy_conflict {
                return Err(AdapterError::Verification(
                    "pyenv profile gained conflicting python-build policy".into(),
                ));
            }
            let managed = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed python-build mirror block is missing".into())
            })?;
            if !is_reviewed(&managed.mirror) || managed.skip_checksum.is_empty() {
                return Err(AdapterError::Verification(
                    "managed python-build mirror URL mode is invalid".into(),
                ));
            }
            let manifest = runtime
                .read(&layout.verification_manifest)?
                .ok_or_else(|| {
                    AdapterError::Verification("pyenv verification manifest disappeared".into())
                })?;
            if utf8(&layout.verification_manifest, &manifest)? != render_manifest() {
                return Err(AdapterError::Verification(
                    "pyenv verification manifest is not canonical".into(),
                ));
            }
            inspect_pyenv(runtime, Some(&managed.mirror))?;
            verify_download(runtime, &layout, &managed.mirror)?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "python-build resolved CPython {PYTHON_VERSION} and verified {ARCHIVE_SHA256} through {}",
                    managed.mirror
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
                "restored {} pyenv configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug)]
struct Snapshot {
    pyenv_version: String,
    python_build_version: String,
    root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ManagedKey {
    Mirror,
    SkipChecksum,
}

impl ManagedKey {
    fn name(self) -> &'static str {
        match self {
            Self::Mirror => MIRROR_ENV,
            Self::SkipChecksum => SKIP_CHECKSUM_ENV,
        }
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
    verification_root: PathBuf,
    verification_manifest: PathBuf,
    verification_archive: PathBuf,
}

#[derive(Clone, Debug)]
struct Assignment {
    range: Range<usize>,
    key: ManagedKey,
    value: String,
}

#[derive(Clone, Debug)]
struct ManagedValues {
    mirror: String,
    skip_checksum: String,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<ManagedValues>,
    unmanaged: Vec<Assignment>,
    dynamic: bool,
    policy_conflict: bool,
}

impl ParsedProfile {
    fn value_for(&self, key: ManagedKey) -> Option<&str> {
        self.managed.as_ref().map(|managed| match key {
            ManagedKey::Mirror => managed.mirror.as_str(),
            ManagedKey::SkipChecksum => managed.skip_checksum.as_str(),
        })
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
            "pyenv v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "pyenv adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "pyenv" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "pyenv operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn reject_custom_definition_environment(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    if ["PYTHON_BUILD_ROOT", "PYTHON_BUILD_DEFINITIONS"]
        .iter()
        .any(|name| {
            runtime
                .environment_variable(name)
                .is_some_and(|value| !value.trim().is_empty())
        })
    {
        return Err(AdapterError::Unsupported(
            "custom python-build definition roots are not reviewed".into(),
        ));
    }
    Ok(())
}

fn inspect_pyenv(runtime: &dyn Runtime, mirror: Option<&str>) -> Result<Snapshot, AdapterError> {
    reject_custom_definition_environment(runtime)?;
    let pyenv = run_pyenv(runtime, mirror, &["--version"], "pyenv --version")?;
    let pyenv_version = parse_version_line(&pyenv, "pyenv")?;
    review_pyenv_version(&pyenv_version)?;
    let root = PathBuf::from(run_pyenv(runtime, mirror, &["root"], "pyenv root")?.trim());
    validate_path(&root, "root")?;
    let python_build = run_pyenv(
        runtime,
        mirror,
        &["install", "--version"],
        "pyenv install --version",
    )?;
    let python_build_version = parse_version_line(&python_build, "python-build")?;
    let definitions = run_pyenv(
        runtime,
        mirror,
        &["install", "--list"],
        "pyenv install --list",
    )?;
    if !definitions
        .lines()
        .any(|line| line.trim() == PYTHON_VERSION)
    {
        return Err(AdapterError::Unsupported(format!(
            "python-build does not list CPython {PYTHON_VERSION}"
        )));
    }
    let definition = root
        .join("plugins/python-build/share/python-build")
        .join(PYTHON_VERSION);
    let contents = runtime.read(&definition)?.ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "python-build definition {} is not readable",
            definition.display()
        ))
    })?;
    validate_definition(utf8(&definition, &contents)?)?;
    Ok(Snapshot {
        pyenv_version,
        python_build_version,
        root,
    })
}

fn run_pyenv(
    runtime: &dyn Runtime,
    mirror: Option<&str>,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let mut command = vec!["CI=true".into()];
    if let Some(mirror) = mirror {
        command.push(format!("{MIRROR_ENV}={mirror}"));
        command.push(format!("{SKIP_CHECKSUM_ENV}=1"));
    }
    command.push("pyenv".into());
    command.extend(arguments.iter().map(|argument| (*argument).into()));
    command_output(runtime.run("env", &command)?, label)
}

fn parse_version_line(output: &str, name: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(name))
                .then(|| fields.next())
                .flatten()
        })
        .map(|version| version.trim_start_matches('v'))
        .filter(|version| valid_version(version))
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("{name} version is unrecognized")))
}

fn review_pyenv_version(value: &str) -> Result<(), AdapterError> {
    let major = value
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    if !matches!(major, Some(2..)) {
        return Err(AdapterError::Unsupported(format!(
            "pyenv {value} is outside the reviewed 2.x+ plugin model"
        )));
    }
    Ok(())
}

fn valid_version(value: &str) -> bool {
    let parts = value.split(['.', '-']).collect::<Vec<_>>();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn validate_definition(text: &str) -> Result<(), AdapterError> {
    let matches = text
        .lines()
        .filter(|line| line.contains(&format!("install_package \"Python-{PYTHON_VERSION}\"")))
        .filter(|line| line.contains(".tar.xz#"))
        .collect::<Vec<_>>();
    if matches.len() != 1 || !matches[0].contains(&format!("{DEFINITION_URL}#{ARCHIVE_SHA256}")) {
        return Err(AdapterError::Unsupported(
            "python-build CPython definition URL, format, or checksum is not reviewed".into(),
        ));
    }
    Ok(())
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("pyenv requires a user home".into()))?;
    validate_path(&home, "home")?;
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().and_then(parse_shell))
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "pyenv requires SHELL to select bash, zsh, or fish initialization".into(),
            )
        })?;
    let profile = if let Some(value) = runtime
        .environment_variable("PROFILE")
        .filter(|value| !value.trim().is_empty())
    {
        if value == "/dev/null" {
            return Err(AdapterError::Unsupported(
                "PROFILE=/dev/null disables persistent python-build configuration".into(),
            ));
        }
        PathBuf::from(value)
    } else if context.environment == ExecutionEnvironment::Container
        && shell == ShellKind::Bash
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.trim().is_empty())
    {
        PathBuf::from(value)
    } else {
        match shell {
            ShellKind::Bash => home.join(".bashrc"),
            ShellKind::Zsh => runtime
                .environment_variable("ZDOTDIR")
                .filter(|value| !value.trim().is_empty())
                .map_or_else(
                    || home.join(".zshrc"),
                    |value| PathBuf::from(value).join(".zshrc"),
                ),
            ShellKind::Fish => home.join(".config/fish/conf.d/mirrorswitch-python-build.fish"),
        }
    };
    validate_user_path(&profile, &home, "shell profile")?;
    let verification_root = home.join(".mirrorswitch/verification/pyenv");
    Ok(Layout {
        shell,
        profile,
        verification_manifest: verification_root.join("release.txt"),
        verification_archive: verification_root.join(ARCHIVE),
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

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let managed = range
        .as_ref()
        .map(|range| managed_values(&text[range.clone()], path, shell))
        .transpose()?;
    let mut unmanaged = Vec::new();
    let mut dynamic = false;
    let mut policy_conflict = false;
    for (start, line) in line_spans(text) {
        if range.as_ref().is_some_and(|range| range.contains(&start)) {
            continue;
        }
        let active = line.trim();
        if active.is_empty() || active.starts_with('#') {
            continue;
        }
        if POLICY_ENVIRONMENTS.iter().any(|name| active.contains(name)) {
            policy_conflict = true;
        }
        if !active.contains(MIRROR_ENV) && !active.contains(SKIP_CHECKSUM_ENV) {
            continue;
        }
        match assignment(active, shell)? {
            Some((key, value)) => unmanaged.push(Assignment {
                range: start..start + line.len(),
                key,
                value: value.into(),
            }),
            None => dynamic = true,
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged,
        dynamic,
        policy_conflict,
    })
}

fn managed_values(
    block: &str,
    path: &Path,
    shell: ShellKind,
) -> Result<ManagedValues, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| assignment(line.trim(), shell).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let mirror = unique_assignment(&values, ManagedKey::Mirror, path)?;
    let skip_checksum = unique_assignment(&values, ManagedKey::SkipChecksum, path)?;
    if values.len() != 2 || !is_reviewed(mirror) || skip_checksum.is_empty() {
        return Err(AdapterError::Unsupported(
            "managed python-build block is incomplete or unreviewed".into(),
        ));
    }
    Ok(ManagedValues {
        mirror: mirror.into(),
        skip_checksum: skip_checksum.into(),
    })
}

fn unique_assignment<'a>(
    values: &[(ManagedKey, &'a str)],
    key: ManagedKey,
    path: &Path,
) -> Result<&'a str, AdapterError> {
    let matches = values
        .iter()
        .filter(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed python-build block in {} must assign {} exactly once",
            path.display(),
            key.name()
        )));
    }
    Ok(matches[0])
}

fn assignment(line: &str, shell: ShellKind) -> Result<Option<(ManagedKey, &str)>, AdapterError> {
    let (key, raw) = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            let Some(key) = parse_key(key.trim()) else {
                return Ok(None);
            };
            (key, value.trim())
        }
        ShellKind::Fish => {
            let Some(rest) = line.strip_prefix("set ") else {
                return Ok(None);
            };
            let mut fields = rest.split_whitespace();
            let Some(flags) = fields.next() else {
                return Ok(None);
            };
            let Some(key) = fields.next().and_then(parse_key) else {
                return Ok(None);
            };
            let Some(value) = fields.next() else {
                return Ok(None);
            };
            if !flags.contains('x') || fields.next().is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "fish {} assignment is not a literal exported value",
                    key.name()
                )));
            }
            (key, value)
        }
    };
    Ok(Some((key, literal_value(raw, key)?)))
}

fn parse_key(value: &str) -> Option<ManagedKey> {
    match value {
        MIRROR_ENV => Some(ManagedKey::Mirror),
        SKIP_CHECKSUM_ENV => Some(ManagedKey::SkipChecksum),
        _ => None,
    }
}

fn literal_value(raw: &str, key: ManagedKey) -> Result<&str, AdapterError> {
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
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} assignment is not a literal value",
            key.name()
        )));
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
            "python-build managed markers in {} are missing, duplicated, or out of order",
            path.display()
        ))),
    }
}

fn profile_sources(parsed: &ParsedProfile, path: &Path, shell: ShellKind) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(managed) = &parsed.managed {
        sources.push(configured_source(
            &managed.mirror,
            "managed-shell-profile",
            path,
            shell,
        ));
    }
    for assignment in &parsed.unmanaged {
        let public = match assignment.key {
            ManagedKey::Mirror => is_adoptable(&assignment.value),
            ManagedKey::SkipChecksum => !assignment.value.is_empty(),
        };
        sources.push(if public {
            configured_source(&assignment.value, "adoptable-shell-profile", path, shell)
        } else {
            policy_source("private-shell-profile", path, shell)
        });
    }
    for key in [ManagedKey::Mirror, ManagedKey::SkipChecksum] {
        let count = usize::from(parsed.managed.is_some())
            + parsed
                .unmanaged
                .iter()
                .filter(|assignment| assignment.key == key)
                .count();
        if count > 1 {
            sources.push(policy_source("duplicate-shell-profile", path, shell));
        }
    }
    if parsed.dynamic {
        sources.push(policy_source("dynamic-shell-profile", path, shell));
    }
    if parsed.policy_conflict {
        sources.push(policy_source("custom-build-policy", path, shell));
    }
    sources
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-shell-profile" => {
                return Err(AdapterError::Unsupported(
                    "existing python-build mirror points to a private or unreviewed endpoint"
                        .into(),
                ));
            }
            "duplicate-shell-profile" => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected shell profile assigns a python-build mirror variable more than once"
                        .into(),
                ));
            }
            "dynamic-shell-profile" => {
                return Err(AdapterError::Unsupported(
                    "selected shell profile computes python-build mirror policy dynamically".into(),
                ));
            }
            "custom-build-policy" | "custom-definition-or-skip-environment" => {
                return Err(AdapterError::Unsupported(
                    "custom python-build definition or mirror bypass policy is active".into(),
                ));
            }
            "process-environment-override" => {
                return Err(AdapterError::Unsupported(
                    "python-build process environment is not represented by the selected profile"
                        .into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "pyenv verification target contains data not managed by MirrorSwitch".into(),
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
    if parsed.dynamic || parsed.policy_conflict {
        return Err(AdapterError::InvalidConfiguration(
            "python-build profile cannot be rewritten safely".into(),
        ));
    }
    for key in [ManagedKey::Mirror, ManagedKey::SkipChecksum] {
        if parsed
            .unmanaged
            .iter()
            .filter(|assignment| assignment.key == key)
            .count()
            > 1
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "python-build profile assigns {} more than once",
                key.name()
            )));
        }
    }
    if parsed
        .unmanaged
        .iter()
        .any(|assignment| assignment.key == ManagedKey::Mirror && !is_adoptable(&assignment.value))
    {
        return Err(AdapterError::Unsupported(
            "private or unreviewed python-build mirror cannot be replaced".into(),
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
    if !parsed.unmanaged.is_empty() {
        let insertion = parsed
            .unmanaged
            .iter()
            .map(|assignment| assignment.range.start)
            .min()
            .expect("non-empty assignments");
        let mut output = text.to_owned();
        let mut ranges = parsed
            .unmanaged
            .iter()
            .map(|assignment| assignment.range.clone())
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
        for range in ranges {
            output.replace_range(range, "");
        }
        output.insert_str(insertion, &block);
        return Ok(output);
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
    let (mirror, skip) = match shell {
        ShellKind::Bash | ShellKind::Zsh => (
            format!("export {MIRROR_ENV}='{endpoint}'"),
            format!("export {SKIP_CHECKSUM_ENV}=1"),
        ),
        ShellKind::Fish => (
            format!("set -gx {MIRROR_ENV} '{endpoint}'"),
            format!("set -gx {SKIP_CHECKSUM_ENV} 1"),
        ),
    };
    format!("{MANAGED_BEGIN}{newline}{mirror}{newline}{skip}{newline}{MANAGED_END}{newline}")
}

fn render_manifest() -> String {
    format!(
        "version={PYTHON_VERSION}\narchive={ARCHIVE}\nrelative_path={PYTHON_VERSION}/{ARCHIVE}\ndefinition_url={DEFINITION_URL}\nsha256={ARCHIVE_SHA256}\n"
    )
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "pyenv" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "pyenv requires exactly one release mirror selection".into(),
        ));
    }
    let selection = matches[0];
    let mut bases = BTreeSet::new();
    for role in [
        EndpointRole::Index,
        EndpointRole::Metadata,
        EndpointRole::Artifacts,
    ] {
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if endpoints.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "pyenv selection requires one HTTPS {role:?} endpoint"
            )));
        }
        bases.insert(normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("pyenv {role:?} endpoint is unsafe"))
        })?);
    }
    if bases.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "python-build index, metadata, and artifact endpoints must share one base".into(),
        ));
    }
    let endpoint = bases.into_iter().next().expect("one endpoint");
    let provider = reviewed_provider(&endpoint).ok_or_else(|| {
        AdapterError::InvalidConfiguration("python-build endpoint is not reviewed".into())
    })?;
    if selection.provider_id != provider {
        return Err(AdapterError::InvalidConfiguration(
            "python-build provider and endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn verify_download(
    runtime: &dyn Runtime,
    layout: &Layout,
    endpoint: &str,
) -> Result<(), AdapterError> {
    let archive = path_text(&layout.verification_archive, "verification archive")?;
    let url = format!("{endpoint}/{PYTHON_VERSION}/{ARCHIVE}");
    let arguments = vec![
        "--fail".into(),
        "--location".into(),
        "--silent".into(),
        "--show-error".into(),
        "--output".into(),
        archive.into(),
        url,
    ];
    command_output(
        runtime.run_in(&layout.verification_root, "curl", &arguments)?,
        "python-build mirror archive download",
    )?;
    let digest = command_output(
        runtime.run("sha256sum", &[archive.into()])?,
        "python-build archive checksum",
    )?;
    if digest.split_whitespace().next() != Some(ARCHIVE_SHA256) {
        return Err(AdapterError::Verification(
            "downloaded CPython archive checksum does not match its definition".into(),
        ));
    }
    Ok(())
}

fn normalized_base(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_owned())
}

fn reviewed_provider(value: &str) -> Option<&'static str> {
    match normalized_base(value)?.as_str() {
        HUAWEI => Some("huaweicloud"),
        NJU => Some("nju"),
        TUNA => Some("tuna"),
        _ => None,
    }
}

fn is_reviewed(value: &str) -> bool {
    reviewed_provider(value).is_some()
}

fn is_adoptable(value: &str) -> bool {
    is_reviewed(value)
        || normalized_base(value).is_some_and(|value| OFFICIAL_MIRRORS.contains(&value.as_str()))
}

fn environment_state(runtime: &dyn Runtime, name: &str) -> &'static str {
    match runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
    {
        None => "unset",
        Some(value) if name == MIRROR_ENV && is_adoptable(&value) => "public",
        Some(_) if name == SKIP_CHECKSUM_ENV => "enabled",
        Some(_) => "custom",
    }
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
            "pyenv current configuration must contain exactly one {format} document"
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

fn configured_source(value: &str, kind: &str, path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
        url: normalized_base(value).unwrap_or_else(|| "<preserved>".into()),
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

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "pyenv-snapshot:<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("pyenv source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "pyenv source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish]
        .into_iter()
        .find(|shell| format == format!("pyenv-selected-{}-profile", shell.name()))
        .ok_or_else(|| AdapterError::InvalidConfiguration("unknown pyenv profile format".into()))
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

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "pyenv {kind} {} is outside the user home",
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
            "pyenv reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, kind: &str) -> Result<&'a str, AdapterError> {
    path.to_str()
        .ok_or_else(|| AdapterError::Verification(format!("pyenv {kind} path is not UTF-8")))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "pyenv configuration {} is not UTF-8",
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
