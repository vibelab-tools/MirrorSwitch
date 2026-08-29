use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Component, Path, PathBuf},
    process::Output,
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const HACKAGE_UPSTREAM: &str = "hackage--language-registry";
const VERIFY_PACKAGE: &str = "StateVar";
const VERIFY_VERSION: &str = "1.2.2";
const VERIFY_PACKAGE_ID: &str = "StateVar-1.2.2";
const VERIFY_TARBALL_SHA256: &str =
    "5e4b39da395656a59827b0280508aafdc70335798b50e5d6fd52596026251825";
const HACKAGE_REPOSITORY: &str = "hackage.haskell.org";
const HACKAGE_KEY_THRESHOLD: u64 = 3;
const HACKAGE_ROOT_KEYS: &[&str] = &[
    "fe331502606802feac15e514d9b9ea83fee8b6ffef71335479a2e68d84adc6b0",
    "1ea9ba32c526d1cc91ab5e5bd364ec5e9e8cb67179a471872f6e26f0ae773d42",
    "0a5c7ea47cd1b15f01f5f51a33adda7e655bc0f0b0615baa8e271f4c3351e21d",
    "51f0161b906011b52c661337b1ae937670da69322113a246a09f807c62f6921",
    "c7de58fc6a224b92b5b513f26fbb8b370f2d97c7cfe0075a951314a55734be93",
    "d26e46f3b631aae1433b89379a6c68bd417eb5d1c408f0643dcc07757fece522",
];
const REVIEWED_ENDPOINTS: &[(&str, &str)] = &[
    ("nju", "https://mirrors.nju.edu.cn/hackage"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/hackage"),
    ("ustc", "https://mirrors.ustc.edu.cn/hackage"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct CabalAdapter;

impl Adapter for CabalAdapter {
    fn key(&self) -> &'static str {
        "cabal"
    }

    fn tool_id(&self) -> &'static str {
        "cabal"
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
        if !runtime.command_exists("cabal") {
            return Ok(None);
        }
        let snapshot = cabal_snapshot(runtime)?;
        let user = read_document(runtime, &snapshot.user_config, "Cabal user config")?;
        let parsed = parse_config(&snapshot.user_config, &user.contents, false)?;
        let analysis = analyze_user_config(&parsed, user.exists)?;
        let projects = read_project_documents(runtime, &snapshot.project_files)?;
        validate_project_policy(&projects, &analysis.repository_name)?;
        let mut evidence = vec![
            format!("cabal-install {}", snapshot.cabal_version),
            snapshot.ghc_version.as_ref().map_or_else(
                || "GHC is not installed; repository commands remain available".into(),
                |version| format!("GHC {version}"),
            ),
            format!("user configuration is {}", snapshot.user_config.display()),
            format!(
                "effective Hackage repository is {} ({})",
                analysis.repository_name,
                analysis.location.label()
            ),
            format!(
                "{} private repository definition(s) preserved",
                analysis.private_count
            ),
        ];
        evidence.push(if projects.is_empty() {
            "no project Cabal configuration detected".into()
        } else {
            format!(
                "{} project configuration file(s) are read-only policy inputs",
                projects.len()
            )
        });
        Ok(Some(DetectedTool {
            tool_id: "cabal".into(),
            executable: Some(PathBuf::from("cabal")),
            version: Some(snapshot.cabal_version),
            evidence,
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
        if detected.tool_id != "cabal" {
            return Err(AdapterError::InvalidConfiguration(
                "Cabal read received another tool's detection result".into(),
            ));
        }
        let snapshot = cabal_snapshot(runtime)?;
        if detected.version.as_deref() != Some(snapshot.cabal_version.as_str()) {
            return Err(AdapterError::Conflict(
                "cabal-install version changed after detection".into(),
            ));
        }
        let user = read_document(runtime, &snapshot.user_config, "Cabal user config")?;
        let parsed = parse_config(&snapshot.user_config, &user.contents, false)?;
        let analysis = analyze_user_config(&parsed, user.exists)?;
        let projects = read_project_documents(runtime, &snapshot.project_files)?;
        validate_project_policy(&projects, &analysis.repository_name)?;

        let mut sources = configured_sources(&parsed, &analysis, &snapshot.user_config);
        let mut files = Vec::new();
        if user.exists {
            files.push(snapshot.user_config.clone());
        }
        let mut documents = vec![ConfigurationDocument {
            path: snapshot.user_config.clone(),
            format: "cabal-user-config".into(),
            contents: user.contents,
        }];
        for project in projects {
            sources.extend(project_sources(&project));
            files.push(project.path.clone());
            documents.push(ConfigurationDocument {
                path: project.path,
                format: "cabal-project-read-only".into(),
                contents: project.contents,
            });
        }
        let verification = read_document(
            runtime,
            &snapshot.verification_config,
            "Cabal verification config",
        )?;
        if verification.exists {
            files.push(snapshot.verification_config.clone());
        }
        documents.push(ConfigurationDocument {
            path: snapshot.verification_config,
            format: "cabal-verification-config".into(),
            contents: verification.contents,
        });
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: format!("cabal-version:{}", snapshot.cabal_version),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["tool-snapshot".into()]),
                ("cabal_version".into(), vec![snapshot.cabal_version.clone()]),
                (
                    "ghc_version".into(),
                    vec![snapshot.ghc_version.unwrap_or_else(|| "missing".into())],
                ),
            ]),
        });
        Ok(CurrentConfiguration {
            tool_id: "cabal".into(),
            scope,
            sources,
            files,
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
        reviewed_cabal_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("cabal-install version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "cabal".into(),
            adapter_key: "cabal".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![HACKAGE_UPSTREAM.into()],
            repository_versions: BTreeMap::from([(HACKAGE_UPSTREAM.into(), "secure".into())]),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![
                EndpointRole::Metadata,
                EndpointRole::Index,
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
        let endpoint = selected_endpoint(selections)?;
        let user = current
            .documents
            .iter()
            .find(|document| document.format == "cabal-user-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Cabal user configuration document is missing".into(),
                )
            })?;
        let parsed = parse_config(&user.path, &user.contents, false)?;
        let analysis = analyze_user_config(&parsed, current.files.contains(&user.path))?;
        let projects = current
            .documents
            .iter()
            .filter(|document| document.format == "cabal-project-read-only")
            .map(|document| {
                Ok(ParsedDocument {
                    path: document.path.clone(),
                    contents: document.contents.clone(),
                    parsed: parse_config(&document.path, &document.contents, true)?,
                })
            })
            .collect::<Result<Vec<_>, AdapterError>>()?;
        validate_project_policy(&projects, &analysis.repository_name)?;
        let rendered = rewrite_user_config(
            utf8(&user.path, &user.contents)?,
            &analysis.location,
            endpoint,
        )?;
        let mut changes = Vec::new();
        if rendered.as_bytes() != user.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &user.path),
                old_contents: current
                    .files
                    .contains(&user.path)
                    .then(|| user.contents.clone()),
                old_mode: None,
                new_contents: rendered.into_bytes(),
                new_mode: None,
                summary: format!(
                    "retarget {HACKAGE_REPOSITORY} to {endpoint} in {}, adding reviewed root trust only when absent; preserve {} private repositories, existing secure/root-key policy, active-repositories, project files and all unrelated Cabal settings",
                    user.path.display(),
                    analysis.private_count
                ),
            });
        }
        let verification = current
            .documents
            .iter()
            .find(|document| document.format == "cabal-verification-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Cabal verification configuration document is missing".into(),
                )
            })?;
        let verification_dir = verification.path.parent().ok_or_else(|| {
            AdapterError::InvalidConfiguration("invalid Cabal verification path".into())
        })?;
        let verification_contents = render_verification_config(endpoint, verification_dir);
        if verification.contents != verification_contents.as_bytes() {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &verification.path),
                old_contents: current
                    .files
                    .contains(&verification.path)
                    .then(|| verification.contents.clone()),
                old_mode: None,
                new_contents: verification_contents.into_bytes(),
                new_mode: None,
                summary: "create an isolated credential-free Cabal config for signed Hackage update and fixed-package verification".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "cabal".into(),
            tool_id: "cabal".into(),
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
            let snapshot = cabal_snapshot(runtime)?;
            let known_targets = [
                rooted(&context.root, &snapshot.user_config),
                rooted(&context.root, &snapshot.verification_config),
            ];
            if receipt
                .changed_targets
                .iter()
                .all(|target| !known_targets.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Cabal transaction receipt contains no known target".into(),
                ));
            }
            let user = read_document(runtime, &snapshot.user_config, "Cabal user config")?;
            let parsed = parse_config(&snapshot.user_config, &user.contents, false)?;
            let analysis = analyze_user_config(&parsed, user.exists)?;
            let endpoint = analysis.current_endpoint.ok_or_else(|| {
                AdapterError::Verification(
                    "Cabal user config did not load a reviewed Hackage mirror".into(),
                )
            })?;
            if !is_reviewed_mirror(&endpoint) {
                return Err(AdapterError::Verification(
                    "Cabal user config did not load a reviewed Hackage mirror".into(),
                ));
            }
            let verification = runtime
                .read(&snapshot.verification_config)?
                .ok_or_else(|| {
                    AdapterError::Verification("Cabal verification config disappeared".into())
                })?;
            let verification_dir = snapshot
                .verification_config
                .parent()
                .ok_or_else(|| AdapterError::Verification("invalid verification path".into()))?;
            if verification != render_verification_config(&endpoint, verification_dir).as_bytes() {
                return Err(AdapterError::Verification(
                    "Cabal verification config is not canonical".into(),
                ));
            }
            let config_argument = format!(
                "--config-file={}",
                path_string(&snapshot.verification_config)?
            );
            run_program(
                runtime,
                Some(verification_dir),
                "cabal",
                &[&config_argument, "update", HACKAGE_REPOSITORY],
                "cabal update Hackage security verification",
            )?;
            let info = run_program(
                runtime,
                Some(verification_dir),
                "cabal",
                &[&config_argument, "info", VERIFY_PACKAGE_ID],
                "cabal info fixed package verification",
            )?;
            for marker in [VERIFY_PACKAGE, VERIFY_VERSION] {
                if !info.contains(marker) {
                    return Err(AdapterError::Verification(format!(
                        "cabal info did not report reviewed marker {marker}"
                    )));
                }
            }
            let destination = verification_dir
                .join("source")
                .join(&receipt.transaction_id);
            let destination_argument = format!("--destdir={}", path_string(&destination)?);
            run_program(
                runtime,
                Some(verification_dir),
                "cabal",
                &[
                    &config_argument,
                    "get",
                    VERIFY_PACKAGE_ID,
                    &destination_argument,
                    "--pristine",
                ],
                "cabal get fixed package verification",
            )?;
            let cabal_file = destination
                .join(VERIFY_PACKAGE_ID)
                .join(format!("{VERIFY_PACKAGE}.cabal"));
            let package = runtime.read(&cabal_file)?.ok_or_else(|| {
                AdapterError::Verification(
                    "cabal get did not extract the fixed verification package".into(),
                )
            })?;
            let package = utf8(&cabal_file, &package)?;
            if !package.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case(&format!("name: {VERIFY_PACKAGE}"))
            }) || !package.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case(&format!("version: {VERIFY_VERSION}"))
            }) {
                return Err(AdapterError::Verification(
                    "fixed verification package metadata is inconsistent".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "cabal-install {} loaded {endpoint}; cabal update verified Hackage Security metadata and cabal info/get resolved {VERIFY_PACKAGE_ID}; the catalog gate separately enforces tarball SHA-256 {VERIFY_TARBALL_SHA256}",
                    snapshot.cabal_version
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
                "restored {} Cabal configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CabalSnapshot {
    cabal_version: String,
    ghc_version: Option<String>,
    user_config: PathBuf,
    project_files: Vec<PathBuf>,
    verification_config: PathBuf,
}

#[derive(Clone, Debug)]
struct TextDocument {
    exists: bool,
    contents: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ParsedDocument {
    path: PathBuf,
    contents: Vec<u8>,
    parsed: ParsedConfig,
}

#[derive(Clone, Debug)]
struct ParsedConfig {
    repositories: Vec<Repository>,
    legacy_repositories: Vec<LegacyRepository>,
    active_repositories: Option<Vec<String>>,
    has_import: bool,
    conditional_relevant_policy: bool,
}

#[derive(Clone, Debug)]
struct Repository {
    name: String,
    url: String,
    url_range: Range<usize>,
    trust_insertion: usize,
    field_indent: String,
    secure: Option<bool>,
    has_root_keys: bool,
    root_keys_nonempty: bool,
    key_threshold: Option<u64>,
}

#[derive(Clone, Debug)]
struct LegacyRepository {
    name: String,
    url: String,
    url_range: Range<usize>,
    line_range: Range<usize>,
}

#[derive(Clone, Debug)]
struct FieldValue {
    value: String,
    range: Range<usize>,
}

#[derive(Clone, Debug)]
struct ParsedLine<'a> {
    start: usize,
    end: usize,
    indent: usize,
    active: &'a str,
}

#[derive(Clone, Debug)]
enum TargetLocation {
    Implicit,
    Repository {
        url_range: Range<usize>,
        trust_insertion: usize,
        field_indent: String,
        add_secure: bool,
        add_root_keys: bool,
    },
    Legacy {
        url_range: Range<usize>,
        line_range: Range<usize>,
    },
}

impl TargetLocation {
    fn label(&self) -> &'static str {
        match self {
            Self::Implicit => "implicit default",
            Self::Repository { .. } => "repository stanza",
            Self::Legacy { .. } => "legacy remote-repo",
        }
    }
}

#[derive(Clone, Debug)]
struct UserAnalysis {
    location: TargetLocation,
    repository_name: String,
    current_endpoint: Option<String>,
    private_count: usize,
}

fn cabal_snapshot(runtime: &dyn Runtime) -> Result<CabalSnapshot, AdapterError> {
    let cabal_version = run_program(
        runtime,
        None,
        "cabal",
        &["--numeric-version"],
        "cabal --numeric-version",
    )?;
    reviewed_cabal_version(&cabal_version)?;
    let version = version_components(&cabal_version).ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "could not parse cabal-install version {cabal_version}"
        ))
    })?;
    let ghc_version = runtime
        .command_exists("ghc")
        .then(|| {
            run_program(
                runtime,
                None,
                "ghc",
                &["--numeric-version"],
                "ghc --numeric-version",
            )
        })
        .transpose()?;
    if let Some(ghc_version) = &ghc_version {
        reviewed_ghc_version(ghc_version)?;
    }
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Cabal user home is unavailable".into()))?;
    validate_path(&home, "Cabal user home")?;
    let user_config = cabal_config_path(runtime, &home, version)?;
    validate_user_path(&home, &user_config, "Cabal user config")?;
    if version >= (3, 10, 0)
        && nonempty_environment(runtime, "CABAL_CONFIG").is_some()
        && runtime.read(&user_config)?.is_none()
    {
        return Err(AdapterError::Unsupported(format!(
            "CABAL_CONFIG selects missing file {}",
            user_config.display()
        )));
    }
    let project_files = project_config_files(runtime)?;
    let verification_config = home.join(".mirrorswitch/verification/cabal/config");
    validate_user_path(&home, &verification_config, "Cabal verification config")?;
    Ok(CabalSnapshot {
        cabal_version,
        ghc_version,
        user_config,
        project_files,
        verification_config,
    })
}

fn cabal_config_path(
    runtime: &dyn Runtime,
    home: &Path,
    version: (u64, u64, u64),
) -> Result<PathBuf, AdapterError> {
    if version < (3, 10, 0) {
        return Ok(home.join(".cabal/config"));
    }
    if let Some(value) = nonempty_environment(runtime, "CABAL_CONFIG") {
        return environment_user_path(home, &value, "CABAL_CONFIG");
    }
    if let Some(value) = nonempty_environment(runtime, "CABAL_DIR") {
        return Ok(environment_user_path(home, &value, "CABAL_DIR")?.join("config"));
    }
    let xdg = match nonempty_environment(runtime, "XDG_CONFIG_HOME") {
        Some(value) => environment_user_path(home, &value, "XDG_CONFIG_HOME")?,
        None => home.join(".config"),
    };
    let xdg_config = xdg.join("cabal/config");
    let legacy = home.join(".cabal/config");
    if runtime.read(&xdg_config)?.is_some() {
        Ok(xdg_config)
    } else if runtime.read(&legacy)?.is_some() {
        Ok(legacy)
    } else {
        Ok(xdg_config)
    }
}

fn nonempty_environment(runtime: &dyn Runtime, name: &str) -> Option<String> {
    runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
}

fn environment_user_path(
    home: &Path,
    value: &str,
    variable: &str,
) -> Result<PathBuf, AdapterError> {
    let path = PathBuf::from(value);
    validate_path(&path, variable)?;
    if !path.is_absolute() || !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "{variable} must select an absolute path inside {}",
            home.display()
        )));
    }
    Ok(path)
}

fn project_config_files(runtime: &dyn Runtime) -> Result<Vec<PathBuf>, AdapterError> {
    let Some(mut directory) = runtime.project_dir() else {
        return Ok(Vec::new());
    };
    validate_path(&directory, "Cabal project directory")?;
    let project_root = loop {
        let candidate = directory.join("cabal.project");
        if runtime.read(&candidate)?.is_some() {
            break Some(directory);
        }
        let Some(parent) = directory.parent() else {
            break None;
        };
        if parent == directory {
            break None;
        }
        directory = parent.to_path_buf();
    };
    let Some(project_root) = project_root else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for name in [
        "cabal.project",
        "cabal.project.freeze",
        "cabal.project.local",
    ] {
        let path = project_root.join(name);
        if runtime.read(&path)?.is_some() {
            files.push(path);
        }
    }
    Ok(files)
}

fn read_document(
    runtime: &dyn Runtime,
    path: &Path,
    label: &str,
) -> Result<TextDocument, AdapterError> {
    let observed = runtime.read(path)?;
    let exists = observed.is_some();
    let contents = observed.unwrap_or_default();
    if contents.contains(&0) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} {} contains NUL bytes",
            path.display()
        )));
    }
    utf8(path, &contents)?;
    Ok(TextDocument { exists, contents })
}

fn read_project_documents(
    runtime: &dyn Runtime,
    paths: &[PathBuf],
) -> Result<Vec<ParsedDocument>, AdapterError> {
    paths
        .iter()
        .map(|path| {
            let document = read_document(runtime, path, "Cabal project config")?;
            Ok(ParsedDocument {
                path: path.clone(),
                parsed: parse_config(path, &document.contents, true)?,
                contents: document.contents,
            })
        })
        .collect()
}

fn parse_config(path: &Path, contents: &[u8], project: bool) -> Result<ParsedConfig, AdapterError> {
    let text = utf8(path, contents)?;
    let lines = parsed_lines(text);
    let mut repositories = Vec::new();
    let mut legacy_repositories = Vec::new();
    let mut active_repositories = None;
    let mut has_import = false;
    let mut has_conditional = false;
    let mut relevant_policy = false;
    let mut index = 0;
    while index < lines.len() {
        let line = &lines[index];
        if line.active.is_empty() || line.active.starts_with("--") {
            index += 1;
            continue;
        }
        let lowercase = line.active.to_ascii_lowercase();
        if lowercase.starts_with("if(")
            || lowercase.starts_with("if (")
            || lowercase.starts_with("elif(")
            || lowercase.starts_with("elif (")
            || lowercase == "else"
        {
            has_conditional = true;
        }
        if line.indent == 0 && lowercase.starts_with("import:") {
            has_import = true;
        }
        if lowercase.starts_with("repository ")
            || lowercase.starts_with("remote-repo:")
            || lowercase.starts_with("active-repositories:")
        {
            relevant_policy = true;
        }
        if line.indent != 0 {
            index += 1;
            continue;
        }
        if let Some(name) = strip_keyword(line.active, "repository") {
            let end = next_top_level(&lines, index + 1);
            repositories.push(parse_repository(path, text, &lines[index..end], name)?);
            index = end;
            continue;
        }
        if let Some(field) = parse_field(text, line, "remote-repo")? {
            legacy_repositories.push(parse_legacy_repository(
                path,
                field,
                line.start..line_end_with_newline(text, line),
            )?);
            index += 1;
            continue;
        }
        if let Some(field) = parse_field_allow_empty(text, line, "active-repositories")? {
            if active_repositories.is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "active-repositories appears more than once in {}",
                    path.display()
                )));
            }
            let end = next_top_level(&lines, index + 1);
            let mut value = field.value;
            for continuation in &lines[index + 1..end] {
                if continuation.active.is_empty() || continuation.active.starts_with("--") {
                    continue;
                }
                value.push(' ');
                value.push_str(strip_inline_comment(continuation.active));
            }
            active_repositories = Some(parse_active_repositories(path, &value)?);
            index = end;
            continue;
        }
        index += 1;
    }
    Ok(ParsedConfig {
        repositories,
        legacy_repositories,
        active_repositories,
        has_import: project && has_import,
        conditional_relevant_policy: project && has_conditional && relevant_policy,
    })
}

fn parsed_lines(text: &str) -> Vec<ParsedLine<'_>> {
    let mut result = Vec::new();
    let mut offset = 0;
    for raw in text.split_inclusive('\n') {
        let content = raw
            .strip_suffix('\n')
            .unwrap_or(raw)
            .strip_suffix('\r')
            .unwrap_or(raw.strip_suffix('\n').unwrap_or(raw));
        let indent = content.len() - content.trim_start_matches([' ', '\t']).len();
        result.push(ParsedLine {
            start: offset,
            end: offset + content.len(),
            indent,
            active: &content[indent..],
        });
        offset += raw.len();
    }
    if text.is_empty() {
        return result;
    }
    if !text.ends_with('\n') && result.is_empty() {
        let indent = text.len() - text.trim_start_matches([' ', '\t']).len();
        result.push(ParsedLine {
            start: 0,
            end: text.len(),
            indent,
            active: &text[indent..],
        });
    }
    result
}

fn next_top_level(lines: &[ParsedLine<'_>], start: usize) -> usize {
    lines[start..]
        .iter()
        .position(|line| {
            line.indent == 0 && !line.active.is_empty() && !line.active.starts_with("--")
        })
        .map_or(lines.len(), |position| start + position)
}

fn strip_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let (head, value) = line.split_once(char::is_whitespace)?;
    head.eq_ignore_ascii_case(keyword)
        .then(|| strip_inline_comment(value).trim())
        .filter(|value| !value.is_empty())
}

fn parse_repository(
    path: &Path,
    text: &str,
    lines: &[ParsedLine<'_>],
    name: &str,
) -> Result<Repository, AdapterError> {
    let mut url = None;
    let mut trust_insertion = None;
    let mut field_indent = None;
    let mut secure = None;
    let mut has_root_keys = false;
    let mut root_keys_nonempty = false;
    let mut key_threshold = None;
    for (position, line) in lines[1..].iter().enumerate() {
        if line.active.is_empty() || line.active.starts_with("--") {
            continue;
        }
        if let Some(field) = parse_field(text, line, "url")? {
            if url.replace(field).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "repository {name} has multiple url fields in {}",
                    path.display()
                )));
            }
            trust_insertion = Some(line_end_with_newline(text, line));
            field_indent = Some(text[line.start..line.start + line.indent].to_owned());
        } else if let Some(field) = parse_field(text, line, "secure")? {
            let value = match field.value.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(AdapterError::InvalidConfiguration(format!(
                        "repository {name} has invalid secure value in {}",
                        path.display()
                    )));
                }
            };
            if secure.replace(value).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "repository {name} has multiple secure fields in {}",
                    path.display()
                )));
            }
        } else if field_name(line, "root-keys") {
            if has_root_keys {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "repository {name} has multiple root-keys fields in {}",
                    path.display()
                )));
            }
            has_root_keys = true;
            let raw = line
                .active
                .split_once(':')
                .map(|(_, value)| strip_inline_comment(value).trim())
                .unwrap_or_default();
            root_keys_nonempty = !raw.is_empty()
                || lines[position + 2..]
                    .iter()
                    .take_while(|continuation| {
                        continuation.indent > line.indent
                            || continuation.active.is_empty()
                            || continuation.active.starts_with("--")
                    })
                    .any(|continuation| {
                        continuation.indent > line.indent
                            && !continuation.active.is_empty()
                            && !continuation.active.starts_with("--")
                    });
        } else if let Some(field) = parse_field(text, line, "key-threshold")? {
            let value = field.value.parse::<u64>().map_err(|_| {
                AdapterError::InvalidConfiguration(format!(
                    "repository {name} has invalid key-threshold in {}",
                    path.display()
                ))
            })?;
            if key_threshold.replace(value).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "repository {name} has multiple key-threshold fields in {}",
                    path.display()
                )));
            }
        }
    }
    let url = url.ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "repository {name} has no url in {}",
            path.display()
        ))
    })?;
    Ok(Repository {
        name: name.to_owned(),
        url: url.value,
        url_range: url.range,
        trust_insertion: trust_insertion.ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "repository {name} has no URL insertion boundary in {}",
                path.display()
            ))
        })?,
        field_indent: field_indent.unwrap_or_else(|| "  ".into()),
        secure,
        has_root_keys,
        root_keys_nonempty,
        key_threshold,
    })
}

fn parse_field(
    text: &str,
    line: &ParsedLine<'_>,
    name: &str,
) -> Result<Option<FieldValue>, AdapterError> {
    parse_field_value(text, line, name, false)
}

fn parse_field_allow_empty(
    text: &str,
    line: &ParsedLine<'_>,
    name: &str,
) -> Result<Option<FieldValue>, AdapterError> {
    parse_field_value(text, line, name, true)
}

fn parse_field_value(
    text: &str,
    line: &ParsedLine<'_>,
    name: &str,
    allow_empty: bool,
) -> Result<Option<FieldValue>, AdapterError> {
    let Some((head, raw_value)) = line.active.split_once(':') else {
        return Ok(None);
    };
    if !head.trim().eq_ignore_ascii_case(name) {
        return Ok(None);
    }
    let value_without_comment = strip_inline_comment(raw_value);
    let leading = value_without_comment.len() - value_without_comment.trim_start().len();
    let trimmed = value_without_comment.trim();
    if trimmed.is_empty() && !allow_empty {
        return Err(AdapterError::InvalidConfiguration(format!(
            "field {name} has no value"
        )));
    }
    let colon = line
        .active
        .find(':')
        .ok_or_else(|| AdapterError::InvalidConfiguration(format!("field {name} is malformed")))?;
    let start = line.start + line.indent + colon + 1 + leading;
    let end = start + trimmed.len();
    if end > line.end || &text[start..end] != trimmed {
        return Err(AdapterError::InvalidConfiguration(format!(
            "field {name} range is inconsistent"
        )));
    }
    Ok(Some(FieldValue {
        value: trimmed.to_owned(),
        range: start..end,
    }))
}

fn field_name(line: &ParsedLine<'_>, name: &str) -> bool {
    line.active
        .split_once(':')
        .is_some_and(|(head, _)| head.trim().eq_ignore_ascii_case(name))
}

fn line_end_with_newline(text: &str, line: &ParsedLine<'_>) -> usize {
    if text[line.end..].starts_with("\r\n") {
        line.end + 2
    } else if text[line.end..].starts_with('\n') {
        line.end + 1
    } else {
        line.end
    }
}

fn strip_inline_comment(value: &str) -> &str {
    value
        .find(" --")
        .map_or(value, |position| &value[..position])
        .trim_end()
}

fn parse_legacy_repository(
    path: &Path,
    field: FieldValue,
    line_range: Range<usize>,
) -> Result<LegacyRepository, AdapterError> {
    if field.value.contains(',') {
        return Err(AdapterError::Unsupported(format!(
            "multi-value remote-repo syntax in {} is not rewritten",
            path.display()
        )));
    }
    let colon = field.value.find(':').ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "remote-repo in {} has no repository name",
            path.display()
        ))
    })?;
    let name = field.value[..colon].trim();
    let raw_url = &field.value[colon + 1..];
    let leading = raw_url.len() - raw_url.trim_start().len();
    let url = raw_url.trim();
    if name.is_empty() || url.is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "remote-repo in {} is incomplete",
            path.display()
        )));
    }
    let start = field.range.start + colon + 1 + leading;
    Ok(LegacyRepository {
        name: name.into(),
        url: url.into(),
        url_range: start..start + url.len(),
        line_range,
    })
}

fn parse_active_repositories(path: &Path, value: &str) -> Result<Vec<String>, AdapterError> {
    let entries = value
        .split(',')
        .flat_map(|part| part.split_whitespace())
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "active-repositories is empty in {}",
            path.display()
        )));
    }
    Ok(entries)
}

fn analyze_user_config(parsed: &ParsedConfig, exists: bool) -> Result<UserAnalysis, AdapterError> {
    if parsed.has_import || parsed.conditional_relevant_policy {
        return Err(AdapterError::Unsupported(
            "Cabal user imports or conditional repository policy cannot be rewritten safely".into(),
        ));
    }
    let mut targets = Vec::new();
    let mut private_count = 0;
    for repository in &parsed.repositories {
        let name_is_hackage = repository.name.eq_ignore_ascii_case(HACKAGE_REPOSITORY);
        let endpoint = normalized_public_hackage(&repository.url);
        if name_is_hackage {
            let endpoint = endpoint.ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "repository {HACKAGE_REPOSITORY} points to an unreviewed or credential-bearing endpoint"
                ))
            })?;
            if repository.secure == Some(false) {
                return Err(AdapterError::Unsupported(
                    "repository hackage.haskell.org explicitly disables secure mode".into(),
                ));
            }
            if repository.has_root_keys != repository.key_threshold.is_some()
                || (repository.has_root_keys && !repository.root_keys_nonempty)
                || repository.key_threshold == Some(0)
            {
                return Err(AdapterError::Unsupported(
                    "repository hackage.haskell.org has incomplete root-keys/key-threshold policy"
                        .into(),
                ));
            }
            targets.push((
                TargetLocation::Repository {
                    url_range: repository.url_range.clone(),
                    trust_insertion: repository.trust_insertion,
                    field_indent: repository.field_indent.clone(),
                    add_secure: repository.secure.is_none(),
                    add_root_keys: !repository.has_root_keys,
                },
                endpoint,
            ));
        } else if endpoint.is_some() {
            return Err(AdapterError::Unsupported(format!(
                "public Hackage endpoint uses repository id {} instead of {HACKAGE_REPOSITORY}",
                repository.name
            )));
        } else {
            private_count += 1;
        }
    }
    for repository in &parsed.legacy_repositories {
        let name_is_hackage = repository.name.eq_ignore_ascii_case(HACKAGE_REPOSITORY);
        let endpoint = normalized_public_hackage(&repository.url);
        if name_is_hackage {
            let endpoint = endpoint.ok_or_else(|| {
                AdapterError::Unsupported(
                    "legacy hackage.haskell.org remote-repo points to an unreviewed or credential-bearing endpoint"
                        .into(),
                )
            })?;
            targets.push((
                TargetLocation::Legacy {
                    url_range: repository.url_range.clone(),
                    line_range: repository.line_range.clone(),
                },
                endpoint,
            ));
        } else if endpoint.is_some() {
            return Err(AdapterError::Unsupported(format!(
                "public Hackage remote-repo uses id {} instead of {HACKAGE_REPOSITORY}",
                repository.name
            )));
        } else {
            private_count += 1;
        }
    }
    let (location, current_endpoint) = match targets.len() {
        0 if parsed.repositories.is_empty() && parsed.legacy_repositories.is_empty() => {
            (TargetLocation::Implicit, None)
        }
        0 => {
            return Err(AdapterError::Unsupported(
                "Cabal configuration contains only custom repositories".into(),
            ));
        }
        1 => targets
            .pop()
            .map(|(location, endpoint)| (location, Some(endpoint)))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Cabal target analysis failed".into())
            })?,
        _ => {
            return Err(AdapterError::Unsupported(
                "Cabal configuration contains multiple public Hackage definitions".into(),
            ));
        }
    };
    if !repository_is_active(parsed.active_repositories.as_deref(), HACKAGE_REPOSITORY) {
        return Err(AdapterError::Unsupported(
            "active-repositories excludes hackage.haskell.org".into(),
        ));
    }
    if !exists && !matches!(location, TargetLocation::Implicit) {
        return Err(AdapterError::InvalidConfiguration(
            "missing Cabal user config cannot contain repository definitions".into(),
        ));
    }
    Ok(UserAnalysis {
        location,
        repository_name: HACKAGE_REPOSITORY.into(),
        current_endpoint,
        private_count,
    })
}

fn validate_project_policy(
    projects: &[ParsedDocument],
    repository_name: &str,
) -> Result<(), AdapterError> {
    for project in projects {
        if project.parsed.has_import {
            return Err(AdapterError::Unsupported(format!(
                "Cabal project import in {} makes repository policy non-local",
                project.path.display()
            )));
        }
        if project.parsed.conditional_relevant_policy {
            return Err(AdapterError::Unsupported(format!(
                "conditional Cabal repository policy in {} cannot be evaluated statically",
                project.path.display()
            )));
        }
        if !project.parsed.repositories.is_empty() || !project.parsed.legacy_repositories.is_empty()
        {
            return Err(AdapterError::Unsupported(format!(
                "read-only project repository definition in {} overrides user Hackage policy",
                project.path.display()
            )));
        }
        if !repository_is_active(
            project.parsed.active_repositories.as_deref(),
            repository_name,
        ) {
            return Err(AdapterError::Unsupported(format!(
                "active-repositories in {} excludes {repository_name}",
                project.path.display()
            )));
        }
    }
    Ok(())
}

fn repository_is_active(active: Option<&[String]>, repository_name: &str) -> bool {
    let Some(active) = active else {
        return true;
    };
    if active.iter().any(|entry| entry == ":none") {
        return false;
    }
    active.iter().any(|entry| {
        entry == ":rest"
            || entry
                .split(':')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(repository_name))
    })
}

fn configured_sources(
    parsed: &ParsedConfig,
    analysis: &UserAnalysis,
    path: &Path,
) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if matches!(analysis.location, TargetLocation::Implicit) {
        sources.push(configured_source(
            "https://hackage.haskell.org",
            Some(HACKAGE_UPSTREAM),
            "implicit-hackage",
            HACKAGE_REPOSITORY,
            path,
        ));
    }
    for repository in &parsed.repositories {
        if repository.name.eq_ignore_ascii_case(HACKAGE_REPOSITORY) {
            sources.push(configured_source(
                normalized_public_hackage(&repository.url)
                    .as_deref()
                    .unwrap_or("unreviewed-hackage"),
                Some(HACKAGE_UPSTREAM),
                "repository-stanza",
                &repository.name,
                path,
            ));
        } else {
            sources.push(configured_source(
                &format!("cabal-private-repository:{}", repository.name),
                None,
                "private-repository",
                &repository.name,
                path,
            ));
        }
    }
    for repository in &parsed.legacy_repositories {
        if repository.name.eq_ignore_ascii_case(HACKAGE_REPOSITORY) {
            sources.push(configured_source(
                normalized_public_hackage(&repository.url)
                    .as_deref()
                    .unwrap_or("unreviewed-hackage"),
                Some(HACKAGE_UPSTREAM),
                "legacy-remote-repo",
                &repository.name,
                path,
            ));
        } else {
            sources.push(configured_source(
                &format!("cabal-private-repository:{}", repository.name),
                None,
                "private-remote-repo",
                &repository.name,
                path,
            ));
        }
    }
    if let Some(active) = &parsed.active_repositories {
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: "cabal-policy:active-repositories".into(),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["active-repositories".into()]),
                ("entries".into(), active.clone()),
                ("path".into(), vec![path.display().to_string()]),
            ]),
        });
    }
    sources
}

fn project_sources(project: &ParsedDocument) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(active) = &project.parsed.active_repositories {
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: "cabal-project-policy:active-repositories".into(),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["project-active-repositories".into()]),
                ("entries".into(), active.clone()),
                ("path".into(), vec![project.path.display().to_string()]),
            ]),
        });
    }
    sources
}

fn configured_source(
    url: &str,
    upstream_id: Option<&str>,
    kind: &str,
    name: &str,
    path: &Path,
) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: upstream_id.map(str::to_owned),
        url: url.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("repository".into(), vec![name.into()]),
            ("path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn rewrite_user_config(
    text: &str,
    location: &TargetLocation,
    endpoint: &str,
) -> Result<String, AdapterError> {
    match location {
        TargetLocation::Repository {
            url_range,
            trust_insertion,
            field_indent,
            add_secure,
            add_root_keys,
        } => {
            if url_range.end > text.len()
                || url_range.start > url_range.end
                || *trust_insertion > text.len()
            {
                return Err(AdapterError::InvalidConfiguration(
                    "Cabal URL replacement range is invalid".into(),
                ));
            }
            let mut edits = vec![(url_range.clone(), endpoint.to_owned())];
            if *add_secure || *add_root_keys {
                let mut trust = String::new();
                if *trust_insertion > 0 && !text[..*trust_insertion].ends_with('\n') {
                    trust.push_str(newline(text));
                }
                trust.push_str(&render_trust_fields(
                    field_indent,
                    newline(text),
                    *add_secure,
                    *add_root_keys,
                ));
                edits.push((*trust_insertion..*trust_insertion, trust));
            }
            edits.sort_by_key(|edit| std::cmp::Reverse(edit.0.start));
            let mut rendered = text.to_owned();
            for (range, replacement) in edits {
                rendered = replace_range(&rendered, range, &replacement);
            }
            Ok(rendered)
        }
        TargetLocation::Legacy {
            url_range,
            line_range,
        } => {
            if url_range.end > text.len()
                || line_range.end > text.len()
                || line_range.start > url_range.start
                || url_range.end > line_range.end
            {
                return Err(AdapterError::InvalidConfiguration(
                    "Cabal legacy repository replacement range is invalid".into(),
                ));
            }
            let line = &text[line_range.clone()];
            let ending = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            let suffix_end = line_range.end - ending.len();
            let suffix = &text[url_range.end..suffix_end];
            let rendered = render_hackage_stanza(endpoint, newline(text), suffix);
            Ok(replace_range(text, line_range.clone(), &rendered))
        }
        TargetLocation::Implicit => {
            let mut rendered = text.to_owned();
            if !rendered.is_empty() && !rendered.ends_with('\n') {
                rendered.push('\n');
            }
            if !rendered.is_empty() && !rendered.ends_with("\n\n") {
                rendered.push('\n');
            }
            rendered.push_str(&render_hackage_stanza(endpoint, newline(text), ""));
            Ok(rendered)
        }
    }
}

fn render_verification_config(endpoint: &str, directory: &Path) -> String {
    format!(
        "{repository}active-repositories: {HACKAGE_REPOSITORY}\nremote-repo-cache: {packages}\nstore-dir: {store}\nlogs-dir: {logs}\n",
        repository = render_hackage_stanza(endpoint, "\n", ""),
        packages = directory.join("packages").display(),
        store = directory.join("store").display(),
        logs = directory.join("logs").display(),
    )
}

fn render_hackage_stanza(endpoint: &str, newline: &str, url_suffix: &str) -> String {
    format!(
        "repository {HACKAGE_REPOSITORY}{newline}  url: {endpoint}{url_suffix}{newline}{}{newline}",
        render_trust_fields("  ", newline, true, true).trim_end_matches(['\r', '\n'])
    )
}

fn render_trust_fields(
    indent: &str,
    newline: &str,
    add_secure: bool,
    add_root_keys: bool,
) -> String {
    let mut rendered = String::new();
    if add_secure {
        rendered.push_str(&format!("{indent}secure: True{newline}"));
    }
    if add_root_keys {
        rendered.push_str(&format!(
            "{indent}root-keys: {}{newline}{indent}key-threshold: {HACKAGE_KEY_THRESHOLD}{newline}",
            HACKAGE_ROOT_KEYS.join(", ")
        ));
    }
    rendered
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&'static str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "cabal"
        || selections[0].upstream_id != HACKAGE_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Cabal requires exactly one Hackage selection".into(),
        ));
    }
    let selection = &selections[0];
    let metadata = unique_endpoint(selection, EndpointRole::Metadata)?;
    let index = unique_endpoint(selection, EndpointRole::Index)?;
    let artifacts = unique_endpoint(selection, EndpointRole::Artifacts)?;
    let expected = REVIEWED_ENDPOINTS
        .iter()
        .find(|(provider, _)| *provider == selection.provider_id)
        .map(|(_, endpoint)| *endpoint)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Cabal selection uses an unreviewed Hackage provider".into(),
            )
        })?;
    if [metadata, index, artifacts]
        .iter()
        .any(|endpoint| normalized_url(endpoint).as_deref() != Some(expected))
    {
        return Err(AdapterError::InvalidConfiguration(
            "Cabal metadata, index and artifact endpoints are not one reviewed Hackage root".into(),
        ));
    }
    Ok(expected)
}

fn unique_endpoint(selection: &MirrorSelection, role: EndpointRole) -> Result<&str, AdapterError> {
    let endpoints = selection
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
        .collect::<Vec<_>>();
    if endpoints.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Cabal selection requires exactly one {role:?} HTTPS endpoint"
        )));
    }
    Ok(&endpoints[0].url)
}

fn normalized_public_hackage(value: &str) -> Option<String> {
    let normalized = normalized_url(value)?;
    if normalized == "http://hackage.haskell.org"
        || normalized == "https://hackage.haskell.org"
        || normalized == "http://hackage.haskell.org/packages/archive"
        || normalized == "https://hackage.haskell.org/packages/archive"
        || normalized == "http://www.hackage.haskell.org"
        || normalized == "https://www.hackage.haskell.org"
    {
        return Some("https://hackage.haskell.org".into());
    }
    REVIEWED_ENDPOINTS
        .iter()
        .map(|(_, endpoint)| *endpoint)
        .find(|endpoint| *endpoint == normalized)
        .map(str::to_owned)
}

fn is_reviewed_mirror(value: &str) -> bool {
    REVIEWED_ENDPOINTS
        .iter()
        .any(|(_, endpoint)| *endpoint == value)
}

fn normalized_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.contains('?') || value.contains('#') || value.contains(char::is_whitespace) {
        return None;
    }
    let (scheme, remainder) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, ""), |(authority, path)| (authority, path));
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let path = path.trim_matches('/');
    Some(if path.is_empty() {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}/{path}")
    })
}

fn reviewed_cabal_version(version: &str) -> Result<(), AdapterError> {
    let (major, minor, _) = version_components(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("could not parse cabal-install version {version}"))
    })?;
    if (major == 2 && minor >= 4) || (major == 3 && minor <= 16) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "cabal-install {version} is outside the reviewed 2.4 through 3.16 range"
        )))
    }
}

fn reviewed_ghc_version(version: &str) -> Result<(), AdapterError> {
    let (major, _, _) = version_components(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("could not parse GHC version {version}"))
    })?;
    if matches!(major, 8 | 9) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "GHC {version} is outside the reviewed 8.x/9.x range"
        )))
    }
}

fn version_components(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.any(|part| part.parse::<u64>().is_err()) {
        return None;
    }
    Some((major, minor, patch))
}

fn run_program(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let output = match directory {
        Some(directory) => runtime.run_in(directory, program, &arguments),
        None => runtime.run(program, &arguments),
    }?;
    output_text(output, operation)
}

fn output_text(output: Output, operation: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with {}: {}{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|error| {
        AdapterError::Runtime(format!("{operation} returned non-UTF-8 output: {error}"))
    })?;
    Ok(stdout.trim().to_owned())
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    message: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Err(AdapterError::Verification(format!(
        "{message}; configuration restored: {}",
        restored.verified
    )))
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os == OperatingSystem::Linux {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(
            "Cabal adapter is limited to Linux in v0.1".into(),
        ))
    }
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope == ConfigurationScope::User {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(
            "Cabal adapter supports only user scope".into(),
        ))
    }
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "cabal" && current.scope == ConfigurationScope::User {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "Cabal operation received another tool or scope".into(),
        ))
    }
}

fn validate_user_path(home: &Path, path: &Path, label: &str) -> Result<(), AdapterError> {
    validate_path(path, label)?;
    if !path.is_absolute() || !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "{label} {} is outside user home {}",
            path.display(),
            home.display()
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, label: &str) -> Result<(), AdapterError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<String, AdapterError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("non-UTF-8 path {}", path.display())))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("{} is not UTF-8: {error}", path.display()))
    })
}

fn replace_range(text: &str, range: Range<usize>, replacement: &str) -> String {
    let mut rendered = String::with_capacity(text.len() - range.len() + replacement.len());
    rendered.push_str(&text[..range.start]);
    rendered.push_str(replacement);
    rendered.push_str(&text[range.end..]);
    rendered
}

fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        return path.to_path_buf();
    }
    root.join(path.strip_prefix("/").unwrap_or(path))
}
