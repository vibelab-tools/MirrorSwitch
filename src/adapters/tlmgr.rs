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

const UPSTREAM: &str = "ctan--language-registry";
const RELEASE: &str = "2026";
const ALIYUN: &str = "https://mirrors.aliyun.com/CTAN/systems/texlive/tlnet";
const HUAWEI: &str = "https://repo.huaweicloud.com/CTAN/systems/texlive/tlnet";
const NJU: &str = "https://mirrors.nju.edu.cn/CTAN/systems/texlive/tlnet";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/CTAN/systems/texlive/tlnet";
const REVIEWED: &[&str] = &[ALIYUN, HUAWEI, NJU, TUNA];
const OFFICIAL: &str = "https://mirror.ctan.org/systems/texlive/tlnet";

#[derive(Clone, Copy, Debug, Default)]
pub struct TlmgrAdapter;

impl Adapter for TlmgrAdapter {
    fn key(&self) -> &'static str {
        "tlmgr"
    }

    fn tool_id(&self) -> &'static str {
        "tlmgr"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System, ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
    }

    fn default_scope_for(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        detected: &DetectedTool,
    ) -> Result<ConfigurationScope, AdapterError> {
        require_supported_context(context)?;
        if detected.tool_id != "tlmgr" {
            return Err(AdapterError::InvalidConfiguration(
                "tlmgr scope selection received another tool's detection result".into(),
            ));
        }
        let installation = inspect_installation(context, runtime)?;
        let paths = scope_paths(runtime, &installation)?;
        Ok(if runtime.read(&paths.user)?.is_some() {
            ConfigurationScope::User
        } else {
            ConfigurationScope::System
        })
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
        if !runtime.command_exists("tlmgr") {
            return Ok(None);
        }
        if !runtime.command_exists("kpsewhich") {
            return Err(AdapterError::Unsupported(
                "tlmgr scope discovery requires kpsewhich".into(),
            ));
        }
        let installation = inspect_installation(context, runtime)?;
        let paths = scope_paths(runtime, &installation)?;
        let system = runtime.read(&paths.system)?.ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "tlmgr installation database {} is missing",
                paths.system.display()
            ))
        })?;
        let parsed = parse_tlpdb(utf8(&paths.system, &system)?, &paths.system)?;
        require_tlpdb_release(&parsed, &installation, ConfigurationScope::System)?;
        let observed_main = repository_main(runtime, ConfigurationScope::System)?;
        if !same_endpoint(&parsed.repositories[parsed.main_index].url, &observed_main) {
            return Err(AdapterError::Conflict(
                "tlmgr repository command and system TLPDB disagree about the main repository"
                    .into(),
            ));
        }
        let user_initialized = runtime.read(&paths.user)?.is_some();
        Ok(Some(DetectedTool {
            tool_id: "tlmgr".into(),
            executable: Some(PathBuf::from("tlmgr")),
            version: Some(installation.release.clone()),
            evidence: vec![
                format!("TeX Live {}", installation.release),
                format!("tlmgr revision {}", installation.revision),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                runtime.home_dir().map_or_else(
                    || "no user home was selected".into(),
                    |path| format!("selected user home is {}", path.display()),
                ),
                runtime.project_dir().map_or_else(
                    || "no project directory was selected".into(),
                    |path| format!("project directory {} remains read-only", path.display()),
                ),
                format!("TeX Live platform {}", installation.platform),
                format!("installation root is {}", installation.root.display()),
                format!("system main repository is {}", public_state(&observed_main)),
                format!("tlmgr user tree initialized: {user_initialized}"),
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
        require_supported_context(context)?;
        require_scope(scope)?;
        if detected.tool_id != "tlmgr" {
            return Err(AdapterError::InvalidConfiguration(
                "tlmgr read received another tool's detection result".into(),
            ));
        }
        let installation = inspect_installation(context, runtime)?;
        if detected.version.as_deref() != Some(installation.release.as_str()) {
            return Err(AdapterError::Conflict(
                "TeX Live release changed after detection".into(),
            ));
        }
        let paths = scope_paths(runtime, &installation)?;
        let path = match scope {
            ConfigurationScope::System => paths.system,
            ConfigurationScope::User => paths.user,
            _ => unreachable!("validated scope"),
        };
        let contents = runtime.read(&path)?.ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "{} tlmgr tree is not initialized at {}",
                scope_name(scope),
                path.display()
            ))
        })?;
        let parsed = parse_tlpdb(utf8(&path, &contents)?, &path)?;
        require_tlpdb_release(&parsed, &installation, scope)?;
        let observed_main = repository_main(runtime, scope)?;
        let main = &parsed.repositories[parsed.main_index];
        let mut sources = vec![if is_public(&main.url) {
            configured_source(&main.url, "replaceable-main", &path)
        } else {
            policy_source("private-main", &path)
        }];
        for repository in parsed
            .repositories
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != parsed.main_index)
            .map(|(_, repository)| repository)
        {
            sources.push(custom_source(repository, &path));
        }
        if !same_endpoint(&main.url, &observed_main) {
            sources.push(policy_source("runtime-mismatch", &path));
        }
        for option in &parsed.preserved_options {
            sources.push(snapshot_source("signature-option-preserved", option));
        }
        sources.push(snapshot_source("texlive-release", &installation.release));
        sources.push(snapshot_source("texlive-platform", &installation.platform));
        Ok(CurrentConfiguration {
            tool_id: "tlmgr".into(),
            scope,
            files: vec![path.clone()],
            sources,
            documents: vec![ConfigurationDocument {
                path,
                format: "texlive-tlpdb".into(),
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
        if detected.version.as_deref() != Some(RELEASE) {
            return Err(AdapterError::Unsupported(
                "only TeX Live 2026 has reviewed rolling CTAN candidates".into(),
            ));
        }
        let platform = current_snapshot_value(current, "texlive-platform")?;
        let platform_sha = platform_archive_sha(platform)?;
        Ok(SelectionRequest {
            tool_id: "tlmgr".into(),
            adapter_key: "tlmgr".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::from([(UPSTREAM.into(), RELEASE.into())]),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("texlive_platform".into(), platform.into()),
                    ("texlive_platform_sha".into(), platform_sha.into()),
                ])],
            )]),
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
        require_supported_context(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let document = find_tlpdb(current)?;
        let text = utf8(&document.path, &document.contents)?;
        let parsed = parse_tlpdb(text, &document.path)?;
        let mut rendered = rewrite_main(text, &parsed, &endpoint).into_bytes();
        if document.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let changes = if rendered == document.contents {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: "replace only the TeX Live main repository token while preserving tags, custom repositories, pinning identity and verification options".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "tlmgr".into(),
            tool_id: "tlmgr".into(),
            scope: current.scope,
            changes,
            requires_elevation: current.scope == ConfigurationScope::System,
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
            let installation = inspect_installation(context, runtime)?;
            let paths = scope_paths(runtime, &installation)?;
            let matching = [
                (ConfigurationScope::System, paths.system),
                (ConfigurationScope::User, paths.user),
            ]
            .into_iter()
            .filter(|(_, path)| {
                receipt
                    .changed_targets
                    .contains(&rooted(&context.root, path))
            })
            .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(AdapterError::Verification(
                    "tlmgr transaction receipt must contain exactly one known TLPDB".into(),
                ));
            }
            let (scope, path) = &matching[0];
            let contents = runtime.read(path)?.ok_or_else(|| {
                AdapterError::Verification("tlmgr TLPDB disappeared after apply".into())
            })?;
            let parsed = parse_tlpdb(utf8(path, &contents)?, path)?;
            require_tlpdb_release(&parsed, &installation, *scope)?;
            let endpoint = parsed.repositories[parsed.main_index].url.clone();
            if !is_reviewed(&endpoint) {
                return Err(AdapterError::Verification(
                    "tlmgr main repository is not a reviewed current tlnet endpoint".into(),
                ));
            }
            let observed = repository_main(runtime, *scope)?;
            if !same_endpoint(&endpoint, &observed) {
                return Err(AdapterError::Verification(
                    "tlmgr repository list did not load the selected main repository".into(),
                ));
            }
            let info = run_tlmgr(
                runtime,
                *scope,
                Some(&endpoint),
                &["info", "texlive.infra"],
                "tlmgr remote package query",
            )?;
            if !info.lines().any(|line| {
                line.trim_start()
                    .strip_prefix("package:")
                    .is_some_and(|value| value.trim() == "texlive.infra")
            }) {
                return Err(AdapterError::Verification(
                    "tlmgr remote query did not return texlive.infra".into(),
                ));
            }
            let platforms = run_tlmgr(
                runtime,
                ConfigurationScope::System,
                Some(&endpoint),
                &["platform", "list"],
                "tlmgr remote platform query",
            )?;
            if !platforms
                .lines()
                .map(str::trim)
                .map(|line| line.strip_prefix("(i) ").unwrap_or(line))
                .any(|line| line == installation.platform)
            {
                return Err(AdapterError::Verification(format!(
                    "tlmgr remote repository lacks platform {}",
                    installation.platform
                )));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "tlmgr loaded TeX Live {RELEASE} texlive.infra and {} through {endpoint}",
                    installation.platform
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
                "restored {} tlmgr database files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug)]
struct Installation {
    release: String,
    revision: String,
    root: PathBuf,
    platform: String,
    texmfhome: PathBuf,
}

#[derive(Debug)]
struct ScopePaths {
    system: PathBuf,
    user: PathBuf,
}

#[derive(Clone, Debug)]
struct Repository {
    url: String,
    tag: Option<String>,
}

#[derive(Debug)]
struct ParsedTlpdb {
    release: Option<String>,
    location_line: Range<usize>,
    repositories: Vec<Repository>,
    main_index: usize,
    preserved_options: Vec<String>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "tlmgr on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "tlmgr on Windows arm64 is unavailable because TeX Live 2026 publishes no native Windows arm64 platform package"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "tlmgr requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if !matches!(scope, ConfigurationScope::System | ConfigurationScope::User) {
        return Err(AdapterError::Unsupported(
            "tlmgr adapter supports system and initialized user scopes only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    require_scope(current.scope)?;
    if current.tool_id != "tlmgr" {
        return Err(AdapterError::InvalidConfiguration(
            "tlmgr operation received another tool".into(),
        ));
    }
    Ok(())
}

fn inspect_installation(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<Installation, AdapterError> {
    let version = run_tlmgr(
        runtime,
        ConfigurationScope::System,
        None,
        &["--version"],
        "tlmgr --version",
    )?;
    let release = version
        .lines()
        .find_map(|line| line.rsplit_once(" version ").map(|(_, value)| value.trim()))
        .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
        .ok_or_else(|| AdapterError::Unsupported("tlmgr release output is unrecognized".into()))?
        .to_owned();
    if release != RELEASE {
        return Err(AdapterError::Unsupported(format!(
            "TeX Live {release} cannot use the reviewed rolling {RELEASE} tlnet repositories"
        )));
    }
    let revision = version
        .lines()
        .find_map(|line| line.strip_prefix("tlmgr revision "))
        .and_then(|value| value.split_whitespace().next())
        .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
        .ok_or_else(|| AdapterError::Unsupported("tlmgr revision output is unrecognized".into()))?
        .to_owned();
    let root = version
        .lines()
        .find_map(|line| line.strip_prefix("tlmgr using installation: "))
        .map(PathBuf::from)
        .ok_or_else(|| AdapterError::Unsupported("tlmgr installation root is missing".into()))?;
    validate_path(&root, "installation root")?;
    let platform = run_tlmgr(
        runtime,
        ConfigurationScope::System,
        None,
        &["print-platform"],
        "tlmgr print-platform",
    )?;
    let platform = platform.trim().to_owned();
    let allowed = match (context.os, context.architecture) {
        (OperatingSystem::Linux, Architecture::X86_64) => {
            ["x86_64-linux", "x86_64-linuxmusl"].as_slice()
        }
        (OperatingSystem::Linux, Architecture::Arm64) => ["aarch64-linux"].as_slice(),
        (OperatingSystem::Macos, _) => ["universal-darwin"].as_slice(),
        (OperatingSystem::Windows, Architecture::X86_64) => ["windows"].as_slice(),
        (OperatingSystem::Windows, Architecture::Arm64) => {
            unreachable!("Windows arm64 is rejected before tlmgr installation inspection")
        }
    };
    if !allowed.contains(&platform.as_str()) {
        return Err(AdapterError::Unsupported(format!(
            "TeX Live platform {platform} is not reviewed for {:?}",
            context.architecture
        )));
    }
    let texmfhome = command_output(
        runtime.run("kpsewhich", &["-var-value=TEXMFHOME".into()])?,
        "kpsewhich TEXMFHOME",
    )?;
    let texmfhome = PathBuf::from(texmfhome.trim());
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("tlmgr requires a user home".into()))?;
    validate_user_path(&texmfhome, &home, "TEXMFHOME")?;
    Ok(Installation {
        release,
        revision,
        root,
        platform,
        texmfhome,
    })
}

fn scope_paths(
    _runtime: &dyn Runtime,
    installation: &Installation,
) -> Result<ScopePaths, AdapterError> {
    let system = installation.root.join("tlpkg/texlive.tlpdb");
    let user = installation.texmfhome.join("tlpkg/texlive.tlpdb");
    validate_path(&system, "system TLPDB")?;
    validate_path(&user, "user TLPDB")?;
    Ok(ScopePaths { system, user })
}

fn run_tlmgr(
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
    repository: Option<&str>,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let mut command = Vec::new();
    if scope == ConfigurationScope::User {
        command.push("--usermode".into());
    }
    if let Some(repository) = repository {
        command.push("--repository".into());
        command.push(repository.into());
    }
    command.extend(arguments.iter().map(|argument| (*argument).into()));
    command_output(runtime.run("tlmgr", &command)?, label)
}

fn repository_main(
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<String, AdapterError> {
    let output = run_tlmgr(
        runtime,
        scope,
        None,
        &["repository", "list"],
        "tlmgr repository list",
    )?;
    let main = output
        .lines()
        .filter_map(|line| line.trim().strip_suffix(" (main)"))
        .map(str::trim)
        .collect::<Vec<_>>();
    if main.len() != 1 {
        return Err(AdapterError::Unsupported(
            "tlmgr repository list must report exactly one main repository".into(),
        ));
    }
    Ok(main[0].into())
}

fn parse_tlpdb(text: &str, path: &Path) -> Result<ParsedTlpdb, AdapterError> {
    let blocks = block_ranges(text);
    let configuration = blocks
        .iter()
        .filter(|range| {
            text[(**range).clone()]
                .lines()
                .next()
                .is_some_and(|line| line.trim_end_matches('\r') == "name 00texlive.config")
        })
        .cloned()
        .collect::<Vec<_>>();
    if configuration.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} contains duplicate 00texlive.config blocks",
            path.display()
        )));
    }
    let release = configuration
        .first()
        .map(|block| {
            let releases = text[block.clone()]
                .lines()
                .filter_map(|line| line.trim_end_matches('\r').strip_prefix("depend release/"))
                .filter(|release| {
                    !release.is_empty()
                        && release.chars().all(|character| character.is_ascii_digit())
                })
                .collect::<Vec<_>>();
            if releases.len() != 1 {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "{} must declare exactly one numeric TeX Live release",
                    path.display()
                )));
            }
            Ok(releases[0].to_owned())
        })
        .transpose()?;
    let installation = blocks
        .into_iter()
        .filter(|range| {
            text[range.clone()]
                .lines()
                .next()
                .is_some_and(|line| line.trim_end_matches('\r') == "name 00texlive.installation")
        })
        .collect::<Vec<_>>();
    if installation.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} must contain exactly one 00texlive.installation block",
            path.display()
        )));
    }
    let block = installation[0].clone();
    let mut locations = Vec::new();
    let mut preserved_options = Vec::new();
    for (relative, line) in line_spans(&text[block.clone()]) {
        let line_without_newline = line.trim_end_matches(['\r', '\n']);
        if let Some(value) = line_without_newline.strip_prefix("depend opt_location:") {
            locations.push((
                block.start + relative..block.start + relative + line_without_newline.len(),
                value,
            ));
        }
        if line_without_newline.starts_with("depend opt_verify_downloads:")
            || line_without_newline.starts_with("depend opt_require_verification:")
        {
            preserved_options.push(line_without_newline.into());
        }
    }
    if locations.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} must contain exactly one opt_location setting",
            path.display()
        )));
    }
    let (location_line, value) = locations.remove(0);
    let repositories = parse_repositories(value)?;
    let main = repositories
        .iter()
        .enumerate()
        .filter(|(_, repository)| repository.tag.as_deref() == Some("main"))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let main_index = match (repositories.as_slice(), main.as_slice()) {
        ([_], []) if repositories[0].tag.is_none() => 0,
        (_, [index])
            if repositories
                .iter()
                .all(|repository| repository.tag.is_some()) =>
        {
            *index
        }
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "tlmgr opt_location must have one untagged repository or exactly one tagged main repository"
                    .into(),
            ));
        }
    };
    Ok(ParsedTlpdb {
        release,
        location_line,
        repositories,
        main_index,
        preserved_options,
    })
}

fn require_tlpdb_release(
    parsed: &ParsedTlpdb,
    installation: &Installation,
    scope: ConfigurationScope,
) -> Result<(), AdapterError> {
    if scope == ConfigurationScope::System && parsed.release.is_none() {
        return Err(AdapterError::InvalidConfiguration(
            "system TLPDB does not declare its TeX Live release".into(),
        ));
    }
    if parsed
        .release
        .as_deref()
        .is_some_and(|release| release != installation.release)
    {
        return Err(AdapterError::Conflict(format!(
            "TLPDB release {} does not match tlmgr release {}",
            parsed.release.as_deref().unwrap_or("<missing>"),
            installation.release
        )));
    }
    Ok(())
}

fn parse_repositories(value: &str) -> Result<Vec<Repository>, AdapterError> {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "tlmgr opt_location is empty".into(),
        ));
    }
    tokens
        .into_iter()
        .map(|token| {
            let (url, tag) = match token.rsplit_once('#') {
                Some((url, tag))
                    if !url.contains('#')
                        && !tag.is_empty()
                        && tag.chars().all(|character| {
                            character.is_ascii_alphanumeric()
                                || matches!(character, '-' | '_' | '.')
                        }) =>
                {
                    (url, Some(tag.to_owned()))
                }
                Some(_) => {
                    return Err(AdapterError::InvalidConfiguration(
                        "tlmgr repository tag is unsafe or ambiguous".into(),
                    ));
                }
                None => (token, None),
            };
            if url.is_empty() {
                return Err(AdapterError::InvalidConfiguration(
                    "tlmgr repository URL is empty".into(),
                ));
            }
            Ok(Repository {
                url: url.into(),
                tag,
            })
        })
        .collect()
}

fn block_ranges(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (offset, line) in line_spans(text) {
        if line.trim().is_empty() {
            if let Some(begin) = start.take() {
                ranges.push(begin..offset);
            }
        } else if start.is_none() {
            start = Some(offset);
        }
    }
    if let Some(begin) = start {
        ranges.push(begin..text.len());
    }
    ranges
}

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
}

fn rewrite_main(text: &str, parsed: &ParsedTlpdb, endpoint: &str) -> String {
    let mut repositories = parsed.repositories.clone();
    repositories[parsed.main_index].url = endpoint.into();
    let rendered = repositories
        .into_iter()
        .map(|repository| match repository.tag {
            Some(tag) => format!("{}#{tag}", repository.url),
            None => repository.url,
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{}depend opt_location:{}{}",
        &text[..parsed.location_line.start],
        rendered,
        &text[parsed.location_line.end..]
    )
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-main" => {
                return Err(AdapterError::Unsupported(
                    "tlmgr main repository is private, authenticated, local, or unreviewed".into(),
                ));
            }
            "runtime-mismatch" => {
                return Err(AdapterError::Conflict(
                    "tlmgr repository command and selected TLPDB disagree".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "tlmgr" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "tlmgr requires exactly one CTAN tlnet selection".into(),
        ));
    }
    let selection = matches[0];
    let mut endpoints = BTreeSet::new();
    for role in [
        EndpointRole::Index,
        EndpointRole::Metadata,
        EndpointRole::Artifacts,
    ] {
        let matches = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "tlmgr selection requires one HTTPS {role:?} endpoint"
            )));
        }
        endpoints.insert(normalized_endpoint(&matches[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("tlmgr {role:?} endpoint is unsafe"))
        })?);
    }
    if endpoints.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "tlmgr index, metadata, and artifacts must share one tlnet endpoint".into(),
        ));
    }
    let endpoint = endpoints.into_iter().next().expect("one endpoint");
    let provider = match endpoint.as_str() {
        ALIYUN => "aliyun",
        HUAWEI => "huaweicloud",
        NJU => "nju",
        TUNA => "tuna",
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "tlmgr tlnet endpoint is not reviewed".into(),
            ));
        }
    };
    if selection.provider_id != provider {
        return Err(AdapterError::InvalidConfiguration(
            "tlmgr provider and tlnet endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn normalized_endpoint(value: &str) -> Option<String> {
    let mut parsed = reqwest::Url::parse(value).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let path = parsed.path().trim_end_matches('/').to_owned();
    parsed.set_path(&path);
    Some(parsed.to_string().trim_end_matches('/').to_owned())
}

fn same_endpoint(left: &str, right: &str) -> bool {
    normalized_endpoint(left)
        .is_some_and(|left| normalized_endpoint(right).as_deref() == Some(&left))
}

fn is_reviewed(value: &str) -> bool {
    normalized_endpoint(value).is_some_and(|value| REVIEWED.contains(&value.as_str()))
}

fn is_public(value: &str) -> bool {
    is_reviewed(value) || normalized_endpoint(value).is_some_and(|value| value == OFFICIAL)
}

fn public_state(value: &str) -> &'static str {
    if is_public(value) { "public" } else { "custom" }
}

fn configured_source(value: &str, kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
        url: normalized_endpoint(value).unwrap_or_else(|| "<preserved>".into()),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn custom_source(repository: &Repository, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["custom-repository-preserved".into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            (
                "tag".into(),
                vec![repository.tag.as_deref().unwrap_or("<untagged>").into()],
            ),
        ]),
    }
}

fn policy_source(kind: &str, path: &Path) -> ConfiguredSource {
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

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("tlmgr-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn current_snapshot_value<'a>(
    current: &'a CurrentConfiguration,
    kind: &str,
) -> Result<&'a str, AdapterError> {
    let matches = current
        .sources
        .iter()
        .filter(|source| {
            source
                .metadata
                .get("kind")
                .is_some_and(|values| values.as_slice() == [kind])
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "tlmgr current configuration must contain one {kind} snapshot"
        )));
    }
    matches[0]
        .url
        .strip_prefix("tlmgr-snapshot:")
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "tlmgr {kind} snapshot has an invalid value"
            ))
        })
}

fn platform_archive_sha(platform: &str) -> Result<&'static str, AdapterError> {
    match platform {
        "x86_64-linux" => Ok("168ce3c58aa35cafaa38e1defb3c3e26553473b35951d64bf54b5b2f00fd086f"),
        "x86_64-linuxmusl" => {
            Ok("bd32c86e19c774b7715824fceab5fe92ca33f6110e8d9d84fc62589249d581ba")
        }
        "aarch64-linux" => Ok("01ad1b1457f65d4717b969b7ca27e08a559831d2c0658581b9659cf93c3c10ff"),
        "universal-darwin" => {
            Ok("be0ea467f6cfd4e077da2688b020e3a50f5480b4cf489706495d2324662e5d3e")
        }
        "windows" => Ok("297273a72f454b632ee6fde6b645a938766de33355b6e0923a794b03c0c1327a"),
        _ => Err(AdapterError::Unsupported(format!(
            "TeX Live platform {platform} has no reviewed infrastructure archive"
        ))),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("tlmgr source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "tlmgr source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn find_tlpdb(current: &CurrentConfiguration) -> Result<&ConfigurationDocument, AdapterError> {
    let documents = current
        .documents
        .iter()
        .filter(|document| document.format == "texlive-tlpdb")
        .collect::<Vec<_>>();
    if documents.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "tlmgr current configuration must contain exactly one TLPDB".into(),
        ));
    }
    Ok(documents[0])
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

fn scope_name(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::System => "system",
        ConfigurationScope::User => "user",
        _ => "unsupported",
    }
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "tlmgr {kind} {} is outside the user home",
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
            "tlmgr reported unsafe {kind} path {}",
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
            "tlmgr configuration {} is not UTF-8",
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
