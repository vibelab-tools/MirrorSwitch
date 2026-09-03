use std::{
    collections::BTreeMap,
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

const RUBYGEMS_UPSTREAM: &str = "rubygems--language-registry";
const REVIEWED_GEM: &str = "net-protocol";
const REVIEWED_VERSION: &str = "0.3.0";
const REVIEWED_DEPENDENCY: &str = "timeout (>= 0)";
const CONFIG_PATH_SCRIPT: &str = "print Gem.configuration.config_file_name";
const MIRROR_SOURCES: &[&str] = &[
    "https://mirrors.aliyun.com/rubygems",
    "https://mirrors.nju.edu.cn/rubygems",
    "https://mirrors.tuna.tsinghua.edu.cn/rubygems",
    "https://mirrors.ustc.edu.cn/rubygems",
];
const REPLACEABLE_PUBLIC_SOURCES: &[&str] = &[
    "https://rubygems.org",
    "http://rubygems.org",
    "http://gems.rubyforge.org",
    "https://mirrors.aliyun.com/rubygems",
    "https://repo.huaweicloud.com/repository/rubygems",
    "https://mirrors.nju.edu.cn/rubygems",
    "https://mirrors.tuna.tsinghua.edu.cn/rubygems",
    "https://mirrors.ustc.edu.cn/rubygems",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct RubyGemsAdapter;

impl Adapter for RubyGemsAdapter {
    fn key(&self) -> &'static str {
        "rubygems"
    }

    fn tool_id(&self) -> &'static str {
        "rubygems"
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
        if !runtime.command_exists("ruby") || !runtime.command_exists("gem") {
            return Ok(None);
        }
        let user_home = runtime.home_dir().ok_or_else(|| {
            AdapterError::Unsupported("RubyGems requires a detected user home".into())
        })?;
        validate_path(&user_home, "user home")?;
        let project = runtime.project_dir();
        if let Some(project) = &project {
            validate_path(project, "project directory")?;
        }
        let snapshot = gem_snapshot(runtime)?;
        reviewed_versions(&snapshot.ruby_version, &snapshot.rubygems_version)?;
        let public_count = snapshot
            .sources
            .iter()
            .filter(|source| is_replaceable_public(source))
            .count();
        Ok(Some(DetectedTool {
            tool_id: "rubygems".into(),
            executable: Some(PathBuf::from("gem")),
            version: Some(snapshot.rubygems_version.clone()),
            evidence: vec![
                format!("Ruby {}", snapshot.ruby_version),
                format!("RubyGems {}", snapshot.rubygems_version),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                format!("selected user home is {}", user_home.display()),
                project.map_or_else(
                    || {
                        "no project directory was selected; project Gemfile remains read-only"
                            .into()
                    },
                    |path| format!("project directory {} remains read-only", path.display()),
                ),
                format!("gem home is {}", snapshot.gem_home.display()),
                format!(
                    "gem sources reports {} ordered source(s), including {public_count} recognized public source(s)",
                    snapshot.sources.len()
                ),
                format!("user configuration is {}", snapshot.config_path.display()),
                format!(
                    "credentials remain in {}",
                    snapshot.credentials_path.display()
                ),
                format!(
                    "gem cert inventory was queried and remains read-only ({} non-empty output line(s))",
                    snapshot.certificate_inventory_lines
                ),
                format!(
                    "GEMRC process override is {}",
                    if gemrc_override(runtime) {
                        "set"
                    } else {
                        "unset"
                    }
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
        require_supported_context(context)?;
        require_scope(scope)?;
        if detected.tool_id != "rubygems" {
            return Err(AdapterError::InvalidConfiguration(
                "RubyGems read received another tool's detection result".into(),
            ));
        }
        let snapshot = gem_snapshot(runtime)?;
        reviewed_versions(&snapshot.ruby_version, &snapshot.rubygems_version)?;
        if detected.version.as_deref() != Some(snapshot.rubygems_version.as_str()) {
            return Err(AdapterError::Conflict(
                "RubyGems version changed after detection".into(),
            ));
        }
        validate_user_path(runtime, &snapshot.config_path)?;
        let observed = runtime.read(&snapshot.config_path)?;
        let exists = observed.is_some();
        let contents = observed.unwrap_or_default();
        let text = utf8(&snapshot.config_path, &contents)?;
        let parsed = parse_gemrc_sources(text, &snapshot.config_path)?;
        if let Some(parsed) = &parsed {
            ensure_same_sources(&parsed.values(), &snapshot.sources)?;
        } else if snapshot.sources.len() != 1 || !is_replaceable_public(&snapshot.sources[0]) {
            return Err(AdapterError::Unsupported(
                "RubyGems has no simple user :sources block, while effective system/default sources cannot be copied safely"
                    .into(),
            ));
        }

        let origin = if parsed.is_some() {
            "user-gemrc"
        } else {
            "effective-default"
        };
        let mut sources = snapshot
            .sources
            .iter()
            .enumerate()
            .map(|(position, source)| ConfiguredSource {
                upstream_id: is_replaceable_public(source).then(|| RUBYGEMS_UPSTREAM.into()),
                url: source.clone(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["gem-source".into()]),
                    ("position".into(), vec![position.to_string()]),
                    ("origin".into(), vec![origin.into()]),
                    (
                        "config_path".into(),
                        vec![snapshot.config_path.display().to_string()],
                    ),
                ]),
            })
            .collect::<Vec<_>>();
        if gemrc_override(runtime) {
            sources.push(policy_source(
                "gemrc-environment-override",
                &snapshot.config_path,
            ));
        }
        Ok(CurrentConfiguration {
            tool_id: "rubygems".into(),
            scope,
            sources,
            files: exists
                .then_some(snapshot.config_path.clone())
                .into_iter()
                .collect(),
            documents: vec![ConfigurationDocument {
                path: snapshot.config_path,
                format: "rubygems-user-gemrc".into(),
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
        reviewed_rubygems_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("RubyGems version is missing".into())
        })?)?;
        validate_policy(current)?;
        replaceable_public_index(current)?;
        Ok(SelectionRequest {
            tool_id: "rubygems".into(),
            adapter_key: "rubygems".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![RUBYGEMS_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Index, EndpointRole::Artifacts],
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
        let public_index = replaceable_public_index(current)?;
        let endpoint = selected_endpoint(selections)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "rubygems-user-gemrc")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("RubyGems user gemrc document is missing".into())
            })?;
        let text = utf8(&document.path, &document.contents)?;
        let parsed = parse_gemrc_sources(text, &document.path)?;
        let mut new_contents =
            rewrite_sources(text, parsed.as_ref(), public_index, endpoint)?.into_bytes();
        if document.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            new_contents.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let preserved = current
            .sources
            .iter()
            .filter(|source| metadata(source, "kind") == Some("gem-source"))
            .count()
            .saturating_sub(1);
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
                    "replace exactly one public RubyGems source in {}; preserve {preserved} private source(s), their order, credentials and unrelated gem options",
                    document.path.display()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "rubygems".into(),
            tool_id: "rubygems".into(),
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
            let snapshot = gem_snapshot(runtime)?;
            validate_user_path(runtime, &snapshot.config_path)?;
            let target = rooted(&context.root, &snapshot.config_path);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "RubyGems transaction receipt does not contain the selected gemrc".into(),
                ));
            }
            let contents = runtime.read(&snapshot.config_path)?.ok_or_else(|| {
                AdapterError::Verification("RubyGems user gemrc disappeared".into())
            })?;
            let parsed = parse_gemrc_sources(
                utf8(&snapshot.config_path, &contents)?,
                &snapshot.config_path,
            )?
            .ok_or_else(|| {
                AdapterError::Verification("RubyGems user gemrc has no :sources block".into())
            })?;
            ensure_same_sources(&parsed.values(), &snapshot.sources)?;
            let public = public_source_index(&snapshot.sources)?;
            let endpoint = normalized_public_url(&snapshot.sources[public])
                .filter(|source| MIRROR_SOURCES.contains(&source.as_str()))
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "gem sources did not load a reviewed RubyGems mirror".into(),
                    )
                })?;
            let output = run_gem(
                runtime,
                &[
                    "dependency",
                    REVIEWED_GEM,
                    "--remote",
                    "--version",
                    REVIEWED_VERSION,
                    "--clear-sources",
                    "--source",
                    &format!("{endpoint}/"),
                ],
                "gem dependency verification",
            )?;
            if !output.contains(&format!("Gem {REVIEWED_GEM}-{REVIEWED_VERSION}"))
                || !output.contains(REVIEWED_DEPENDENCY)
            {
                return Err(AdapterError::Verification(
                    "gem dependency did not return the reviewed gem and dependency metadata".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "gem sources loaded {endpoint}; {REVIEWED_GEM} {REVIEWED_VERSION} dependency metadata was resolved by the real client"
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
                "restored {} RubyGems configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GemSnapshot {
    ruby_version: String,
    rubygems_version: String,
    gem_home: PathBuf,
    config_path: PathBuf,
    credentials_path: PathBuf,
    certificate_inventory_lines: usize,
    sources: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GemrcSources {
    entries: Vec<GemrcSourceEntry>,
}

impl GemrcSources {
    fn values(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.value.clone())
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GemrcSourceEntry {
    value: String,
    value_range: Range<usize>,
}

fn gem_snapshot(runtime: &dyn Runtime) -> Result<GemSnapshot, AdapterError> {
    let ruby = run_program(runtime, "ruby", &["--version"], "ruby --version")?;
    let ruby_version = ruby_version(&ruby)?;
    let rubygems_version = run_gem(runtime, &["--version"], "gem --version")?;
    reviewed_rubygems_version(&rubygems_version)?;
    let gem_home = PathBuf::from(run_gem(
        runtime,
        &["environment", "home"],
        "gem environment home",
    )?);
    validate_path(&gem_home, "gem home")?;
    let config_path = PathBuf::from(run_program(
        runtime,
        "ruby",
        &["-rrubygems", "-e", CONFIG_PATH_SCRIPT],
        "RubyGems configuration path query",
    )?);
    validate_path(&config_path, "configuration")?;
    let credentials_path = PathBuf::from(run_gem(
        runtime,
        &["environment", "credentials"],
        "gem environment credentials",
    )?);
    validate_path(&credentials_path, "credentials")?;
    let certificate_inventory_lines = run_gem(runtime, &["cert", "--list"], "gem cert --list")?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let sources = parse_gem_sources(&run_gem(
        runtime,
        &["sources", "--list"],
        "gem sources --list",
    )?)?;
    Ok(GemSnapshot {
        ruby_version,
        rubygems_version,
        gem_home,
        config_path,
        credentials_path,
        certificate_inventory_lines,
        sources,
    })
}

fn run_gem(
    runtime: &dyn Runtime,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    run_program(runtime, "gem", arguments, operation)
}

fn run_program(
    runtime: &dyn Runtime,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let output = runtime.run(
        program,
        &arguments
            .iter()
            .map(|argument| (*argument).into())
            .collect::<Vec<_>>(),
    )?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 stdout")))
}

fn parse_gem_sources(output: &str) -> Result<Vec<String>, AdapterError> {
    let sources = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("***"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if sources.is_empty()
        || sources
            .iter()
            .any(|source| source_identity(source).is_none())
    {
        return Err(AdapterError::Runtime(
            "gem sources --list returned no sources or an invalid source URL".into(),
        ));
    }
    Ok(sources)
}

fn parse_gemrc_sources(text: &str, path: &Path) -> Result<Option<GemrcSources>, AdapterError> {
    let mut lines = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let content = inclusive.trim_end_matches(['\r', '\n']);
        lines.push((offset, content));
        offset += inclusive.len();
    }
    if text.is_empty() {
        lines.clear();
    }

    let mut source_key = None;
    for (index, (_, line)) in lines.iter().enumerate() {
        if line.trim_start().starts_with(":sources:") {
            if line.len() != line.trim_start().len() || line.trim() != ":sources:" {
                return Err(complex_gemrc(path));
            }
            if source_key.replace(index).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "{} contains duplicate :sources keys",
                    path.display()
                )));
            }
        }
    }
    let Some(source_key) = source_key else {
        return Ok(None);
    };

    let mut entries = Vec::new();
    for (line_offset, line) in lines.iter().skip(source_key + 1).copied() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let leading = line.len() - line.trim_start().len();
        let content = &line[leading..];
        if !content.starts_with('-') {
            if leading == 0 {
                break;
            }
            return Err(complex_gemrc(path));
        }
        let after_dash = &content[1..];
        if after_dash.is_empty() || !after_dash.starts_with(char::is_whitespace) {
            return Err(complex_gemrc(path));
        }
        let value_leading = after_dash.len() - after_dash.trim_start().len();
        let token = &after_dash[value_leading..];
        let token_offset = line_offset + leading + 1 + value_leading;
        entries.push(parse_source_token(token, token_offset, path)?);
    }
    if entries.is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} has an empty :sources list",
            path.display()
        )));
    }
    Ok(Some(GemrcSources { entries }))
}

fn parse_source_token(
    token: &str,
    token_offset: usize,
    path: &Path,
) -> Result<GemrcSourceEntry, AdapterError> {
    let token = token.trim_end();
    if token.is_empty() {
        return Err(complex_gemrc(path));
    }
    let (value, range) =
        if let Some(quote) = token.chars().next().filter(|c| matches!(c, '\'' | '"')) {
            let remainder = &token[quote.len_utf8()..];
            let close = remainder.find(quote).ok_or_else(|| complex_gemrc(path))?;
            let value = &remainder[..close];
            let suffix = remainder[close + quote.len_utf8()..].trim_start();
            if value.contains('\\') || !suffix.is_empty() && !suffix.starts_with('#') {
                return Err(complex_gemrc(path));
            }
            (
                value,
                token_offset + quote.len_utf8()..token_offset + quote.len_utf8() + close,
            )
        } else {
            let comment = token
                .char_indices()
                .find(|(index, character)| {
                    *character == '#'
                        && *index > 0
                        && token[..*index]
                            .chars()
                            .last()
                            .is_some_and(char::is_whitespace)
                })
                .map_or(token.len(), |(index, _)| index);
            let value = token[..comment].trim_end();
            (value, token_offset..token_offset + value.len())
        };
    if source_identity(value).is_none() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} contains an invalid RubyGems source URL",
            path.display()
        )));
    }
    Ok(GemrcSourceEntry {
        value: value.into(),
        value_range: range,
    })
}

fn complex_gemrc(path: &Path) -> AdapterError {
    AdapterError::Unsupported(format!(
        "{} uses a complex or inline YAML :sources form that MirrorSwitch will not rewrite",
        path.display()
    ))
}

fn rewrite_sources(
    text: &str,
    parsed: Option<&GemrcSources>,
    public_index: usize,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    if let Some(parsed) = parsed {
        let entry = parsed.entries.get(public_index).ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "RubyGems source ordering changed while planning".into(),
            )
        })?;
        if !is_replaceable_public(&entry.value) {
            return Err(AdapterError::InvalidConfiguration(
                "RubyGems public source position changed while planning".into(),
            ));
        }
        let mut rewritten = text.to_owned();
        rewritten.replace_range(entry.value_range.clone(), &endpoint);
        return Ok(rewritten);
    }
    if public_index != 0 {
        return Err(AdapterError::InvalidConfiguration(
            "RubyGems implicit default source position is invalid".into(),
        ));
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut rewritten = text.to_owned();
    if !rewritten.is_empty() && !rewritten.ends_with(['\n', '\r']) {
        rewritten.push_str(newline);
    }
    rewritten.push_str(":sources:");
    rewritten.push_str(newline);
    rewritten.push_str("- ");
    rewritten.push_str(&endpoint);
    rewritten.push_str(newline);
    Ok(rewritten)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "rubygems"
        || selections[0].upstream_id != RUBYGEMS_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "RubyGems requires exactly one mirror selection".into(),
        ));
    }
    let index = selections[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    let artifacts = selections[0]
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .collect::<Vec<_>>();
    if index.len() != 1
        || artifacts.len() != 1
        || normalized_public_url(&index[0].url) != normalized_public_url(&artifacts[0].url)
        || !normalized_public_url(&index[0].url)
            .is_some_and(|source| MIRROR_SOURCES.contains(&source.as_str()))
    {
        return Err(AdapterError::InvalidConfiguration(
            "RubyGems selection lacks one reviewed HTTPS index/artifact endpoint pair".into(),
        ));
    }
    Ok(index[0].url.trim_end_matches('/'))
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current
        .sources
        .iter()
        .any(|source| metadata(source, "kind") == Some("gemrc-environment-override"))
    {
        return Err(AdapterError::Unsupported(
            "GEMRC overrides the user configuration file; change that environment policy explicitly"
                .into(),
        ));
    }
    Ok(())
}

fn replaceable_public_index(current: &CurrentConfiguration) -> Result<usize, AdapterError> {
    let sources = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind") == Some("gem-source"))
        .map(|source| source.url.clone())
        .collect::<Vec<_>>();
    public_source_index(&sources)
}

fn public_source_index(sources: &[String]) -> Result<usize, AdapterError> {
    let matches = sources
        .iter()
        .enumerate()
        .filter(|(_, source)| is_replaceable_public(source))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(AdapterError::InvalidConfiguration(
            "RubyGems has no recognized public source to replace without changing private source policy"
                .into(),
        )),
        _ => Err(AdapterError::InvalidConfiguration(
            "RubyGems has multiple public sources; replacing one would leave ambiguous fallback policy"
                .into(),
        )),
    }
}

fn ensure_same_sources(configured: &[String], effective: &[String]) -> Result<(), AdapterError> {
    let configured = configured
        .iter()
        .map(|source| source_identity(source).expect("parsed gemrc source"))
        .collect::<Vec<_>>();
    let effective = effective
        .iter()
        .map(|source| source_identity(source).expect("validated gem source"))
        .collect::<Vec<_>>();
    if configured != effective {
        return Err(AdapterError::Unsupported(
            "gem sources order does not match the selected user :sources block; a higher-precedence source policy is active"
                .into(),
        ));
    }
    Ok(())
}

fn is_replaceable_public(value: &str) -> bool {
    normalized_public_url(value)
        .is_some_and(|source| REPLACEABLE_PUBLIC_SOURCES.contains(&source.as_str()))
}

fn normalized_public_url(value: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "https" | "http")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    source_identity(value)
}

fn source_identity(value: &str) -> Option<String> {
    let mut parsed = reqwest::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
        return None;
    }
    let path = parsed.path().trim_end_matches('/').to_owned();
    parsed.set_path(if path.is_empty() { "/" } else { &path });
    Some(parsed.to_string().trim_end_matches('/').to_owned())
}

fn ruby_version(output: &str) -> Result<String, AdapterError> {
    let mut fields = output.split_whitespace();
    if fields.next() != Some("ruby") {
        return Err(AdapterError::Unsupported(
            "ruby --version output is unrecognized".into(),
        ));
    }
    fields
        .next()
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("ruby version is missing".into()))
}

fn reviewed_versions(ruby: &str, rubygems: &str) -> Result<(), AdapterError> {
    let (ruby_major, ruby_minor) = version_pair(ruby).ok_or_else(|| {
        AdapterError::Unsupported(format!("Ruby {ruby} version format is unrecognized"))
    })?;
    if ruby_major < 2 || ruby_major == 2 && ruby_minor < 6 {
        return Err(AdapterError::Unsupported(format!(
            "Ruby {ruby} is outside the reviewed 2.6+ source model"
        )));
    }
    reviewed_rubygems_version(rubygems)
}

fn reviewed_rubygems_version(value: &str) -> Result<(), AdapterError> {
    let (major, _) = version_pair(value).ok_or_else(|| {
        AdapterError::Unsupported(format!("RubyGems {value} version format is unrecognized"))
    })?;
    if major < 3 {
        return Err(AdapterError::Unsupported(format!(
            "RubyGems {value} is outside the reviewed 3.x/4.x gemrc model"
        )));
    }
    Ok(())
}

fn version_pair(value: &str) -> Option<(u64, u64)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    if parts.next().is_none()
        || value
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some((major, minor))
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "RubyGems on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "RubyGems requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "RubyGems writes only the user gemrc and never a project Gemfile".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "rubygems" {
        return Err(AdapterError::InvalidConfiguration(
            "RubyGems operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "RubyGems reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_user_path(runtime: &dyn Runtime, path: &Path) -> Result<(), AdapterError> {
    validate_path(path, "configuration")?;
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("RubyGems requires a detected user home".into())
    })?;
    validate_path(&home, "home")?;
    if !path.starts_with(&home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "RubyGems configuration {} is outside the selected user home",
            path.display()
        )));
    }
    Ok(())
}

fn gemrc_override(runtime: &dyn Runtime) -> bool {
    runtime
        .environment_variable("GEMRC")
        .is_some_and(|value| !value.is_empty())
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

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "RubyGems configuration {} is not UTF-8",
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
