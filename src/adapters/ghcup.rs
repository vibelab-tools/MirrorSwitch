use std::{
    collections::{BTreeMap, BTreeSet},
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

const GHCUP_UPSTREAM: &str = "ghcup--release-artifacts";
const METADATA_BASE: &str =
    "https://mirrors.nju.edu.cn/ghcup/yaml_v2/haskell/ghcup-metadata/master/";
const METADATA_FILE: &str = "ghcup-0.0.9.yaml";
const ARTIFACT_BASE: &str = "https://mirror.nju.edu.cn/ghcup/packages/";
const ARTIFACT_HOST: &str = "mirror.nju.edu.cn";
const ARTIFACT_PREFIX: &str = "ghcup/packages";
const REVIEWED_METADATA_URLS: &[&str] =
    &["https://mirrors.nju.edu.cn/ghcup/yaml_v2/haskell/ghcup-metadata/master/ghcup-0.0.9.yaml"];
const VERIFY_TOOLS: &[(&str, &str)] = &[
    ("ghc", "9.10.3"),
    ("cabal", "3.14.2.0"),
    ("hls", "2.13.0.0"),
    ("stack", "3.7.1"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct GhcupAdapter;

impl Adapter for GhcupAdapter {
    fn key(&self) -> &'static str {
        "ghcup"
    }

    fn tool_id(&self) -> &'static str {
        "ghcup"
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
        if !runtime.command_exists("ghcup") {
            return Ok(None);
        }
        let user_home = runtime
            .home_dir()
            .ok_or_else(|| AdapterError::Unsupported("GHCup user home is unavailable".into()))?;
        validate_path(&user_home, "GHCup user home")?;
        let project = runtime.project_dir();
        if let Some(project) = &project {
            validate_path(project, "GHCup project directory")?;
        }
        let version = ghcup_version(runtime)?;
        reviewed_version(&version)?;
        let path = config_path(context, runtime)?;
        let document = read_document(runtime, &path)?;
        let parsed = parse_config(&path, &document.contents)?;
        let channels = release_channels(&parsed)?;
        let gpg =
            top_level_scalar(&parsed, "gpg-setting")?.unwrap_or_else(|| "GPGNone (default)".into());
        let checksum =
            top_level_scalar(&parsed, "no-verify")?.unwrap_or_else(|| "false (default)".into());
        let installed = installed_tool_summary(runtime);
        Ok(Some(DetectedTool {
            tool_id: "ghcup".into(),
            executable: Some(PathBuf::from("ghcup")),
            version: Some(version.clone()),
            evidence: vec![
                format!("GHCup {version}"),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                format!("selected user home is {}", user_home.display()),
                project.map_or_else(
                    || {
                        "no project directory was selected; project configuration remains read-only"
                            .into()
                    },
                    |path| format!("project directory {} remains read-only", path.display()),
                ),
                format!("configuration is {}", path.display()),
                format!("{} release channel(s) configured", channels.len()),
                format!("metadata GPG policy is {gpg}"),
                format!("no-verify is {checksum}"),
                installed,
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
        if detected.tool_id != "ghcup" {
            return Err(AdapterError::InvalidConfiguration(
                "GHCup read received another tool's detection result".into(),
            ));
        }
        let version = ghcup_version(runtime)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "GHCup version changed after detection".into(),
            ));
        }
        let path = config_path(context, runtime)?;
        let document = read_document(runtime, &path)?;
        let parsed = parse_config(&path, &document.contents)?;
        let mut sources = release_channels(&parsed)?
            .into_iter()
            .map(|channel| ConfiguredSource {
                upstream_id: Some(GHCUP_UPSTREAM.into()),
                url: redact_channel(&channel),
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["release-channel".into()]),
                    ("path".into(), vec![path.display().to_string()]),
                ]),
            })
            .collect::<Vec<_>>();
        if let Some(mirror) = downloads_mirror(&parsed)? {
            sources.push(ConfiguredSource {
                upstream_id: Some(GHCUP_UPSTREAM.into()),
                url: mirror,
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["bindist-mirror".into()]),
                    ("path".into(), vec![path.display().to_string()]),
                ]),
            });
        }
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: format!("ghcup-version:{version}"),
            enabled: true,
            metadata: BTreeMap::from([("kind".into(), vec!["tool-snapshot".into()])]),
        });
        Ok(CurrentConfiguration {
            tool_id: "ghcup".into(),
            scope,
            files: document
                .exists
                .then_some(path.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path,
                format: "ghcup-user-config".into(),
                contents: document.contents,
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
        reviewed_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("GHCup version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "ghcup".into(),
            adapter_key: "ghcup".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![GHCUP_UPSTREAM.into()],
            repository_versions: BTreeMap::from([(GHCUP_UPSTREAM.into(), "0.0.9".into())]),
            probe_contexts: BTreeMap::from([(
                GHCUP_UPSTREAM.into(),
                ghcup_probe_contexts(context),
            )]),
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
        selections: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_supported_context(context)?;
        require_current(current)?;
        let selected = selected_endpoints(selections)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "ghcup-user-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "GHCup user configuration document is missing".into(),
                )
            })?;
        let old = utf8(&document.path, &document.contents)?;
        let mut rendered = rewrite_config(old, &selected.metadata_url)?.into_bytes();
        if document.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let changes = (rendered != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current
                    .files
                    .contains(&document.path)
                    .then(|| document.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: format!(
                    "replace only the default GHCup metadata channel with the signed NJU mirror and map downloads.haskell.org to {}; preserve custom channels, GPG/checksum policy and unrelated settings",
                    selected.artifact_base
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "ghcup".into(),
            tool_id: "ghcup".into(),
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
            let path = config_path(context, runtime)?;
            let target = rooted(&context.root, &path);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "GHCup transaction receipt does not contain its configuration".into(),
                ));
            }
            let contents = runtime.read(&path)?.ok_or_else(|| {
                AdapterError::Verification("GHCup configuration disappeared".into())
            })?;
            let text = utf8(&path, &contents)?;
            let parsed = parse_config(&path, &contents)?;
            let channels = release_channels(&parsed)?;
            let managed = metadata_url();
            if channels.iter().filter(|value| *value == &managed).count() != 1 {
                return Err(AdapterError::Verification(
                    "GHCup metadata channel is missing or duplicated".into(),
                ));
            }
            if downloads_mirror(&parsed)?.as_deref() != Some(ARTIFACT_BASE) {
                return Err(AdapterError::Verification(
                    "GHCup bindist mirror is not the reviewed NJU endpoint".into(),
                ));
            }
            if rewrite_config(text, &managed)? != text {
                return Err(AdapterError::Verification(
                    "GHCup managed configuration is not canonical".into(),
                ));
            }
            for (tool, version) in VERIFY_TOOLS {
                let output = run_ghcup(
                    runtime,
                    &[
                        "--metadata-fetching-mode",
                        "Strict",
                        "list",
                        "--tool",
                        tool,
                        "--raw-format",
                    ],
                    &format!("GHCup {tool} metadata plan"),
                )?;
                if !output.split_whitespace().any(|token| token == *version) {
                    return Err(AdapterError::Verification(format!(
                        "GHCup metadata plan did not contain {tool} {version}"
                    )));
                }
            }
            Ok(VerificationResult {
                valid: true,
                summary: "GHCup parsed signed NJU metadata and resolved fixed GHC 9.10.3, Cabal 3.14.2.0, HLS 2.13.0.0 and Stack 3.7.1 plans".into(),
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
                "restored {} GHCup configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct TextDocument {
    exists: bool,
    contents: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ParsedConfig {
    text: String,
    sections: Vec<Section>,
}

#[derive(Clone, Debug)]
struct Section {
    key: String,
    value: String,
    value_range: Option<Range<usize>>,
    start: usize,
    body_start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct ListEntry {
    value: String,
    range: Range<usize>,
}

#[derive(Clone, Debug)]
struct ChildBlock {
    key: String,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct SelectedEndpoints {
    metadata_url: String,
    artifact_base: String,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "GHCup on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "GHCup on Windows arm64 is unavailable because the reviewed metadata has no Windows arm64 GHC toolchain"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "GHCup requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "GHCup supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "ghcup" {
        return Err(AdapterError::InvalidConfiguration(
            "GHCup operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn config_path(context: &SystemContext, runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("GHCup user home is unavailable".into()))?;
    validate_path(&home, "GHCup user home")?;
    let path = if context.os == OperatingSystem::Windows {
        environment_path(runtime, "GHCUP_INSTALL_BASE_PREFIX")?
            .unwrap_or_else(|| PathBuf::from(r"C:\"))
            .join("ghcup")
            .join("config.yaml")
    } else if runtime.environment_variable("GHCUP_USE_XDG_DIRS").is_some() {
        environment_path(runtime, "XDG_CONFIG_HOME")?
            .unwrap_or_else(|| home.join(".config"))
            .join("ghcup/config.yaml")
    } else {
        environment_path(runtime, "GHCUP_INSTALL_BASE_PREFIX")?
            .unwrap_or(home)
            .join(".ghcup/config.yaml")
    };
    validate_path(&path, "GHCup configuration")?;
    Ok(path)
}

fn environment_path(runtime: &dyn Runtime, name: &str) -> Result<Option<PathBuf>, AdapterError> {
    runtime
        .environment_variable(name)
        .map(|value| {
            if value.is_empty() {
                return Err(AdapterError::Unsupported(format!(
                    "{name} is empty and does not identify a safe absolute path"
                )));
            }
            let path = PathBuf::from(value);
            validate_path(&path, name)?;
            Ok(path)
        })
        .transpose()
}

fn validate_path(path: &Path, label: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} path {} is not a safe absolute path",
            path.display()
        )));
    }
    Ok(())
}

fn read_document(runtime: &dyn Runtime, path: &Path) -> Result<TextDocument, AdapterError> {
    let observed = runtime.read(path)?;
    let exists = observed.is_some();
    let contents = observed.unwrap_or_default();
    if contents.contains(&0) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "GHCup configuration {} contains NUL bytes",
            path.display()
        )));
    }
    utf8(path, &contents)?;
    Ok(TextDocument { exists, contents })
}

fn ghcup_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = run_ghcup(runtime, &["--numeric-version"], "ghcup --numeric-version")?;
    output
        .split_ascii_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("GHCup returned an empty version".into()))
}

fn reviewed_version(value: &str) -> Result<(), AdapterError> {
    let parts = value
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            AdapterError::Unsupported(format!("GHCup {value} has an unrecognized version"))
        })?;
    let reviewed = (3..=4).contains(&parts.len())
        && (matches!(parts.as_slice(), [0, 1, patch, ..] if *patch >= 50)
            || matches!(parts.as_slice(), [0, 2, ..]));
    if !reviewed {
        return Err(AdapterError::Unsupported(format!(
            "GHCup {value} predates the reviewed metadata/mirror model"
        )));
    }
    Ok(())
}

fn installed_tool_summary(runtime: &dyn Runtime) -> String {
    let arguments = [
        "--offline",
        "list",
        "--raw-format",
        "--show-criteria",
        "installed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    match runtime.run("ghcup", &arguments) {
        Ok(output) if output.status.success() => {
            let count = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            format!("offline installed-tool query reported {count} record(s)")
        }
        _ => "installed-tool query needs a usable local metadata cache".into(),
    }
}

fn run_ghcup(
    runtime: &dyn Runtime,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let output = runtime.run(
        "ghcup",
        &arguments
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>(),
    )?;
    output_text(output, operation)
}

fn output_text(output: Output, operation: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 output")))
}

fn parse_config(path: &Path, contents: &[u8]) -> Result<ParsedConfig, AdapterError> {
    let text = utf8(path, contents)?.to_owned();
    if text.contains('\t') {
        return Err(AdapterError::Unsupported(format!(
            "GHCup YAML {} contains tabs and cannot be rewritten safely",
            path.display()
        )));
    }
    let mut sections = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let active_end = yaml_comment_offset(line);
        let active = line[..active_end].trim_end();
        if active.trim().is_empty() || active.trim() == "---" || active.starts_with(' ') {
            offset += inclusive.len();
            continue;
        }
        let delimiter = active.find(':').ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "GHCup YAML {} has an unsupported top-level line",
                path.display()
            ))
        })?;
        let key = yaml_scalar(active[..delimiter].trim())?;
        let raw_value = active[delimiter + 1..].trim();
        let value = yaml_scalar(raw_value)?;
        let value_range = if raw_value.is_empty() {
            None
        } else {
            let start = offset + delimiter + 1 + active[delimiter + 1..].find(raw_value).unwrap();
            Some(start..start + raw_value.len())
        };
        sections.push(Section {
            key,
            value,
            value_range,
            start: offset,
            body_start: offset + inclusive.len(),
            end: text.len(),
        });
        offset += inclusive.len();
    }
    for index in 0..sections.len().saturating_sub(1) {
        sections[index].end = sections[index + 1].start;
    }
    let mut keys = BTreeSet::new();
    if sections.iter().any(|section| !keys.insert(&section.key)) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "GHCup YAML {} contains duplicate top-level keys",
            path.display()
        )));
    }
    Ok(ParsedConfig { text, sections })
}

fn yaml_comment_offset(line: &str) -> usize {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            continue;
        }
        if character == '#' && quote.is_none() {
            return index;
        }
    }
    line.len()
}

fn yaml_scalar(value: &str) -> Result<String, AdapterError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.starts_with(['&', '*', '!', '[', '{', '|', '>']) {
        return Err(AdapterError::Unsupported(
            "GHCup managed YAML uses an alias, tag, flow value or multiline scalar".into(),
        ));
    }
    if let Some(quote) = value
        .chars()
        .next()
        .filter(|value| matches!(value, '\'' | '"'))
    {
        if value.len() < 2 || !value.ends_with(quote) {
            return Err(AdapterError::InvalidConfiguration(
                "GHCup YAML contains an unterminated quoted scalar".into(),
            ));
        }
        return Ok(value[1..value.len() - 1].to_owned());
    }
    Ok(value.to_owned())
}

fn section<'a>(parsed: &'a ParsedConfig, key: &str) -> Option<&'a Section> {
    parsed.sections.iter().find(|section| section.key == key)
}

fn top_level_scalar(parsed: &ParsedConfig, key: &str) -> Result<Option<String>, AdapterError> {
    let Some(section) = section(parsed, key) else {
        return Ok(None);
    };
    if section.value.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "GHCup {key} uses a nested value that MirrorSwitch does not interpret"
        )));
    }
    Ok(Some(section.value.clone()))
}

fn list_entries(parsed: &ParsedConfig, section: &Section) -> Result<Vec<ListEntry>, AdapterError> {
    if !section.value.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "GHCup {} is not a block sequence",
            section.key
        )));
    }
    let mut entries = Vec::new();
    let mut offset = section.body_start;
    for inclusive in parsed.text[section.body_start..section.end].split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let active_end = yaml_comment_offset(line);
        let active = line[..active_end].trim_end();
        if active.trim().is_empty() {
            offset += inclusive.len();
            continue;
        }
        let indent = active.len() - active.trim_start_matches(' ').len();
        if indent != 2 || !active[indent..].starts_with('-') {
            return Err(AdapterError::Unsupported(format!(
                "GHCup {} uses a non-scalar or non-two-space sequence",
                section.key
            )));
        }
        let raw = active[indent + 1..].trim();
        if raw.is_empty() {
            return Err(AdapterError::Unsupported(format!(
                "GHCup {} contains a nested sequence item",
                section.key
            )));
        }
        let value = yaml_scalar(raw)?;
        let start = offset + active.find(raw).unwrap();
        entries.push(ListEntry {
            value,
            range: start..start + raw.len(),
        });
        offset += inclusive.len();
    }
    Ok(entries)
}

fn release_channels(parsed: &ParsedConfig) -> Result<Vec<String>, AdapterError> {
    let Some(source) = section(parsed, "url-source") else {
        return Ok(vec!["GHCupURL".into()]);
    };
    if source.value.is_empty() {
        let entries = list_entries(parsed, source)?;
        if entries.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "GHCup url-source is empty".into(),
            ));
        }
        Ok(entries.into_iter().map(|entry| entry.value).collect())
    } else {
        Ok(vec![source.value.clone()])
    }
}

fn child_blocks(parsed: &ParsedConfig, parent: &Section) -> Result<Vec<ChildBlock>, AdapterError> {
    if !parent.value.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "GHCup {} uses an inline value",
            parent.key
        )));
    }
    let mut children = Vec::<ChildBlock>::new();
    let mut offset = parent.body_start;
    for inclusive in parsed.text[parent.body_start..parent.end].split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let active = line[..yaml_comment_offset(line)].trim_end();
        if active.trim().is_empty() {
            offset += inclusive.len();
            continue;
        }
        let indent = active.len() - active.trim_start_matches(' ').len();
        if indent == 2 {
            let trimmed = active.trim();
            let delimiter = trimmed.find(':').ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "GHCup {} has an unsupported child mapping",
                    parent.key
                ))
            })?;
            if !trimmed[delimiter + 1..].trim().is_empty() {
                return Err(AdapterError::Unsupported(format!(
                    "GHCup {} child mappings must use block form",
                    parent.key
                )));
            }
            let key = yaml_scalar(trimmed[..delimiter].trim())?;
            if let Some(previous) = children.last_mut() {
                previous.end = offset;
            }
            children.push(ChildBlock {
                key,
                start: offset,
                end: parent.end,
            });
        } else if indent < 4 {
            return Err(AdapterError::Unsupported(format!(
                "GHCup {} has unsafe indentation",
                parent.key
            )));
        }
        offset += inclusive.len();
    }
    let mut keys = BTreeSet::new();
    if children.iter().any(|child| !keys.insert(&child.key)) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "GHCup {} contains duplicate child keys",
            parent.key
        )));
    }
    Ok(children)
}

fn downloads_mirror(parsed: &ParsedConfig) -> Result<Option<String>, AdapterError> {
    let Some(mirrors) = section(parsed, "mirrors") else {
        return Ok(None);
    };
    let Some(child) = child_blocks(parsed, mirrors)?
        .into_iter()
        .find(|child| child.key == "downloads.haskell.org")
    else {
        return Ok(None);
    };
    let block = &parsed.text[child.start..child.end];
    let host = nested_scalar(block, "host")?;
    let prefix = nested_scalar(block, "pathPrefix")?;
    Ok(match (host.as_deref(), prefix.as_deref()) {
        (Some(ARTIFACT_HOST), Some(ARTIFACT_PREFIX)) => Some(ARTIFACT_BASE.into()),
        (Some(host), Some(prefix)) => Some(format!("https://{host}/{prefix}/")),
        _ => None,
    })
}

fn nested_scalar(block: &str, key: &str) -> Result<Option<String>, AdapterError> {
    let mut found = None;
    for line in block.lines() {
        let active = line[..yaml_comment_offset(line)].trim();
        let Some((raw_key, raw_value)) = active.split_once(':') else {
            continue;
        };
        if yaml_scalar(raw_key)? == key {
            if found.is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "GHCup mirror mapping contains duplicate {key} values"
                )));
            }
            let value = yaml_scalar(raw_value)?;
            if value.is_empty() {
                return Err(AdapterError::Unsupported(format!(
                    "GHCup mirror {key} is not a scalar"
                )));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn rewrite_config(text: &str, metadata_url: &str) -> Result<String, AdapterError> {
    let parsed = parse_config(Path::new("config.yaml"), text.as_bytes())?;
    let mut edits = Vec::<(Range<usize>, String)>::new();
    let mut append = String::new();
    rewrite_url_source(&parsed, metadata_url, &mut edits, &mut append)?;
    rewrite_mirrors(&parsed, &mut edits, &mut append)?;
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0.start));
    let mut output = parsed.text;
    for (range, replacement) in edits {
        output.replace_range(range, &replacement);
    }
    if !append.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        if !output.is_empty() && !output.ends_with("\n\n") {
            output.push('\n');
        }
        output.push_str(&append);
    }
    if text.contains("\r\n") {
        output = output.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    Ok(output)
}

fn rewrite_url_source(
    parsed: &ParsedConfig,
    metadata_url: &str,
    edits: &mut Vec<(Range<usize>, String)>,
    append: &mut String,
) -> Result<(), AdapterError> {
    let Some(source) = section(parsed, "url-source") else {
        append.push_str(&format!("url-source:\n  - {metadata_url}\n"));
        return Ok(());
    };
    if source.value.is_empty() {
        let entries = list_entries(parsed, source)?;
        if entries.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "GHCup url-source is empty".into(),
            ));
        }
        let managed = entries
            .iter()
            .filter(|entry| is_default_or_reviewed_channel(&entry.value))
            .collect::<Vec<_>>();
        if managed.len() > 1 {
            return Err(AdapterError::InvalidConfiguration(
                "GHCup url-source contains duplicate default/managed channels".into(),
            ));
        }
        if let Some(entry) = managed.first() {
            edits.push((entry.range.clone(), metadata_url.into()));
        } else {
            edits.push((
                source.body_start..source.body_start,
                format!("  - {metadata_url}\n"),
            ));
        }
    } else {
        let replacement = if is_default_or_reviewed_channel(&source.value) {
            metadata_url.to_owned()
        } else {
            format!("\n  - {metadata_url}\n  - {}", source.value)
        };
        edits.push((
            source.value_range.clone().ok_or_else(|| {
                AdapterError::InvalidConfiguration("GHCup url-source value is missing".into())
            })?,
            replacement,
        ));
    }
    Ok(())
}

fn rewrite_mirrors(
    parsed: &ParsedConfig,
    edits: &mut Vec<(Range<usize>, String)>,
    append: &mut String,
) -> Result<(), AdapterError> {
    let block = managed_mirror_block();
    let Some(mirrors) = section(parsed, "mirrors") else {
        append.push_str("mirrors:\n");
        append.push_str(&block);
        return Ok(());
    };
    let children = child_blocks(parsed, mirrors)?;
    if let Some(child) = children
        .iter()
        .find(|child| child.key == "downloads.haskell.org")
    {
        edits.push((child.start..child.end, block));
    } else {
        edits.push((mirrors.end..mirrors.end, block));
    }
    Ok(())
}

fn managed_mirror_block() -> String {
    format!(
        "  downloads.haskell.org:\n    authority:\n      host: {ARTIFACT_HOST}\n    pathPrefix: {ARTIFACT_PREFIX}\n"
    )
}

fn is_default_or_reviewed_channel(value: &str) -> bool {
    matches!(value, "GHCupURL" | "default")
        || REVIEWED_METADATA_URLS
            .iter()
            .any(|candidate| normalized_url(value) == normalized_url(candidate))
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<SelectedEndpoints, AdapterError> {
    if selections.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "GHCup requires exactly one complete provider selection".into(),
        ));
    }
    let selection = &selections[0];
    if selection.tool_id != "ghcup"
        || selection.upstream_id != GHCUP_UPSTREAM
        || selection.provider_id != "nju"
    {
        return Err(AdapterError::InvalidConfiguration(
            "GHCup selection is not the reviewed NJU chain".into(),
        ));
    }
    let metadata = unique_endpoint(selection, EndpointRole::Metadata)?;
    let artifacts = unique_endpoint(selection, EndpointRole::Artifacts)?;
    if normalized_url(metadata) != normalized_url(METADATA_BASE)
        || normalized_url(artifacts) != normalized_url(ARTIFACT_BASE)
    {
        return Err(AdapterError::InvalidConfiguration(
            "GHCup selection mixes metadata and bindist layouts".into(),
        ));
    }
    Ok(SelectedEndpoints {
        metadata_url: format!("{}{METADATA_FILE}", trailing_slash(metadata)),
        artifact_base: trailing_slash(artifacts),
    })
}

fn unique_endpoint(selection: &MirrorSelection, role: EndpointRole) -> Result<&str, AdapterError> {
    let matches = selection
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "GHCup selection requires exactly one {role:?} HTTPS endpoint"
        )));
    }
    Ok(&matches[0].url)
}

fn ghcup_probe_contexts(context: &SystemContext) -> Vec<BTreeMap<String, String>> {
    let values = match (context.os, context.architecture) {
        (OperatingSystem::Linux, Architecture::X86_64) => [
            ("ghc_file", "ghc-9.10.3-x86_64-deb12-linux.tar.xz"),
            (
                "ghc_sha",
                "1ac63f04eac0ad551d45cbde38f27e0e3f43ceefd98833fae1fa3f2dbd042367",
            ),
            (
                "cabal_file",
                "cabal-install-3.14.2.0-x86_64-linux-rocky8.tar.xz",
            ),
            (
                "cabal_sha",
                "8fbdb305c455585649147f8dcd5c5921cc48afcfa4b09f456e39e11ada122617",
            ),
            (
                "hls_file",
                "haskell-language-server-2.13.0.0-x86_64-linux-rocky8.tar.xz",
            ),
            (
                "hls_sha",
                "3f0613893674783a99ffa8b5be3033d2797af632d6eb45d6f3fb0524d8c9e939",
            ),
            ("stack_file", "stack-3.7.1-linux-x86_64.tar.gz"),
            (
                "stack_sha",
                "aae7aadfba87588f85a7b346a224ee88b4b89728251ed4c5df5d912b389c239f",
            ),
        ],
        (OperatingSystem::Linux, Architecture::Arm64) => [
            ("ghc_file", "ghc-9.10.3-aarch64-deb11-linux.tar.xz"),
            (
                "ghc_sha",
                "052789dfe7f6fba6dc3822de0da272e8a5bd358c37adae17d8e82cff39bc1008",
            ),
            (
                "cabal_file",
                "cabal-install-3.14.2.0-aarch64-linux-deb10.tar.xz",
            ),
            (
                "cabal_sha",
                "cf2e19f664d34ae5edcd2d7ccb7022a7c9691607d42414c26a3de4aa252bed80",
            ),
            (
                "hls_file",
                "haskell-language-server-2.13.0.0-aarch64-linux-deb11.tar.xz",
            ),
            (
                "hls_sha",
                "eba07111ce65f082b4eef7382fce73bdb0dce73df2848f6d839ec59cb548f8cf",
            ),
            ("stack_file", "stack-3.7.1-linux-aarch64.tar.gz"),
            (
                "stack_sha",
                "11f97204de91f249487cb74d17c6a58aba11876b0ec431ccb67152991e13404d",
            ),
        ],
        (OperatingSystem::Macos, Architecture::X86_64) => [
            ("ghc_file", "ghc-9.10.3-x86_64-apple-darwin.tar.xz"),
            (
                "ghc_sha",
                "01e4ff9530c124408db0b0f9ec7e4be35b300a6aee939c5758d1acf22d51693f",
            ),
            (
                "cabal_file",
                "cabal-install-3.14.2.0-x86_64-apple-darwin.tar.xz",
            ),
            (
                "cabal_sha",
                "1a45b672939f72b88187ae1b623e42440ab37c03338484d928f47cdde0f5189f",
            ),
            (
                "hls_file",
                "haskell-language-server-2.13.0.0-x86_64-apple-darwin.tar.xz",
            ),
            (
                "hls_sha",
                "c4b52ec3eb914643d49d151ef6eeaaf941f1332a485ef9bbdd98ee961deae382",
            ),
            ("stack_file", "stack-3.7.1-osx-x86_64.tar.gz"),
            (
                "stack_sha",
                "a45175d882373afafc3b0dc8c7cf1aab6d046f6134fe465e03b2e61a7add1098",
            ),
        ],
        (OperatingSystem::Macos, Architecture::Arm64) => [
            ("ghc_file", "ghc-9.10.3-aarch64-apple-darwin.tar.xz"),
            (
                "ghc_sha",
                "9f50ddd87be5cb994c719402778d6c7fdd341934fd4fbc0fcc3ecb40d49f860c",
            ),
            (
                "cabal_file",
                "cabal-install-3.14.2.0-aarch64-apple-darwin.tar.xz",
            ),
            (
                "cabal_sha",
                "a7ce265f063030a2d3648b31419de11ba0d17c67fa5e74a6d285607f6d55d235",
            ),
            (
                "hls_file",
                "haskell-language-server-2.13.0.0-aarch64-apple-darwin.tar.xz",
            ),
            (
                "hls_sha",
                "919fb3949665a8eccfa4865b5ea3442b8f7438a069501550ef75fdd34834f040",
            ),
            ("stack_file", "stack-3.7.1-osx-aarch64.tar.gz"),
            (
                "stack_sha",
                "c08d0e3ce2bf1518f3fa654014acd25801f921ef0d4879882ac35c075605feb0",
            ),
        ],
        (OperatingSystem::Windows, Architecture::X86_64) => [
            ("ghc_file", "ghc-9.10.3-x86_64-unknown-mingw32.tar.xz"),
            (
                "ghc_sha",
                "ad17bdbee5f195d50024da1447f458071d9d8a34f90d76907c873abaf95d893f",
            ),
            ("cabal_file", "cabal-install-3.14.2.0-x86_64-mingw64.zip"),
            (
                "cabal_sha",
                "e45f979e7c24591c6131619666be8f3345345ccf779d8bb7d19cd73ead8b940b",
            ),
            (
                "hls_file",
                "haskell-language-server-2.13.0.0-x86_64-mingw64.zip",
            ),
            (
                "hls_sha",
                "12eec35adab02016fa8bea4bcde0ffc5ccd0f1a149e8024d63e5c211ac305bdc",
            ),
            ("stack_file", "stack-3.7.1-windows-x86_64.tar.gz"),
            (
                "stack_sha",
                "244b230db60c5f5dee70bd3d4f1f0d7097aee2254429a75369961db7060631af",
            ),
        ],
        (OperatingSystem::Windows, Architecture::Arm64) => {
            unreachable!("Windows arm64 is rejected before GHCup candidate selection")
        }
    };
    vec![
        values
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect(),
    ]
}

fn metadata_url() -> String {
    format!("{METADATA_BASE}{METADATA_FILE}")
}

fn normalized_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn trailing_slash(value: &str) -> String {
    format!("{}/", value.trim().trim_end_matches('/'))
}

fn redact_channel(value: &str) -> String {
    if value.contains('@') || value.contains('?') {
        "<private-release-channel>".into()
    } else if value.starts_with("http://") || value.starts_with("https://") {
        value.into()
    } else {
        format!("ghcup-channel:{value}")
    }
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "GHCup configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}

fn verification_failure(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<VerificationResult, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    if !restored.verified {
        return Err(AdapterError::Verification(format!(
            "{reason}; automatic restore could not be verified"
        )));
    }
    Ok(VerificationResult {
        valid: false,
        summary: format!("{reason}; original GHCup configuration restored"),
    })
}
