use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde_json::Value;

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

const MAIN_MANIFEST: &str = "bucket/jq.json";
const BUCKETS: &[BucketDefinition] = &[
    BucketDefinition {
        id: "main",
        upstream: "scoop-main--git-mirror",
        official: "https://github.com/ScoopInstaller/Main.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-main.git",
    },
    BucketDefinition {
        id: "extras",
        upstream: "scoop-extras--git-mirror",
        official: "https://github.com/ScoopInstaller/Extras.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-extras.git",
    },
    BucketDefinition {
        id: "versions",
        upstream: "scoop-versions--git-mirror",
        official: "https://github.com/ScoopInstaller/Versions.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-versions.git",
    },
    BucketDefinition {
        id: "java",
        upstream: "scoop-java--git-mirror",
        official: "https://github.com/ScoopInstaller/Java.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-java.git",
    },
    BucketDefinition {
        id: "nerd-fonts",
        upstream: "scoop-nerd-fonts--git-mirror",
        official: "https://github.com/matthewjberger/scoop-nerd-fonts.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-nerd-fonts.git",
    },
    BucketDefinition {
        id: "nonportable",
        upstream: "scoop-nonportable--git-mirror",
        official: "https://github.com/ScoopInstaller/Nonportable.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-nonportable.git",
    },
    BucketDefinition {
        id: "nirsoft",
        upstream: "scoop-nirsoft--git-mirror",
        official: "https://github.com/kodybrown/scoop-nirsoft.git",
        mirror: "https://mirrors.nju.edu.cn/git/scoop-nirsoft.git",
    },
];

const BUCKET_LIST_SCRIPT: &str = r#"$ErrorActionPreference='Stop'; $items=@(& scoop bucket list | ForEach-Object { [pscustomobject]@{ name=[string]$_.Name; source=[string]$_.Source } }); if (-not $?) { exit 2 }; ConvertTo-Json -Compress -Depth 4 -InputObject $items"#;

#[derive(Clone, Copy, Debug, Default)]
pub struct ScoopAdapter;

impl Adapter for ScoopAdapter {
    fn key(&self) -> &'static str {
        "scoop"
    }
    fn tool_id(&self) -> &'static str {
        "scoop"
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
        require_windows(context)?;
        if !runtime.command_exists("scoop") {
            return Ok(None);
        }
        let powershell = powershell(runtime)?;
        let version = scoop_version(runtime)?;
        let state = scoop_state(context, runtime, powershell)?;
        let official = state
            .buckets
            .iter()
            .filter(|bucket| bucket.definition.is_some())
            .count();
        Ok(Some(DetectedTool {
            tool_id: "scoop".into(),
            executable: Some(PathBuf::from("scoop")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Scoop {version}"),
                format!("Scoop user root is {}", state.root.display()),
                format!(
                    "Scoop reports {} buckets: {official} reviewed official and {} custom",
                    state.buckets.len(),
                    state.buckets.len().saturating_sub(official)
                ),
                format!("effective Scoop architecture is {}", state.architecture),
                format!(
                    "Scoop configuration is {}; proxy/token values remain redacted",
                    state.config_path.display()
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
        require_windows(context)?;
        if scope != ConfigurationScope::User {
            return Err(AdapterError::Unsupported(
                "Scoop bucket metadata is user-scoped".into(),
            ));
        }
        if detected.tool_id != "scoop"
            || detected.version.as_deref() != Some(&scoop_version(runtime)?)
        {
            return Err(AdapterError::Conflict(
                "Scoop identity or version changed after detection".into(),
            ));
        }
        let powershell = powershell(runtime)?;
        let state = scoop_state(context, runtime, powershell)?;
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = Vec::new();
        let mut has_main = false;
        for (position, bucket) in state.buckets.iter().enumerate() {
            let Some(definition) = bucket.definition else {
                sources.push(ConfiguredSource {
                    upstream_id: None,
                    url: "redacted://custom-scoop-bucket".into(),
                    enabled: true,
                    metadata: BTreeMap::from([
                        ("kind".into(), vec!["custom-bucket".into()]),
                        ("alias".into(), vec![bucket.name.clone()]),
                        ("position".into(), vec![position.to_string()]),
                    ]),
                });
                continue;
            };
            let directory = state.root.join("buckets").join(&bucket.name);
            let config = directory.join(".git").join("config");
            let contents = runtime.read(&config)?.ok_or_else(|| {
                AdapterError::Unsupported(format!("Scoop bucket {} has no Git config", bucket.name))
            })?;
            let origin = git_origin(utf8(&config, &contents)?, &config)?;
            if normalize_url(&origin) != normalize_url(&bucket.source) {
                return Err(AdapterError::Conflict(format!(
                    "Scoop and Git disagree about bucket {} origin",
                    bucket.name
                )));
            }
            let mut metadata = BTreeMap::from([
                ("kind".into(), vec!["official-bucket".into()]),
                ("bucket_id".into(), vec![definition.id.into()]),
                ("alias".into(), vec![bucket.name.clone()]),
                ("position".into(), vec![position.to_string()]),
                ("config_path".into(), vec![config.display().to_string()]),
                ("architecture".into(), vec![state.architecture.clone()]),
            ]);
            if definition.id == "main" {
                let manifest = runtime
                    .read(&directory.join(MAIN_MANIFEST))?
                    .ok_or_else(|| {
                        AdapterError::Unsupported("Scoop main bucket has no jq manifest".into())
                    })?;
                let asset = validate_main_manifest(&manifest, &state.architecture)?;
                metadata.insert("manifest_version".into(), vec![asset.version]);
                metadata.insert("asset_url".into(), vec![asset.url]);
                metadata.insert("asset_hash".into(), vec![asset.hash]);
                has_main = true;
            }
            sources.push(ConfiguredSource {
                upstream_id: Some(definition.upstream.into()),
                url: bucket.source.clone(),
                enabled: true,
                metadata,
            });
            files.push(config.clone());
            documents.push(ConfigurationDocument {
                path: config,
                format: format!("scoop-bucket-{}", definition.id),
                contents,
            });
        }
        if !has_main {
            return Err(AdapterError::Unsupported(
                "Scoop main bucket is required for architecture-specific download verification"
                    .into(),
            ));
        }
        Ok(CurrentConfiguration {
            tool_id: "scoop".into(),
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
        require_windows(context)?;
        require_current(current)?;
        let mut upstreams = current
            .sources
            .iter()
            .filter_map(|source| source.upstream_id.clone())
            .collect::<Vec<_>>();
        upstreams.sort();
        upstreams.dedup();
        if upstreams.is_empty() {
            return Err(AdapterError::Unsupported(
                "Scoop has no reviewed official buckets".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "scoop".into(),
            adapter_key: "scoop".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: upstreams,
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Git],
            allowed_delivery_modes: vec![DeliveryMode::Mirror],
            composition_policy: CompositionPolicy::Single,
            overrides: BTreeMap::new(),
        })
    }

    fn plan(
        &self,
        context: &SystemContext,
        current: &CurrentConfiguration,
        selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_windows(context)?;
        require_current(current)?;
        let mut changes = Vec::new();
        for document in &current.documents {
            let bucket_id = document
                .format
                .strip_prefix("scoop-bucket-")
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Scoop document has an unknown format".into(),
                    )
                })?;
            let definition = definition_by_id(bucket_id).ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Scoop document references an unknown bucket".into(),
                )
            })?;
            let endpoint = selected_endpoint(selection, definition)?;
            let rendered = rewrite_git_origin(
                utf8(&document.path, &document.contents)?,
                &document.path,
                endpoint,
            )?
            .into_bytes();
            if rendered != document.contents {
                changes.push(PlannedFileChange {
                    target: rooted(&context.root, &document.path),
                    old_contents: Some(document.contents.clone()),
                    old_mode: None,
                    new_contents: rendered,
                    new_mode: None,
                    summary: format!("change only the {} bucket Git origin", definition.id),
                });
            }
        }
        Ok(ChangePlan {
            adapter_key: "scoop".into(),
            tool_id: "scoop".into(),
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
        if plan.adapter_key != "scoop" || plan.tool_id != "scoop" {
            return Err(AdapterError::InvalidConfiguration(
                "Scoop apply received another adapter's plan".into(),
            ));
        }
        runtime.apply_plan(plan)
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let detected = DetectedTool {
                tool_id: "scoop".into(),
                executable: Some(PathBuf::from("scoop")),
                version: Some(scoop_version(runtime)?),
                evidence: Vec::new(),
            };
            let current =
                self.read_current(context, runtime, &detected, ConfigurationScope::User)?;
            let official = current
                .sources
                .iter()
                .filter(|source| source.upstream_id.is_some())
                .collect::<Vec<_>>();
            if official.is_empty() || official.iter().any(|source| !is_nju_mirror(&source.url)) {
                return Err(AdapterError::Verification(
                    "Scoop did not read every official bucket from the selected NJU mirror".into(),
                ));
            }
            for source in official {
                let config = single_metadata(source, "config_path")?;
                let directory = Path::new(config)
                    .parent()
                    .and_then(Path::parent)
                    .ok_or_else(|| {
                        AdapterError::InvalidConfiguration(
                            "Scoop bucket config path has no repository root".into(),
                        )
                    })?;
                command_success(
                    runtime.run(
                        "git",
                        &[
                            "-C".into(),
                            directory.display().to_string(),
                            "ls-remote".into(),
                            "--exit-code".into(),
                            "origin".into(),
                            "HEAD".into(),
                        ],
                    )?,
                    "git ls-remote Scoop bucket",
                )?;
            }
            command_success(
                runtime.run("scoop", &["search".into(), "jq".into()])?,
                "scoop search jq",
            )?;
            let architecture = scoop_architecture(context.architecture);
            command_success(
                runtime.run(
                    "scoop",
                    &[
                        "download".into(),
                        "--no-update-scoop".into(),
                        "--arch".into(),
                        architecture.into(),
                        "jq".into(),
                    ],
                )?,
                "scoop download jq",
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            return verification_failure(runtime, receipt, error.to_string());
        }
        Ok(VerificationResult { valid: true, summary: "Scoop read every mirrored bucket and downloaded the architecture-specific jq asset with its manifest hash".into() })
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
                "restored {} Scoop bucket Git configuration file(s)",
                restored.restored_files
            ),
        })
    }
}

#[derive(Clone, Copy)]
struct BucketDefinition {
    id: &'static str,
    upstream: &'static str,
    official: &'static str,
    mirror: &'static str,
}
struct Bucket {
    name: String,
    source: String,
    definition: Option<&'static BucketDefinition>,
}
struct ScoopState {
    root: PathBuf,
    config_path: PathBuf,
    architecture: String,
    buckets: Vec<Bucket>,
}
struct ManifestAsset {
    version: String,
    url: String,
    hash: String,
}

fn require_windows(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Windows || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Scoop bucket configuration requires a native Windows host".into(),
        ));
    }
    if let Some(version) = context
        .distribution
        .as_ref()
        .and_then(|distribution| distribution.version_id.as_deref())
    {
        let numbers = version
            .split(|character: char| !character.is_ascii_digit())
            .filter(|value| !value.is_empty())
            .filter_map(|value| value.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if numbers.len() < 3 || numbers[0] != 10 || numbers[1] != 0 || numbers[2] < 17_763 {
            return Err(AdapterError::Unsupported(format!(
                "Scoop requires Windows 10 1809 / build 17763 or later, observed {version}"
            )));
        }
    }
    Ok(())
}

fn powershell(runtime: &dyn Runtime) -> Result<&'static str, AdapterError> {
    if runtime.command_exists("powershell") {
        Ok("powershell")
    } else if runtime.command_exists("pwsh") {
        Ok("pwsh")
    } else {
        Err(AdapterError::Unsupported(
            "Scoop inspection requires PowerShell".into(),
        ))
    }
}

fn scoop_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = runtime.run("scoop", &["--version".into()])?;
    let text = command_text(output, "scoop --version")?;
    for token in text.split_whitespace() {
        let candidate = token
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '.')
            .trim_start_matches('v');
        let mut parts = candidate.split('.');
        if parts
            .next()
            .is_some_and(|value| value.parse::<u32>().is_ok())
            && parts
                .next()
                .is_some_and(|value| value.parse::<u32>().is_ok())
        {
            return Ok(candidate.into());
        }
    }
    Err(AdapterError::Unsupported(
        "Scoop version output has no semantic version".into(),
    ))
}

fn scoop_state(
    context: &SystemContext,
    runtime: &dyn Runtime,
    powershell: &str,
) -> Result<ScoopState, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Scoop requires a user profile".into()))?;
    let config_path = runtime
        .environment_variable("SCOOP_CONFIG")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config").join("scoop").join("config.json"));
    if !config_path.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "SCOOP_CONFIG must be absolute".into(),
        ));
    }
    let config: Value = match runtime.read(&config_path)? {
        Some(contents) => serde_json::from_slice(&contents).map_err(|error| {
            AdapterError::InvalidConfiguration(format!("Scoop config is invalid JSON: {error}"))
        })?,
        None => Value::Object(Default::default()),
    };
    let root = runtime
        .environment_variable("SCOOP")
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            config
                .get("root_path")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("scoop"));
    if !root.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "Scoop root path must be absolute".into(),
        ));
    }
    let architecture = config
        .get("default_architecture")
        .and_then(Value::as_str)
        .unwrap_or_else(|| scoop_architecture(context.architecture));
    if architecture != scoop_architecture(context.architecture) {
        return Err(AdapterError::Unsupported(format!(
            "Scoop default architecture {architecture} conflicts with the host"
        )));
    }
    let output = runtime.run(
        powershell,
        &[
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            BUCKET_LIST_SCRIPT.into(),
        ],
    )?;
    let text = command_text(output, "scoop bucket list")?;
    let value: Value = serde_json::from_str(&text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Scoop bucket list returned invalid JSON: {error}"
        ))
    })?;
    let values = match value {
        Value::Array(values) => values,
        Value::Object(_) => vec![value],
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Scoop bucket list is not an object array".into(),
            ));
        }
    };
    let mut buckets = Vec::new();
    for value in values {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| safe_bucket_name(value))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Scoop bucket has an unsafe name".into())
            })?
            .to_owned();
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!("Scoop bucket {name} has no source"))
            })?
            .to_owned();
        let definition = definition_by_url(&source);
        buckets.push(Bucket {
            name,
            source,
            definition,
        });
    }
    Ok(ScoopState {
        root,
        config_path,
        architecture: architecture.into(),
        buckets,
    })
}

fn validate_main_manifest(
    contents: &[u8],
    architecture: &str,
) -> Result<ManifestAsset, AdapterError> {
    let manifest: Value = serde_json::from_slice(contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("Scoop jq manifest is invalid JSON: {error}"))
    })?;
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Scoop jq manifest has no version".into())
        })?;
    let asset = manifest
        .get("architecture")
        .and_then(|value| value.get(architecture))
        .ok_or_else(|| {
            AdapterError::Unsupported(format!("Scoop jq manifest has no {architecture} asset"))
        })?;
    let url = asset.get("url").and_then(Value::as_str).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Scoop jq manifest asset has no URL".into())
    })?;
    let parsed = reqwest::Url::parse(url.split('#').next().unwrap_or(url)).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("Scoop jq asset URL is invalid: {error}"))
    })?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AdapterError::Unsupported(
            "Scoop jq asset URL is not anonymous HTTPS".into(),
        ));
    }
    let hash = asset
        .get("hash")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Scoop jq manifest asset has no SHA-256".into())
        })?;
    Ok(ManifestAsset {
        version: version.into(),
        url: url.into(),
        hash: hash.to_ascii_lowercase(),
    })
}

fn definition_by_url(url: &str) -> Option<&'static BucketDefinition> {
    BUCKETS.iter().find(|definition| {
        normalize_url(url) == normalize_url(definition.official)
            || normalize_url(url) == normalize_url(definition.mirror)
    })
}
fn definition_by_id(id: &str) -> Option<&'static BucketDefinition> {
    BUCKETS.iter().find(|definition| definition.id == id)
}
fn is_nju_mirror(url: &str) -> bool {
    BUCKETS
        .iter()
        .any(|definition| normalize_url(url) == normalize_url(definition.mirror))
}
fn safe_bucket_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
fn scoop_architecture(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "64bit",
        Architecture::Arm64 => "arm64",
    }
}
fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn selected_endpoint<'a>(
    selections: &'a [MirrorSelection],
    definition: &BucketDefinition,
) -> Result<&'a str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "scoop" && selection.upstream_id == definition.upstream
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Scoop plan requires one {} bucket selection",
            definition.id
        )));
    }
    let endpoint = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| endpoint.role == EndpointRole::Git && endpoint.protocol == Protocol::Https)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Scoop {} selection has no HTTPS Git endpoint",
                definition.id
            ))
        })?;
    if normalize_url(&endpoint.url) != normalize_url(definition.mirror) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Scoop {} selection is not the reviewed NJU mirror",
            definition.id
        )));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "scoop"
        && current.scope == ConfigurationScope::User
        && !current.documents.is_empty()
    {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "Scoop requires at least the main bucket Git configuration".into(),
        ))
    }
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
                "{} contains duplicate origin URLs",
                path.display()
            )));
        }
    }
    origin.ok_or_else(|| {
        AdapterError::Unsupported(format!("{} has no origin remote", path.display()))
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
            "{} origin could not be rewritten",
            path.display()
        )))
    }
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Scoop source is missing {key}"))
    })?;
    if values.len() == 1 {
        Ok(&values[0])
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "Scoop source has ambiguous {key}"
        )))
    }
}
fn command_text(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    command_success(output.clone(), label)?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 output")))
}
fn command_success(output: std::process::Output, label: &str) -> Result<(), AdapterError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "{label} failed with status {}",
            output.status
        )))
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
fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Scoop configuration {} is not UTF-8",
            path.display()
        ))
    })
}
fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.into()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
