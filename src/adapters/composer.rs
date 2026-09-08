use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    process::Output,
};

use serde_json::{Map, Value, json};

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

const PACKAGIST_UPSTREAM: &str = "packagist--language-registry";
const REVIEWED_PACKAGE: &str = "psr/log";
const REVIEWED_VERSION: &str = "3.0.2";
const REVIEWED_REFERENCE: &str = "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3";
const REVIEWED_SOURCE: &str = "https://github.com/php-fig/log.git";
const HUAWEI_ENDPOINT: &str = "https://repo.huaweicloud.com/repository/php";
const REVIEWED_SOURCE_ENDPOINT: &str = "https://github.com/php-fig/log";
const PUBLIC_PACKAGIST_ENDPOINTS: &[&str] = &[
    "https://repo.packagist.org",
    "https://packagist.org",
    "https://mirrors.aliyun.com/composer",
    "https://repo.huaweicloud.com/repository/php",
    "https://packagist.mirrors.sjtug.sjtu.edu.cn",
    "https://mirrors.tuna.tsinghua.edu.cn/packagist",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct ComposerAdapter;

impl Adapter for ComposerAdapter {
    fn key(&self) -> &'static str {
        "composer"
    }

    fn tool_id(&self) -> &'static str {
        "composer"
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
        if !runtime.command_exists("composer") || !runtime.command_exists("php") {
            return Ok(None);
        }
        let snapshot = composer_snapshot(runtime)?;
        let global = read_json_document(runtime, &snapshot.global_config, "global config")?;
        analyze_global(global.value.as_ref())?;
        let global_repositories = repository_entries(global.value.as_ref(), "global config")?;
        let project = snapshot
            .project_config
            .as_ref()
            .map(|path| read_json_document(runtime, path, "project config"))
            .transpose()?;
        if let Some(project) = &project {
            validate_project_policy(project.value.as_ref())?;
        }
        let project_repositories = project
            .as_ref()
            .map(|document| repository_entries(document.value.as_ref(), "project config"))
            .transpose()?
            .unwrap_or_default();
        let auth_sources = authentication_sources(runtime, &snapshot);
        let auth_evidence = if auth_sources.is_empty() {
            "none".into()
        } else {
            auth_sources.join(", ")
        };
        Ok(Some(DetectedTool {
            tool_id: "composer".into(),
            executable: Some(PathBuf::from("composer")),
            version: Some(snapshot.composer_version.clone()),
            evidence: vec![
                format!("Composer {}", snapshot.composer_version),
                format!("PHP {}", snapshot.php_version),
                format!(
                    "native platform is {:?} {:?}; composer resolved through native PATH semantics",
                    context.os, context.architecture
                ),
                format!("selected user home is {}", snapshot.user_home.display()),
                format!("Composer {} repository protocol", snapshot.protocol),
                format!("Composer home is {}", snapshot.home.display()),
                format!(
                    "global configuration is {}",
                    snapshot.global_config.display()
                ),
                snapshot.project_config.as_ref().map_or_else(
                    || "no project Composer configuration detected".into(),
                    |path| format!("project configuration is {}", path.display()),
                ),
                format!(
                    "{} global and {} project repository definition(s) detected",
                    global_repositories.len(),
                    project_repositories.len()
                ),
                format!("authentication sources detected: {auth_evidence}"),
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
        if detected.tool_id != "composer" {
            return Err(AdapterError::InvalidConfiguration(
                "Composer read received another tool's detection result".into(),
            ));
        }
        let snapshot = composer_snapshot(runtime)?;
        if detected.version.as_deref() != Some(snapshot.composer_version.as_str()) {
            return Err(AdapterError::Conflict(
                "Composer version changed after detection".into(),
            ));
        }
        let global = read_json_document(runtime, &snapshot.global_config, "global config")?;
        let global_analysis = analyze_global(global.value.as_ref())?;
        let mut sources =
            configured_sources(global.value.as_ref(), "global", &snapshot.global_config)?;
        if global_analysis.location == PackagistLocation::Implicit {
            sources.push(configured_source(
                "https://repo.packagist.org",
                "composer",
                "packagist.org",
                "effective-default",
                &snapshot.global_config,
                true,
            ));
        }

        let mut documents = vec![ConfigurationDocument {
            path: snapshot.global_config.clone(),
            format: "composer-global-config".into(),
            contents: global.contents.clone(),
        }];
        let mut files = global
            .exists
            .then_some(snapshot.global_config.clone())
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(path) = &snapshot.project_config {
            let project = read_json_document(runtime, path, "project config")?;
            validate_project_policy(project.value.as_ref())?;
            sources.extend(configured_sources(project.value.as_ref(), "project", path)?);
            if project.exists {
                files.push(path.clone());
            }
            documents.push(ConfigurationDocument {
                path: path.clone(),
                format: "composer-project-config-read-only".into(),
                contents: project.contents,
            });
        }
        let verification = read_json_document(
            runtime,
            &snapshot.verification_config,
            "verification config",
        )?;
        if verification.exists {
            files.push(snapshot.verification_config.clone());
        }
        documents.push(ConfigurationDocument {
            path: snapshot.verification_config.clone(),
            format: "composer-verification-config".into(),
            contents: verification.contents,
        });
        for source in authentication_sources(runtime, &snapshot) {
            sources.push(ConfiguredSource {
                upstream_id: None,
                url: source,
                enabled: true,
                metadata: BTreeMap::from([("kind".into(), vec!["authentication-source".into()])]),
            });
        }
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: format!("composer-version:{}", snapshot.composer_version),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["tool-snapshot".into()]),
                (
                    "composer_version".into(),
                    vec![snapshot.composer_version.clone()],
                ),
            ]),
        });
        Ok(CurrentConfiguration {
            tool_id: "composer".into(),
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
        require_supported_context(context)?;
        require_current(current)?;
        let protocol =
            reviewed_composer_version(detected.version.as_deref().ok_or_else(|| {
                AdapterError::InvalidConfiguration("Composer version is missing".into())
            })?)?;
        validate_current_policy(current)?;
        Ok(SelectionRequest {
            tool_id: "composer".into(),
            adapter_key: "composer".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![PACKAGIST_UPSTREAM.into()],
            repository_versions: BTreeMap::from([(PACKAGIST_UPSTREAM.into(), protocol.to_owned())]),
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
                EndpointRole::Artifacts,
                EndpointRole::Git,
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
        validate_current_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "composer-global-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Composer global configuration document is missing".into(),
                )
            })?;
        let composer_version = current
            .sources
            .iter()
            .find_map(|source| metadata(source, "composer_version"))
            .unwrap_or("2.0.0");
        let major = version_components(composer_version)
            .map(|version| version.0)
            .unwrap_or(2);
        let text = utf8(&document.path, &document.contents)?;
        let mut new_contents = rewrite_global_config(text, major, endpoint)?.into_bytes();
        if document.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            new_contents.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let private_count = current
            .sources
            .iter()
            .filter(|source| {
                metadata(source, "kind") == Some("composer-repository")
                    && source.upstream_id.is_none()
            })
            .count();
        let mut changes = (new_contents != document.contents)
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
                    "map only global Packagist to {endpoint} in {}; preserve {private_count} private/VCS repository definition(s), authentication, project composer.json and lockfiles",
                    document.path.display()
                ),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let verification = current
            .documents
            .iter()
            .find(|document| document.format == "composer-verification-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Composer verification configuration document is missing".into(),
                )
            })?;
        let expected_verification = rewrite_global_config("", major, endpoint)?.into_bytes();
        if verification.contents != expected_verification {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &verification.path),
                old_contents: current
                    .files
                    .contains(&verification.path)
                    .then(|| verification.contents.clone()),
                old_mode: None,
                new_contents: expected_verification,
                new_mode: None,
                summary: "create an isolated credential-free Composer verification config".into(),
            });
        }
        Ok(ChangePlan {
            adapter_key: "composer".into(),
            tool_id: "composer".into(),
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
            let snapshot = composer_snapshot(runtime)?;
            let known_targets = [
                rooted(context.root.as_path(), &snapshot.global_config),
                rooted(context.root.as_path(), &snapshot.verification_config),
            ];
            if receipt
                .changed_targets
                .iter()
                .all(|target| !known_targets.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Composer transaction receipt contains no known config".into(),
                ));
            }
            let document = read_json_document(runtime, &snapshot.global_config, "global config")?;
            let analysis = analyze_global(document.value.as_ref())?;
            if analysis
                .url
                .as_deref()
                .and_then(normalized_public_url)
                .as_deref()
                != Some(HUAWEI_ENDPOINT)
            {
                return Err(AdapterError::Verification(
                    "Composer global config did not load the reviewed Packagist mirror".into(),
                ));
            }
            let repositories = document
                .value
                .as_ref()
                .and_then(|value| value.get("repositories"));
            let replaces_default = match (&analysis.location, repositories) {
                (PackagistLocation::ObjectKey(key), Some(Value::Object(_))) => {
                    key == "packagist.org" || analysis.disabled_packagist
                }
                (_, Some(Value::Array(_))) => analysis.disabled_packagist,
                _ => false,
            };
            if !replaces_default {
                return Err(AdapterError::Verification(
                    "Composer config still permits the implicit official Packagist fallback".into(),
                ));
            }
            let verification = read_json_document(
                runtime,
                &snapshot.verification_config,
                "verification config",
            )?;
            let composer_major = version_components(&snapshot.composer_version)
                .map(|version| version.0)
                .ok_or_else(|| {
                    AdapterError::Verification("Composer version changed while verifying".into())
                })?;
            let expected_verification =
                rewrite_global_config("", composer_major, HUAWEI_ENDPOINT)?.into_bytes();
            if verification.contents != expected_verification {
                return Err(AdapterError::Verification(
                    "Composer isolated verification config is not canonical".into(),
                ));
            }
            let listed = run_composer_at_home(
                runtime,
                &snapshot.home,
                false,
                &["config", "--global", "--list", "--source"],
                "composer global config verification",
            )?;
            if !listed.contains(HUAWEI_ENDPOINT) {
                return Err(AdapterError::Verification(
                    "composer config did not report the selected Packagist mirror".into(),
                ));
            }
            let diagnosed = run_composer_diagnose(runtime, &snapshot.verification_home)?;
            if !diagnosed
                .lines()
                .any(|line| line.contains(HUAWEI_ENDPOINT) && line.contains("OK"))
            {
                return Err(AdapterError::Verification(
                    "composer diagnose did not confirm connectivity to the selected mirror".into(),
                ));
            }
            let shown = run_composer_at_home(
                runtime,
                &snapshot.verification_home,
                true,
                &[
                    "show",
                    REVIEWED_PACKAGE,
                    REVIEWED_VERSION,
                    "--all",
                    "--no-interaction",
                    "--no-plugins",
                ],
                "composer package query",
            )?;
            for marker in [
                REVIEWED_PACKAGE,
                REVIEWED_VERSION,
                REVIEWED_REFERENCE,
                REVIEWED_SOURCE,
                HUAWEI_ENDPOINT,
            ] {
                if !shown.contains(marker) {
                    return Err(AdapterError::Verification(format!(
                        "composer package query did not report reviewed marker {marker}"
                    )));
                }
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Composer {} loaded {HUAWEI_ENDPOINT}; diagnose passed and {REVIEWED_PACKAGE} {REVIEWED_VERSION} resolved with reviewed dist and VCS source references",
                    snapshot.composer_version
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
                "restored {} Composer configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComposerSnapshot {
    composer_version: String,
    php_version: String,
    protocol: &'static str,
    user_home: PathBuf,
    home: PathBuf,
    global_config: PathBuf,
    verification_home: PathBuf,
    verification_config: PathBuf,
    project_config: Option<PathBuf>,
    project_auth: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct JsonDocument {
    exists: bool,
    contents: Vec<u8>,
    value: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositoryEntry {
    name: String,
    repository_type: String,
    url: String,
    enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PackagistLocation {
    Implicit,
    ObjectKey(String),
    ArrayDirect(usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GlobalAnalysis {
    location: PackagistLocation,
    url: Option<String>,
    disabled_packagist: bool,
}

fn composer_snapshot(runtime: &dyn Runtime) -> Result<ComposerSnapshot, AdapterError> {
    let composer_output = run_program(
        runtime,
        "composer",
        &["--version", "--no-ansi"],
        "composer --version",
    )?;
    let composer_version = prefixed_version(&composer_output, "Composer version")?;
    let protocol = reviewed_composer_version(&composer_version)?;
    let php_output = run_program(runtime, "php", &["--version"], "php --version")?;
    let php_version = prefixed_version(&php_output, "PHP")?;
    reviewed_php_version(&php_version)?;
    let user_home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Composer user home is unavailable".into()))?;
    let home_arguments = ["config", "--global", "home"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let home = PathBuf::from(output_text(
        runtime.run_in_with_environment(
            &user_home,
            "composer",
            &home_arguments,
            &BTreeMap::new(),
            &["COMPOSER".into(), "COMPOSER_AUTH".into()],
        )?,
        "Composer home query",
    )?);
    validate_path(&home, "home")?;
    validate_user_path(runtime, &home)?;
    let global_config = home.join("config.json");
    let verification_home = user_home.join(".mirrorswitch/verification/composer");
    let verification_config = verification_home.join("config.json");
    validate_user_path(runtime, &verification_home)?;
    validate_user_path(runtime, &verification_config)?;
    if global_config == verification_config {
        return Err(AdapterError::Unsupported(
            "Composer global config collides with the isolated verification config".into(),
        ));
    }
    let project_config = project_config_path(runtime)?;
    let project_auth = runtime
        .project_dir()
        .map(|directory| directory.join("auth.json"))
        .filter(|path| runtime.read(path).ok().flatten().is_some());
    Ok(ComposerSnapshot {
        composer_version,
        php_version,
        protocol,
        user_home,
        home,
        global_config,
        verification_home,
        verification_config,
        project_config,
        project_auth,
    })
}

fn project_config_path(runtime: &dyn Runtime) -> Result<Option<PathBuf>, AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(None);
    };
    validate_path(&project, "project directory")?;
    let configured = runtime
        .environment_variable("COMPOSER")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let path = match configured {
        Some(path) if path.is_absolute() => path,
        Some(path) => project.join(path),
        None => project.join("composer.json"),
    };
    validate_path(&path, "project configuration")?;
    if !path.starts_with(&project) {
        return Err(AdapterError::Unsupported(format!(
            "COMPOSER selects {} outside the detected project directory",
            path.display()
        )));
    }
    Ok(runtime.read(&path)?.is_some().then_some(path))
}

fn authentication_sources(runtime: &dyn Runtime, snapshot: &ComposerSnapshot) -> Vec<String> {
    let mut sources = Vec::new();
    let global_auth = snapshot.home.join("auth.json");
    if runtime.read(&global_auth).ok().flatten().is_some() {
        sources.push(format!("global auth.json at {}", global_auth.display()));
    }
    if let Some(path) = &snapshot.project_auth {
        sources.push(format!("project auth.json at {}", path.display()));
    }
    if runtime.environment_variable("COMPOSER_AUTH").is_some() {
        sources.push("COMPOSER_AUTH environment".into());
    }
    sources
}

fn read_json_document(
    runtime: &dyn Runtime,
    path: &Path,
    label: &str,
) -> Result<JsonDocument, AdapterError> {
    let observed = runtime.read(path)?;
    let exists = observed.is_some();
    let contents = observed.unwrap_or_default();
    if !exists {
        return Ok(JsonDocument {
            exists,
            contents,
            value: None,
        });
    }
    let text = utf8(path, &contents)?;
    let value = serde_json::from_str::<Value>(text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("{} is not valid JSON: {error}", path.display()))
    })?;
    if !value.is_object() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} {} must contain a JSON object",
            path.display()
        )));
    }
    Ok(JsonDocument {
        exists,
        contents,
        value: Some(value),
    })
}

fn repository_entries(
    root: Option<&Value>,
    label: &str,
) -> Result<Vec<RepositoryEntry>, AdapterError> {
    let Some(repositories) = root.and_then(|value| value.get("repositories")) else {
        return Ok(Vec::new());
    };
    match repositories {
        Value::Object(entries) => entries
            .iter()
            .map(|(name, value)| repository_from_named(name, value, label))
            .collect(),
        Value::Array(entries) => entries
            .iter()
            .enumerate()
            .map(|(index, value)| repository_from_array(index, value, label))
            .collect(),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "{label} repositories must be an object or array"
        ))),
    }
}

fn repository_from_named(
    name: &str,
    value: &Value,
    label: &str,
) -> Result<RepositoryEntry, AdapterError> {
    if value == &Value::Bool(false) {
        return Ok(RepositoryEntry {
            name: name.into(),
            repository_type: "disabled".into(),
            url: String::new(),
            enabled: false,
        });
    }
    let object = value.as_object().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "{label} repository {name} must be an object or false"
        ))
    })?;
    repository_from_object(name, object, label)
}

fn repository_from_array(
    index: usize,
    value: &Value,
    label: &str,
) -> Result<RepositoryEntry, AdapterError> {
    let object = value.as_object().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("{label} repository #{index} must be an object"))
    })?;
    if object.len() == 1 {
        let (name, nested) = object.iter().next().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("{label} repository #{index} is empty"))
        })?;
        if nested == &Value::Bool(false) || nested.as_object().is_some() {
            return repository_from_named(name, nested, label);
        }
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("#{index}"));
    repository_from_object(&name, object, label)
}

fn repository_from_object(
    name: &str,
    object: &Map<String, Value>,
    label: &str,
) -> Result<RepositoryEntry, AdapterError> {
    let repository_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let url = object
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if repository_type == "composer" && url.is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} Composer repository {name} has no URL"
        )));
    }
    Ok(RepositoryEntry {
        name: name.into(),
        repository_type,
        url,
        enabled: true,
    })
}

fn analyze_global(root: Option<&Value>) -> Result<GlobalAnalysis, AdapterError> {
    validate_transport_policy(root, "global config")?;
    let entries = repository_entries(root, "global config")?;
    let repositories = root.and_then(|value| value.get("repositories"));
    let mut matches = Vec::new();
    let mut disabled_packagist = false;
    for (index, entry) in entries.iter().enumerate() {
        let named = is_packagist_name(&entry.name);
        let public = normalized_public_url(&entry.url).is_some();
        if named && !entry.enabled {
            disabled_packagist = true;
            continue;
        }
        if named && entry.repository_type != "composer" {
            return Err(AdapterError::Conflict(format!(
                "global repository {} is named Packagist but has type {}",
                entry.name, entry.repository_type
            )));
        }
        if named && !public {
            return Err(AdapterError::Conflict(format!(
                "global repository {} uses a private or unreviewed Packagist URL",
                entry.name
            )));
        }
        if named || public {
            matches.push((index, entry.url.clone()));
        }
    }
    if matches.len() > 1 {
        return Err(AdapterError::Conflict(
            "global Composer config has multiple public Packagist mappings".into(),
        ));
    }
    let Some((index, url)) = matches.into_iter().next() else {
        if disabled_packagist {
            return Err(AdapterError::Conflict(
                "global Composer config explicitly disables Packagist without a public replacement"
                    .into(),
            ));
        }
        return Ok(GlobalAnalysis {
            location: PackagistLocation::Implicit,
            url: Some("https://repo.packagist.org".into()),
            disabled_packagist,
        });
    };
    let location = match repositories {
        Some(Value::Object(entries)) => PackagistLocation::ObjectKey(
            entries
                .keys()
                .nth(index)
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration("repository index changed".into())
                })?
                .clone(),
        ),
        Some(Value::Array(values)) => {
            let value = &values[index];
            if value
                .as_object()
                .is_some_and(|object| object.contains_key("type") || object.contains_key("name"))
            {
                PackagistLocation::ArrayDirect(index)
            } else {
                return Err(AdapterError::InvalidConfiguration(
                    "wrapped Packagist repositories are not a valid Composer 2 global array entry"
                        .into(),
                ));
            }
        }
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Composer repository shape changed".into(),
            ));
        }
    };
    Ok(GlobalAnalysis {
        location,
        url: Some(url),
        disabled_packagist,
    })
}

fn validate_project_policy(root: Option<&Value>) -> Result<(), AdapterError> {
    validate_transport_policy(root, "project config")?;
    if repository_entries(root, "project config")?
        .iter()
        .any(|entry| is_packagist_name(&entry.name) || normalized_public_url(&entry.url).is_some())
    {
        return Err(AdapterError::Unsupported(
            "project Composer config controls Packagist precedence; only the global user source can be changed automatically"
                .into(),
        ));
    }
    Ok(())
}

fn validate_transport_policy(root: Option<&Value>, label: &str) -> Result<(), AdapterError> {
    let config = root
        .and_then(|value| value.get("config"))
        .and_then(Value::as_object);
    if config
        .and_then(|config| config.get("disable-tls"))
        .and_then(Value::as_bool)
        == Some(true)
        || config
            .and_then(|config| config.get("secure-http"))
            .and_then(Value::as_bool)
            == Some(false)
    {
        return Err(AdapterError::Unsupported(format!(
            "{label} disables Composer HTTPS transport"
        )));
    }
    Ok(())
}

fn configured_sources(
    root: Option<&Value>,
    origin: &str,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    repository_entries(root, &format!("{origin} config"))?
        .into_iter()
        .map(|entry| {
            Ok(configured_source(
                &entry.url,
                &entry.repository_type,
                &entry.name,
                origin,
                path,
                entry.enabled,
            ))
        })
        .collect()
}

fn configured_source(
    url: &str,
    repository_type: &str,
    name: &str,
    origin: &str,
    path: &Path,
    enabled: bool,
) -> ConfiguredSource {
    let metadata = BTreeMap::from([
        ("kind".into(), vec!["composer-repository".into()]),
        ("name".into(), vec![name.into()]),
        ("repository_type".into(), vec![repository_type.into()]),
        ("origin".into(), vec![origin.into()]),
        ("config_path".into(), vec![path.display().to_string()]),
    ]);
    ConfiguredSource {
        upstream_id: normalized_public_url(url).map(|_| PACKAGIST_UPSTREAM.into()),
        url: url.into(),
        enabled,
        metadata,
    }
}

fn rewrite_global_config(
    text: &str,
    composer_major: u64,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let mut root = if text.is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str::<Value>(text).map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "Composer global config is not valid JSON: {error}"
            ))
        })?
    };
    let analysis = analyze_global(Some(&root))?;
    let object = root.as_object_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Composer global config must be an object".into())
    })?;
    let disabled_packagist = analysis.disabled_packagist;
    match analysis.location {
        PackagistLocation::Implicit => match object.get_mut("repositories") {
            None => {
                if composer_major == 1 {
                    object.insert(
                        "repositories".into(),
                        json!({"packagist.org": {"type": "composer", "url": endpoint}}),
                    );
                } else {
                    object.insert(
                        "repositories".into(),
                        json!([
                            {"name": "mirrorswitch-packagist", "type": "composer", "url": endpoint},
                            {"packagist.org": false}
                        ]),
                    );
                }
            }
            Some(Value::Object(repositories)) => {
                repositories.insert(
                    "packagist.org".into(),
                    json!({"type": "composer", "url": endpoint}),
                );
            }
            Some(Value::Array(repositories)) => {
                repositories.push(json!({
                    "name": "mirrorswitch-packagist",
                    "type": "composer",
                    "url": endpoint
                }));
                repositories.push(json!({"packagist.org": false}));
            }
            Some(_) => {
                return Err(AdapterError::InvalidConfiguration(
                    "Composer repositories must be an object or array".into(),
                ));
            }
        },
        PackagistLocation::ObjectKey(key) => {
            let repositories = object
                .get_mut("repositories")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Composer Packagist repository changed while planning".into(),
                    )
                })?;
            let mut repository = repositories.remove(&key).ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Composer Packagist repository changed while planning".into(),
                )
            })?;
            let repository = repository.as_object_mut().ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Composer Packagist repository changed while planning".into(),
                )
            })?;
            repository.insert("url".into(), Value::String(endpoint.into()));
            repositories.insert("packagist.org".into(), Value::Object(repository.clone()));
        }
        PackagistLocation::ArrayDirect(index) => {
            let repositories = object
                .get_mut("repositories")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Composer Packagist repository changed while planning".into(),
                    )
                })?;
            let repository = repositories
                .get_mut(index)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Composer Packagist repository changed while planning".into(),
                    )
                })?;
            repository.insert(
                "name".into(),
                Value::String("mirrorswitch-packagist".into()),
            );
            repository.insert("url".into(), Value::String(endpoint.into()));
            if !disabled_packagist {
                repositories.push(json!({"packagist.org": false}));
            }
        }
    }
    let mut rendered = serde_json::to_string_pretty(&root).map_err(|error| {
        AdapterError::Runtime(format!("could not render Composer config: {error}"))
    })?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    if newline == "\r\n" {
        rendered = rendered.replace('\n', newline);
    }
    rendered.push_str(newline);
    Ok(rendered)
}

fn validate_current_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    let document = current
        .documents
        .iter()
        .find(|document| document.format == "composer-global-config")
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Composer global config is missing".into())
        })?;
    let text = utf8(&document.path, &document.contents)?;
    let root = if text.is_empty() {
        None
    } else {
        Some(serde_json::from_str::<Value>(text).map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "Composer global config is not valid JSON: {error}"
            ))
        })?)
    };
    analyze_global(root.as_ref())?;
    Ok(())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "composer"
        || selections[0].upstream_id != PACKAGIST_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Composer requires exactly one Packagist mirror selection".into(),
        ));
    }
    let selection = &selections[0];
    let index = unique_endpoint(selection, EndpointRole::Index)?;
    let artifacts = unique_endpoint(selection, EndpointRole::Artifacts)?;
    let source = unique_endpoint(selection, EndpointRole::Git)?;
    let index = normalized_public_url(index).ok_or_else(|| {
        AdapterError::InvalidConfiguration("selected Composer index is not reviewed".into())
    })?;
    if index != HUAWEI_ENDPOINT
        || normalized_public_url(artifacts).as_deref() != Some(index.as_str())
        || normalized_url(source).as_deref() != Some(REVIEWED_SOURCE_ENDPOINT)
    {
        return Err(AdapterError::InvalidConfiguration(
            "Composer metadata, dist and VCS source endpoints are not a reviewed complete chain"
                .into(),
        ));
    }
    Ok(HUAWEI_ENDPOINT)
}

fn unique_endpoint(selection: &MirrorSelection, role: EndpointRole) -> Result<&str, AdapterError> {
    let endpoints = selection
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
        .collect::<Vec<_>>();
    if endpoints.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Composer selection requires exactly one {role:?} HTTPS endpoint"
        )));
    }
    Ok(&endpoints[0].url)
}

fn run_composer_at_home(
    runtime: &dyn Runtime,
    home: &Path,
    remove_auth: bool,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    output_text(
        run_composer_at_home_output(runtime, home, remove_auth, arguments)?,
        operation,
    )
}

fn run_composer_diagnose(runtime: &dyn Runtime, home: &Path) -> Result<String, AdapterError> {
    let output = run_composer_at_home_output(
        runtime,
        home,
        true,
        &["diagnose", "--no-interaction", "--no-plugins"],
    )?;
    if !output.status.success() && output.status.code() != Some(2) {
        return Err(AdapterError::Runtime(format!(
            "composer diagnose failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime("composer diagnose returned non-UTF-8 stdout".into()))
}

fn run_composer_at_home_output(
    runtime: &dyn Runtime,
    home: &Path,
    remove_auth: bool,
    arguments: &[&str],
) -> Result<Output, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let home_value = home.to_str().ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "Composer home path {} is not UTF-8",
            home.display()
        ))
    })?;
    let mut removed_environment = vec!["COMPOSER".into()];
    if remove_auth {
        removed_environment.push("COMPOSER_AUTH".into());
    }
    runtime.run_in_with_environment(
        home,
        "composer",
        &arguments,
        &BTreeMap::from([("COMPOSER_HOME".into(), home_value.into())]),
        &removed_environment,
    )
}

fn run_program(
    runtime: &dyn Runtime,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    run_program_in(runtime, None, program, arguments, operation)
}

fn run_program_in(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = match directory {
        Some(directory) => runtime.run_in(directory, program, &arguments),
        None => runtime.run(program, &arguments),
    }?;
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
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 stdout")))
}

fn prefixed_version(output: &str, prefix: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix(prefix)
                .and_then(|remainder| remainder.split_whitespace().next())
                .filter(|version| version_components(version).is_some())
                .map(str::to_owned)
        })
        .ok_or_else(|| AdapterError::Runtime(format!("could not parse {prefix} version")))
}

fn reviewed_composer_version(version: &str) -> Result<&'static str, AdapterError> {
    let (major, minor, _) = version_components(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("Composer version {version} is not understood"))
    })?;
    match (major, minor) {
        (1, 10..) => Ok("v1"),
        (2, _) => Ok("v2"),
        _ => Err(AdapterError::Unsupported(format!(
            "Composer {version} is outside the reviewed 1.10+/2.x range"
        ))),
    }
}

fn reviewed_php_version(version: &str) -> Result<(), AdapterError> {
    let (major, _, _) = version_components(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("PHP version {version} is not understood"))
    })?;
    if major < 7 {
        return Err(AdapterError::Unsupported(format!(
            "PHP {version} is outside the reviewed 7.x+ range"
        )));
    }
    Ok(())
}

fn version_components(version: &str) -> Option<(u64, u64, u64)> {
    let numeric = version.trim_start_matches('v');
    let mut parts = numeric.split(['.', '-', '+']);
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next().unwrap_or("0").parse().ok()?,
    ))
}

fn normalized_public_url(value: &str) -> Option<String> {
    let normalized = normalized_url(value)?;
    PUBLIC_PACKAGIST_ENDPOINTS
        .contains(&normalized.as_str())
        .then_some(normalized)
}

fn normalized_url(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('/');
    if !value.starts_with("https://")
        || value.contains(['\n', '\r', '\0'])
        || value[8..].contains('@')
    {
        return None;
    }
    Some(value.to_owned())
}

fn is_packagist_name(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "packagist" | "packagist.org"
    )
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn validate_user_path(runtime: &dyn Runtime, path: &Path) -> Result<(), AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Composer user home is unavailable".into()))?;
    validate_path(&home, "user home")?;
    if !path.starts_with(&home) {
        return Err(AdapterError::Unsupported(format!(
            "Composer home {} is outside user home {}",
            path.display(),
            home.display()
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, label: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Composer {label} path {} is not an absolute normalized path",
            path.display()
        )));
    }
    Ok(())
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Composer on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "Composer on Windows arm64 is unavailable because PHP does not publish a native Windows arm64 runtime"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Composer adapter requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Composer only changes global user config; project composer.json and lockfiles are read-only"
                .into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "composer" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Composer requires a user-scoped Composer configuration".into(),
        ));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Composer configuration {} is not UTF-8",
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
    Err(AdapterError::Verification(format!(
        "{reason}; configuration restored: {}",
        restored.verified
    )))
}
