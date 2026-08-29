use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

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

const PYPI_UPSTREAM: &str = "pypi--language-registry";
const SOURCE_NAME: &str = "mirrorswitch-pypi";
const OFFICIAL_INDEXES: &[&str] = &["https://pypi.org/simple", "https://pypi.python.org/simple"];
const MIRROR_INDEXES: &[&str] = &[
    "https://mirrors.aliyun.com/pypi/simple",
    "https://repo.huaweicloud.com/repository/pypi/simple",
    "https://mirrors.nju.edu.cn/pypi/web/simple",
    "https://mirror.sjtu.edu.cn/pypi/web/simple",
    "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple",
    "https://mirrors.ustc.edu.cn/pypi/simple",
];
const MIRROR_ARTIFACTS: &[&str] = &[
    "https://mirrors.aliyun.com/pypi/packages",
    "https://repo.huaweicloud.com/repository/pypi/packages",
    "https://mirrors.nju.edu.cn/pypi/web/packages",
    "https://mirror.sjtu.edu.cn/pypi-packages",
    "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages",
    "https://mirrors.ustc.edu.cn/pypi/packages",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct UvAdapter;

impl Adapter for UvAdapter {
    fn key(&self) -> &'static str {
        "uv"
    }

    fn tool_id(&self) -> &'static str {
        "uv"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::User, ConfigurationScope::Project]
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
        if !runtime.command_exists("uv") {
            return Ok(None);
        }
        let project = project_dir(runtime)?;
        let version = run_uv(runtime, project.as_deref(), &["--version"], "uv --version")?;
        reviewed_version(&version)?;
        let layout = config_layout(runtime, project.as_deref())?;
        let mut evidence = vec![
            version.clone(),
            format!("system configuration path is {}", layout.system.display()),
            format!("user configuration path is {}", layout.user.display()),
            "uv configuration is independent from pip configuration".into(),
        ];
        if let Some(project) = project {
            evidence.push(format!(
                "project configuration root is {}",
                project.display()
            ));
            evidence.push(format!(
                "effective project format is {}",
                if layout.project_is_pyproject {
                    "pyproject.toml [tool.uv]"
                } else {
                    "uv.toml"
                }
            ));
        }
        Ok(Some(DetectedTool {
            tool_id: "uv".into(),
            executable: Some(PathBuf::from("uv")),
            version: Some(version),
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
        reviewed_version(
            detected.version.as_deref().ok_or_else(|| {
                AdapterError::InvalidConfiguration("uv version is missing".into())
            })?,
        )?;
        let project = project_dir(runtime)?;
        if scope == ConfigurationScope::Project && project.is_none() {
            return Err(AdapterError::Unsupported(
                "uv project scope requires an explicit project directory".into(),
            ));
        }
        let layout = config_layout(runtime, project.as_deref())?;
        let selected = match scope {
            ConfigurationScope::User => layout.user.clone(),
            ConfigurationScope::Project => layout.project.clone().expect("validated project"),
            _ => unreachable!("validated uv scope"),
        };
        let mut paths = vec![
            (layout.system, ConfigFormat::Standalone, Origin::System),
            (layout.user, ConfigFormat::Standalone, Origin::User),
        ];
        if let Some(project_path) = layout.project {
            paths.push((
                project_path,
                if layout.project_is_pyproject {
                    ConfigFormat::Pyproject
                } else {
                    ConfigFormat::Standalone
                },
                Origin::Project,
            ));
        }
        if let Some(ignored) = layout.ignored_pyproject {
            paths.push((ignored, ConfigFormat::Ignored, Origin::Project));
        }

        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = environment_sources(runtime);
        let mut seen = BTreeSet::new();
        for (path, format, origin) in paths {
            validate_path(&path)?;
            if !seen.insert(path.clone()) {
                continue;
            }
            let observed = runtime.read(&path)?;
            let exists = observed.is_some();
            let contents = observed.unwrap_or_default();
            if exists {
                files.push(path.clone());
            }
            if format != ConfigFormat::Ignored {
                let mut discovered =
                    config_sources(utf8(&path, &contents)?, format, origin, &path)?;
                mark_index_credentials(runtime, &mut discovered);
                sources.extend(discovered);
            }
            documents.push(ConfigurationDocument {
                path: path.clone(),
                format: if path == selected {
                    match format {
                        ConfigFormat::Pyproject => "uv-selected-pyproject",
                        _ => "uv-selected-standalone",
                    }
                } else if format == ConfigFormat::Ignored {
                    "uv-ignored-pyproject"
                } else {
                    "uv-config-read-only"
                }
                .into(),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "uv".into(),
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
        Ok(SelectionRequest {
            tool_id: "uv".into(),
            adapter_key: "uv".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![PYPI_UPSTREAM.into()],
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
            allowed_delivery_modes: vec![DeliveryMode::Mirror, DeliveryMode::Proxy],
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
        validate_policy(current)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("uv-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("uv selected config is missing".into())
            })?;
        let target = selected_default(current, &document.path)?;
        validate_precedence(current, &document.path)?;
        let new_contents = rewrite_config(
            utf8(&document.path, &document.contents)?,
            document.format == "uv-selected-pyproject",
            target.as_deref(),
            endpoint,
        )?
        .into_bytes();
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "set one uv default index in explicit {} scope; preserve explicit named indexes and project source pins without adding searchable indexes",
                    if current.scope == ConfigurationScope::User {
                        "user"
                    } else {
                        "project"
                    }
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "uv".into(),
            tool_id: "uv".into(),
            scope: current.scope,
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
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let project = project_dir(runtime)?;
            let resolved = run_uv(
                runtime,
                project.as_deref(),
                &[
                    "pip",
                    "install",
                    "-v",
                    "--dry-run",
                    "--system",
                    "--no-cache",
                    "sampleproject==4.0.0",
                ],
                "uv pip dry-run resolution",
            )?;
            if !resolved.to_ascii_lowercase().contains("sampleproject")
                || !resolved.contains("4.0.0")
            {
                return Err(AdapterError::Verification(
                    "uv dry-run did not resolve sampleproject 4.0.0".into(),
                ));
            }
            let observed = MIRROR_INDEXES
                .iter()
                .find(|endpoint| resolved.to_ascii_lowercase().contains(**endpoint))
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "uv verbose resolution did not use a reviewed mirror index".into(),
                    )
                })?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "uv configuration and real dry-run package resolution used {observed}"
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
                "restored {} uv configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigFormat {
    Standalone,
    Pyproject,
    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    System,
    User,
    Project,
    Environment,
}

#[derive(Clone, Debug)]
struct ConfigLayout {
    system: PathBuf,
    user: PathBuf,
    project: Option<PathBuf>,
    project_is_pyproject: bool,
    ignored_pyproject: Option<PathBuf>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "uv adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if !matches!(
        scope,
        ConfigurationScope::User | ConfigurationScope::Project
    ) {
        return Err(AdapterError::Unsupported(
            "uv supports user and explicit project scopes".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "uv" {
        return Err(AdapterError::InvalidConfiguration(
            "uv operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    let token = version
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|token| !token.is_empty())
        .ok_or_else(|| AdapterError::Unsupported(format!("unrecognized uv version {version}")))?;
    let parts = token
        .split('.')
        .take(3)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterError::Unsupported(format!("unrecognized uv version {version}")))?;
    if parts.len() != 3 || parts[0] != 0 || (parts[1], parts[2]) < (4, 23) || parts[1] > 12 {
        return Err(AdapterError::Unsupported(format!(
            "uv {version} is outside the reviewed 0.4.23 through 0.12.x index model"
        )));
    }
    Ok(())
}

fn run_uv(
    runtime: &dyn Runtime,
    project: Option<&Path>,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|value| (*value).into())
        .collect::<Vec<_>>();
    let output = if let Some(project) = project {
        runtime.run_in(project, "uv", &arguments)?
    } else {
        runtime.run("uv", &arguments)?
    };
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 stdout")))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| AdapterError::Runtime(format!("{operation} returned non-UTF-8 stderr")))?;
    Ok(format!("{stdout}\n{stderr}").trim().to_owned())
}

fn project_dir(runtime: &dyn Runtime) -> Result<Option<PathBuf>, AdapterError> {
    let project = runtime.project_dir();
    if let Some(project) = &project {
        validate_path(project)?;
    }
    Ok(project)
}

fn config_layout(
    runtime: &dyn Runtime,
    project: Option<&Path>,
) -> Result<ConfigLayout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("uv user configuration requires a home directory".into())
    })?;
    validate_path(&home)?;
    let user_root = runtime
        .environment_variable("XDG_CONFIG_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    validate_path(&user_root)?;
    let mut system = PathBuf::from("/etc/uv/uv.toml");
    if let Some(roots) = runtime
        .environment_variable("XDG_CONFIG_DIRS")
        .filter(|value| !value.trim().is_empty())
    {
        for root in roots.split(':').filter(|value| !value.is_empty()) {
            let candidate = PathBuf::from(root).join("uv/uv.toml");
            validate_path(&candidate)?;
            if runtime.read(&candidate)?.is_some() {
                system = candidate;
                break;
            }
        }
    }
    let (project_path, project_is_pyproject, ignored_pyproject) = if let Some(project) = project {
        let standalone = project.join("uv.toml");
        let pyproject = project.join("pyproject.toml");
        if runtime.read(&standalone)?.is_some() {
            (Some(standalone), false, Some(pyproject))
        } else if runtime.read(&pyproject)?.is_some() {
            (Some(pyproject), true, None)
        } else {
            (Some(standalone), false, None)
        }
    } else {
        (None, false, None)
    };
    Ok(ConfigLayout {
        system,
        user: user_root.join("uv/uv.toml"),
        project: project_path,
        project_is_pyproject,
        ignored_pyproject,
    })
}

fn config_sources(
    text: &str,
    format: ConfigFormat,
    origin: Origin,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let document = parse_document(path, text)?;
    let root = match format {
        ConfigFormat::Standalone => document.as_item(),
        ConfigFormat::Pyproject => item_at(&document, &["tool", "uv"]).unwrap_or(&Item::None),
        ConfigFormat::Ignored => return Ok(Vec::new()),
    };
    let Some(table) = root.as_table_like() else {
        if format == ConfigFormat::Pyproject && root.is_none() {
            return Ok(Vec::new());
        }
        return Err(AdapterError::InvalidConfiguration(format!(
            "uv settings in {} are not a table",
            path.display()
        )));
    };
    let mut sources = Vec::new();
    if let Some(indexes) = table.get("index") {
        let indexes = indexes.as_array_of_tables().ok_or_else(|| {
            AdapterError::InvalidConfiguration("uv index is not an array of tables".into())
        })?;
        let mut names = BTreeSet::new();
        for (order, index) in indexes.iter().enumerate() {
            let name = index.get("name").and_then(Item::as_str).unwrap_or("");
            if !name.is_empty() && !names.insert(name.to_ascii_lowercase()) {
                return Err(AdapterError::InvalidConfiguration(
                    "uv named indexes must be unique".into(),
                ));
            }
            let url = index.get("url").and_then(Item::as_str).ok_or_else(|| {
                AdapterError::InvalidConfiguration("uv index has no string URL".into())
            })?;
            if index
                .get("format")
                .and_then(Item::as_str)
                .is_some_and(|value| value != "simple")
            {
                sources.push(index_source(
                    "<preserved>",
                    "additional-index",
                    origin,
                    path,
                    name,
                    false,
                    index.get("explicit").and_then(Item::as_bool) == Some(true),
                    order,
                ));
                continue;
            }
            sources.push(index_source(
                url,
                if index.get("default").and_then(Item::as_bool) == Some(true) {
                    "default-index"
                } else {
                    "additional-index"
                },
                origin,
                path,
                name,
                index.get("default").and_then(Item::as_bool) == Some(true),
                index.get("explicit").and_then(Item::as_bool) == Some(true),
                order,
            ));
        }
    }
    if let Some(url) = table.get("index-url").and_then(Item::as_str) {
        sources.push(index_source(
            url,
            "default-index",
            origin,
            path,
            "",
            true,
            false,
            0,
        ));
    }
    for key in ["extra-index-url"] {
        if let Some(values) = table.get(key).and_then(Item::as_array) {
            for (order, value) in values.iter().enumerate() {
                let url = value.as_str().ok_or_else(|| {
                    AdapterError::InvalidConfiguration("uv extra index URL is not a string".into())
                })?;
                sources.push(index_source(
                    url,
                    "additional-index",
                    origin,
                    path,
                    "",
                    false,
                    false,
                    order,
                ));
            }
        }
    }
    if let Some(strategy) = table.get("index-strategy").and_then(Item::as_str) {
        sources.push(policy_source("index-strategy", strategy, origin, path));
    }
    if let Some(pip) = table.get("pip").and_then(Item::as_table_like) {
        for key in ["index-url", "extra-index-url", "index-strategy"] {
            if pip.get(key).is_some() {
                sources.push(policy_source("pip-override", "configured", origin, path));
            }
        }
    }
    Ok(sources)
}

fn environment_sources(runtime: &dyn Runtime) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    for key in ["UV_DEFAULT_INDEX", "UV_INDEX_URL"] {
        if let Some(value) = runtime
            .environment_variable(key)
            .filter(|value| !value.trim().is_empty())
        {
            sources.push(index_source(
                &value,
                "environment-default",
                Origin::Environment,
                Path::new(":env:"),
                "",
                true,
                false,
                0,
            ));
        }
    }
    for key in ["UV_INDEX", "UV_EXTRA_INDEX_URL"] {
        if runtime
            .environment_variable(key)
            .is_some_and(|value| !value.trim().is_empty())
        {
            sources.push(policy_source(
                "environment-additional",
                "configured",
                Origin::Environment,
                Path::new(":env:"),
            ));
        }
    }
    if runtime
        .environment_variable("UV_CONFIG_FILE")
        .is_some_and(|value| !value.trim().is_empty())
    {
        sources.push(policy_source(
            "configuration-override",
            "configured",
            Origin::Environment,
            Path::new(":env:"),
        ));
    }
    if runtime
        .environment_variable("UV_NO_CONFIG")
        .is_some_and(|value| environment_flag_enabled(&value))
    {
        sources.push(policy_source(
            "configuration-override",
            "configured",
            Origin::Environment,
            Path::new(":env:"),
        ));
    }
    if index_credentials_configured(runtime, SOURCE_NAME) {
        sources.push(policy_source(
            "generated-index-credentials",
            "configured",
            Origin::Environment,
            Path::new(":env:"),
        ));
    }
    if let Some(strategy) = runtime
        .environment_variable("UV_INDEX_STRATEGY")
        .filter(|value| !value.trim().is_empty())
    {
        sources.push(policy_source(
            "index-strategy",
            &strategy,
            Origin::Environment,
            Path::new(":env:"),
        ));
    }
    sources
}

fn mark_index_credentials(runtime: &dyn Runtime, sources: &mut [ConfiguredSource]) {
    for source in sources {
        let Some(name) = source
            .metadata
            .get("source_name")
            .and_then(|values| values.first())
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        source.metadata.insert(
            "credentials".into(),
            vec![index_credentials_configured(runtime, name).to_string()],
        );
    }
}

fn index_credentials_configured(runtime: &dyn Runtime, name: &str) -> bool {
    let suffix = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    [
        format!("UV_INDEX_{suffix}_USERNAME"),
        format!("UV_INDEX_{suffix}_PASSWORD"),
    ]
    .iter()
    .any(|key| {
        runtime
            .environment_variable(key)
            .is_some_and(|value| !value.is_empty())
    })
}

fn environment_flag_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off"
    )
}

#[allow(clippy::too_many_arguments)]
fn index_source(
    url: &str,
    kind: &str,
    origin: Origin,
    path: &Path,
    name: &str,
    default: bool,
    explicit: bool,
    order: usize,
) -> ConfiguredSource {
    let public = is_public_index(url);
    ConfiguredSource {
        upstream_id: public.then(|| PYPI_UPSTREAM.into()),
        url: if public {
            url.into()
        } else {
            "<redacted>".into()
        },
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin_scope".into(), vec![origin_name(origin).into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("source_name".into(), vec![name.into()]),
            ("default".into(), vec![default.to_string()]),
            ("explicit".into(), vec![explicit.to_string()]),
            ("credentials".into(), vec!["false".into()]),
            ("order".into(), vec![order.to_string()]),
        ]),
    }
}

fn policy_source(kind: &str, value: &str, origin: Origin, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: value.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin_scope".into(), vec![origin_name(origin).into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("source_name".into(), vec!["".into()]),
        ]),
    }
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        if matches!(
            kind,
            "environment-default" | "environment-additional" | "configuration-override"
        ) {
            return Err(AdapterError::Unsupported(
                "uv environment index or configuration overrides must be changed outside MirrorSwitch"
                    .into(),
            ));
        }
        if kind == "additional-index" && metadata(source, "explicit")? != "true" {
            return Err(AdapterError::Unsupported(
                "uv has a searchable additional index; MirrorSwitch will not combine it with an automatic public default"
                    .into(),
            ));
        }
        if kind == "pip-override" {
            return Err(AdapterError::Unsupported(
                "uv.pip index settings override the shared uv index model and require separate handling"
                    .into(),
            ));
        }
    }
    let effective_strategy = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some("index-strategy"))
        .max_by_key(|source| origin_priority(metadata(source, "origin_scope").unwrap_or("")));
    if effective_strategy.is_some_and(|source| source.url != "first-index") {
        return Err(AdapterError::Unsupported(
            "uv effective index strategy is not the dependency-confusion-resistant first-index mode"
                .into(),
        ));
    }
    Ok(())
}

fn origin_priority(origin: &str) -> u8 {
    match origin {
        "environment" => 3,
        "project" => 2,
        "user" => 1,
        "system" => 0,
        _ => 0,
    }
}

fn selected_default(
    current: &CurrentConfiguration,
    selected: &Path,
) -> Result<Option<String>, AdapterError> {
    let selected_path = selected.display().to_string();
    let defaults = current
        .sources
        .iter()
        .filter(|source| {
            metadata(source, "kind").ok() == Some("default-index")
                && metadata(source, "config_path").ok() == Some(selected_path.as_str())
        })
        .collect::<Vec<_>>();
    if defaults.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "uv selected scope defines multiple default indexes".into(),
        ));
    }
    if let Some(source) = defaults.first() {
        if source.upstream_id.is_none() {
            return Err(AdapterError::Unsupported(
                "uv selected scope has a private or unmapped default index".into(),
            ));
        }
        if metadata(source, "explicit")? == "true" {
            return Err(AdapterError::Unsupported(
                "uv selected default is explicit and cannot serve general package resolution"
                    .into(),
            ));
        }
        if metadata(source, "credentials")? == "true" {
            return Err(AdapterError::Unsupported(
                "uv selected default has name-scoped environment credentials".into(),
            ));
        }
        let name = metadata(source, "source_name")?;
        if current.scope == ConfigurationScope::User
            && !name.is_empty()
            && current.sources.iter().any(|candidate| {
                metadata(candidate, "origin_scope").ok() == Some("project")
                    && metadata(candidate, "source_name")
                        .ok()
                        .is_some_and(|candidate_name| candidate_name.eq_ignore_ascii_case(name))
            })
        {
            return Err(AdapterError::Unsupported(
                "uv project index with the same name has higher precedence than the user default"
                    .into(),
            ));
        }
        return Ok(Some(name.into()));
    }
    if current.sources.iter().any(|source| {
        let selected_or_higher = metadata(source, "config_path").ok()
            == Some(selected_path.as_str())
            || (current.scope == ConfigurationScope::User
                && metadata(source, "origin_scope").ok() == Some("project"));
        selected_or_higher
            && metadata(source, "source_name")
                .ok()
                .is_some_and(|name| name.eq_ignore_ascii_case(SOURCE_NAME))
    }) {
        return Err(AdapterError::Unsupported(format!(
            "uv selected scope already defines the reserved index name {SOURCE_NAME}"
        )));
    }
    if current
        .sources
        .iter()
        .any(|source| metadata(source, "kind").ok() == Some("generated-index-credentials"))
    {
        return Err(AdapterError::Unsupported(
            "uv reserved index name has environment credentials".into(),
        ));
    }
    Ok(None)
}

fn validate_precedence(
    current: &CurrentConfiguration,
    selected: &Path,
) -> Result<(), AdapterError> {
    let selected_path = selected.display().to_string();
    for source in &current.sources {
        if metadata(source, "kind")? != "default-index"
            || metadata(source, "config_path")? == selected_path
        {
            continue;
        }
        let origin = metadata(source, "origin_scope")?;
        if current.scope == ConfigurationScope::User && origin == "project" {
            return Err(AdapterError::Unsupported(
                "uv project default index has higher precedence than user scope".into(),
            ));
        }
    }
    Ok(())
}

fn rewrite_config(
    text: &str,
    pyproject: bool,
    selected_name: Option<&str>,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let mut document = parse_document(Path::new("uv configuration"), text)?;
    let table: &mut dyn toml_edit::TableLike = if pyproject {
        if document.get("tool").is_none() {
            document["tool"] = Item::Table(Table::new());
        }
        let tool = document["tool"].as_table_mut().ok_or_else(|| {
            AdapterError::InvalidConfiguration("pyproject tool entry is not a table".into())
        })?;
        if tool.get("uv").is_none() {
            tool["uv"] = Item::Table(Table::new());
        }
        tool["uv"].as_table_mut().ok_or_else(|| {
            AdapterError::InvalidConfiguration("pyproject tool.uv entry is not a table".into())
        })?
    } else {
        document.as_table_mut()
    };
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    if selected_name == Some("") && table.get("index-url").is_some() {
        table.insert("index-url", value(endpoint));
        return Ok(document.to_string());
    }
    if table.get("index").is_none() {
        table.insert("index", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let indexes = table
        .get_mut("index")
        .and_then(Item::as_array_of_tables_mut)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("uv index is not an array of tables".into())
        })?;
    if let Some(name) = selected_name {
        let target = if name.is_empty() {
            indexes
                .iter_mut()
                .find(|index| index.get("default").and_then(Item::as_bool) == Some(true))
        } else {
            indexes.iter_mut().find(|index| {
                index
                    .get("name")
                    .and_then(Item::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(name))
            })
        };
        if let Some(target) = target {
            target["url"] = value(endpoint);
        } else {
            return Err(AdapterError::InvalidConfiguration(
                "uv selected default index disappeared".into(),
            ));
        }
    } else {
        let mut index = Table::new();
        index["name"] = value(SOURCE_NAME);
        index["url"] = value(endpoint);
        index["default"] = value(true);
        indexes.push(index);
    }
    Ok(document.to_string())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "uv"
        || selections[0].upstream_id != PYPI_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "uv plan requires exactly one PyPI mirror selection".into(),
        ));
    }
    let index = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "uv selection has no HTTPS Simple API endpoint".into(),
            )
        })?;
    let artifact = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("uv selection has no HTTPS artifact endpoint".into())
        })?;
    let index_value = normalized_index(&index.url)
        .ok_or_else(|| AdapterError::InvalidConfiguration("uv index endpoint is unsafe".into()))?;
    let artifact_value = normalized_index(&artifact.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("uv artifact endpoint is unsafe".into())
    })?;
    let provider = MIRROR_INDEXES
        .iter()
        .position(|candidate| *candidate == index_value);
    if provider.is_none_or(|provider| MIRROR_ARTIFACTS[provider] != artifact_value) {
        return Err(AdapterError::InvalidConfiguration(
            "uv index and artifact endpoints do not belong to one reviewed provider".into(),
        ));
    }
    Ok(index.url.trim_end_matches('/'))
}

fn parse_document(path: &Path, text: &str) -> Result<DocumentMut, AdapterError> {
    text.parse::<DocumentMut>().map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "uv configuration {} is invalid TOML",
            path.display()
        ))
    })
}

fn item_at<'a>(document: &'a DocumentMut, path: &[&str]) -> Option<&'a Item> {
    let mut item = document.as_item();
    for key in path {
        item = item.get(key)?;
    }
    Some(item)
}

fn is_official_index(value: &str) -> bool {
    normalized_index(value).is_some_and(|value| OFFICIAL_INDEXES.contains(&value.as_str()))
}

fn is_known_mirror(value: &str) -> bool {
    normalized_index(value).is_some_and(|value| MIRROR_INDEXES.contains(&value.as_str()))
}

fn is_public_index(value: &str) -> bool {
    is_official_index(value) || is_known_mirror(value)
}

fn normalized_index(value: &str) -> Option<String> {
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

fn origin_name(origin: Origin) -> &'static str {
    match origin {
        Origin::System => "system",
        Origin::User => "user",
        Origin::Project => "project",
        Origin::Environment => "environment",
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("uv source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "uv source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "uv reported unsafe configuration path {}",
            path.display()
        )));
    }
    Ok(())
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
            "uv configuration {} is not UTF-8",
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
