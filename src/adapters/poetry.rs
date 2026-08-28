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
pub struct PoetryAdapter;

impl Adapter for PoetryAdapter {
    fn key(&self) -> &'static str {
        "poetry"
    }

    fn tool_id(&self) -> &'static str {
        "poetry"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::Project]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::Project
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
        if !runtime.command_exists("poetry") {
            return Ok(None);
        }
        let project = project_dir(runtime)?;
        let version = run_poetry(
            runtime,
            project.as_deref(),
            &["--version"],
            "poetry --version",
        )?;
        let generation = poetry_generation(&version)?;
        let config = config_layout(runtime)?;
        let mut evidence = vec![
            format!("{version}; {}", generation.name()),
            format!("global configuration path is {}", config.config.display()),
            format!("credential file path is {}", config.auth.display()),
            "package sources are project-local; no global installation-source override exists"
                .into(),
        ];
        if let Some(project) = project {
            evidence.push(format!("project root is {}", project.display()));
        } else {
            evidence.push("explicit project scope is required before planning".into());
        }
        Ok(Some(DetectedTool {
            tool_id: "poetry".into(),
            executable: Some(PathBuf::from("poetry")),
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
        let version = detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Poetry version is missing".into())
        })?;
        let generation = poetry_generation(version)?;
        let project = project_dir(runtime)?.ok_or_else(|| {
            AdapterError::Unsupported(
                "Poetry has no global package-source override; select an explicit project directory"
                    .into(),
            )
        })?;
        let pyproject = project.join("pyproject.toml");
        let layout = config_layout(runtime)?;
        let paths = [
            (layout.config, "poetry-global-config"),
            (layout.auth, "poetry-global-auth"),
            (project.join("poetry.toml"), "poetry-project-local-config"),
            (pyproject.clone(), "poetry-selected-project"),
        ];
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = Vec::new();
        let mut project_names = BTreeSet::new();
        for (path, format) in paths {
            validate_path(&path)?;
            let observed = runtime.read(&path)?;
            let exists = observed.is_some();
            if path == pyproject && !exists {
                return Err(AdapterError::Unsupported(format!(
                    "Poetry project scope requires an existing {}",
                    path.display()
                )));
            }
            let contents = observed.unwrap_or_default();
            if exists {
                files.push(path.clone());
            }
            let text = utf8(&path, &contents)?;
            if format == "poetry-selected-project" {
                let parsed = project_sources(text, generation, &path)?;
                project_names.extend(parsed.iter().filter_map(|source| {
                    (metadata(source, "kind").ok() == Some("package-source"))
                        .then(|| metadata(source, "source_name").ok().map(str::to_owned))
                        .flatten()
                }));
                sources.extend(parsed);
            } else {
                sources.extend(configuration_sources(text, format, &path)?);
            }
            documents.push(ConfigurationDocument {
                path,
                format: format.into(),
                contents,
            });
        }
        project_names.insert(SOURCE_NAME.into());
        sources.extend(environment_sources(runtime, &project_names));
        let keyring = run_poetry(
            runtime,
            Some(&project),
            &["config", "keyring.enabled"],
            "poetry config keyring.enabled",
        )?;
        sources.push(policy_source(
            "keyring",
            if keyring.eq_ignore_ascii_case("true") {
                "enabled"
            } else {
                "disabled"
            },
            "effective",
            Path::new(":poetry:"),
            "*",
        ));
        if !sources.iter().any(|source| {
            metadata(source, "kind").ok() == Some("package-source")
                && metadata(source, "priority").ok() == Some("primary")
        }) {
            sources.push(package_source(
                "https://pypi.org/simple/",
                "implicit",
                Path::new(":poetry:"),
                "PyPI",
                "primary",
                false,
                0,
            ));
        }
        Ok(CurrentConfiguration {
            tool_id: "poetry".into(),
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
            tool_id: "poetry".into(),
            adapter_key: "poetry".into(),
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
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "poetry-selected-project")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Poetry project document is missing".into())
            })?;
        let target = target_source(current)?;
        validate_target_policy(current, &target, endpoint)?;
        let new_contents =
            rewrite_project(utf8(&document.path, &document.contents)?, &target, endpoint)?
                .into_bytes();
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: format!(
                    "set the explicit Poetry project primary source {}; preserve supplemental and explicit sources, credentials, dependency constraints, and global publishing configuration",
                    target.name()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "poetry".into(),
            tool_id: "poetry".into(),
            scope: ConfigurationScope::Project,
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
            let project = project_dir(runtime)?.ok_or_else(|| {
                AdapterError::Verification("Poetry project context disappeared".into())
            })?;
            let path = project.join("pyproject.toml");
            let contents = runtime.read(&path)?.ok_or_else(|| {
                AdapterError::Verification("Poetry pyproject.toml disappeared".into())
            })?;
            let version = run_poetry(runtime, Some(&project), &["--version"], "poetry --version")?;
            let sources =
                project_sources(utf8(&path, &contents)?, poetry_generation(&version)?, &path)?;
            let selected = sources
                .iter()
                .filter(|source| {
                    metadata(source, "kind").ok() == Some("package-source")
                        && metadata(source, "priority").ok() == Some("primary")
                        && is_known_mirror(&source.url)
                })
                .collect::<Vec<_>>();
            if selected.len() != 1 {
                return Err(AdapterError::Verification(
                    "Poetry project does not expose exactly one reviewed primary mirror".into(),
                ));
            }
            let name = metadata(selected[0], "source_name")?;
            let shown = run_poetry(
                runtime,
                Some(&project),
                &["source", "show", name, "--no-ansi"],
                "poetry source show",
            )?;
            if !shown.contains(name)
                || !shown.contains(selected[0].url.trim_end_matches('/'))
                || !shown.to_ascii_lowercase().contains("primary")
            {
                return Err(AdapterError::Verification(
                    "Poetry source output does not match the planned primary mirror".into(),
                ));
            }
            let resolved = run_poetry(
                runtime,
                Some(&project),
                &[
                    "debug",
                    "resolve",
                    "--no-cache",
                    "--no-ansi",
                    "sampleproject==4.0.0",
                ],
                "poetry debug resolve",
            )?;
            if !resolved.to_ascii_lowercase().contains("sampleproject")
                || !resolved.contains("4.0.0")
            {
                return Err(AdapterError::Verification(
                    "Poetry resolution did not select sampleproject 4.0.0".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: "Poetry source inspection and real dependency resolution validated the project mirror"
                    .into(),
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
                "restored {} Poetry project files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PoetryGeneration {
    One,
    Two,
}

impl PoetryGeneration {
    fn name(self) -> &'static str {
        match self {
            Self::One => "1.5+ source-priority model",
            Self::Two => "2.x source-priority model",
        }
    }
}

#[derive(Clone, Debug)]
struct ConfigLayout {
    config: PathBuf,
    auth: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceTarget {
    Insert,
    Rewrite(String),
}

impl SourceTarget {
    fn name(&self) -> &str {
        match self {
            Self::Insert => SOURCE_NAME,
            Self::Rewrite(name) => name,
        }
    }

    fn rewrites_existing(&self) -> bool {
        matches!(self, Self::Rewrite(_))
    }
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Poetry adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::Project {
        return Err(AdapterError::Unsupported(
            "Poetry package sources are project-local and require explicit project scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "poetry" {
        return Err(AdapterError::InvalidConfiguration(
            "Poetry operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn poetry_generation(version: &str) -> Result<PoetryGeneration, AdapterError> {
    let token = version
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|token| !token.is_empty())
        .ok_or_else(|| {
            AdapterError::Unsupported(format!("unrecognized Poetry version {version}"))
        })?;
    let mut parts = token.split('.');
    let major = parts.next().and_then(|value| value.parse::<u64>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u64>().ok());
    match (major, minor) {
        (Some(1), Some(minor)) if minor >= 5 => Ok(PoetryGeneration::One),
        (Some(2), Some(minor)) if minor <= 4 => Ok(PoetryGeneration::Two),
        (Some(1), _) => Err(AdapterError::Unsupported(
            "Poetry support starts at 1.5.0, where primary, supplemental, and explicit priorities are available"
                .into(),
        )),
        (Some(2), _) => Err(AdapterError::Unsupported(
            "Poetry 2.x support is reviewed through 2.4".into(),
        )),
        _ => Err(AdapterError::Unsupported(format!(
            "Poetry {version} is outside the reviewed 1.5+ and 2.0-2.4 range"
        ))),
    }
}

fn run_poetry(
    runtime: &dyn Runtime,
    project: Option<&Path>,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = if let Some(project) = project {
        runtime.run_in(project, "poetry", &arguments)?
    } else {
        runtime.run("poetry", &arguments)?
    };
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

fn project_dir(runtime: &dyn Runtime) -> Result<Option<PathBuf>, AdapterError> {
    let project = runtime
        .environment_variable("POETRY_PROJECT")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| runtime.project_dir());
    if let Some(project) = &project {
        validate_path(project)?;
    }
    Ok(project)
}

fn config_layout(runtime: &dyn Runtime) -> Result<ConfigLayout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("Poetry configuration discovery requires a home directory".into())
    })?;
    validate_path(&home)?;
    let directory = runtime
        .environment_variable("POETRY_CONFIG_DIR")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            runtime
                .environment_variable("XDG_CONFIG_HOME")
                .filter(|value| !value.trim().is_empty())
                .map(|value| PathBuf::from(value).join("pypoetry"))
        })
        .unwrap_or_else(|| home.join(".config/pypoetry"));
    validate_path(&directory)?;
    Ok(ConfigLayout {
        config: directory.join("config.toml"),
        auth: directory.join("auth.toml"),
    })
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Poetry reported unsafe configuration path {}",
            path.display()
        )));
    }
    Ok(())
}

fn parse_document(path: &Path, text: &str) -> Result<DocumentMut, AdapterError> {
    text.parse::<DocumentMut>().map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Poetry configuration {} is invalid TOML",
            path.display()
        ))
    })
}

fn project_sources(
    text: &str,
    _generation: PoetryGeneration,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let document = parse_document(path, text)?;
    let Some(item) = item_at(&document, &["tool", "poetry", "source"]) else {
        return Ok(Vec::new());
    };
    let tables = item.as_array_of_tables().ok_or_else(|| {
        AdapterError::InvalidConfiguration(
            "Poetry project sources are not an array of tables".into(),
        )
    })?;
    let mut names = BTreeSet::new();
    let mut sources = Vec::new();
    for (order, table) in tables.iter().enumerate() {
        let name = table.get("name").and_then(Item::as_str).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Poetry source {order} has no string name"))
        })?;
        if name.trim().is_empty() || !names.insert(name.to_ascii_lowercase()) {
            return Err(AdapterError::InvalidConfiguration(
                "Poetry source names must be non-empty and unique".into(),
            ));
        }
        let priority = table
            .get("priority")
            .map(|item| {
                item.as_str().ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Poetry source {name} has a non-string priority"
                    ))
                })
            })
            .transpose()?
            .unwrap_or("primary")
            .to_ascii_lowercase();
        if !matches!(priority.as_str(), "primary" | "supplemental" | "explicit") {
            return Err(AdapterError::Unsupported(format!(
                "Poetry source {name} uses deprecated or unknown priority {priority}; supported priorities are primary, supplemental, and explicit"
            )));
        }
        let url = table
            .get("url")
            .map(|item| {
                item.as_str().ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Poetry source {name} has a non-string URL"
                    ))
                })
            })
            .transpose()?;
        if name.eq_ignore_ascii_case("pypi") {
            if url.is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "Poetry reserves source name PyPI and does not allow it to have a custom URL"
                        .into(),
                ));
            }
            sources.push(package_source(
                "https://pypi.org/simple/",
                "project",
                path,
                name,
                &priority,
                false,
                order,
            ));
            continue;
        }
        let url = url.ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Poetry source {name} has no URL"))
        })?;
        sources.push(package_source(
            url,
            "project",
            path,
            name,
            &priority,
            url_has_credentials(url),
            order,
        ));
    }
    Ok(sources)
}

fn configuration_sources(
    text: &str,
    format: &str,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let document = parse_document(path, text)?;
    let origin = if format == "poetry-project-local-config" {
        "project-local"
    } else {
        "global"
    };
    let mut sources = Vec::new();
    for section in ["http-basic", "pypi-token"] {
        if let Some(table) = item_at(&document, &[section]).and_then(Item::as_table_like) {
            for (name, item) in table.iter() {
                let configured = if section == "http-basic" {
                    item.as_table_like().is_some_and(|credentials| {
                        ["username", "password"].iter().any(|key| {
                            credentials
                                .get(key)
                                .and_then(Item::as_str)
                                .is_some_and(|value| !value.is_empty())
                        })
                    })
                } else {
                    item.as_str().is_some_and(|value| !value.is_empty())
                };
                if configured {
                    sources.push(policy_source(
                        "credential",
                        "<redacted>",
                        origin,
                        path,
                        name,
                    ));
                }
            }
        }
    }
    if let Some(table) = item_at(&document, &["certificates"]).and_then(Item::as_table_like) {
        for (name, item) in table.iter() {
            let Some(certificate) = item.as_table_like() else {
                continue;
            };
            if certificate.get("cert").is_some() || certificate.get("client-cert").is_some() {
                sources.push(policy_source(
                    "certificate",
                    "<configured>",
                    origin,
                    path,
                    name,
                ));
            }
        }
    }
    if let Some(table) = item_at(&document, &["repositories"]).and_then(Item::as_table_like) {
        for (name, item) in table.iter() {
            if item
                .as_table_like()
                .and_then(|repository| repository.get("url"))
                .and_then(Item::as_str)
                .is_some()
            {
                sources.push(policy_source(
                    "publish-repository",
                    "<preserved>",
                    origin,
                    path,
                    name,
                ));
            }
        }
    }
    Ok(sources)
}

fn environment_sources(runtime: &dyn Runtime, names: &BTreeSet<String>) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    for name in names {
        let suffix = environment_suffix(name);
        if [
            format!("POETRY_HTTP_BASIC_{suffix}_USERNAME"),
            format!("POETRY_HTTP_BASIC_{suffix}_PASSWORD"),
            format!("POETRY_PYPI_TOKEN_{suffix}"),
        ]
        .iter()
        .any(|key| {
            runtime
                .environment_variable(key)
                .is_some_and(|value| !value.is_empty())
        }) {
            sources.push(policy_source(
                "credential",
                "<redacted>",
                "environment",
                Path::new(":env:"),
                name,
            ));
        }
        if [
            format!("POETRY_CERTIFICATES_{suffix}_CERT"),
            format!("POETRY_CERTIFICATES_{suffix}_CLIENT_CERT"),
        ]
        .iter()
        .any(|key| {
            runtime
                .environment_variable(key)
                .is_some_and(|value| !value.is_empty())
        }) {
            sources.push(policy_source(
                "certificate",
                "<configured>",
                "environment",
                Path::new(":env:"),
                name,
            ));
        }
    }
    sources
}

fn environment_suffix(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn package_source(
    url: &str,
    origin: &str,
    path: &Path,
    name: &str,
    priority: &str,
    has_credentials: bool,
    order: usize,
) -> ConfiguredSource {
    let public = is_public_index(url);
    let kind = if origin == "implicit" {
        "implicit-pypi"
    } else {
        "package-source"
    };
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
            ("origin_scope".into(), vec![origin.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("source_name".into(), vec![name.into()]),
            ("priority".into(), vec![priority.into()]),
            ("has_credentials".into(), vec![has_credentials.to_string()]),
            ("order".into(), vec![order.to_string()]),
        ]),
    }
}

fn policy_source(
    kind: &str,
    value: &str,
    origin: &str,
    path: &Path,
    name: &str,
) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: value.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin_scope".into(), vec![origin.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("source_name".into(), vec![name.into()]),
        ]),
    }
}

fn target_source(current: &CurrentConfiguration) -> Result<SourceTarget, AdapterError> {
    let configured = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some("package-source"))
        .collect::<Vec<_>>();
    if configured.iter().any(|source| {
        metadata(source, "source_name").is_ok_and(|name| name.eq_ignore_ascii_case(SOURCE_NAME))
            && metadata(source, "priority").ok() != Some("primary")
    }) {
        return Err(AdapterError::Unsupported(format!(
            "Poetry source name {SOURCE_NAME} already exists with a non-primary priority"
        )));
    }
    let primary = configured
        .iter()
        .filter(|source| metadata(source, "priority").ok() == Some("primary"))
        .copied()
        .collect::<Vec<_>>();
    if primary.is_empty() {
        return Ok(SourceTarget::Insert);
    }
    if primary.len() != 1 {
        return Err(AdapterError::Unsupported(
            "Poetry has multiple configured primary sources; changing one would not define an exclusive PyPI replacement"
                .into(),
        ));
    }
    let source = primary[0];
    let name = metadata(source, "source_name")?;
    if name.eq_ignore_ascii_case("pypi") {
        return Err(AdapterError::Unsupported(
            "Poetry has an explicit built-in PyPI source; replacing its reserved name could break source-constrained dependencies"
                .into(),
        ));
    }
    if source.upstream_id.is_none() {
        return Err(AdapterError::Unsupported(
            "Poetry has a private or unmapped primary source that must not be combined with an automatic public replacement"
                .into(),
        ));
    }
    Ok(SourceTarget::Rewrite(name.into()))
}

fn validate_target_policy(
    current: &CurrentConfiguration,
    target: &SourceTarget,
    endpoint: &str,
) -> Result<(), AdapterError> {
    let name = target.name();
    if target.rewrites_existing()
        && current.sources.iter().any(|source| {
            metadata(source, "kind").ok() == Some("package-source")
                && metadata(source, "source_name")
                    .is_ok_and(|configured| configured.eq_ignore_ascii_case(name))
                && normalized_index(&source.url).as_deref() == normalized_index(endpoint).as_deref()
        })
    {
        return Ok(());
    }
    for source in &current.sources {
        if !metadata(source, "source_name")
            .is_ok_and(|configured| configured.eq_ignore_ascii_case(name))
        {
            continue;
        }
        let kind = metadata(source, "kind")?;
        if kind == "credential"
            || source
                .metadata
                .get("has_credentials")
                .is_some_and(|values| values == &["true"])
        {
            return Err(AdapterError::Unsupported(
                "Poetry credentials cannot follow a package source to a public mirror".into(),
            ));
        }
        if kind == "certificate" {
            return Err(AdapterError::Unsupported(
                "Poetry source-specific certificate settings cannot follow a changed mirror host"
                    .into(),
            ));
        }
    }
    if target.rewrites_existing()
        && current.sources.iter().any(|source| {
            metadata(source, "kind").ok() == Some("keyring") && source.url == "enabled"
        })
    {
        return Err(AdapterError::Unsupported(
            "Poetry keyring is enabled, so credentials for the existing source name cannot be ruled out; use a new explicit project source or disable the keyring"
                .into(),
        ));
    }
    Ok(())
}

fn rewrite_project(
    text: &str,
    target: &SourceTarget,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let mut document = parse_document(Path::new("pyproject.toml"), text)?;
    if document.get("tool").is_none() {
        document["tool"] = Item::Table(Table::new());
    }
    let tool = document["tool"].as_table_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Poetry project tool entry is not a table".into())
    })?;
    if tool.get("poetry").is_none() {
        tool["poetry"] = Item::Table(Table::new());
    }
    let poetry = tool["poetry"].as_table_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Poetry project tool.poetry entry is not a table".into())
    })?;
    if poetry.get("source").is_none() {
        poetry["source"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    let sources = poetry["source"].as_array_of_tables_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration(
            "Poetry project sources are not an array of tables".into(),
        )
    })?;
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    match target {
        SourceTarget::Insert => {
            let mut source = Table::new();
            source["name"] = value(SOURCE_NAME);
            source["url"] = value(endpoint);
            source["priority"] = value("primary");
            sources.insert(0, source);
        }
        SourceTarget::Rewrite(name) => {
            let source = sources
                .iter_mut()
                .find(|source| {
                    source
                        .get("name")
                        .and_then(Item::as_str)
                        .is_some_and(|configured| configured.eq_ignore_ascii_case(name))
                })
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Poetry selected primary source disappeared".into(),
                    )
                })?;
            source["url"] = value(endpoint);
        }
    }
    Ok(document.to_string())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "poetry"
        || selections[0].upstream_id != PYPI_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Poetry plan requires exactly one PyPI mirror selection".into(),
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
                "Poetry selection has no HTTPS Simple API endpoint".into(),
            )
        })?;
    let artifact = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Poetry selection has no HTTPS package artifact endpoint".into(),
            )
        })?;
    let index_normalized = normalized_index(&index.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Poetry index endpoint is unsafe".into())
    })?;
    let artifact_normalized = normalized_index(&artifact.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Poetry artifact endpoint is unsafe".into())
    })?;
    let provider = MIRROR_INDEXES
        .iter()
        .position(|candidate| *candidate == index_normalized);
    if provider.is_none_or(|provider| MIRROR_ARTIFACTS[provider] != artifact_normalized) {
        return Err(AdapterError::InvalidConfiguration(
            "Poetry index and artifact endpoints do not belong to one reviewed provider".into(),
        ));
    }
    Ok(index.url.trim_end_matches('/'))
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

fn url_has_credentials(value: &str) -> bool {
    reqwest::Url::parse(value).map_or_else(
        |_| value.contains('@') || value.contains("${"),
        |url| !url.username().is_empty() || url.password().is_some(),
    )
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Poetry source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Poetry source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
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
            "Poetry configuration {} is not UTF-8",
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
