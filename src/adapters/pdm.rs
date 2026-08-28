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
pub struct PdmAdapter;

impl Adapter for PdmAdapter {
    fn key(&self) -> &'static str {
        "pdm"
    }

    fn tool_id(&self) -> &'static str {
        "pdm"
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
        if !runtime.command_exists("pdm") {
            return Ok(None);
        }
        let project = project_dir(runtime)?;
        let version = run_pdm(runtime, project.as_deref(), &["--version"], "pdm --version")?;
        if pdm_major(&version) != Some(2) {
            return Err(AdapterError::Unsupported(format!(
                "PDM adapter supports the reviewed 2.x configuration model, not {version}"
            )));
        }
        let effective = run_pdm(
            runtime,
            project.as_deref(),
            &["config", "pypi.url"],
            "pdm effective pypi.url",
        )?;
        let class = if is_official_index(&effective) {
            "official PyPI"
        } else if is_known_mirror(&effective) {
            "reviewed mirror"
        } else {
            "custom or private index"
        };
        let layout = config_layout(runtime)?;
        let mut evidence = vec![
            version.clone(),
            format!("effective default source is a {class}"),
            format!("user configuration path is {}", layout.user.display()),
        ];
        if let Some(project) = project {
            evidence.push(format!(
                "project configuration root is {}",
                project.display()
            ));
        }
        Ok(Some(DetectedTool {
            tool_id: "pdm".into(),
            executable: Some(PathBuf::from("pdm")),
            version: Some(version),
            evidence,
        }))
    }

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        require_linux(context)?;
        require_scope(scope)?;
        let layout = config_layout(runtime)?;
        let selected = match scope {
            ConfigurationScope::User => layout.user.clone(),
            ConfigurationScope::Project => layout
                .project
                .as_ref()
                .map(|project| project.join("pyproject.toml"))
                .ok_or_else(|| {
                    AdapterError::Unsupported(
                        "PDM project scope requires an explicit project directory".into(),
                    )
                })?,
            _ => unreachable!("validated PDM scope"),
        };

        let mut paths = Vec::new();
        paths.extend(
            layout
                .sites
                .iter()
                .cloned()
                .map(|path| (path, "pdm-site-config", "site")),
        );
        paths.push((layout.user.clone(), "pdm-user-config", "user"));
        if let Some(project) = &layout.project {
            paths.push((
                project.join("pdm.toml"),
                "pdm-project-local-config",
                "project-local",
            ));
            paths.push((
                project.join("pyproject.toml"),
                "pdm-project-metadata",
                "project",
            ));
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
            if scope == ConfigurationScope::Project && path == selected && !exists {
                return Err(AdapterError::Unsupported(format!(
                    "PDM project scope requires an existing {}",
                    path.display()
                )));
            }
            if exists {
                files.push(path.clone());
            }
            let text = utf8(&path, &contents)?;
            if format == "pdm-project-metadata" {
                sources.extend(project_sources(text, origin, &path)?);
            } else {
                sources.extend(config_sources(text, origin, &path)?);
            }
            documents.push(ConfigurationDocument {
                path: path.clone(),
                format: if path == selected {
                    "pdm-selected-config".into()
                } else {
                    format.into()
                },
                contents,
            });
        }

        let project = layout.project.as_deref();
        let effective = run_pdm(
            runtime,
            project,
            &["config", "pypi.url"],
            "pdm effective pypi.url",
        )?;
        sources.push(index_source(
            &effective,
            "effective-default",
            "effective",
            Path::new(":pdm:"),
            "pypi",
            None,
            url_has_credentials(&effective),
        ));
        sources.push(policy_source(
            "verification-context",
            if verification_ready(runtime, project)? {
                "ready"
            } else {
                "unready"
            },
            "runtime",
            Path::new(":pdm:"),
            "pypi",
        ));

        Ok(CurrentConfiguration {
            tool_id: "pdm".into(),
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
            tool_id: "pdm".into(),
            adapter_key: "pdm".into(),
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
        validate_precedence(current)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "pdm-selected-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected PDM document is missing".into())
            })?;
        let text = utf8(&document.path, &document.contents)?;
        let new_contents = match current.scope {
            ConfigurationScope::User => rewrite_user_config(text, endpoint)?,
            ConfigurationScope::Project => rewrite_project_config(text, endpoint)?,
            _ => unreachable!("validated PDM scope"),
        }
        .into_bytes();
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: match current.scope {
                    ConfigurationScope::User => "set PDM's user pypi.url while preserving site, project-local, private, credential and custom-index configuration".into(),
                    ConfigurationScope::Project => "set or add the named pypi project source without changing private source order, credentials, include/exclude package rules or resolver priority".into(),
                    _ => unreachable!("validated PDM scope"),
                },
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "pdm".into(),
            tool_id: "pdm".into(),
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
            let project = project_dir(runtime)?.ok_or_else(|| {
                AdapterError::Verification("PDM verification project disappeared".into())
            })?;
            let project_text = runtime
                .read(&project.join("pyproject.toml"))?
                .ok_or_else(|| {
                    AdapterError::Verification("PDM pyproject.toml disappeared".into())
                })?;
            let project_text = utf8(&project.join("pyproject.toml"), &project_text)?;
            let project_default = named_project_source(project_text, "pypi")?;
            let endpoint = if let Some(source) = project_default {
                source.url
            } else {
                run_pdm(
                    runtime,
                    Some(&project),
                    &["config", "pypi.url"],
                    "pdm effective pypi.url",
                )?
            };
            if !is_known_mirror(&endpoint) {
                return Err(AdapterError::Verification(
                    "PDM effective default is not a reviewed mirror".into(),
                ));
            }
            let resolved = run_pdm(
                runtime,
                Some(&project),
                &["--no-cache", "show", "sampleproject"],
                "pdm sampleproject resolution",
            )?;
            let resolved = resolved.to_ascii_lowercase();
            if !resolved.contains("sampleproject") || !resolved.contains("4.0.0") {
                return Err(AdapterError::Verification(
                    "PDM returned no sampleproject 4.0.0 metadata".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "PDM effective source and uncached sampleproject resolution passed through {}",
                    normalized_index(&endpoint).unwrap_or(endpoint)
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
                "restored {} PDM configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct ConfigLayout {
    user: PathBuf,
    sites: Vec<PathBuf>,
    project: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct ProjectSource {
    url: String,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "PDM adapter requires Linux".into(),
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
            "PDM supports user and explicit project scopes in the Linux MVP".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "pdm" {
        return Err(AdapterError::InvalidConfiguration(
            "PDM operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
}

fn config_layout(runtime: &dyn Runtime) -> Result<ConfigLayout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("PDM user scope requires a home directory".into())
    })?;
    validate_path(&home)?;
    let user = if let Some(path) = nonempty_environment(runtime, "PDM_CONFIG_FILE") {
        PathBuf::from(path)
    } else if let Some(path) = nonempty_environment(runtime, "XDG_CONFIG_HOME") {
        PathBuf::from(path).join("pdm/config.toml")
    } else {
        home.join(".config/pdm/config.toml")
    };
    validate_path(&user)?;
    let site_roots =
        nonempty_environment(runtime, "XDG_CONFIG_DIRS").unwrap_or_else(|| "/etc/xdg".into());
    let mut sites = Vec::new();
    for root in site_roots.split(':').filter(|root| !root.is_empty()) {
        let path = PathBuf::from(root).join("pdm/config.toml");
        validate_path(&path)?;
        sites.push(path);
    }
    Ok(ConfigLayout {
        user,
        sites,
        project: project_dir(runtime)?,
    })
}

fn project_dir(runtime: &dyn Runtime) -> Result<Option<PathBuf>, AdapterError> {
    let project = nonempty_environment(runtime, "PDM_PROJECT")
        .map(PathBuf::from)
        .or_else(|| runtime.project_dir());
    if let Some(project) = &project {
        validate_path(project)?;
    }
    Ok(project)
}

fn nonempty_environment(runtime: &dyn Runtime, name: &str) -> Option<String> {
    runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
}

fn verification_ready(runtime: &dyn Runtime, project: Option<&Path>) -> Result<bool, AdapterError> {
    let Some(project) = project else {
        return Ok(false);
    };
    if runtime.read(&project.join("pyproject.toml"))?.is_none()
        || runtime.read(&project.join(".pdm-python"))?.is_none()
    {
        return Ok(false);
    }
    Ok(runtime.read(&project.join(".venv/pyvenv.cfg"))?.is_some()
        || runtime
            .read(&project.join("__pypackages__/.gitignore"))?
            .is_some())
}

fn validate_path(path: &Path) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PDM reported unsafe configuration path {}",
            path.display()
        )));
    }
    Ok(())
}

fn run_pdm(
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
        runtime.run_in(project, "pdm", &arguments)?
    } else {
        runtime.run("pdm", &arguments)?
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

fn parse_document(path: &Path, text: &str) -> Result<DocumentMut, AdapterError> {
    text.parse::<DocumentMut>().map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "PDM configuration {} is invalid TOML",
            path.display()
        ))
    })
}

fn config_sources(
    text: &str,
    origin: &str,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let document = parse_document(path, text)?;
    let mut sources = Vec::new();
    let Some(pypi) = item_at(&document, &["pypi"]) else {
        return Ok(sources);
    };
    let Some(table) = pypi.as_table_like() else {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PDM pypi configuration in {} is not a table",
            path.display()
        )));
    };
    if let Some(url) = table.get("url").and_then(Item::as_str) {
        sources.push(index_source(
            url,
            "default-index",
            origin,
            path,
            "pypi",
            table.get("verify_ssl").and_then(Item::as_bool),
            table_has_credentials(table) || url_has_credentials(url),
        ));
    }
    for (name, item) in table.iter() {
        if matches!(
            name,
            "url"
                | "verify_ssl"
                | "username"
                | "password"
                | "ca_certs"
                | "client_cert"
                | "client_key"
                | "ignore_stored_index"
                | "json_api"
        ) {
            continue;
        }
        let Some(extra) = item.as_table_like() else {
            continue;
        };
        let Some(url) = extra.get("url").and_then(Item::as_str) else {
            continue;
        };
        sources.push(index_source(
            url,
            "extra-index",
            origin,
            path,
            name,
            extra.get("verify_ssl").and_then(Item::as_bool),
            table_has_credentials(extra) || url_has_credentials(url),
        ));
    }
    for (key, kind) in [
        ("verify_ssl", "verify-ssl"),
        ("json_api", "json-api"),
        ("ignore_stored_index", "ignore-stored-index"),
    ] {
        if let Some(value) = table.get(key).and_then(Item::as_bool) {
            sources.push(policy_source(
                kind,
                if value { "true" } else { "false" },
                origin,
                path,
                "pypi",
            ));
        }
    }
    if table_has_credentials(table) {
        sources.push(policy_source(
            "credential",
            "<redacted>",
            origin,
            path,
            "pypi",
        ));
    }
    Ok(sources)
}

fn project_sources(
    text: &str,
    origin: &str,
    path: &Path,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let document = parse_document(path, text)?;
    let mut sources = Vec::new();
    if let Some(item) = item_at(&document, &["tool", "pdm", "source"]) {
        let tables = item.as_array_of_tables().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "PDM sources in {} are not an array of tables",
                path.display()
            ))
        })?;
        for (index, table) in tables.iter().enumerate() {
            let name = table.get("name").and_then(Item::as_str).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "PDM source {} in {} has no string name",
                    index,
                    path.display()
                ))
            })?;
            let url = table.get("url").and_then(Item::as_str).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "PDM source {name} in {} has no string URL",
                    path.display()
                ))
            })?;
            let mut source = index_source(
                url,
                "project-index",
                origin,
                path,
                name,
                table.get("verify_ssl").and_then(Item::as_bool),
                table_has_credentials(table) || url_has_credentials(url),
            );
            source
                .metadata
                .insert("order".into(), vec![index.to_string()]);
            for key in ["include_packages", "exclude_packages"] {
                if let Some(array) = table.get(key).and_then(Item::as_array) {
                    source
                        .metadata
                        .insert(format!("{key}_count"), vec![array.len().to_string()]);
                }
            }
            if let Some(source_type) = table.get("type") {
                let source_type = source_type.as_str().ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "PDM source {name} in {} has a non-string type",
                        path.display()
                    ))
                })?;
                source
                    .metadata
                    .insert("source_type".into(), vec![source_type.into()]);
            }
            sources.push(source);
        }
    }
    if let Some(priority) = item_at(
        &document,
        &["tool", "pdm", "resolution", "respect-source-order"],
    )
    .and_then(Item::as_bool)
    {
        sources.push(policy_source(
            "respect-source-order",
            if priority { "true" } else { "false" },
            origin,
            path,
            "pypi",
        ));
    }
    Ok(sources)
}

fn environment_sources(runtime: &dyn Runtime) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(url) = nonempty_environment(runtime, "PDM_PYPI_URL") {
        sources.push(index_source(
            &url,
            "environment-default",
            "environment",
            Path::new(":env:"),
            "pypi",
            None,
            url_has_credentials(&url),
        ));
    }
    if ["PDM_PYPI_USERNAME", "PDM_PYPI_PASSWORD"]
        .iter()
        .any(|key| nonempty_environment(runtime, key).is_some())
    {
        sources.push(policy_source(
            "credential",
            "<redacted>",
            "environment",
            Path::new(":env:"),
            "pypi",
        ));
    }
    for (key, kind) in [
        ("PDM_PYPI_VERIFY_SSL", "verify-ssl"),
        ("PDM_PYPI_JSON_API", "json-api"),
        ("PDM_IGNORE_STORED_INDEX", "ignore-stored-index"),
    ] {
        if let Some(value) = nonempty_environment(runtime, key) {
            sources.push(policy_source(
                kind,
                normalize_environment_bool(&value)
                    .unwrap_or_else(|| value.to_ascii_lowercase())
                    .as_str(),
                "environment",
                Path::new(":env:"),
                "pypi",
            ));
        }
    }
    sources
}

fn index_source(
    url: &str,
    kind: &str,
    origin: &str,
    path: &Path,
    name: &str,
    verify_ssl: Option<bool>,
    has_credentials: bool,
) -> ConfiguredSource {
    let public = is_public_index(url);
    let observed = if public { url } else { "<redacted>" };
    let mut metadata = BTreeMap::from([
        ("kind".into(), vec![kind.into()]),
        ("origin_scope".into(), vec![origin.into()]),
        ("config_path".into(), vec![path.display().to_string()]),
        ("source_name".into(), vec![name.into()]),
        ("has_credentials".into(), vec![has_credentials.to_string()]),
    ]);
    if let Some(verify_ssl) = verify_ssl {
        metadata.insert("verify_ssl".into(), vec![verify_ssl.to_string()]);
    }
    ConfiguredSource {
        upstream_id: public.then(|| PYPI_UPSTREAM.into()),
        url: observed.into(),
        enabled: true,
        metadata,
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

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if !current.sources.iter().any(|source| {
        metadata(source, "kind").ok() == Some("verification-context") && source.url == "ready"
    }) {
        return Err(AdapterError::Unsupported(
            "PDM verification requires an existing project with pyproject.toml, .pdm-python and an initialized .venv or __pypackages__ environment".into(),
        ));
    }
    for source in &current.sources {
        if metadata(source, "source_name").ok() != Some("pypi") {
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
                "PDM default PyPI credentials cannot be retargeted to a public mirror".into(),
            ));
        }
        if kind == "verify-ssl" && source.url != "true"
            || source
                .metadata
                .get("verify_ssl")
                .is_some_and(|values| values == &["false"])
        {
            return Err(AdapterError::InvalidConfiguration(
                "PDM TLS verification is disabled for the default PyPI source".into(),
            ));
        }
        if kind == "json-api" && source.url == "true" {
            return Err(AdapterError::Unsupported(
                "PDM pypi.json_api bypasses the selected Simple API mirror".into(),
            ));
        }
        if source
            .metadata
            .get("source_type")
            .is_some_and(|values| values != &["index"])
        {
            return Err(AdapterError::Unsupported(
                "PDM source named pypi is not a PEP 503 index".into(),
            ));
        }
    }
    Ok(())
}

fn validate_precedence(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    let project_default = current.sources.iter().find(|source| {
        metadata(source, "kind").ok() == Some("project-index")
            && metadata(source, "source_name").ok() == Some("pypi")
    });
    match current.scope {
        ConfigurationScope::User => {
            if current
                .sources
                .iter()
                .any(|source| metadata(source, "kind").ok() == Some("environment-default"))
            {
                return Err(AdapterError::Unsupported(
                    "PDM_PYPI_URL overrides the user configuration".into(),
                ));
            }
            if project_default.is_some() {
                return Err(AdapterError::Unsupported(
                    "a project source named pypi replaces the user pypi.url".into(),
                ));
            }
            if current.sources.iter().any(|source| {
                metadata(source, "kind").ok() == Some("default-index")
                    && metadata(source, "origin_scope").ok() == Some("project-local")
            }) {
                return Err(AdapterError::Unsupported(
                    "project-local pdm.toml overrides the user pypi.url".into(),
                ));
            }
            let user_default = current.sources.iter().find(|source| {
                metadata(source, "kind").ok() == Some("default-index")
                    && metadata(source, "origin_scope").ok() == Some("user")
            });
            if user_default.is_some_and(|source| source.upstream_id.is_none()) {
                return Err(AdapterError::Unsupported(
                    "the user PDM default is private or unmapped".into(),
                ));
            }
            if user_default.is_none()
                && current.sources.iter().any(|source| {
                    metadata(source, "kind").ok() == Some("default-index")
                        && metadata(source, "origin_scope").ok() == Some("site")
                        && source.upstream_id.is_none()
                })
            {
                return Err(AdapterError::Unsupported(
                    "the site PDM default is private and has no user override".into(),
                ));
            }
        }
        ConfigurationScope::Project => {
            if let Some(source) = project_default {
                if source.upstream_id.is_none() {
                    return Err(AdapterError::Unsupported(
                        "the project source named pypi is private or unmapped".into(),
                    ));
                }
            } else if current.sources.iter().any(|source| {
                metadata(source, "kind").ok() == Some("effective-default")
                    && source.upstream_id.is_none()
            }) {
                return Err(AdapterError::Unsupported(
                    "adding a project pypi source would replace a private effective default".into(),
                ));
            }
        }
        _ => unreachable!("validated PDM scope"),
    }
    Ok(())
}

fn rewrite_user_config(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let mut document = parse_document(Path::new("pdm-user-config"), text)?;
    document["pypi"]["url"] = value(endpoint);
    Ok(document.to_string())
}

fn rewrite_project_config(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let mut document = parse_document(Path::new("pyproject.toml"), text)?;
    if document["tool"]["pdm"].get("source").is_none() {
        document["tool"]["pdm"]["source"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    let sources = document["tool"]["pdm"]["source"]
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "PDM project sources are not an array of tables".into(),
            )
        })?;
    if let Some(source) = sources
        .iter_mut()
        .find(|source| source.get("name").and_then(Item::as_str) == Some("pypi"))
    {
        source["url"] = value(endpoint);
    } else {
        let mut source = Table::new();
        source["name"] = value("pypi");
        source["url"] = value(endpoint);
        source["verify_ssl"] = value(true);
        sources.insert(0, source);
    }
    Ok(document.to_string())
}

fn named_project_source(text: &str, name: &str) -> Result<Option<ProjectSource>, AdapterError> {
    let document = parse_document(Path::new("pyproject.toml"), text)?;
    let Some(item) = item_at(&document, &["tool", "pdm", "source"]) else {
        return Ok(None);
    };
    let tables = item.as_array_of_tables().ok_or_else(|| {
        AdapterError::InvalidConfiguration("PDM project sources are not an array of tables".into())
    })?;
    Ok(tables.iter().find_map(|table| {
        (table.get("name").and_then(Item::as_str) == Some(name)).then(|| ProjectSource {
            url: table
                .get("url")
                .and_then(Item::as_str)
                .unwrap_or_default()
                .into(),
        })
    }))
}

fn item_at<'a>(document: &'a DocumentMut, path: &[&str]) -> Option<&'a Item> {
    let mut item = document.as_item();
    for key in path {
        item = item.get(key)?;
    }
    Some(item)
}

fn table_has_credentials(table: &dyn toml_edit::TableLike) -> bool {
    ["username", "password"].iter().any(|key| {
        table
            .get(key)
            .and_then(Item::as_str)
            .is_some_and(|value| !value.is_empty())
    })
}

fn url_has_credentials(value: &str) -> bool {
    reqwest::Url::parse(value).map_or_else(
        |_| value.contains('@') || value.contains("${"),
        |url| !url.username().is_empty() || url.password().is_some(),
    )
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "pdm"
        || selections[0].upstream_id != PYPI_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "PDM plan requires exactly one PyPI mirror selection".into(),
        ));
    }
    let endpoint = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Index && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("PDM selection has no HTTPS index endpoint".into())
        })?;
    if !is_known_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "PDM selection is not a reviewed complete PyPI mirror".into(),
        ));
    }
    let artifact = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "PDM selection has no HTTPS artifact endpoint".into(),
            )
        })?;
    let index = normalized_index(&endpoint.url)
        .ok_or_else(|| AdapterError::InvalidConfiguration("PDM index endpoint is unsafe".into()))?;
    let artifact = normalized_index(&artifact.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("PDM artifact endpoint is unsafe".into())
    })?;
    let provider = MIRROR_INDEXES
        .iter()
        .position(|candidate| *candidate == index);
    if provider.is_none_or(|provider| MIRROR_ARTIFACTS[provider] != artifact) {
        return Err(AdapterError::InvalidConfiguration(
            "PDM index and artifact endpoints do not belong to one reviewed provider".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
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

fn normalize_environment_bool(value: &str) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some("true".into()),
        "0" | "false" | "no" | "off" => Some("false".into()),
        _ => None,
    }
}

fn pdm_major(version: &str) -> Option<u64> {
    version
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|token| !token.is_empty())?
        .split('.')
        .next()?
        .parse()
        .ok()
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("PDM source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PDM source has ambiguous {key} metadata"
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
            "PDM configuration {} is not UTF-8",
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
