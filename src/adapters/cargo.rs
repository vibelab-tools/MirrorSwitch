use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    process::Output,
};

use toml_edit::{DocumentMut, Item, Table, value};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const SPARSE_UPSTREAM: &str = "crates.io-index--language-registry";
const GIT_UPSTREAM: &str = "crates.io-index--git-mirror";
const SOURCE_NAME: &str = "mirrorswitch-crates-io";
const REVIEWED_CRATE: &str = "itoa";
const REVIEWED_VERSION: &str = "1.0.18";
const SPARSE_INDEXES: &[&str] = &[
    "https://mirrors.aliyun.com/crates.io-index",
    "https://mirrors.nju.edu.cn/crates.io-index",
    "https://mirrors.ustc.edu.cn/crates.io-index",
];
const PUBLIC_REGISTRIES: &[&str] = &[
    "https://github.com/rust-lang/crates.io-index",
    "https://mirrors.tuna.tsinghua.edu.cn/crates.io-index.git",
    "https://mirrors.ustc.edu.cn/crates.io-index",
    "sparse+https://index.crates.io",
    "sparse+https://mirrors.aliyun.com/crates.io-index",
    "sparse+https://mirrors.nju.edu.cn/crates.io-index",
    "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index",
    "sparse+https://mirrors.ustc.edu.cn/crates.io-index",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct CargoAdapter;

impl Adapter for CargoAdapter {
    fn key(&self) -> &'static str {
        "cargo"
    }

    fn tool_id(&self) -> &'static str {
        "cargo"
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
        if !runtime.command_exists("cargo") {
            return Ok(None);
        }
        if !runtime.command_exists("rustc") {
            return Err(AdapterError::Unsupported(
                "Cargo is installed but rustc is unavailable".into(),
            ));
        }
        let snapshot = tool_snapshot(runtime)?;
        let protocol = reviewed_protocol(&snapshot.cargo_version)?;
        let live = live_configuration(runtime)?;
        let source_count = std::iter::once(&live.user)
            .chain(live.projects.iter())
            .map(|document| {
                config_sources(&document.contents, &document.path, &document.origin).map(
                    |sources| {
                        sources
                            .iter()
                            .filter(|source| metadata(source, "kind") == Some("source-registry"))
                            .count()
                    },
                )
            })
            .collect::<Result<Vec<_>, AdapterError>>()?
            .into_iter()
            .sum::<usize>();
        Ok(Some(DetectedTool {
            tool_id: "cargo".into(),
            executable: Some(PathBuf::from("cargo")),
            version: Some(snapshot.cargo_version.clone()),
            evidence: vec![
                format!("Cargo {}", snapshot.cargo_version),
                format!("Rust {}", snapshot.rust_version),
                format!("reviewed crates.io protocol is {}", protocol.name()),
                format!("Cargo home is {}", live.cargo_home.display()),
                format!("user configuration is {}", live.user.path.display()),
                format!(
                    "{} project/ancestor Cargo configuration file(s) detected",
                    live.projects.len()
                ),
                format!("{source_count} configured registry source(s) detected"),
                format!(
                    "Cargo credential files under {} remain untouched",
                    live.cargo_home.display()
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
        if detected.tool_id != "cargo" {
            return Err(AdapterError::InvalidConfiguration(
                "Cargo read received another tool's detection result".into(),
            ));
        }
        let snapshot = tool_snapshot(runtime)?;
        if detected.version.as_deref() != Some(snapshot.cargo_version.as_str()) {
            return Err(AdapterError::Conflict(
                "Cargo version changed after detection".into(),
            ));
        }
        let protocol = reviewed_protocol(&snapshot.cargo_version)?;
        let live = live_configuration(runtime)?;
        current_from_live(runtime, live, protocol)
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_linux(context)?;
        require_current(current)?;
        let protocol = reviewed_protocol(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Cargo version is missing".into())
        })?)?;
        let analysis = analyze_current(current, protocol)?;
        let (upstream, roles) = match protocol {
            RegistryProtocol::Sparse => (
                SPARSE_UPSTREAM,
                vec![EndpointRole::Index, EndpointRole::Artifacts],
            ),
            RegistryProtocol::Git => (
                GIT_UPSTREAM,
                vec![EndpointRole::Git, EndpointRole::Artifacts],
            ),
        };
        if analysis.protocol != protocol {
            return Err(AdapterError::InvalidConfiguration(
                "Cargo protocol evidence changed while selecting".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "cargo".into(),
            adapter_key: "cargo".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![upstream.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: roles,
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
        let protocol = current_protocol(current)?;
        let analysis = analyze_current(current, protocol)?;
        if protocol != RegistryProtocol::Sparse {
            return Err(AdapterError::Unsupported(
                "no complete reviewed git-index candidate also mirrors crate downloads; Cargo must be upgraded to 1.68+ for sparse mirrors"
                    .into(),
            ));
        }
        let endpoint = selected_sparse_endpoint(selections)?;
        let document = current
            .documents
            .iter()
            .find(|document| document.format == "cargo-user-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Cargo user configuration is missing".into())
            })?;
        let text = utf8(&document.path, &document.contents)?;
        let new_contents =
            rewrite_user_config(text, &document.path, &analysis.mapping, endpoint)?.into_bytes();
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
                    "map only crates.io to a checksum-complete sparse registry in {}; preserve private registries, credentials, source chains and project configuration",
                    document.path.display()
                ),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "cargo".into(),
            tool_id: "cargo".into(),
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
            let snapshot = tool_snapshot(runtime)?;
            let protocol = reviewed_protocol(&snapshot.cargo_version)?;
            if protocol != RegistryProtocol::Sparse {
                return Err(AdapterError::Verification(
                    "Cargo verification no longer uses the sparse protocol".into(),
                ));
            }
            let current = current_from_live(runtime, live_configuration(runtime)?, protocol)?;
            let analysis = analyze_current(&current, protocol)?;
            let document = current
                .documents
                .iter()
                .find(|document| document.format == "cargo-user-config")
                .ok_or_else(|| {
                    AdapterError::Verification("Cargo user configuration disappeared".into())
                })?;
            let target = rooted(&context.root, &document.path);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "Cargo transaction receipt does not contain the selected user config".into(),
                ));
            }
            let registry = analysis.mapping.registry.as_deref().ok_or_else(|| {
                AdapterError::Verification("Cargo crates.io replacement disappeared".into())
            })?;
            let endpoint = sparse_endpoint(registry)
                .filter(|endpoint| SPARSE_INDEXES.contains(&endpoint.as_str()))
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "Cargo crates.io replacement is not a reviewed sparse mirror".into(),
                    )
                })?;
            let output = run_cargo(
                runtime,
                &[
                    "info",
                    &format!("{REVIEWED_CRATE}@{REVIEWED_VERSION}"),
                    "--registry",
                    "crates-io",
                    "--verbose",
                    "--color",
                    "never",
                ],
                "cargo info checksum verification",
            )?;
            let stdout = String::from_utf8(output.stdout).map_err(|_| {
                AdapterError::Verification("cargo info returned non-UTF-8 stdout".into())
            })?;
            if !stdout.lines().any(|line| line.trim() == "version: 1.0.18")
                || !stdout.contains(REVIEWED_CRATE)
            {
                return Err(AdapterError::Verification(
                    "cargo info did not return the reviewed crate version".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Cargo loaded sparse+{endpoint}/ and checksum-verified {REVIEWED_CRATE} {REVIEWED_VERSION} through the real client"
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
                "restored {} Cargo configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryProtocol {
    Sparse,
    Git,
}

impl RegistryProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::Sparse => "sparse",
            Self::Git => "git",
        }
    }
}

#[derive(Clone, Debug)]
struct ToolSnapshot {
    cargo_version: String,
    rust_version: String,
}

#[derive(Clone, Debug)]
struct LiveConfiguration {
    cargo_home: PathBuf,
    user: LiveDocument,
    projects: Vec<LiveDocument>,
}

#[derive(Clone, Debug)]
struct LiveDocument {
    path: PathBuf,
    contents: Vec<u8>,
    exists: bool,
    origin: String,
}

#[derive(Clone, Debug)]
struct CurrentAnalysis {
    protocol: RegistryProtocol,
    mapping: SourceMapping,
}

#[derive(Clone, Debug)]
struct SourceMapping {
    terminal_name: Option<String>,
    registry: Option<String>,
}

fn tool_snapshot(runtime: &dyn Runtime) -> Result<ToolSnapshot, AdapterError> {
    let cargo = run_program(runtime, None, "cargo", &["--version"], "cargo --version")?;
    let rust = run_program(runtime, None, "rustc", &["--version"], "rustc --version")?;
    Ok(ToolSnapshot {
        cargo_version: tool_version(&cargo, "cargo")?,
        rust_version: tool_version(&rust, "rustc")?,
    })
}

fn tool_version(output: &Output, tool: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{tool} --version failed with status {}",
            output.status
        )));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{tool} --version returned non-UTF-8")))?;
    let mut fields = stdout.split_whitespace();
    if fields.next() != Some(tool) {
        return Err(AdapterError::Unsupported(format!(
            "{tool} --version output is unrecognized"
        )));
    }
    let version = fields
        .next()
        .ok_or_else(|| AdapterError::Unsupported(format!("{tool} version is missing")))?;
    version_numbers(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("{tool} version {version} is unrecognized"))
    })?;
    Ok(version.into())
}

fn reviewed_protocol(version: &str) -> Result<RegistryProtocol, AdapterError> {
    let (major, minor, _) = version_numbers(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("Cargo version {version} is unrecognized"))
    })?;
    if major != 1 || minor < 39 {
        return Err(AdapterError::Unsupported(format!(
            "Cargo {version} is outside the reviewed 1.39+ config model"
        )));
    }
    Ok(if minor >= 68 {
        RegistryProtocol::Sparse
    } else {
        RegistryProtocol::Git
    })
}

fn version_numbers(value: &str) -> Option<(u64, u64, u64)> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

fn live_configuration(runtime: &dyn Runtime) -> Result<LiveConfiguration, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Cargo requires a detected user home".into()))?;
    validate_path(&home, "home")?;
    let cargo_home = runtime
        .environment_variable("CARGO_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cargo"));
    validate_path(&cargo_home, "CARGO_HOME")?;
    if !cargo_home.starts_with(&home) || cargo_home == home {
        return Err(AdapterError::Unsupported(format!(
            "Cargo home {} is outside the selected user home",
            cargo_home.display()
        )));
    }
    let user = selected_config(runtime, &cargo_home, "user", true)?;
    let mut projects = Vec::new();
    if let Some(project) = runtime.project_dir() {
        validate_path(&project, "project")?;
        let mut directory = Some(project.as_path());
        while let Some(current) = directory {
            let cargo_dir = current.join(".cargo");
            if let Some(document) = existing_config(runtime, &cargo_dir, "project")? {
                if document.path != user.path {
                    projects.push(document);
                }
            }
            directory = current.parent().filter(|parent| *parent != current);
        }
    }
    projects.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(LiveConfiguration {
        cargo_home,
        user,
        projects,
    })
}

fn selected_config(
    runtime: &dyn Runtime,
    directory: &Path,
    origin: &str,
    create: bool,
) -> Result<LiveDocument, AdapterError> {
    if let Some(document) = existing_config(runtime, directory, origin)? {
        return Ok(document);
    }
    if !create {
        return Err(AdapterError::Runtime(
            "internal Cargo config discovery requested a missing file".into(),
        ));
    }
    Ok(LiveDocument {
        path: directory.join("config.toml"),
        contents: Vec::new(),
        exists: false,
        origin: origin.into(),
    })
}

fn existing_config(
    runtime: &dyn Runtime,
    directory: &Path,
    origin: &str,
) -> Result<Option<LiveDocument>, AdapterError> {
    let legacy = directory.join("config");
    if let Some(contents) = runtime.read(&legacy)? {
        return Ok(Some(LiveDocument {
            path: legacy,
            contents,
            exists: true,
            origin: origin.into(),
        }));
    }
    let modern = directory.join("config.toml");
    Ok(runtime.read(&modern)?.map(|contents| LiveDocument {
        path: modern,
        contents,
        exists: true,
        origin: origin.into(),
    }))
}

fn current_from_live(
    runtime: &dyn Runtime,
    live: LiveConfiguration,
    protocol: RegistryProtocol,
) -> Result<CurrentConfiguration, AdapterError> {
    let mut sources = Vec::new();
    let mut files = Vec::new();
    let mut documents = Vec::new();
    for document in std::iter::once(&live.user).chain(live.projects.iter()) {
        sources.extend(config_sources(
            &document.contents,
            &document.path,
            &document.origin,
        )?);
        if document.exists {
            files.push(document.path.clone());
        }
        documents.push(ConfigurationDocument {
            path: document.path.clone(),
            format: if document.origin == "user" {
                "cargo-user-config"
            } else {
                "cargo-project-config"
            }
            .into(),
            contents: document.contents.clone(),
        });
    }
    sources.push(policy_source(
        "cargo-protocol",
        protocol.name(),
        &live.user.path,
        "user",
    ));
    for variable in [
        "CARGO_REGISTRIES_CRATES_IO_INDEX",
        "CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
    ] {
        if runtime
            .environment_variable(variable)
            .is_some_and(|value| !value.is_empty())
        {
            sources.push(policy_source(
                "registry-environment-override",
                variable,
                &live.user.path,
                "environment",
            ));
        }
    }
    if runtime
        .environment_variable("CARGO_NET_OFFLINE")
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true"))
    {
        sources.push(policy_source(
            "offline-environment-override",
            "true",
            &live.user.path,
            "environment",
        ));
    }
    Ok(CurrentConfiguration {
        tool_id: "cargo".into(),
        scope: ConfigurationScope::User,
        sources,
        files,
        documents,
    })
}

fn config_sources(
    contents: &[u8],
    path: &Path,
    origin: &str,
) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let text = utf8(path, contents)?;
    let document = parse_document(path, text)?;
    let mut sources = Vec::new();
    if document.get("include").is_some() {
        sources.push(policy_source("include-policy", "<set>", path, origin));
    }
    if item_at(&document, &["net", "offline"]).and_then(Item::as_bool) == Some(true) {
        sources.push(policy_source("offline-config", "true", path, origin));
    }
    if let Some(source_tables) = document.get("source").and_then(Item::as_table_like) {
        for (name, item) in source_tables.iter() {
            let Some(table) = item.as_table_like() else {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Cargo source {name} in {} is not a table",
                    path.display()
                )));
            };
            for (key, kind) in [
                ("replace-with", "source-replacement"),
                ("registry", "source-registry"),
                ("git", "source-git"),
                ("directory", "source-directory"),
                ("local-registry", "source-local-registry"),
            ] {
                if let Some(setting) = table.get(key) {
                    let setting = setting.as_str().ok_or_else(|| {
                        AdapterError::InvalidConfiguration(format!(
                            "Cargo source {name}.{key} in {} is not a string",
                            path.display()
                        ))
                    })?;
                    sources.push(config_source(setting, kind, name, path, origin));
                }
            }
        }
    }
    if let Some(registries) = document.get("registries").and_then(Item::as_table_like) {
        for (name, item) in registries.iter() {
            let Some(table) = item.as_table_like() else {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Cargo registry {name} in {} is not a table",
                    path.display()
                )));
            };
            if let Some(index) = table.get("index") {
                let index = index.as_str().ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Cargo registry {name}.index in {} is not a string",
                        path.display()
                    ))
                })?;
                sources.push(config_source(index, "named-registry", name, path, origin));
            }
            if table.get("token").is_some() || table.get("credential-provider").is_some() {
                sources.push(config_source(
                    "<redacted>",
                    "credential-setting",
                    name,
                    path,
                    origin,
                ));
            }
        }
    }
    if document
        .get("registry")
        .and_then(Item::as_table_like)
        .is_some_and(|table| {
            table.get("token").is_some() || table.get("credential-provider").is_some()
        })
    {
        sources.push(config_source(
            "<redacted>",
            "credential-setting",
            "crates-io",
            path,
            origin,
        ));
    }
    Ok(sources)
}

fn config_source(url: &str, kind: &str, name: &str, path: &Path, origin: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: (kind == "source-registry" && is_public_registry(url))
            .then(|| SPARSE_UPSTREAM.into()),
        url: url.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("name".into(), vec![name.into()]),
            ("origin".into(), vec![origin.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn policy_source(kind: &str, value: &str, path: &Path, origin: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: value.into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("origin".into(), vec![origin.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn analyze_current(
    current: &CurrentConfiguration,
    protocol: RegistryProtocol,
) -> Result<CurrentAnalysis, AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind") {
            Some("registry-environment-override") => {
                return Err(AdapterError::Unsupported(format!(
                    "{} overrides persistent Cargo configuration",
                    source.url
                )));
            }
            Some("offline-environment-override" | "offline-config") => {
                return Err(AdapterError::Unsupported(
                    "Cargo offline mode prevents mirror validation".into(),
                ));
            }
            Some("include-policy") => {
                return Err(AdapterError::Unsupported(
                    "Cargo include configuration is not rewritten without resolving every included file"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    let user = current
        .documents
        .iter()
        .find(|document| document.format == "cargo-user-config")
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Cargo user configuration is missing".into())
        })?;
    let user_document = parse_document(&user.path, utf8(&user.path, &user.contents)?)?;
    validate_registry_protocol(&user_document, &user.path, protocol)?;
    let mapping = resolve_mapping(&user_document, &user.path)?;
    if let Some(registry) = &mapping.registry {
        if !is_public_registry(registry) {
            return Err(AdapterError::Unsupported(
                "Cargo crates.io replacement terminates at a private or unknown registry".into(),
            ));
        }
        if registry_protocol(registry) == Some(RegistryProtocol::Sparse)
            && protocol == RegistryProtocol::Git
        {
            return Err(AdapterError::Unsupported(
                "Cargo version does not support the configured sparse replacement".into(),
            ));
        }
    } else if source_table(&user_document, SOURCE_NAME).is_some() {
        return Err(AdapterError::Unsupported(format!(
            "Cargo user config already defines reserved source {SOURCE_NAME}"
        )));
    }

    let terminal = mapping.terminal_name.as_deref().unwrap_or(SOURCE_NAME);
    for project in current
        .documents
        .iter()
        .filter(|document| document.format == "cargo-project-config")
    {
        let document = parse_document(&project.path, utf8(&project.path, &project.contents)?)?;
        validate_registry_protocol(&document, &project.path, protocol)?;
        if source_table(&document, "crates-io").is_some() {
            return Err(AdapterError::Unsupported(format!(
                "Cargo project configuration {} overrides crates.io",
                project.path.display()
            )));
        }
        if source_table(&document, terminal).is_some()
            || (terminal != SOURCE_NAME && source_table(&document, SOURCE_NAME).is_some())
        {
            return Err(AdapterError::Unsupported(format!(
                "Cargo project configuration {} overrides the selected replacement source",
                project.path.display()
            )));
        }
    }
    Ok(CurrentAnalysis { protocol, mapping })
}

fn validate_registry_protocol(
    document: &DocumentMut,
    path: &Path,
    protocol: RegistryProtocol,
) -> Result<(), AdapterError> {
    let Some(table) = item_at(document, &["registries", "crates-io"]).and_then(Item::as_table_like)
    else {
        return Ok(());
    };
    if table.get("index").is_some() {
        return Err(AdapterError::Unsupported(format!(
            "{} overrides the crates.io index through registries.crates-io",
            path.display()
        )));
    }
    if let Some(configured) = table.get("protocol") {
        let configured = configured.as_str().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Cargo crates.io protocol in {} is not a string",
                path.display()
            ))
        })?;
        if configured != protocol.name() {
            return Err(AdapterError::Unsupported(format!(
                "Cargo crates.io protocol in {} conflicts with the reviewed {} model",
                path.display(),
                protocol.name()
            )));
        }
    }
    Ok(())
}

fn resolve_mapping(document: &DocumentMut, path: &Path) -> Result<SourceMapping, AdapterError> {
    let Some(crates_io) = source_table(document, "crates-io") else {
        return Ok(SourceMapping {
            terminal_name: None,
            registry: None,
        });
    };
    reject_conflicting_source_kind(crates_io, "crates-io", path)?;
    let Some(mut name) = crates_io
        .get("replace-with")
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "Cargo source.crates-io.replace-with in {} is not a string",
                    path.display()
                ))
            })
        })
        .transpose()?
    else {
        if crates_io
            .iter()
            .any(|(key, _)| matches!(key, "registry" | "git" | "directory" | "local-registry"))
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Cargo source.crates-io in {} has an unsupported source kind",
                path.display()
            )));
        }
        return Ok(SourceMapping {
            terminal_name: None,
            registry: None,
        });
    };
    if name.is_empty() || name == "crates-io" {
        return Err(AdapterError::InvalidConfiguration(
            "Cargo crates.io replacement is empty or cyclic".into(),
        ));
    }
    let mut visited = BTreeSet::from(["crates-io".to_owned()]);
    loop {
        if !visited.insert(name.clone()) {
            return Err(AdapterError::InvalidConfiguration(
                "Cargo source replacement chain contains a cycle".into(),
            ));
        }
        let table = source_table(document, &name).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Cargo replacement source {name} is undefined in {}",
                path.display()
            ))
        })?;
        reject_conflicting_source_kind(table, &name, path)?;
        if let Some(next) = table.get("replace-with") {
            name = next
                .as_str()
                .filter(|next| !next.is_empty())
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Cargo source {name}.replace-with in {} is not a non-empty string",
                        path.display()
                    ))
                })?
                .into();
            continue;
        }
        let registry = table
            .get("registry")
            .and_then(Item::as_str)
            .ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "Cargo replacement source {name} is not a registry source"
                ))
            })?;
        return Ok(SourceMapping {
            terminal_name: Some(name),
            registry: Some(registry.into()),
        });
    }
}

fn reject_conflicting_source_kind(
    table: &dyn toml_edit::TableLike,
    name: &str,
    path: &Path,
) -> Result<(), AdapterError> {
    let kinds = ["registry", "git", "directory", "local-registry"]
        .iter()
        .filter(|key| table.get(key).is_some())
        .count();
    if kinds > 1 || kinds == 1 && table.get("replace-with").is_some() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Cargo source {name} in {} combines conflicting source kinds",
            path.display()
        )));
    }
    Ok(())
}

fn rewrite_user_config(
    text: &str,
    path: &Path,
    mapping: &SourceMapping,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let mut document = parse_document(path, text)?;
    if document.get("source").is_none() {
        document["source"] = Item::Table(Table::new());
    }
    let sources = document["source"].as_table_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Cargo source configuration is not a table".into())
    })?;
    let terminal = mapping.terminal_name.as_deref().unwrap_or(SOURCE_NAME);
    if mapping.terminal_name.is_none() {
        if sources.get("crates-io").is_none() {
            sources["crates-io"] = Item::Table(Table::new());
        }
        let crates_io = sources["crates-io"].as_table_like_mut().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Cargo source.crates-io is not a table".into())
        })?;
        crates_io.insert("replace-with", value(SOURCE_NAME));
        if sources.get(SOURCE_NAME).is_none() {
            sources[SOURCE_NAME] = Item::Table(Table::new());
        }
    }
    let target = sources[terminal].as_table_like_mut().ok_or_else(|| {
        AdapterError::InvalidConfiguration("Cargo replacement source disappeared".into())
    })?;
    target.insert(
        "registry",
        value(format!("sparse+{}/", endpoint.trim_end_matches('/'))),
    );
    Ok(document.to_string())
}

fn selected_sparse_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "cargo"
        || selections[0].upstream_id != SPARSE_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Cargo sparse plan requires exactly one crates.io mirror selection".into(),
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
        || !reviewed_endpoint_pair(&index[0].url, &artifacts[0].url)
    {
        return Err(AdapterError::InvalidConfiguration(
            "Cargo selection lacks one reviewed sparse index/crate endpoint pair".into(),
        ));
    }
    Ok(index[0].url.trim_end_matches('/'))
}

fn reviewed_endpoint_pair(index: &str, artifacts: &str) -> bool {
    let Some(index) = normalized_http_url(index) else {
        return false;
    };
    let Some(artifacts) = normalized_http_url(artifacts) else {
        return false;
    };
    matches!(
        (index.as_str(), artifacts.as_str()),
        (
            "https://mirrors.aliyun.com/crates.io-index",
            "https://mirrors.aliyun.com/crates/api/v1/crates"
        ) | (
            "https://mirrors.nju.edu.cn/crates.io-index",
            "https://mirror.nju.edu.cn/crates.io/crates"
        ) | (
            "https://mirrors.ustc.edu.cn/crates.io-index",
            "https://mirrors.ustc.edu.cn/crates.io/api/v1/crates"
        )
    )
}

fn is_public_registry(value: &str) -> bool {
    normalized_registry(value)
        .is_some_and(|registry| PUBLIC_REGISTRIES.contains(&registry.as_str()))
}

fn registry_protocol(value: &str) -> Option<RegistryProtocol> {
    if value.starts_with("sparse+") {
        sparse_endpoint(value)?;
        Some(RegistryProtocol::Sparse)
    } else {
        normalized_http_url(value)?;
        Some(RegistryProtocol::Git)
    }
}

fn normalized_registry(value: &str) -> Option<String> {
    if let Some(sparse) = value.strip_prefix("sparse+") {
        Some(format!("sparse+{}", normalized_http_url(sparse)?))
    } else {
        normalized_http_url(value)
    }
}

fn sparse_endpoint(value: &str) -> Option<String> {
    normalized_http_url(value.strip_prefix("sparse+")?)
}

fn normalized_http_url(value: &str) -> Option<String> {
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

fn current_protocol(current: &CurrentConfiguration) -> Result<RegistryProtocol, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind") == Some("cargo-protocol"))
        .map(|source| source.url.as_str())
        .collect::<Vec<_>>();
    match values.as_slice() {
        ["sparse"] => Ok(RegistryProtocol::Sparse),
        ["git"] => Ok(RegistryProtocol::Git),
        _ => Err(AdapterError::InvalidConfiguration(
            "Cargo protocol evidence is missing or ambiguous".into(),
        )),
    }
}

fn run_cargo(
    runtime: &dyn Runtime,
    arguments: &[&str],
    operation: &str,
) -> Result<Output, AdapterError> {
    let output = run_program(
        runtime,
        runtime.project_dir().as_deref(),
        "cargo",
        arguments,
        operation,
    )?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    Ok(output)
}

fn run_program(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<Output, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    match directory {
        Some(directory) => runtime.run_in(directory, program, &arguments),
        None => runtime.run(program, &arguments),
    }
    .map_err(|error| AdapterError::Runtime(format!("{operation}: {error}")))
}

fn parse_document(path: &Path, text: &str) -> Result<DocumentMut, AdapterError> {
    text.parse::<DocumentMut>().map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Cargo configuration {} is invalid TOML",
            path.display()
        ))
    })
}

fn source_table<'a>(document: &'a DocumentMut, name: &str) -> Option<&'a dyn toml_edit::TableLike> {
    document
        .get("source")
        .and_then(Item::as_table_like)?
        .get(name)?
        .as_table_like()
}

fn item_at<'a>(document: &'a DocumentMut, path: &[&str]) -> Option<&'a Item> {
    let mut item = document.as_item();
    for key in path {
        item = item.get(key)?;
    }
    Some(item)
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Cargo v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Cargo v0.1 writes only the user configuration".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "cargo" {
        return Err(AdapterError::InvalidConfiguration(
            "Cargo operation received another tool's configuration".into(),
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
            "Cargo reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Cargo configuration {} is not UTF-8",
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
