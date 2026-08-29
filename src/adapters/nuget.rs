use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
    process::Output,
};

use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};

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

const NUGET_UPSTREAM: &str = "nuget--language-registry";
const OFFICIAL_V3: &str = "https://api.nuget.org/v3/index.json";
const HUAWEI_V3: &str = "https://repo.huaweicloud.com/repository/nuget/v3/index.json";
const HUAWEI_INDEX_ROOT: &str = "https://repo.huaweicloud.com/repository/nuget/v3";
const HUAWEI_REGISTRATION_ROOT: &str =
    "https://repo.huaweicloud.com/artifactory/api/nuget/v3/nuget-remote/registration-semver2";
const HUAWEI_FLAT_ROOT: &str = "https://repo.huaweicloud.com/artifactory/api/nuget/v3/nuget-remote";
const VERIFY_PACKAGE: &str = "NuGet.Versioning";
const VERIFY_PACKAGE_LOWER: &str = "nuget.versioning";
const VERIFY_VERSION: &str = "6.12.1";
const VERIFY_NUPKG_SHA256: &str =
    "7ff7a30aecc20302ace0de0473ac9fd91a2fae1053d278f48510cffb4dff232e";
const VERIFY_PROJECT_MARKER: &str =
    "<!-- Managed by MirrorSwitch: NuGet verification project v1 -->";

#[derive(Clone, Copy, Debug, Default)]
pub struct NugetAdapter;

impl Adapter for NugetAdapter {
    fn key(&self) -> &'static str {
        "nuget"
    }

    fn tool_id(&self) -> &'static str {
        "nuget"
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
        let snapshot = nuget_snapshot(runtime)?;
        if snapshot.clients.is_empty() {
            return Ok(None);
        }
        let documents = read_configuration_documents(runtime, &snapshot)?;
        for client in &snapshot.clients {
            analyze_client(&documents, client.kind)?;
        }
        let mut evidence = snapshot
            .clients
            .iter()
            .map(|client| {
                format!(
                    "{} {} uses {}",
                    client.kind.display_name(),
                    client.version,
                    client.user_config.display()
                )
            })
            .collect::<Vec<_>>();
        evidence.push(format!(
            "{} machine, {} additional-user and {} project NuGet.Config file(s) are read-only",
            documents
                .iter()
                .filter(|document| document.kind == ConfigKind::Machine)
                .count(),
            documents
                .iter()
                .filter(|document| matches!(document.kind, ConfigKind::AdditionalUser(_)))
                .count(),
            documents
                .iter()
                .filter(|document| document.kind == ConfigKind::Project)
                .count()
        ));
        evidence.push(format!(
            "package source credentials detected for {} source key(s); values remain redacted",
            documents
                .iter()
                .map(|document| parse_config(&document.path, &document.contents))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .flat_map(|config| config.credential_keys.iter())
                .map(|key| normalize_key(key))
                .collect::<BTreeSet<_>>()
                .len()
        ));
        Ok(Some(DetectedTool {
            tool_id: "nuget".into(),
            executable: Some(PathBuf::from(snapshot.clients[0].kind.command())),
            version: Some(snapshot.version_token()),
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
        if detected.tool_id != "nuget" {
            return Err(AdapterError::InvalidConfiguration(
                "NuGet read received another tool's detection result".into(),
            ));
        }
        let snapshot = nuget_snapshot(runtime)?;
        if snapshot.clients.is_empty() {
            return Err(AdapterError::Conflict(
                "NuGet clients disappeared after detection".into(),
            ));
        }
        if detected.version.as_deref() != Some(snapshot.version_token().as_str()) {
            return Err(AdapterError::Conflict(
                "dotnet or NuGet CLI version changed after detection".into(),
            ));
        }
        let records = read_configuration_documents(runtime, &snapshot)?;
        let mut sources = Vec::new();
        let mut files = Vec::new();
        let mut documents = Vec::new();
        for record in &records {
            let parsed = parse_config(&record.path, &record.contents)?;
            sources.extend(configured_sources(record, &parsed));
            if record.exists {
                files.push(record.path.clone());
            }
            documents.push(ConfigurationDocument {
                path: record.path.clone(),
                format: record.kind.format().into(),
                contents: record.contents.clone(),
            });
        }
        for client in &snapshot.clients {
            sources.push(ConfiguredSource {
                upstream_id: None,
                url: format!("client:{}", client.kind.id()),
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["nuget-client".into()]),
                    ("client".into(), vec![client.kind.id().into()]),
                    ("version".into(), vec![client.version.clone()]),
                ]),
            });
        }
        for (path, format, contents) in verification_documents(runtime, &snapshot)? {
            let exists = runtime.read(&path)?.is_some();
            if exists {
                files.push(path.clone());
                let canonical = if format == "nuget-verification-config" {
                    render_verification_config()
                } else if format == "nuget-verification-project" {
                    render_verification_project()
                } else {
                    return Err(AdapterError::InvalidConfiguration(
                        "unknown NuGet verification document format".into(),
                    ));
                };
                if contents != canonical.as_bytes() {
                    sources.push(policy_source("verification-target-conflict", &path));
                }
            }
            documents.push(ConfigurationDocument {
                path,
                format: format.into(),
                contents,
            });
        }
        let current = CurrentConfiguration {
            tool_id: "nuget".into(),
            scope,
            sources,
            files,
            documents,
        };
        validate_current_policy(&current)?;
        Ok(current)
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        _detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_linux(context)?;
        require_current(current)?;
        validate_current_policy(current)?;
        Ok(SelectionRequest {
            tool_id: "nuget".into(),
            adapter_key: "nuget".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![NUGET_UPSTREAM.into()],
            repository_versions: BTreeMap::from([(NUGET_UPSTREAM.into(), "v3".into())]),
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
                EndpointRole::Metadata,
                EndpointRole::Artifacts,
            ],
            allowed_delivery_modes: vec![DeliveryMode::Proxy],
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
        validate_current_policy(current)?;
        let endpoint = selected_service_index(selections)?;
        let clients = current_clients(current)?;
        let mut changes = Vec::new();
        for client in &clients {
            let analysis = analyze_client_current(current, client.kind)?;
            let document = current
                .documents
                .iter()
                .find(|document| document.format == client.kind.user_format())
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "{} user NuGet.Config is missing from the current snapshot",
                        client.kind.display_name()
                    ))
                })?;
            let text = utf8(&document.path, &document.contents)?;
            let rendered = rewrite_user_config(text, &analysis.target_key, endpoint)?;
            if rendered.as_bytes() != document.contents {
                changes.push(PlannedFileChange {
                    target: rooted(&context.root, &document.path),
                    old_contents: current
                        .files
                        .contains(&document.path)
                        .then(|| document.contents.clone()),
                    old_mode: None,
                    new_contents: rendered.into_bytes(),
                    new_mode: None,
                    summary: format!(
                        "retarget only NuGet.org v3 source key {} in {}; preserve private feeds, credentials, disabled sources, package source mappings and all read-only project/machine configs",
                        analysis.target_key,
                        document.path.display()
                    ),
                });
            }
        }
        let verification_config = current
            .documents
            .iter()
            .find(|document| document.format == "nuget-verification-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "NuGet verification config is missing from the current snapshot".into(),
                )
            })?;
        add_managed_document_change(
            context,
            current,
            verification_config,
            render_verification_config().into_bytes(),
            "create an isolated credential-free NuGet.Config used only for fixed package verification",
            &mut changes,
        );
        if clients
            .iter()
            .any(|client| client.kind == ClientKind::Dotnet)
        {
            let project = current
                .documents
                .iter()
                .find(|document| document.format == "nuget-verification-project")
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "NuGet verification project is missing from the current snapshot".into(),
                    )
                })?;
            add_managed_document_change(
                context,
                current,
                project,
                render_verification_project().into_bytes(),
                "create an isolated SDK project used only for a fixed NuGet restore check",
                &mut changes,
            );
        }
        Ok(ChangePlan {
            adapter_key: "nuget".into(),
            tool_id: "nuget".into(),
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
            let snapshot = nuget_snapshot(runtime)?;
            if snapshot.clients.is_empty() {
                return Err(AdapterError::Verification(
                    "NuGet clients disappeared before verification".into(),
                ));
            }
            let known_targets = snapshot
                .clients
                .iter()
                .map(|client| rooted(&context.root, &client.user_config))
                .chain([
                    rooted(&context.root, &snapshot.verification_config),
                    rooted(&context.root, &snapshot.verification_project),
                ])
                .collect::<BTreeSet<_>>();
            if receipt
                .changed_targets
                .iter()
                .all(|target| !known_targets.contains(target))
            {
                return Err(AdapterError::Verification(
                    "NuGet transaction receipt contains no known target".into(),
                ));
            }
            for client in &snapshot.clients {
                let contents = runtime.read(&client.user_config)?.ok_or_else(|| {
                    AdapterError::Verification(format!(
                        "{} user NuGet.Config disappeared",
                        client.kind.display_name()
                    ))
                })?;
                let config = parse_config(&client.user_config, &contents)?;
                let source = config
                    .source_additions()
                    .into_iter()
                    .find(|source| normalized_public_v3(&source.url).as_deref() == Some(HUAWEI_V3))
                    .ok_or_else(|| {
                        AdapterError::Verification(format!(
                            "{} user NuGet.Config did not load the reviewed v3 service index",
                            client.kind.display_name()
                        ))
                    })?;
                if source
                    .protocol_version
                    .as_deref()
                    .is_some_and(|value| value != "3")
                {
                    return Err(AdapterError::Verification(
                        "NuGet source protocolVersion is not v3".into(),
                    ));
                }
                let listed = list_sources(runtime, client, &client.user_config)?;
                if !listed.contains(HUAWEI_V3) {
                    return Err(AdapterError::Verification(format!(
                        "{} source listing did not report the selected service index",
                        client.kind.display_name()
                    )));
                }
            }
            let verification_config =
                runtime
                    .read(&snapshot.verification_config)?
                    .ok_or_else(|| {
                        AdapterError::Verification("NuGet verification config disappeared".into())
                    })?;
            if verification_config != render_verification_config().as_bytes() {
                return Err(AdapterError::Verification(
                    "NuGet verification config is not canonical".into(),
                ));
            }
            let verification_dir = snapshot
                .verification_config
                .parent()
                .ok_or_else(|| AdapterError::Verification("invalid verification path".into()))?;
            let mut verified_clients = Vec::new();
            for client in &snapshot.clients {
                let package = match client.kind {
                    ClientKind::Dotnet => {
                        let project =
                            runtime
                                .read(&snapshot.verification_project)?
                                .ok_or_else(|| {
                                    AdapterError::Verification(
                                        "NuGet verification project disappeared".into(),
                                    )
                                })?;
                        if project != render_verification_project().as_bytes() {
                            return Err(AdapterError::Verification(
                                "NuGet verification project is not canonical".into(),
                            ));
                        }
                        verify_with_dotnet(runtime, &snapshot, verification_dir)?
                    }
                    ClientKind::Nuget => verify_with_nuget(runtime, &snapshot, verification_dir)?,
                };
                let bytes = runtime.read(&package)?.ok_or_else(|| {
                    AdapterError::Verification(format!(
                        "{} did not save the verification nupkg",
                        client.kind.display_name()
                    ))
                })?;
                if bytes.len() < 4 || !bytes.starts_with(b"PK") {
                    return Err(AdapterError::Verification(format!(
                        "{} verification result is not a NuGet package archive",
                        client.kind.display_name()
                    )));
                }
                verified_clients.push(format!(
                    "{} ({:x})",
                    client.kind.display_name(),
                    Sha256::digest(&bytes)
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} loaded {HUAWEI_V3} and downloaded client-verified {VERIFY_PACKAGE} {VERIFY_VERSION}; the catalog gate separately enforces the reviewed nupkg SHA-256 {VERIFY_NUPKG_SHA256}",
                    verified_clients.join(" and ")
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
                "restored {} NuGet configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ClientKind {
    Dotnet,
    Nuget,
}

impl ClientKind {
    fn command(self) -> &'static str {
        match self {
            Self::Dotnet => "dotnet",
            Self::Nuget => "nuget",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Dotnet => "dotnet",
            Self::Nuget => "NuGet CLI",
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Dotnet => "dotnet",
            Self::Nuget => "nuget-cli",
        }
    }

    fn user_format(self) -> &'static str {
        match self {
            Self::Dotnet => "nuget-user-dotnet",
            Self::Nuget => "nuget-user-cli",
        }
    }

    fn additional_format(self) -> &'static str {
        match self {
            Self::Dotnet => "nuget-additional-user-dotnet-read-only",
            Self::Nuget => "nuget-additional-user-cli-read-only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientSnapshot {
    kind: ClientKind,
    version: String,
    user_config: PathBuf,
    additional_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NugetSnapshot {
    clients: Vec<ClientSnapshot>,
    machine_configs: Vec<PathBuf>,
    project_configs: Vec<PathBuf>,
    verification_config: PathBuf,
    verification_project: PathBuf,
}

impl NugetSnapshot {
    fn version_token(&self) -> String {
        self.clients
            .iter()
            .map(|client| format!("{}={}", client.kind.id(), client.version))
            .collect::<Vec<_>>()
            .join(";")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigKind {
    Machine,
    AdditionalUser(ClientKind),
    User(ClientKind),
    Project,
}

impl ConfigKind {
    fn format(self) -> &'static str {
        match self {
            Self::Machine => "nuget-machine-read-only",
            Self::AdditionalUser(client) => client.additional_format(),
            Self::User(client) => client.user_format(),
            Self::Project => "nuget-project-read-only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigRecord {
    path: PathBuf,
    kind: ConfigKind,
    exists: bool,
    contents: Vec<u8>,
}

type VerificationDocument = (PathBuf, &'static str, Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceOperation {
    Clear,
    Remove(String),
    Add(SourceEntry),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceEntry {
    key: String,
    url: String,
    protocol_version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BoolOperation {
    Clear,
    Remove(String),
    Add(String, bool),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedConfig {
    source_operations: Vec<SourceOperation>,
    disabled_operations: Vec<BoolOperation>,
    credential_keys: BTreeSet<String>,
    mapping_keys: BTreeSet<String>,
    mapping_present: bool,
    mapping_clear: bool,
}

impl ParsedConfig {
    fn source_additions(&self) -> Vec<&SourceEntry> {
        self.source_operations
            .iter()
            .filter_map(|operation| match operation {
                SourceOperation::Add(source) => Some(source),
                _ => None,
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
struct ClientAnalysis {
    target_key: String,
}

#[derive(Default)]
struct EffectiveConfig {
    sources: BTreeMap<String, SourceEntry>,
    disabled: BTreeMap<String, bool>,
    credentials: BTreeSet<String>,
    mapping_keys: BTreeSet<String>,
    mapping_present: bool,
    has_source_instruction: bool,
}

fn nuget_snapshot(runtime: &dyn Runtime) -> Result<NugetSnapshot, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("NuGet user home is unavailable".into()))?;
    validate_path(&home, "user home")?;
    let mut clients = Vec::new();
    if runtime.command_exists("dotnet") {
        let version = run_program(runtime, None, "dotnet", &["--version"], "dotnet --version")?;
        reviewed_dotnet_version(&version)?;
        clients.push(ClientSnapshot {
            kind: ClientKind::Dotnet,
            version,
            user_config: home.join(".nuget/NuGet/NuGet.Config"),
            additional_directory: home.join(".nuget/config"),
        });
    }
    if runtime.command_exists("nuget") {
        let output = run_program(runtime, None, "nuget", &["help"], "nuget help")?;
        let version = nuget_cli_version(&output)?;
        reviewed_nuget_cli_version(&version)?;
        clients.push(ClientSnapshot {
            kind: ClientKind::Nuget,
            version,
            user_config: home.join(".config/NuGet/NuGet.Config"),
            additional_directory: home.join(".config/NuGet/config"),
        });
    }
    let common = runtime
        .environment_variable("NUGET_COMMON_APPLICATION_DATA")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    if let Some(path) = &common {
        validate_path(path, "NUGET_COMMON_APPLICATION_DATA")?;
    }
    let machine_directory = common.as_ref().map_or_else(
        || PathBuf::from("/etc/opt/NuGet/Config"),
        |path| path.join("NuGet/Config"),
    );
    let machine_configs = list_config_files(runtime, &machine_directory)?;
    let project_configs = project_config_files(runtime)?;
    let verification_directory = home.join(".nuget/mirrorswitch/verification");
    Ok(NugetSnapshot {
        clients,
        machine_configs,
        project_configs,
        verification_config: verification_directory.join("NuGet.Config"),
        verification_project: verification_directory.join("MirrorSwitch.NuGet.Verification.csproj"),
    })
}

fn list_config_files(
    runtime: &dyn Runtime,
    directory: &Path,
) -> Result<Vec<PathBuf>, AdapterError> {
    validate_path(directory, "config directory")?;
    Ok(runtime
        .list_files(directory)?
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("config"))
        })
        .collect())
}

fn project_config_files(runtime: &dyn Runtime) -> Result<Vec<PathBuf>, AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(Vec::new());
    };
    validate_path(&project, "project directory")?;
    let mut directories = project
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    directories.reverse();
    let mut configs = Vec::new();
    for directory in directories {
        let matches = runtime
            .list_files(&directory)?
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("NuGet.Config"))
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(AdapterError::Unsupported(format!(
                "{} contains multiple case-variant NuGet.Config files",
                directory.display()
            )));
        }
        configs.extend(matches);
    }
    Ok(configs)
}

fn read_configuration_documents(
    runtime: &dyn Runtime,
    snapshot: &NugetSnapshot,
) -> Result<Vec<ConfigRecord>, AdapterError> {
    let mut records = Vec::new();
    for path in &snapshot.machine_configs {
        records.push(read_record(runtime, path, ConfigKind::Machine)?);
    }
    for client in &snapshot.clients {
        for path in list_config_files(runtime, &client.additional_directory)? {
            records.push(read_record(
                runtime,
                &path,
                ConfigKind::AdditionalUser(client.kind),
            )?);
        }
        records.push(read_record(
            runtime,
            &client.user_config,
            ConfigKind::User(client.kind),
        )?);
    }
    for path in &snapshot.project_configs {
        records.push(read_record(runtime, path, ConfigKind::Project)?);
    }
    Ok(records)
}

fn read_record(
    runtime: &dyn Runtime,
    path: &Path,
    kind: ConfigKind,
) -> Result<ConfigRecord, AdapterError> {
    validate_path(path, "configuration")?;
    let observed = runtime.read(path)?;
    let exists = observed.is_some();
    let contents = observed.unwrap_or_default();
    if exists && contents.is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "NuGet.Config {} is empty",
            path.display()
        )));
    }
    Ok(ConfigRecord {
        path: path.to_path_buf(),
        kind,
        exists,
        contents,
    })
}

fn verification_documents(
    runtime: &dyn Runtime,
    snapshot: &NugetSnapshot,
) -> Result<Vec<VerificationDocument>, AdapterError> {
    let mut documents = vec![(
        snapshot.verification_config.clone(),
        "nuget-verification-config",
        runtime
            .read(&snapshot.verification_config)?
            .unwrap_or_default(),
    )];
    if snapshot
        .clients
        .iter()
        .any(|client| client.kind == ClientKind::Dotnet)
    {
        documents.push((
            snapshot.verification_project.clone(),
            "nuget-verification-project",
            runtime
                .read(&snapshot.verification_project)?
                .unwrap_or_default(),
        ));
    }
    Ok(documents)
}

fn parse_config(path: &Path, contents: &[u8]) -> Result<ParsedConfig, AdapterError> {
    if contents.is_empty() {
        return Ok(ParsedConfig {
            source_operations: Vec::new(),
            disabled_operations: Vec::new(),
            credential_keys: BTreeSet::new(),
            mapping_keys: BTreeSet::new(),
            mapping_present: false,
            mapping_clear: false,
        });
    }
    let text = utf8(path, contents)?;
    let document = Document::parse(text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "NuGet.Config {} is invalid XML: {error}",
            path.display()
        ))
    })?;
    let root = document.root_element();
    if !name_is(root, "configuration") {
        return Err(AdapterError::InvalidConfiguration(format!(
            "NuGet.Config {} root is not configuration",
            path.display()
        )));
    }
    reject_prefixed_node(text, root, "configuration")?;
    let source_operations = parse_source_operations(text, root)?;
    let disabled_operations = parse_disabled_operations(root)?;
    let credential_keys = direct_section(root, "packageSourceCredentials")?
        .map(|section| {
            section
                .children()
                .filter(Node::is_element)
                .map(|node| node.tag_name().name().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let mapping = direct_section(root, "packageSourceMapping")?;
    let mapping_keys = mapping
        .map(|section| {
            section
                .children()
                .filter(Node::is_element)
                .filter(|node| name_is(*node, "packageSource"))
                .map(|node| required_attribute(node, "key", "packageSourceMapping"))
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mapping_clear = mapping.is_some_and(|section| {
        section
            .children()
            .filter(Node::is_element)
            .any(|node| name_is(node, "clear"))
    });
    if let Some(section) = mapping {
        for node in section.children().filter(Node::is_element) {
            if !name_is(node, "packageSource") && !name_is(node, "clear") {
                return Err(AdapterError::Unsupported(format!(
                    "NuGet packageSourceMapping contains unsupported element {}",
                    node.tag_name().name()
                )));
            }
        }
    }
    Ok(ParsedConfig {
        source_operations,
        disabled_operations,
        credential_keys,
        mapping_keys,
        mapping_present: mapping.is_some(),
        mapping_clear,
    })
}

fn parse_source_operations(
    text: &str,
    root: Node<'_, '_>,
) -> Result<Vec<SourceOperation>, AdapterError> {
    let Some(section) = direct_section(root, "packageSources")? else {
        return Ok(Vec::new());
    };
    reject_prefixed_node(text, section, "packageSources")?;
    let mut operations = Vec::new();
    for node in section.children().filter(Node::is_element) {
        if name_is(node, "clear") {
            operations.push(SourceOperation::Clear);
        } else if name_is(node, "remove") {
            operations.push(SourceOperation::Remove(required_attribute(
                node,
                "key",
                "packageSources remove",
            )?));
        } else if name_is(node, "add") {
            operations.push(SourceOperation::Add(SourceEntry {
                key: required_attribute(node, "key", "packageSources add")?,
                url: required_attribute(node, "value", "packageSources add")?,
                protocol_version: attribute(node, "protocolVersion").map(str::to_owned),
            }));
        } else {
            return Err(AdapterError::Unsupported(format!(
                "NuGet packageSources contains unsupported element {}",
                node.tag_name().name()
            )));
        }
    }
    Ok(operations)
}

fn parse_disabled_operations(root: Node<'_, '_>) -> Result<Vec<BoolOperation>, AdapterError> {
    let Some(section) = direct_section(root, "disabledPackageSources")? else {
        return Ok(Vec::new());
    };
    let mut operations = Vec::new();
    for node in section.children().filter(Node::is_element) {
        if name_is(node, "clear") {
            operations.push(BoolOperation::Clear);
        } else if name_is(node, "remove") {
            operations.push(BoolOperation::Remove(required_attribute(
                node,
                "key",
                "disabledPackageSources remove",
            )?));
        } else if name_is(node, "add") {
            let key = required_attribute(node, "key", "disabledPackageSources add")?;
            let value = required_attribute(node, "value", "disabledPackageSources add")?;
            let value = match value.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(AdapterError::InvalidConfiguration(format!(
                        "disabledPackageSources value for {key} is not true or false"
                    )));
                }
            };
            operations.push(BoolOperation::Add(key, value));
        } else {
            return Err(AdapterError::Unsupported(format!(
                "NuGet disabledPackageSources contains unsupported element {}",
                node.tag_name().name()
            )));
        }
    }
    Ok(operations)
}

fn direct_section<'a>(
    root: Node<'a, 'a>,
    name: &str,
) -> Result<Option<Node<'a, 'a>>, AdapterError> {
    let sections = root
        .children()
        .filter(Node::is_element)
        .filter(|node| name_is(*node, name))
        .collect::<Vec<_>>();
    if sections.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "NuGet.Config contains more than one {name} section"
        )));
    }
    Ok(sections.into_iter().next())
}

fn analyze_client(
    documents: &[ConfigRecord],
    client: ClientKind,
) -> Result<ClientAnalysis, AdapterError> {
    let mut effective = EffectiveConfig::default();
    for record in ordered_records(documents, client) {
        let parsed = parse_config(&record.path, &record.contents)?;
        validate_immutable_record(record, &parsed)?;
        apply_config(&mut effective, &parsed);
    }
    finalize_analysis(&effective)
}

fn analyze_client_current(
    current: &CurrentConfiguration,
    client: ClientKind,
) -> Result<ClientAnalysis, AdapterError> {
    let records = current_records(current, client)?;
    analyze_client(&records, client)
}

fn ordered_records(records: &[ConfigRecord], client: ClientKind) -> Vec<&ConfigRecord> {
    let mut ordered = Vec::new();
    ordered.extend(
        records
            .iter()
            .filter(|record| record.kind == ConfigKind::Machine),
    );
    ordered.extend(
        records
            .iter()
            .filter(|record| record.kind == ConfigKind::AdditionalUser(client)),
    );
    ordered.extend(
        records
            .iter()
            .filter(|record| record.kind == ConfigKind::User(client)),
    );
    ordered.extend(
        records
            .iter()
            .filter(|record| record.kind == ConfigKind::Project),
    );
    ordered
}

fn current_records(
    current: &CurrentConfiguration,
    client: ClientKind,
) -> Result<Vec<ConfigRecord>, AdapterError> {
    let mut records = Vec::new();
    for document in &current.documents {
        let kind = match document.format.as_str() {
            "nuget-machine-read-only" => Some(ConfigKind::Machine),
            "nuget-additional-user-dotnet-read-only" if client == ClientKind::Dotnet => {
                Some(ConfigKind::AdditionalUser(client))
            }
            "nuget-additional-user-cli-read-only" if client == ClientKind::Nuget => {
                Some(ConfigKind::AdditionalUser(client))
            }
            "nuget-user-dotnet" if client == ClientKind::Dotnet => Some(ConfigKind::User(client)),
            "nuget-user-cli" if client == ClientKind::Nuget => Some(ConfigKind::User(client)),
            "nuget-project-read-only" => Some(ConfigKind::Project),
            _ => None,
        };
        if let Some(kind) = kind {
            records.push(ConfigRecord {
                path: document.path.clone(),
                kind,
                exists: current.files.contains(&document.path),
                contents: document.contents.clone(),
            });
        }
    }
    if !records
        .iter()
        .any(|record| record.kind == ConfigKind::User(client))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} user NuGet.Config is absent from the current snapshot",
            client.display_name()
        )));
    }
    Ok(records)
}

fn validate_immutable_record(
    record: &ConfigRecord,
    parsed: &ParsedConfig,
) -> Result<(), AdapterError> {
    if !matches!(
        record.kind,
        ConfigKind::Project | ConfigKind::AdditionalUser(_)
    ) {
        return Ok(());
    }
    for operation in &parsed.source_operations {
        match operation {
            SourceOperation::Clear => {
                return Err(AdapterError::Unsupported(format!(
                    "read-only {} contains packageSources clear and overrides the user source",
                    record.path.display()
                )));
            }
            SourceOperation::Remove(key) if is_nuget_org_key(key) => {
                return Err(AdapterError::Unsupported(format!(
                    "read-only {} removes the NuGet.org source key",
                    record.path.display()
                )));
            }
            SourceOperation::Add(source)
                if is_nuget_org_key(&source.key)
                    || normalized_public_v3(&source.url).is_some()
                    || is_public_v2(&source.url) =>
            {
                return Err(AdapterError::Unsupported(format!(
                    "read-only {} overrides a public NuGet source",
                    record.path.display()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn apply_config(effective: &mut EffectiveConfig, parsed: &ParsedConfig) {
    if !parsed.source_operations.is_empty() {
        effective.has_source_instruction = true;
    }
    for operation in &parsed.source_operations {
        match operation {
            SourceOperation::Clear => effective.sources.clear(),
            SourceOperation::Remove(key) => {
                effective.sources.remove(&normalize_key(key));
            }
            SourceOperation::Add(source) => {
                effective
                    .sources
                    .insert(normalize_key(&source.key), source.clone());
            }
        }
    }
    for operation in &parsed.disabled_operations {
        match operation {
            BoolOperation::Clear => effective.disabled.clear(),
            BoolOperation::Remove(key) => {
                effective.disabled.remove(&normalize_key(key));
            }
            BoolOperation::Add(key, value) => {
                effective.disabled.insert(normalize_key(key), *value);
            }
        }
    }
    effective.credentials.extend(
        parsed
            .credential_keys
            .iter()
            .map(|key| normalize_key(&decode_xml_name(key))),
    );
    if parsed.mapping_present {
        effective.mapping_present = true;
        if parsed.mapping_clear {
            effective.mapping_keys.clear();
        }
        effective
            .mapping_keys
            .extend(parsed.mapping_keys.iter().map(|key| normalize_key(key)));
    }
}

fn finalize_analysis(effective: &EffectiveConfig) -> Result<ClientAnalysis, AdapterError> {
    if effective
        .sources
        .values()
        .any(|source| is_public_v2(&source.url))
    {
        return Err(AdapterError::Unsupported(
            "NuGet.org v2 is configured and cannot be interchanged with a v3 service index".into(),
        ));
    }
    for source in effective.sources.values() {
        if is_nuget_org_key(&source.key) && normalized_public_v3(&source.url).is_none() {
            return Err(AdapterError::Unsupported(
                "a NuGet.org source key points to a private or unreviewed endpoint".into(),
            ));
        }
    }
    let public = effective
        .sources
        .values()
        .filter(|source| normalized_public_v3(&source.url).is_some())
        .collect::<Vec<_>>();
    if public.len() > 1 {
        return Err(AdapterError::Unsupported(
            "effective NuGet configuration contains multiple public v3 sources".into(),
        ));
    }
    let target_key = if let Some(source) = public.first() {
        if source
            .protocol_version
            .as_deref()
            .is_some_and(|version| version != "3")
        {
            return Err(AdapterError::Unsupported(
                "the public NuGet source explicitly selects a non-v3 protocol".into(),
            ));
        }
        source.key.clone()
    } else if !effective.has_source_instruction && effective.sources.is_empty() {
        "nuget.org".into()
    } else {
        return Err(AdapterError::Unsupported(
            "NuGet configuration contains only custom sources; no public source is inferred".into(),
        ));
    };
    let normalized = normalize_key(&target_key);
    if effective
        .disabled
        .get(&normalized)
        .copied()
        .unwrap_or(false)
    {
        return Err(AdapterError::Unsupported(
            "the effective NuGet.org source is explicitly disabled".into(),
        ));
    }
    if effective.credentials.contains(&normalized) {
        return Err(AdapterError::Unsupported(
            "the effective NuGet.org source key has credentials and cannot be retargeted".into(),
        ));
    }
    if effective.mapping_present && !effective.mapping_keys.contains(&normalized) {
        return Err(AdapterError::Unsupported(format!(
            "packageSourceMapping does not contain the effective public source key {target_key}"
        )));
    }
    Ok(ClientAnalysis { target_key })
}

fn configured_sources(record: &ConfigRecord, parsed: &ParsedConfig) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    for source in parsed.source_additions() {
        sources.push(ConfiguredSource {
            upstream_id: normalized_public_v3(&source.url).map(|_| NUGET_UPSTREAM.into()),
            url: source.url.clone(),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["nuget-package-source".into()]),
                ("key".into(), vec![source.key.clone()]),
                ("origin".into(), vec![record.kind.format().into()]),
                (
                    "config_path".into(),
                    vec![record.path.display().to_string()],
                ),
                (
                    "protocol_version".into(),
                    vec![
                        source
                            .protocol_version
                            .clone()
                            .unwrap_or_else(|| "auto".into()),
                    ],
                ),
            ]),
        });
    }
    for key in &parsed.credential_keys {
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: "nuget-credential-source:<redacted>".into(),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["nuget-credentials".into()]),
                ("key".into(), vec![key.clone()]),
                (
                    "config_path".into(),
                    vec![record.path.display().to_string()],
                ),
            ]),
        });
    }
    for key in &parsed.mapping_keys {
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: format!("nuget-package-source-mapping:{key}"),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["nuget-package-source-mapping".into()]),
                ("key".into(), vec![key.clone()]),
                (
                    "config_path".into(),
                    vec![record.path.display().to_string()],
                ),
            ]),
        });
    }
    sources
}

fn validate_current_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    require_current(current)?;
    if current.sources.iter().any(|source| {
        source
            .metadata
            .get("kind")
            .is_some_and(|values| values == &["verification-target-conflict"])
    }) {
        return Err(AdapterError::Unsupported(
            "NuGet verification target exists without the MirrorSwitch marker".into(),
        ));
    }
    for client in current_clients(current)? {
        analyze_client_current(current, client.kind)?;
    }
    Ok(())
}

fn current_clients(current: &CurrentConfiguration) -> Result<Vec<ClientSnapshot>, AdapterError> {
    let mut clients = Vec::new();
    for source in &current.sources {
        if metadata(source, "kind") != Some("nuget-client") {
            continue;
        }
        let kind = match metadata(source, "client") {
            Some("dotnet") => ClientKind::Dotnet,
            Some("nuget-cli") => ClientKind::Nuget,
            _ => {
                return Err(AdapterError::InvalidConfiguration(
                    "NuGet client metadata is invalid".into(),
                ));
            }
        };
        let document = current
            .documents
            .iter()
            .find(|document| document.format == kind.user_format())
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("NuGet user config document is missing".into())
            })?;
        clients.push(ClientSnapshot {
            kind,
            version: metadata(source, "version").unwrap_or_default().into(),
            user_config: document.path.clone(),
            additional_directory: PathBuf::new(),
        });
    }
    clients.sort_by_key(|client| client.kind);
    if clients.is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "NuGet current configuration contains no client".into(),
        ));
    }
    Ok(clients)
}

fn rewrite_user_config(
    text: &str,
    target_key: &str,
    endpoint: &str,
) -> Result<String, AdapterError> {
    if text.is_empty() {
        return Ok(render_new_config(target_key, endpoint));
    }
    let document = Document::parse(text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("user NuGet.Config is invalid XML: {error}"))
    })?;
    let root = document.root_element();
    if !name_is(root, "configuration") {
        return Err(AdapterError::InvalidConfiguration(
            "user NuGet.Config root is not configuration".into(),
        ));
    }
    reject_prefixed_node(text, root, "configuration")?;
    let section = direct_section(root, "packageSources")?;
    if let Some(section) = section {
        reject_prefixed_node(text, section, "packageSources")?;
        let matches = section
            .children()
            .filter(Node::is_element)
            .filter(|node| name_is(*node, "add"))
            .filter(|node| {
                attribute(*node, "key").is_some_and(|key| key.eq_ignore_ascii_case(target_key))
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(AdapterError::Unsupported(format!(
                "user NuGet.Config contains duplicate source key {target_key}"
            )));
        }
        if let Some(source) = matches.first() {
            let current = required_attribute(*source, "value", "packageSources add")?;
            if normalized_public_v3(&current).is_none() {
                return Err(AdapterError::Unsupported(format!(
                    "user source key {target_key} points to an unreviewed endpoint"
                )));
            }
            let range = attribute_value_range(text, source.range(), "value")?;
            return Ok(replace_range(text, range, endpoint));
        }
        return insert_source(text, section, target_key, endpoint);
    }
    insert_package_sources(text, root, target_key, endpoint)
}

fn insert_source(
    text: &str,
    section: Node<'_, '_>,
    key: &str,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let nl = newline(text);
    let add = format!(
        "    <add key=\"{}\" value=\"{}\" protocolVersion=\"3\" />",
        xml_escape(key),
        xml_escape(endpoint)
    );
    let raw = &text[section.range()];
    if is_self_closing_start(raw)? {
        let replacement = format!("<packageSources>{nl}{add}{nl}  </packageSources>");
        return Ok(replace_range(text, section.range(), &replacement));
    }
    let closing = closing_tag_start(text, section.range(), "packageSources")?;
    let prefix = if text[..closing].ends_with(nl) {
        ""
    } else {
        nl
    };
    Ok(format!(
        "{}{}{}{}{}",
        &text[..closing],
        prefix,
        add,
        nl,
        &text[closing..]
    ))
}

fn insert_package_sources(
    text: &str,
    root: Node<'_, '_>,
    key: &str,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let nl = newline(text);
    let block = format!(
        "  <packageSources>{nl}    <add key=\"{}\" value=\"{}\" protocolVersion=\"3\" />{nl}  </packageSources>",
        xml_escape(key),
        xml_escape(endpoint)
    );
    let raw = &text[root.range()];
    if is_self_closing_start(raw)? {
        let replacement = format!("<configuration>{nl}{block}{nl}</configuration>");
        return Ok(replace_range(text, root.range(), &replacement));
    }
    let closing = closing_tag_start(text, root.range(), "configuration")?;
    let prefix = if text[..closing].ends_with(nl) {
        ""
    } else {
        nl
    };
    Ok(format!(
        "{}{}{}{}{}",
        &text[..closing],
        prefix,
        block,
        nl,
        &text[closing..]
    ))
}

fn attribute_value_range(
    text: &str,
    node_range: Range<usize>,
    target: &str,
) -> Result<Range<usize>, AdapterError> {
    let bytes = text.as_bytes();
    let mut index = node_range.start + 1;
    while index < node_range.end && !bytes[index].is_ascii_whitespace() && bytes[index] != b'>' {
        index += 1;
    }
    loop {
        while index < node_range.end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= node_range.end || matches!(bytes[index], b'>' | b'/') {
            break;
        }
        let name_start = index;
        while index < node_range.end
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'>' | b'/')
        {
            index += 1;
        }
        let name = &text[name_start..index];
        while index < node_range.end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= node_range.end || bytes[index] != b'=' {
            return Err(AdapterError::Unsupported(
                "NuGet.Config attribute layout is outside the reviewed model".into(),
            ));
        }
        index += 1;
        while index < node_range.end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= node_range.end || !matches!(bytes[index], b'\'' | b'\"') {
            return Err(AdapterError::Unsupported(
                "NuGet.Config attribute is not quoted".into(),
            ));
        }
        let quote = bytes[index];
        index += 1;
        let value_start = index;
        while index < node_range.end && bytes[index] != quote {
            index += 1;
        }
        if index >= node_range.end {
            return Err(AdapterError::InvalidConfiguration(
                "NuGet.Config attribute quote is unterminated".into(),
            ));
        }
        if name.eq_ignore_ascii_case(target) {
            return Ok(value_start..index);
        }
        index += 1;
    }
    Err(AdapterError::InvalidConfiguration(format!(
        "NuGet package source has no {target} attribute"
    )))
}

fn closing_tag_start(text: &str, range: Range<usize>, name: &str) -> Result<usize, AdapterError> {
    text[range.clone()]
        .rfind("</")
        .map(|offset| range.start + offset)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("NuGet {name} closing tag is missing"))
        })
}

fn is_self_closing_start(raw: &str) -> Result<bool, AdapterError> {
    let mut quote = None;
    for (index, byte) in raw.bytes().enumerate() {
        match (quote, byte) {
            (None, b'\'' | b'\"') => quote = Some(byte),
            (Some(active), value) if active == value => quote = None,
            (None, b'>') => return Ok(raw[..index].trim_end().ends_with('/')),
            _ => {}
        }
    }
    Err(AdapterError::InvalidConfiguration(
        "NuGet.Config start tag is unterminated".into(),
    ))
}

fn render_new_config(key: &str, endpoint: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"{}\" value=\"{}\" protocolVersion=\"3\" />\n  </packageSources>\n</configuration>\n",
        xml_escape(key),
        xml_escape(endpoint)
    )
}

fn render_verification_config() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <clear />\n    <add key=\"mirrorswitch-nuget\" value=\"{HUAWEI_V3}\" protocolVersion=\"3\" />\n  </packageSources>\n</configuration>\n"
    )
}

fn render_verification_project() -> String {
    format!(
        r#"{VERIFY_PROJECT_MARKER}
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <NuGetAudit>false</NuGetAudit>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="{VERIFY_PACKAGE}" Version="{VERIFY_VERSION}" />
  </ItemGroup>
</Project>
"#
    )
}

fn add_managed_document_change(
    context: &SystemContext,
    current: &CurrentConfiguration,
    document: &ConfigurationDocument,
    contents: Vec<u8>,
    summary: &str,
    changes: &mut Vec<PlannedFileChange>,
) {
    if document.contents != contents {
        changes.push(PlannedFileChange {
            target: rooted(&context.root, &document.path),
            old_contents: current
                .files
                .contains(&document.path)
                .then(|| document.contents.clone()),
            old_mode: None,
            new_contents: contents,
            new_mode: None,
            summary: summary.into(),
        });
    }
}

fn selected_service_index(selections: &[MirrorSelection]) -> Result<&'static str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "nuget"
        || selections[0].upstream_id != NUGET_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "NuGet requires exactly one v3 source selection".into(),
        ));
    }
    let selection = &selections[0];
    let index = unique_endpoint(selection, EndpointRole::Index)?;
    let registration = unique_endpoint(selection, EndpointRole::Metadata)?;
    let artifacts = unique_endpoint(selection, EndpointRole::Artifacts)?;
    if normalized_url(index).as_deref() != Some(HUAWEI_INDEX_ROOT)
        || normalized_url(registration).as_deref() != Some(HUAWEI_REGISTRATION_ROOT)
        || normalized_url(artifacts).as_deref() != Some(HUAWEI_FLAT_ROOT)
    {
        return Err(AdapterError::InvalidConfiguration(
            "NuGet index, registration and flat-container endpoints are not one reviewed v3 chain"
                .into(),
        ));
    }
    Ok(HUAWEI_V3)
}

fn unique_endpoint(selection: &MirrorSelection, role: EndpointRole) -> Result<&str, AdapterError> {
    let endpoints = selection
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
        .collect::<Vec<_>>();
    if endpoints.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "NuGet selection requires exactly one {role:?} HTTPS endpoint"
        )));
    }
    Ok(&endpoints[0].url)
}

fn list_sources(
    runtime: &dyn Runtime,
    client: &ClientSnapshot,
    config: &Path,
) -> Result<String, AdapterError> {
    let config = path_string(config)?;
    match client.kind {
        ClientKind::Dotnet => run_program(
            runtime,
            None,
            "dotnet",
            &[
                "nuget",
                "list",
                "source",
                "--format",
                "Detailed",
                "--configfile",
                &config,
            ],
            "dotnet nuget list source",
        ),
        ClientKind::Nuget => run_program(
            runtime,
            None,
            "nuget",
            &[
                "sources",
                "List",
                "-Format",
                "Detailed",
                "-NonInteractive",
                "-ForceEnglishOutput",
                "-ConfigFile",
                &config,
            ],
            "nuget sources List",
        ),
    }
}

fn verify_with_dotnet(
    runtime: &dyn Runtime,
    snapshot: &NugetSnapshot,
    directory: &Path,
) -> Result<PathBuf, AdapterError> {
    let project = path_string(&snapshot.verification_project)?;
    let config = path_string(&snapshot.verification_config)?;
    let packages = directory.join("packages/dotnet");
    let packages_arg = path_string(&packages)?;
    run_program(
        runtime,
        Some(directory),
        "dotnet",
        &[
            "restore",
            &project,
            "--configfile",
            &config,
            "--packages",
            &packages_arg,
            "--force",
            "--disable-parallel",
            "--verbosity",
            "normal",
            "-p:RestoreNoCache=true",
            "-p:NuGetAudit=false",
        ],
        "dotnet restore NuGet verification package",
    )?;
    let metadata = packages
        .join(VERIFY_PACKAGE_LOWER)
        .join(VERIFY_VERSION)
        .join(".nupkg.metadata");
    let metadata_contents = runtime.read(&metadata)?.ok_or_else(|| {
        AdapterError::Verification("dotnet restore did not write .nupkg.metadata".into())
    })?;
    let metadata_text = utf8(&metadata, &metadata_contents)?;
    if !metadata_text.contains(HUAWEI_V3) {
        return Err(AdapterError::Verification(
            "dotnet restore metadata did not record the selected Huawei source".into(),
        ));
    }
    Ok(packages
        .join(VERIFY_PACKAGE_LOWER)
        .join(VERIFY_VERSION)
        .join(format!("{VERIFY_PACKAGE_LOWER}.{VERIFY_VERSION}.nupkg")))
}

fn verify_with_nuget(
    runtime: &dyn Runtime,
    snapshot: &NugetSnapshot,
    directory: &Path,
) -> Result<PathBuf, AdapterError> {
    let packages = directory.join("packages/cli");
    let packages_arg = path_string(&packages)?;
    let config = path_string(&snapshot.verification_config)?;
    run_program(
        runtime,
        Some(directory),
        "nuget",
        &[
            "install",
            VERIFY_PACKAGE,
            "-Version",
            VERIFY_VERSION,
            "-Source",
            HUAWEI_V3,
            "-OutputDirectory",
            &packages_arg,
            "-DirectDownload",
            "-NoHttpCache",
            "-NonInteractive",
            "-ForceEnglishOutput",
            "-PackageSaveMode",
            "nupkg",
            "-ConfigFile",
            &config,
        ],
        "NuGet CLI install verification package",
    )?;
    Ok(packages
        .join(format!("{VERIFY_PACKAGE}.{VERIFY_VERSION}"))
        .join(format!("{VERIFY_PACKAGE}.{VERIFY_VERSION}.nupkg")))
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

fn reviewed_dotnet_version(version: &str) -> Result<(), AdapterError> {
    let (major, _, _) = version_components(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("dotnet SDK version {version} is not understood"))
    })?;
    if !(6..=10).contains(&major) {
        return Err(AdapterError::Unsupported(format!(
            "dotnet SDK {version} is outside the reviewed 6.x through 10.x NuGet model"
        )));
    }
    Ok(())
}

fn nuget_cli_version(output: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .find_map(|line| {
            let candidate = line
                .trim()
                .strip_prefix("NuGet Version:")
                .map(str::trim)
                .unwrap_or_else(|| line.trim());
            candidate
                .split_whitespace()
                .find(|token| version_components(token).is_some())
                .map(str::to_owned)
        })
        .ok_or_else(|| AdapterError::Unsupported("NuGet CLI version is not understood".into()))
}

fn reviewed_nuget_cli_version(version: &str) -> Result<(), AdapterError> {
    let (major, _, _) = version_components(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("NuGet CLI version {version} is not understood"))
    })?;
    if !(6..=7).contains(&major) {
        return Err(AdapterError::Unsupported(format!(
            "NuGet CLI {version} is outside the reviewed 6.x/7.x source-mapping model"
        )));
    }
    Ok(())
}

fn version_components(version: &str) -> Option<(u64, u64, u64)> {
    let version = version.trim_start_matches('v');
    let mut parts = version.split(['.', '-', '+']);
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next().unwrap_or("0").parse().ok()?,
    ))
}

fn normalized_public_v3(value: &str) -> Option<String> {
    let normalized = normalized_url(value)?;
    matches!(normalized.as_str(), OFFICIAL_V3 | HUAWEI_V3).then_some(normalized)
}

fn is_public_v2(value: &str) -> bool {
    matches!(
        value.trim().trim_end_matches('/'),
        "https://www.nuget.org/api/v2"
            | "https://nuget.org/api/v2"
            | "http://www.nuget.org/api/v2"
            | "http://nuget.org/api/v2"
    )
}

fn normalized_url(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('/');
    if !value.starts_with("https://")
        || value.contains(['\n', '\r', '\0'])
        || value[8..].contains('@')
        || value.contains(['?', '#'])
    {
        return None;
    }
    Some(value.to_owned())
}

fn is_nuget_org_key(value: &str) -> bool {
    matches!(
        normalize_key(value).as_str(),
        "nuget.org" | "nuget official package source"
    )
}

fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn decode_xml_name(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 7 <= bytes.len()
            && bytes[index] == b'_'
            && matches!(bytes[index + 1], b'x' | b'X')
            && bytes[index + 6] == b'_'
        {
            let hex = &value[index + 2..index + 6];
            if let Ok(codepoint) = u32::from_str_radix(hex, 16)
                && let Some(character) = char::from_u32(codepoint)
            {
                decoded.push(character);
                index += 7;
                continue;
            }
        }
        let Some(character) = value[index..].chars().next() else {
            break;
        };
        decoded.push(character);
        index += character.len_utf8();
    }
    decoded
}

fn name_is(node: Node<'_, '_>, name: &str) -> bool {
    node.tag_name().name().eq_ignore_ascii_case(name)
}

fn attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attributes()
        .find(|attribute| attribute.name().eq_ignore_ascii_case(name))
        .map(|attribute| attribute.value())
}

fn required_attribute(
    node: Node<'_, '_>,
    name: &str,
    context: &str,
) -> Result<String, AdapterError> {
    attribute(node, name)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("{context} has no {name} attribute"))
        })
}

fn reject_prefixed_node(text: &str, node: Node<'_, '_>, label: &str) -> Result<(), AdapterError> {
    if node.tag_name().namespace().is_some() {
        return Err(AdapterError::Unsupported(format!(
            "namespaced NuGet {label} XML is outside the formatting-preserving model"
        )));
    }
    let opening = &text[node.range()];
    let name = opening
        .strip_prefix('<')
        .and_then(|value| value.split([' ', '\t', '\r', '\n', '/', '>']).next())
        .unwrap_or_default();
    if name.contains(':') {
        return Err(AdapterError::Unsupported(format!(
            "prefixed NuGet {label} XML is outside the formatting-preserving model"
        )));
    }
    Ok(())
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn policy_source(kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("nuget-policy:{kind}"),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "NuGet adapter v0.1 only supports Linux".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "NuGet adapter requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "NuGet v0.1 changes user config only; project and machine configs are read-only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "nuget" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "NuGet requires a user-scoped NuGet configuration".into(),
        ));
    }
    Ok(())
}

fn validate_path(path: &Path, label: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "NuGet {label} path {} is not absolute and normalized",
            path.display()
        )));
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<String, AdapterError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("path {} is not UTF-8", path.display())))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "NuGet configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn replace_range(text: &str, range: Range<usize>, replacement: &str) -> String {
    format!(
        "{}{}{}",
        &text[..range.start],
        replacement,
        &text[range.end..]
    )
}

fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
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
