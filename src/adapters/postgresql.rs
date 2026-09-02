use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
};

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

const UPSTREAM: &str = "postgresql-pgdg--repository-metadata";
const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: PostgreSQL package repository v1";
const DEFAULT_KEYRING: &str = "/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc";
const CHANNEL: &str = "17";
const ACTIONABLE_ENDPOINTS: &[(&str, &str)] = &[
    ("aliyun", "https://mirrors.aliyun.com/postgresql"),
    ("huaweicloud", "https://repo.huaweicloud.com/postgresql"),
    ("nju", "https://mirrors.nju.edu.cn/postgresql"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct PostgreSqlAdapter;

impl Adapter for PostgreSqlAdapter {
    fn key(&self) -> &'static str {
        "postgresql"
    }

    fn tool_id(&self) -> &'static str {
        "postgresql"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
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
        let manager = manager(runtime)?;
        let documents = read_documents(runtime, manager)?;
        let installed = installed_version(runtime)?;
        let configured_channel = unique_configured_channel(&documents)?;
        let channel = match installed.as_deref() {
            Some(version) => {
                let channel = channel_from_version(version)?;
                if configured_channel
                    .as_deref()
                    .is_some_and(|configured| configured != channel)
                {
                    return Err(AdapterError::Unsupported(format!(
                        "installed PostgreSQL {version} does not match configured channel {}",
                        configured_channel.as_deref().unwrap_or("unknown")
                    )));
                }
                channel.into()
            }
            None if configured_channel.is_some() => configured_channel.clone().unwrap(),
            None => return Ok(None),
        };
        if channel != CHANNEL {
            return Err(AdapterError::Unsupported(format!(
                "PostgreSQL channel {channel} is outside reviewed PGDG 17 coverage"
            )));
        }
        let platform = platform(context, manager)?;
        let configured = documents
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        if configured > 1 {
            return Err(AdapterError::InvalidConfiguration(
                "multiple PostgreSQL Community server repositories are active".into(),
            ));
        }
        if installed.is_none() && configured == 0 {
            return Ok(None);
        }
        Ok(Some(DetectedTool {
            tool_id: "postgresql".into(),
            executable: Some(PathBuf::from(manager.command())),
            version: installed.clone().or_else(|| Some(channel.clone())),
            evidence: vec![
                format!("package manager is {}", manager.name()),
                format!("target PostgreSQL channel is {channel}"),
                format!(
                    "installed PostgreSQL version is {}",
                    installed.as_deref().unwrap_or("not detected")
                ),
                format!("configured PostgreSQL Community server repositories: {configured}"),
                format!("repository family/release is {}/{}", platform.family, platform.release),
                format!("repository architecture is {}", platform.architecture),
                "PostgreSQL majors, distribution packages, private repositories, and service data are separate surfaces".into(),
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
        if detected.tool_id != "postgresql" {
            return Err(AdapterError::InvalidConfiguration(
                "PostgreSQL package read received another tool's detection result".into(),
            ));
        }
        let manager = manager(runtime)?;
        let observed = read_documents(runtime, manager)?;
        let installed = installed_version(runtime)?;
        let configured_channel = unique_configured_channel(&observed)?;
        let channel = match installed.as_deref() {
            Some(version) => channel_from_version(version)?.to_owned(),
            None => configured_channel.clone().ok_or_else(|| {
                AdapterError::Unsupported(
                    "PostgreSQL channel cannot be inferred from the binary or repository".into(),
                )
            })?,
        };
        if channel != CHANNEL {
            return Err(AdapterError::Unsupported(format!(
                "PostgreSQL channel {channel} is outside reviewed PGDG 17 coverage"
            )));
        }
        if configured_channel
            .as_deref()
            .is_some_and(|configured| configured != channel)
        {
            return Err(AdapterError::Unsupported(
                "installed PostgreSQL version and configured server channel differ".into(),
            ));
        }
        let platform = platform(context, manager)?;
        let effective_version = installed.as_deref().unwrap_or(&channel);
        if detected.version.as_deref() != Some(effective_version) {
            return Err(AdapterError::Conflict(
                "PostgreSQL package target version changed after detection".into(),
            ));
        }
        let target = choose_target(manager, &observed);
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = vec![snapshot_source("manager", manager.name())];
        sources.push(snapshot_source("channel", &channel));
        sources.push(snapshot_source("family", &platform.family));
        sources.push(snapshot_source("release", &platform.release));
        sources.push(snapshot_source("architecture", &platform.architecture));
        sources.push(snapshot_source(
            "repository-version",
            &platform.repository_version(&channel),
        ));
        if let Some(version) = &installed {
            sources.push(snapshot_source("installed-version", version));
        }
        let modern_count = observed
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        if modern_count > 1 {
            sources.push(policy_source(
                "multiple-modern-repositories",
                Path::new(":repo:"),
            ));
        }
        for document in observed {
            if document.exists {
                files.push(document.path.clone());
            }
            if document.path == target
                && document.exists
                && is_managed_path(&document.path)
                && utf8(&document.path, &document.contents)?.lines().next() != Some(MANAGED_MARKER)
            {
                sources.push(policy_source("managed-target-conflict", &document.path));
            }
            if let Some(source) = &document.source {
                sources.push(configured_source(source, &document.path));
                if source.channel != channel
                    || source.family != platform.family
                    || source.release != platform.release
                {
                    sources.push(policy_source("coverage-mismatch", &document.path));
                }
                match manager {
                    Manager::Apt => {
                        let keyring = source.signed_by.as_deref().ok_or_else(|| {
                            AdapterError::Unsupported(
                                "modern PostgreSQL APT source has no explicit Signed-By keyring"
                                    .into(),
                            )
                        })?;
                        let keyring = PathBuf::from(keyring);
                        validate_path(&keyring, "APT keyring")?;
                        if runtime.read(&keyring)?.is_none() {
                            sources.push(policy_source("keyring-missing", &keyring));
                        } else {
                            sources.push(policy_source("keyring-preserved", &keyring));
                        }
                    }
                    Manager::Rpm if source.gpgcheck != Some(true) => {
                        sources.push(policy_source("gpgcheck-disabled", &document.path));
                    }
                    Manager::Rpm if source.signed_by.is_none() => {
                        sources.push(policy_source("gpgkey-missing", &document.path));
                    }
                    Manager::Rpm => {}
                }
            }
            if document.path != target && document.exists {
                sources.push(policy_source("related-config-preserved", &document.path));
            }
            documents.push(ConfigurationDocument {
                path: document.path.clone(),
                format: if document.path == target {
                    "postgresql-package-target".into()
                } else {
                    "postgresql-package-read-only".into()
                },
                contents: document.contents,
            });
        }
        if manager == Manager::Apt && modern_count == 0 {
            let keyring = PathBuf::from(DEFAULT_KEYRING);
            if runtime.read(&keyring)?.is_none() {
                sources.push(policy_source("keyring-missing", &keyring));
            } else {
                sources.push(policy_source("keyring-preserved", &keyring));
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "postgresql".into(),
            scope,
            files,
            sources,
            documents,
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        _detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_linux(context)?;
        require_current(current)?;
        let repository_version = current_value(current, "repository-version")?;
        let platform = Platform {
            family: current_value(current, "family")?,
            release: current_value(current, "release")?,
            architecture: current_value(current, "architecture")?,
        };
        Ok(SelectionRequest {
            tool_id: "postgresql".into(),
            adapter_key: "postgresql".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::from([(UPSTREAM.into(), repository_version)]),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("family".into(), current_value(current, "family")?),
                    ("release".into(), current_value(current, "release")?),
                    (
                        "architecture".into(),
                        current_value(current, "architecture")?,
                    ),
                    ("channel".into(), current_value(current, "channel")?),
                    ("platform_tag".into(), platform_tag(&platform)?.into()),
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
                EndpointRole::Packages,
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let (provider, endpoint) = selected_endpoint(selections)?;
        let manager = Manager::from_name(&current_value(current, "manager")?)?;
        let channel = current_value(current, "channel")?;
        let platform = Platform {
            family: current_value(current, "family")?,
            release: current_value(current, "release")?,
            architecture: current_value(current, "architecture")?,
        };
        let mapped = mapped_uri(manager, &provider, &endpoint, &platform)?;
        let target = find_document(current, "postgresql-package-target")?;
        let rendered = if target.contents.is_empty() {
            render_new(manager, &mapped, &platform)
        } else {
            rewrite_existing(
                manager,
                utf8(&target.path, &target.contents)?,
                &target.path,
                &mapped,
                &channel,
            )?
        }
        .into_bytes();
        let changes = if target.contents == rendered {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &target.path),
                old_contents: current
                    .files
                    .contains(&target.path)
                    .then(|| target.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: format!(
                    "map only the PostgreSQL {channel} {} package channel while preserving GPG, pinning, credentials, and unrelated repositories",
                    manager.name()
                ),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "postgresql".into(),
            tool_id: "postgresql".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
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
            let manager = manager(runtime)?;
            let documents = read_documents(runtime, manager)?;
            let target = choose_target(manager, &documents);
            let physical = rooted(&context.root, &target);
            if !receipt.changed_targets.contains(&physical) {
                return Err(AdapterError::Verification(
                    "PostgreSQL package transaction contains no known target".into(),
                ));
            }
            let selected = documents
                .iter()
                .find(|document| document.path == target)
                .and_then(|document| document.source.as_ref())
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "PostgreSQL package repository is not active after apply".into(),
                    )
                })?;
            let output = match manager {
                Manager::Apt => verify_apt(runtime, &target)?,
                Manager::Rpm => verify_rpm(runtime, &target, selected.repo_id.as_deref())?,
            };
            if !output.contains("postgresql-17") && !output.contains("postgresql17-server") {
                return Err(AdapterError::Verification(
                    "system package manager did not expose PostgreSQL 17 server packages".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} refreshed and queried PostgreSQL 17 server packages through {}",
                    manager.name(),
                    selected.uri
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
                "restored {} PostgreSQL package repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Manager {
    Apt,
    Rpm,
}

impl Manager {
    fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Rpm => "rpm",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Apt => "apt-get",
            Self::Rpm => "dnf",
        }
    }

    fn from_name(value: &str) -> Result<Self, AdapterError> {
        match value {
            "apt" => Ok(Self::Apt),
            "rpm" => Ok(Self::Rpm),
            _ => Err(AdapterError::InvalidConfiguration(
                "unknown PostgreSQL package manager".into(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct RepositorySource {
    uri: String,
    channel: String,
    family: String,
    release: String,
    signed_by: Option<String>,
    gpgcheck: Option<bool>,
    repo_id: Option<String>,
}

#[derive(Clone, Debug)]
struct ObservedDocument {
    path: PathBuf,
    contents: Vec<u8>,
    exists: bool,
    source: Option<RepositorySource>,
}

#[derive(Clone, Debug)]
struct Platform {
    family: String,
    release: String,
    architecture: String,
}

impl Platform {
    fn repository_version(&self, channel: &str) -> String {
        format!(
            "{}-{}-{channel}-{}",
            self.family, self.release, self.architecture
        )
    }
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "PostgreSQL package adapter supports Linux only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "PostgreSQL package repositories require system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "postgresql" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "PostgreSQL package operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn manager(runtime: &dyn Runtime) -> Result<Manager, AdapterError> {
    if runtime.command_exists("apt-get") && runtime.command_exists("apt-cache") {
        Ok(Manager::Apt)
    } else if runtime.command_exists("dnf") {
        Ok(Manager::Rpm)
    } else {
        Err(AdapterError::Unsupported(
            "PostgreSQL packages require apt-get/apt-cache or dnf".into(),
        ))
    }
}

fn read_documents(
    runtime: &dyn Runtime,
    manager: Manager,
) -> Result<Vec<ObservedDocument>, AdapterError> {
    let (main, directory, target, extensions) = match manager {
        Manager::Apt => (
            Some(PathBuf::from("/etc/apt/sources.list")),
            PathBuf::from("/etc/apt/sources.list.d"),
            PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-postgresql.sources"),
            &["list", "sources"][..],
        ),
        Manager::Rpm => (
            None,
            PathBuf::from("/etc/yum.repos.d"),
            PathBuf::from("/etc/yum.repos.d/mirrorswitch-postgresql.repo"),
            &["repo"][..],
        ),
    };
    let mut paths = BTreeSet::from([target]);
    if let Some(main) = main {
        paths.insert(main);
    }
    for path in runtime.list_files(&directory)? {
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.contains(&extension))
        {
            paths.insert(path);
        }
    }
    let mut documents = Vec::new();
    for path in paths {
        let contents = runtime.read(&path)?;
        let exists = contents.is_some();
        let contents = contents.unwrap_or_default();
        let source = if exists {
            parse_repository(manager, utf8(&path, &contents)?, &path)?
        } else {
            None
        };
        documents.push(ObservedDocument {
            path,
            contents,
            exists,
            source,
        });
    }
    Ok(documents)
}

fn parse_repository(
    manager: Manager,
    text: &str,
    path: &Path,
) -> Result<Option<RepositorySource>, AdapterError> {
    match manager {
        Manager::Apt => parse_apt_repository(text, path),
        Manager::Rpm => parse_rpm_repository(text, path),
    }
}

fn parse_apt_repository(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut matches = Vec::<(String, String, Vec<String>, Option<String>)>::new();
    for stanza in text.split("\n\n") {
        let mut deb822_uri = None;
        let mut deb822_suite = None;
        let mut deb822_components = Vec::new();
        for line in stanza.lines() {
            let active = line.split('#').next().unwrap_or_default().trim();
            if active.is_empty() {
                continue;
            }
            if let Some(value) = active.strip_prefix("URIs:") {
                for uri in value
                    .split_whitespace()
                    .filter(|uri| is_postgresql_apt_uri(uri))
                {
                    if deb822_uri
                        .replace(uri.trim_end_matches('/').into())
                        .is_some()
                    {
                        return Err(AdapterError::InvalidConfiguration(format!(
                            "multiple PostgreSQL APT URIs exist in {}",
                            path.display()
                        )));
                    }
                }
                continue;
            }
            if let Some(value) = active.strip_prefix("Suites:") {
                deb822_suite = value.split_whitespace().next().map(str::to_owned);
                continue;
            }
            if let Some(value) = active.strip_prefix("Components:") {
                deb822_components = value.split_whitespace().map(str::to_owned).collect();
                continue;
            }
            if !active.starts_with("deb ") {
                continue;
            }
            let fields = active.split_whitespace().collect::<Vec<_>>();
            for (index, value) in fields.iter().enumerate() {
                if !is_postgresql_apt_uri(value) {
                    continue;
                }
                let suite = fields.get(index + 1).ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "PostgreSQL APT source in {} has no suite",
                        path.display()
                    ))
                })?;
                matches.push((
                    value.trim_end_matches('/').to_owned(),
                    (*suite).to_owned(),
                    fields[index + 2..]
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    apt_signed_by(active),
                ));
            }
        }
        if let Some(uri) = deb822_uri {
            matches.push((
                uri,
                deb822_suite.ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "PostgreSQL deb822 source in {} has no suite",
                        path.display()
                    ))
                })?,
                deb822_components,
                apt_signed_by(stanza),
            ));
        }
    }
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "multiple PostgreSQL APT URIs exist in {}",
            path.display()
        )));
    }
    matches
        .first()
        .map(|(uri, suite, components, signed_by)| {
            let (family, release) = apt_identity(suite, components, path)?;
            Ok(RepositorySource {
                uri: uri.clone(),
                channel: CHANNEL.into(),
                family,
                release,
                signed_by: signed_by.clone(),
                gpgcheck: None,
                repo_id: None,
            })
        })
        .transpose()
}

fn apt_identity(
    suite: &str,
    components: &[String],
    path: &Path,
) -> Result<(String, String), AdapterError> {
    if components != ["main"] {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PostgreSQL PGDG source in {} must use the main component",
            path.display()
        )));
    }
    let release = suite.strip_suffix("-pgdg").ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "PostgreSQL APT source in {} has no PGDG suite",
            path.display()
        ))
    })?;
    let family = if release == "bookworm" {
        "debian"
    } else {
        "ubuntu"
    };
    Ok((family.into(), release.into()))
}

fn apt_signed_by(text: &str) -> Option<String> {
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or_default().trim();
        if let Some(value) = active.strip_prefix("Signed-By:") {
            return Some(value.trim().into());
        }
        if let Some(index) = active.find("signed-by=") {
            let value = &active[index + "signed-by=".len()..];
            let value = value.split([']', ' ', ',']).next().unwrap_or_default();
            if !value.is_empty() {
                return Some(value.into());
            }
        }
    }
    None
}

fn parse_rpm_repository(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut section = None::<String>;
    let mut values: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for line in text.lines() {
        let active = line.split(['#', ';']).next().unwrap_or_default().trim();
        if active.starts_with('[') && active.ends_with(']') {
            let name = active[1..active.len() - 1].trim();
            if name.is_empty() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "empty RPM repository section in {}",
                    path.display()
                )));
            }
            section = Some(name.into());
            continue;
        }
        let Some((key, value)) = active.split_once('=') else {
            continue;
        };
        let Some(section) = &section else {
            continue;
        };
        values
            .entry(section.clone())
            .or_default()
            .insert(key.trim().to_ascii_lowercase(), value.trim().into());
    }
    let matches = values
        .iter()
        .filter_map(|(repo_id, values)| {
            let uri = values.get("baseurl")?;
            (values.get("enabled").is_none_or(|value| value != "0") && is_postgresql_rpm_uri(uri))
                .then(|| (repo_id.clone(), uri.trim_end_matches('/').to_owned()))
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "multiple PostgreSQL Community server RPM repositories exist in {}",
            path.display()
        )));
    }
    matches
        .first()
        .map(|(repo_id, uri)| {
            let values = &values[repo_id];
            let (channel, release) = rpm_identity(uri).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "PostgreSQL RPM URI in {} has an unknown channel or release",
                    path.display()
                ))
            })?;
            Ok(RepositorySource {
                uri: uri.clone(),
                channel: channel.into(),
                family: "el".into(),
                release: release.into(),
                signed_by: values.get("gpgkey").cloned(),
                gpgcheck: values.get("gpgcheck").map(|value| value == "1"),
                repo_id: Some(repo_id.clone()),
            })
        })
        .transpose()
}

fn is_postgresql_apt_uri(value: &str) -> bool {
    [
        "http://apt.postgresql.org/pub/repos/apt",
        "https://apt.postgresql.org/pub/repos/apt",
        "https://mirrors.aliyun.com/postgresql/repos/apt",
        "https://repo.huaweicloud.com/postgresql/repos/apt",
        "https://mirrors.nju.edu.cn/postgresql/repos/apt",
    ]
    .contains(&value.trim_end_matches('/'))
}

fn is_postgresql_rpm_uri(value: &str) -> bool {
    let value = value.trim_end_matches('/');
    (value.starts_with("http://download.postgresql.org/pub/repos/yum/17/redhat/rhel-9-")
        || value.starts_with("https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-9-")
        || ACTIONABLE_ENDPOINTS
            .iter()
            .any(|(_, endpoint)| value.starts_with(&format!("{endpoint}/repos/yum/"))))
        && value.contains("/repos/yum/17/redhat/rhel-9-")
}

fn rpm_identity(value: &str) -> Option<(&'static str, &'static str)> {
    (value.contains("/yum/17/redhat/rhel-9-") || value.contains("/repos/yum/17/redhat/rhel-9-"))
        .then_some((CHANNEL, "9"))
}

fn unique_configured_channel(
    documents: &[ObservedDocument],
) -> Result<Option<String>, AdapterError> {
    let values = documents
        .iter()
        .filter_map(|document| {
            document
                .source
                .as_ref()
                .map(|source| source.channel.clone())
        })
        .collect::<BTreeSet<_>>();
    if values.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "configured PostgreSQL repositories cross product channels".into(),
        ));
    }
    Ok(values.into_iter().next())
}

fn choose_target(manager: Manager, documents: &[ObservedDocument]) -> PathBuf {
    documents
        .iter()
        .find(|document| document.source.is_some())
        .map(|document| document.path.clone())
        .unwrap_or_else(|| match manager {
            Manager::Apt => {
                PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-postgresql.sources")
            }
            Manager::Rpm => PathBuf::from("/etc/yum.repos.d/mirrorswitch-postgresql.repo"),
        })
}

fn is_managed_path(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name == "mirrorswitch-postgresql.sources" || name == "mirrorswitch-postgresql.repo"
    })
}

fn installed_version(runtime: &dyn Runtime) -> Result<Option<String>, AdapterError> {
    if !runtime.command_exists("psql") {
        return Ok(None);
    }
    let output = runtime.run("psql", &["--version".into()])?;
    if !output.status.success() {
        return Ok(None);
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("psql --version is not UTF-8".into()))?;
    Ok(output
        .split_whitespace()
        .map(|token| token.trim_matches([',', ';']))
        .find(|token| version_pair(token).is_some())
        .map(str::to_owned))
}

fn version_pair(value: &str) -> Option<(u64, u64)> {
    let core = value
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()
        .unwrap_or(value);
    let mut parts = core.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn channel_from_version(value: &str) -> Result<&'static str, AdapterError> {
    match version_pair(value) {
        Some((17, _)) => Ok(CHANNEL),
        Some((major, minor)) => Err(AdapterError::Unsupported(format!(
            "installed PostgreSQL {major}.{minor} is outside reviewed PGDG 17 coverage"
        ))),
        None => Err(AdapterError::Unsupported(format!(
            "installed PostgreSQL version {value} is invalid"
        ))),
    }
}

fn platform(context: &SystemContext, manager: Manager) -> Result<Platform, AdapterError> {
    let distribution = context.distribution.as_ref().ok_or_else(|| {
        AdapterError::Unsupported(
            "PostgreSQL packages require a detected Linux distribution".into(),
        )
    })?;
    let architecture = match (manager, context.architecture) {
        (Manager::Apt, Architecture::X86_64) => "amd64",
        (Manager::Apt, Architecture::Arm64) => "arm64",
        (Manager::Rpm, Architecture::X86_64) => "x86_64",
        (Manager::Rpm, Architecture::Arm64) => "aarch64",
    };
    match manager {
        Manager::Apt => {
            let suite = distribution.version_codename.as_deref().ok_or_else(|| {
                AdapterError::Unsupported("PostgreSQL APT requires a distribution codename".into())
            })?;
            let supported = matches!(
                (distribution.id.as_str(), suite),
                ("debian", "bookworm") | ("ubuntu", "jammy" | "noble")
            );
            if !supported {
                return Err(AdapterError::Unsupported(format!(
                    "PostgreSQL 17 APT coverage excludes {} {}",
                    distribution.id, suite
                )));
            }
            Ok(Platform {
                family: distribution.id.clone(),
                release: suite.into(),
                architecture: architecture.into(),
            })
        }
        Manager::Rpm => {
            let release = distribution
                .version_id
                .as_deref()
                .and_then(|value| value.split('.').next())
                .unwrap_or("unknown");
            if !matches!(
                distribution.id.as_str(),
                "rhel" | "rocky" | "almalinux" | "centos"
            ) || release != "9"
            {
                return Err(AdapterError::Unsupported(format!(
                    "PostgreSQL 17 RPM coverage is EL9 only, not {} {}",
                    distribution.id, release
                )));
            }
            Ok(Platform {
                family: "el".into(),
                release: "9".into(),
                architecture: architecture.into(),
            })
        }
    }
}

fn mapped_uri(
    manager: Manager,
    provider: &str,
    endpoint: &str,
    platform: &Platform,
) -> Result<String, AdapterError> {
    match (manager, provider) {
        (Manager::Apt, "aliyun" | "huaweicloud" | "nju")
            if provider != "huaweicloud" || platform.release != "noble" =>
        {
            Ok(format!("{endpoint}/repos/apt"))
        }
        (Manager::Apt, _) => Err(AdapterError::InvalidConfiguration(
            "selected provider lacks the requested PostgreSQL PGDG APT suite".into(),
        )),
        (Manager::Rpm, "aliyun" | "huaweicloud" | "nju") => Ok(format!(
            "{endpoint}/repos/yum/17/redhat/rhel-9-{}",
            platform.architecture
        )),
        (Manager::Rpm, _) => Err(AdapterError::InvalidConfiguration(
            "selected provider has no reviewed PostgreSQL RPM repository".into(),
        )),
    }
}

fn platform_tag(platform: &Platform) -> Result<&'static str, AdapterError> {
    match (platform.family.as_str(), platform.release.as_str()) {
        ("debian", "bookworm") => Ok("12"),
        ("ubuntu", "jammy") => Ok("22.04"),
        ("ubuntu", "noble") => Ok("24.04"),
        ("el", "9") => Ok("rhel9.7"),
        _ => Err(AdapterError::Unsupported(
            "PostgreSQL package tag is unavailable".into(),
        )),
    }
}

fn render_new(manager: Manager, mapped_uri: &str, platform: &Platform) -> String {
    match manager {
        Manager::Apt => format!(
            "{MANAGED_MARKER}\nTypes: deb\nURIs: {mapped_uri}\nSuites: {}-pgdg\nComponents: main\nArchitectures: {}\nSigned-By: {DEFAULT_KEYRING}\n",
            platform.release, platform.architecture
        ),
        Manager::Rpm => {
            let key = if platform.architecture == "aarch64" {
                "PGDG-RPM-GPG-KEY-AARCH64-RHEL"
            } else {
                "PGDG-RPM-GPG-KEY-RHEL"
            };
            format!(
                "{MANAGED_MARKER}\n[mirrorswitch-postgresql]\nname=PostgreSQL 17 PGDG\nbaseurl={mapped_uri}\nenabled=1\ngpgcheck=1\ngpgkey=https://download.postgresql.org/pub/repos/yum/keys/{key}\n"
            )
        }
    }
}

fn rewrite_existing(
    manager: Manager,
    text: &str,
    path: &Path,
    mapped_uri: &str,
    channel: &str,
) -> Result<String, AdapterError> {
    let source = parse_repository(manager, text, path)?.ok_or_else(|| {
        AdapterError::InvalidConfiguration("selected PostgreSQL repository disappeared".into())
    })?;
    if source.channel != channel {
        return Err(AdapterError::Unsupported(
            "PostgreSQL repository channel changed during planning".into(),
        ));
    }
    replace_active_once(manager, text, &source.uri, mapped_uri, path)
}

fn replace_active_once(
    manager: Manager,
    text: &str,
    old: &str,
    new: &str,
    path: &Path,
) -> Result<String, AdapterError> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let active = line.split('#').next().unwrap_or_default();
        let eligible = manager == Manager::Apt
            || active
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("baseurl"));
        if eligible {
            for (index, _) in active.match_indices(old) {
                ranges.push(offset + index..offset + index + old.len());
            }
        }
        offset += line.len();
    }
    if ranges.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PostgreSQL repository URI in {} is missing or duplicated",
            path.display()
        )));
    }
    let range: Range<usize> = ranges.remove(0);
    Ok(format!(
        "{}{}{}",
        &text[..range.start],
        new,
        &text[range.end..]
    ))
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<(String, String), AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "postgresql"
        || selections[0].upstream_id != UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "PostgreSQL packages require exactly one repository selection".into(),
        ));
    }
    let selection = &selections[0];
    let role_url = |role| -> Result<String, AdapterError> {
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if endpoints.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "PostgreSQL package selection needs one HTTPS {role:?} endpoint"
            )));
        }
        normalized_endpoint(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration("PostgreSQL package endpoint is unsafe".into())
        })
    };
    let index = role_url(EndpointRole::Index)?;
    if role_url(EndpointRole::Metadata)? != index || role_url(EndpointRole::Packages)? != index {
        return Err(AdapterError::InvalidConfiguration(
            "PostgreSQL package index, metadata, and package endpoints must match".into(),
        ));
    }
    if !ACTIONABLE_ENDPOINTS
        .iter()
        .any(|(provider, endpoint)| selection.provider_id == *provider && index == *endpoint)
    {
        return Err(AdapterError::InvalidConfiguration(
            "PostgreSQL package provider and endpoint are not reviewed".into(),
        ));
    }
    Ok((selection.provider_id.clone(), index))
}

fn normalized_endpoint(value: &str) -> Option<String> {
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

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "multiple-modern-repositories" => {
                return Err(AdapterError::InvalidConfiguration(
                    "multiple modern PostgreSQL package repositories are active".into(),
                ));
            }
            "coverage-mismatch" => {
                return Err(AdapterError::Unsupported(
                    "PostgreSQL repository distribution, release, or channel does not match the host"
                        .into(),
                ));
            }
            "keyring-missing" => {
                return Err(AdapterError::Unsupported(
                    "PostgreSQL APT keyring is missing; repository security cannot be preserved"
                        .into(),
                ));
            }
            "gpgcheck-disabled" => {
                return Err(AdapterError::Unsupported(
                    "PostgreSQL RPM repository has gpgcheck disabled".into(),
                ));
            }
            "gpgkey-missing" => {
                return Err(AdapterError::Unsupported(
                    "PostgreSQL RPM repository has no GPG key configured".into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "PostgreSQL package target belongs to another MirrorSwitch format".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn verify_apt(runtime: &dyn Runtime, target: &Path) -> Result<String, AdapterError> {
    let target = path_string(target)?;
    let options = [
        format!("Dir::Etc::sourcelist={target}"),
        "Dir::Etc::sourceparts=-".into(),
        "APT::Get::List-Cleanup=0".into(),
    ];
    let mut update = vec!["update".into()];
    for option in &options {
        update.extend(["-o".into(), option.clone()]);
    }
    command_output(runtime.run("apt-get", &update)?, "PostgreSQL APT refresh")?;
    let mut query = Vec::new();
    for option in &options {
        query.extend(["-o".into(), option.clone()]);
    }
    query.extend(["policy".into(), "postgresql-17".into()]);
    command_output(runtime.run("apt-cache", &query)?, "PostgreSQL APT query")
}

fn verify_rpm(
    runtime: &dyn Runtime,
    target: &Path,
    repo_id: Option<&str>,
) -> Result<String, AdapterError> {
    let repo_id = repo_id.unwrap_or("mirrorswitch-postgresql");
    let repository_directory = target.parent().ok_or_else(|| {
        AdapterError::InvalidConfiguration("RPM repository path has no parent".into())
    })?;
    let common = [
        format!("--setopt=reposdir={}", path_string(repository_directory)?),
        "--disablerepo=*".into(),
        format!("--enablerepo={repo_id}"),
        "--refresh".into(),
        "-y".into(),
    ];
    let mut refresh = common.to_vec();
    refresh.extend(["-q".into(), "makecache".into()]);
    command_output(runtime.run("dnf", &refresh)?, "PostgreSQL RPM refresh")?;
    let mut query = common.to_vec();
    query.extend([
        "-q".into(),
        "list".into(),
        "--showduplicates".into(),
        "postgresql17-server".into(),
    ]);
    command_output(runtime.run("dnf", &query)?, "PostgreSQL RPM query")
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

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<&'a ConfigurationDocument, AdapterError> {
    let matches = current
        .documents
        .iter()
        .filter(|document| document.format == format)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PostgreSQL package state must contain one {format} document"
        )));
    }
    Ok(matches[0])
}

fn current_value(current: &CurrentConfiguration, kind: &str) -> Result<String, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some(kind))
        .map(|source| metadata(source, "value").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PostgreSQL package state has ambiguous {kind}"
        )));
    }
    Ok(values[0].clone())
}

fn configured_source(source: &RepositorySource, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
        url: source.uri.clone(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["modern-repository".into()]),
            ("channel".into(), vec![source.channel.clone()]),
            ("family".into(), vec![source.family.clone()]),
            ("release".into(), vec![source.release.clone()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("postgresql-package-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
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

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "PostgreSQL package source is missing {key} metadata"
        ))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PostgreSQL package source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn path_string(path: &Path) -> Result<&str, AdapterError> {
    path.to_str().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("path {} is not UTF-8", path.display()))
    })
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "PostgreSQL package {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "PostgreSQL package configuration {} is not UTF-8",
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
        "{reason}; repository configuration restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
