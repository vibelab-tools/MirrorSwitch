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

const UPSTREAM: &str = "kubernetes--repository-metadata";
const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: Kubernetes package repository v1";
const DEFAULT_KEYRING: &str = "/etc/apt/keyrings/kubernetes-apt-keyring.gpg";
const ACTIONABLE_ENDPOINTS: &[(&str, &str)] = &[
    ("nju", "https://mirrors.nju.edu.cn/kubernetes"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/kubernetes"),
    ("ustc", "https://mirrors.ustc.edu.cn/kubernetes"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct KubernetesPackagesAdapter;

impl Adapter for KubernetesPackagesAdapter {
    fn key(&self) -> &'static str {
        "kubernetes-packages"
    }

    fn tool_id(&self) -> &'static str {
        "kubernetes-packages"
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
        let configured_minor = unique_configured_minor(&documents)?;
        let Some(minor) = installed
            .as_deref()
            .and_then(version_minor)
            .map(|minor| format!("v1.{minor}"))
            .or_else(|| configured_minor.clone())
        else {
            return Ok(None);
        };
        review_minor(&minor)?;
        if let Some(version) = &installed {
            review_installed_minor(version, &minor)?;
        }
        if configured_minor
            .as_deref()
            .is_some_and(|configured| configured != minor)
        {
            return Err(AdapterError::Unsupported(format!(
                "installed Kubernetes {} does not match configured channel {}",
                installed.as_deref().unwrap_or("unknown"),
                configured_minor.as_deref().unwrap_or("unknown")
            )));
        }
        let modern = documents
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        let legacy = documents.iter().filter(|document| document.legacy).count();
        Ok(Some(DetectedTool {
            tool_id: "kubernetes-packages".into(),
            executable: Some(PathBuf::from(manager.command())),
            version: installed.clone().or_else(|| Some(minor.clone())),
            evidence: vec![
                format!("package manager is {}", manager.name()),
                format!("target Kubernetes minor channel is {minor}"),
                format!(
                    "installed Kubernetes tool version is {}",
                    installed.as_deref().unwrap_or("not detected")
                ),
                format!("modern pkgs.k8s.io-style repositories: {modern}"),
                format!("legacy Kubernetes repositories: {legacy}"),
                format!(
                    "repository architecture is {}",
                    architecture_name(context.architecture, manager)
                ),
                "Kubernetes container registries are not package repositories".into(),
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
        if detected.tool_id != "kubernetes-packages" {
            return Err(AdapterError::InvalidConfiguration(
                "Kubernetes package read received another tool's detection result".into(),
            ));
        }
        let manager = manager(runtime)?;
        let observed = read_documents(runtime, manager)?;
        let installed = installed_version(runtime)?;
        let configured_minor = unique_configured_minor(&observed)?;
        let minor = installed
            .as_deref()
            .and_then(version_minor)
            .map(|minor| format!("v1.{minor}"))
            .or(configured_minor)
            .ok_or_else(|| {
                AdapterError::Unsupported(
                    "Kubernetes package minor cannot be inferred from installed tools or repository"
                        .into(),
                )
            })?;
        review_minor(&minor)?;
        if let Some(version) = &installed {
            review_installed_minor(version, &minor)?;
        }
        let effective_version = installed.as_deref().unwrap_or(&minor);
        if detected.version.as_deref() != Some(effective_version) {
            return Err(AdapterError::Conflict(
                "Kubernetes package target version changed after detection".into(),
            ));
        }
        let target = choose_target(manager, &observed);
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut sources = vec![snapshot_source("manager", manager.name())];
        sources.push(snapshot_source("minor", &minor));
        if let Some(version) = &installed {
            sources.push(snapshot_source("installed-version", version));
        }
        let modern_count = observed
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        let legacy_count = observed.iter().filter(|document| document.legacy).count();
        if modern_count > 1 {
            sources.push(policy_source(
                "multiple-modern-repositories",
                Path::new(":repo:"),
            ));
        }
        if legacy_count > 0 {
            sources.push(policy_source("legacy-repository", Path::new(":repo:")));
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
                if source.minor != minor {
                    sources.push(policy_source("minor-mismatch", &document.path));
                }
                match manager {
                    Manager::Apt => {
                        let keyring = source.signed_by.as_deref().ok_or_else(|| {
                            AdapterError::Unsupported(
                                "modern Kubernetes APT source has no explicit Signed-By keyring"
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
                    Manager::Rpm => {}
                }
            }
            if document.path != target && document.exists {
                sources.push(policy_source("related-config-preserved", &document.path));
            }
            documents.push(ConfigurationDocument {
                path: document.path.clone(),
                format: if document.path == target {
                    "kubernetes-package-target".into()
                } else {
                    "kubernetes-package-read-only".into()
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
            tool_id: "kubernetes-packages".into(),
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
        let minor = current_value(current, "minor")?;
        let (deb_arch, rpm_arch) = match context.architecture {
            Architecture::X86_64 => ("amd64", "x86_64"),
            Architecture::Arm64 => ("arm64", "aarch64"),
        };
        Ok(SelectionRequest {
            tool_id: "kubernetes-packages".into(),
            adapter_key: "kubernetes-packages".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("minor".into(), minor),
                    ("deb_arch".into(), deb_arch.into()),
                    ("rpm_arch".into(), rpm_arch.into()),
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
        let endpoint = selected_endpoint(selections)?;
        let manager = Manager::from_name(&current_value(current, "manager")?)?;
        let minor = current_value(current, "minor")?;
        let target = find_document(current, "kubernetes-package-target")?;
        let rendered = if target.contents.is_empty() {
            render_new(manager, &endpoint, &minor)
        } else {
            rewrite_existing(
                manager,
                utf8(&target.path, &target.contents)?,
                &target.path,
                &endpoint,
                &minor,
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
                    "map only the Kubernetes {minor} {} package channel while preserving GPG, pinning, and unrelated repositories",
                    manager.name()
                ),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "kubernetes-packages".into(),
            tool_id: "kubernetes-packages".into(),
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
                    "Kubernetes package transaction contains no known target".into(),
                ));
            }
            let selected = documents
                .iter()
                .find(|document| document.path == target)
                .and_then(|document| document.source.as_ref())
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "Kubernetes package repository is not active after apply".into(),
                    )
                })?;
            let minor_number = selected.minor.trim_start_matches('v');
            let output = match manager {
                Manager::Apt => verify_apt(runtime, &target)?,
                Manager::Rpm => verify_rpm(runtime, &target, selected.repo_id.as_deref())?,
            };
            if !output.contains("kubeadm") || !output.contains(minor_number) {
                return Err(AdapterError::Verification(
                    "system package manager did not expose kubeadm in the selected minor channel"
                        .into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} refreshed and queried kubeadm from Kubernetes {} through {}",
                    manager.name(),
                    selected.minor,
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
                "restored {} Kubernetes package repository files from {}",
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
                "unknown Kubernetes package manager".into(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct RepositorySource {
    uri: String,
    minor: String,
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
    legacy: bool,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Kubernetes package adapter supports Linux only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "Kubernetes package repositories require system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "kubernetes-packages" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "Kubernetes package operation received another tool or scope".into(),
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
            "Kubernetes packages require apt-get/apt-cache or dnf".into(),
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
            PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-kubernetes.sources"),
            &["list", "sources"][..],
        ),
        Manager::Rpm => (
            None,
            PathBuf::from("/etc/yum.repos.d"),
            PathBuf::from("/etc/yum.repos.d/mirrorswitch-kubernetes.repo"),
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
        let (source, legacy) = if exists {
            parse_repository(manager, utf8(&path, &contents)?, &path)?
        } else {
            (None, false)
        };
        documents.push(ObservedDocument {
            path,
            contents,
            exists,
            source,
            legacy,
        });
    }
    Ok(documents)
}

fn parse_repository(
    manager: Manager,
    text: &str,
    path: &Path,
) -> Result<(Option<RepositorySource>, bool), AdapterError> {
    match manager {
        Manager::Apt => parse_apt_repository(text, path),
        Manager::Rpm => parse_rpm_repository(text, path),
    }
}

fn parse_apt_repository(
    text: &str,
    path: &Path,
) -> Result<(Option<RepositorySource>, bool), AdapterError> {
    let mut matches = Vec::new();
    let mut legacy = false;
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or_default().trim();
        if active.is_empty() {
            continue;
        }
        if active.contains("apt.kubernetes.io") || active.contains("packages.cloud.google.com/apt")
        {
            legacy = true;
        }
        for token in active.split_whitespace() {
            if !token.starts_with("https://") || !is_modern_uri(token, "deb") {
                continue;
            }
            matches.push(token.trim_end_matches('/').to_owned());
        }
    }
    matches.sort();
    matches.dedup();
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "multiple Kubernetes APT URIs exist in {}",
            path.display()
        )));
    }
    let source = matches
        .first()
        .map(|uri| {
            Ok(RepositorySource {
                uri: uri.clone(),
                minor: uri_minor(uri)
                    .ok_or_else(|| {
                        AdapterError::InvalidConfiguration(format!(
                            "Kubernetes APT URI in {} has no minor channel",
                            path.display()
                        ))
                    })?
                    .into(),
                signed_by: apt_signed_by(text),
                gpgcheck: None,
                repo_id: None,
            })
        })
        .transpose()?;
    Ok((source, legacy))
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

fn parse_rpm_repository(
    text: &str,
    path: &Path,
) -> Result<(Option<RepositorySource>, bool), AdapterError> {
    let mut section = None::<String>;
    let mut matches = Vec::new();
    let mut legacy = false;
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
        if key.trim().eq_ignore_ascii_case("baseurl") {
            if value.contains("packages.cloud.google.com/yum")
                || value.contains("yum.kubernetes.io")
            {
                legacy = true;
            }
            if value.starts_with("https://") && is_modern_uri(value.trim(), "rpm") {
                matches.push((
                    section.clone(),
                    value.trim().trim_end_matches('/').to_owned(),
                ));
            }
        }
    }
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "multiple Kubernetes RPM repositories exist in {}",
            path.display()
        )));
    }
    let source = matches
        .first()
        .map(|(repo_id, uri)| {
            let section = &values[repo_id];
            Ok(RepositorySource {
                uri: uri.clone(),
                minor: uri_minor(uri)
                    .ok_or_else(|| {
                        AdapterError::InvalidConfiguration(format!(
                            "Kubernetes RPM URI in {} has no minor channel",
                            path.display()
                        ))
                    })?
                    .into(),
                signed_by: section.get("gpgkey").cloned(),
                gpgcheck: section.get("gpgcheck").map(|value| value == "1"),
                repo_id: Some(repo_id.clone()),
            })
        })
        .transpose()?;
    Ok((source, legacy))
}

fn is_modern_uri(value: &str, manager_path: &str) -> bool {
    value.contains("/core:/stable:/v1.")
        && value
            .trim_end_matches('/')
            .ends_with(&format!("/{manager_path}"))
        && (value.starts_with("https://pkgs.k8s.io/")
            || ACTIONABLE_ENDPOINTS
                .iter()
                .any(|(_, endpoint)| value.starts_with(endpoint)))
}

fn uri_minor(value: &str) -> Option<&str> {
    let after = value.split_once("/core:/stable:/")?.1;
    let minor = after.split('/').next()?;
    (minor.starts_with("v1.")
        && minor[3..]
            .chars()
            .all(|character| character.is_ascii_digit()))
    .then_some(minor)
}

fn unique_configured_minor(documents: &[ObservedDocument]) -> Result<Option<String>, AdapterError> {
    let values = documents
        .iter()
        .filter_map(|document| document.source.as_ref().map(|source| source.minor.clone()))
        .collect::<BTreeSet<_>>();
    if values.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "configured Kubernetes repositories cross minor channels".into(),
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
                PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-kubernetes.sources")
            }
            Manager::Rpm => PathBuf::from("/etc/yum.repos.d/mirrorswitch-kubernetes.repo"),
        })
}

fn is_managed_path(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name == "mirrorswitch-kubernetes.sources" || name == "mirrorswitch-kubernetes.repo"
    })
}

fn installed_version(runtime: &dyn Runtime) -> Result<Option<String>, AdapterError> {
    if runtime.command_exists("kubeadm") {
        return optional_command_version(runtime, "kubeadm", &["version", "-o", "short"]);
    }
    if runtime.command_exists("kubelet") {
        return optional_command_version(runtime, "kubelet", &["--version"]);
    }
    Ok(None)
}

fn optional_command_version(
    runtime: &dyn Runtime,
    command: &str,
    arguments: &[&str],
) -> Result<Option<String>, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = runtime.run(command, &arguments)?;
    if !output.status.success() {
        return Ok(None);
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{command} version is not UTF-8")))?;
    Ok(output
        .split_whitespace()
        .find(|token| version_minor(token).is_some())
        .map(str::to_owned))
}

fn version_minor(value: &str) -> Option<u64> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let core = value.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    (parts.next()? == "1")
        .then(|| parts.next()?.parse().ok())
        .flatten()
}

fn review_minor(value: &str) -> Result<(), AdapterError> {
    let minor = value
        .strip_prefix("v1.")
        .and_then(|minor| minor.parse::<u64>().ok());
    if !matches!(minor, Some(35..=37)) {
        return Err(AdapterError::Unsupported(format!(
            "Kubernetes package channel {value} is outside maintained v1.35 through v1.37"
        )));
    }
    Ok(())
}

fn review_installed_minor(version: &str, minor: &str) -> Result<(), AdapterError> {
    let installed = version_minor(version).ok_or_else(|| {
        AdapterError::Unsupported(format!("installed Kubernetes version {version} is invalid"))
    })?;
    if minor != format!("v1.{installed}") {
        return Err(AdapterError::Unsupported(format!(
            "installed Kubernetes {version} does not match configured channel {minor}"
        )));
    }
    Ok(())
}

fn architecture_name(architecture: Architecture, manager: Manager) -> &'static str {
    match (architecture, manager) {
        (Architecture::X86_64, Manager::Apt) => "amd64",
        (Architecture::Arm64, Manager::Apt) => "arm64",
        (Architecture::X86_64, Manager::Rpm) => "x86_64",
        (Architecture::Arm64, Manager::Rpm) => "aarch64",
    }
}

fn render_new(manager: Manager, endpoint: &str, minor: &str) -> String {
    match manager {
        Manager::Apt => format!(
            "{MANAGED_MARKER}\nTypes: deb\nURIs: {endpoint}/core:/stable:/{minor}/deb/\nSuites: /\nSigned-By: {DEFAULT_KEYRING}\n"
        ),
        Manager::Rpm => format!(
            "{MANAGED_MARKER}\n[mirrorswitch-kubernetes]\nname=Kubernetes {minor}\nbaseurl={endpoint}/core:/stable:/{minor}/rpm/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey={endpoint}/core:/stable:/{minor}/rpm/repodata/repomd.xml.key\n"
        ),
    }
}

fn rewrite_existing(
    manager: Manager,
    text: &str,
    path: &Path,
    endpoint: &str,
    minor: &str,
) -> Result<String, AdapterError> {
    let (source, _) = parse_repository(manager, text, path)?;
    let source = source.ok_or_else(|| {
        AdapterError::InvalidConfiguration("selected Kubernetes repository disappeared".into())
    })?;
    if source.minor != minor {
        return Err(AdapterError::Unsupported(
            "Kubernetes repository minor changed during planning".into(),
        ));
    }
    let manager_path = if manager == Manager::Apt {
        "deb"
    } else {
        "rpm"
    };
    let replacement = format!("{endpoint}/core:/stable:/{minor}/{manager_path}");
    replace_active_once(manager, text, &source.uri, &replacement, path)
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
            "Kubernetes repository URI in {} is missing or duplicated",
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

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "kubernetes-packages"
        || selections[0].upstream_id != UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Kubernetes packages require exactly one repository selection".into(),
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
                "Kubernetes package selection needs one HTTPS {role:?} endpoint"
            )));
        }
        normalized_endpoint(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration("Kubernetes package endpoint is unsafe".into())
        })
    };
    let index = role_url(EndpointRole::Index)?;
    if role_url(EndpointRole::Metadata)? != index || role_url(EndpointRole::Packages)? != index {
        return Err(AdapterError::InvalidConfiguration(
            "Kubernetes package index, metadata, and package endpoints must match".into(),
        ));
    }
    if !ACTIONABLE_ENDPOINTS
        .iter()
        .any(|(provider, endpoint)| selection.provider_id == *provider && index == *endpoint)
    {
        return Err(AdapterError::InvalidConfiguration(
            "Kubernetes package provider and endpoint are not reviewed".into(),
        ));
    }
    Ok(index)
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
            "legacy-repository" => {
                return Err(AdapterError::Unsupported(
                    "legacy apt.kubernetes.io/YUM repository is not rewritten across repository generations"
                        .into(),
                ));
            }
            "multiple-modern-repositories" => {
                return Err(AdapterError::InvalidConfiguration(
                    "multiple modern Kubernetes package repositories are active".into(),
                ));
            }
            "minor-mismatch" => {
                return Err(AdapterError::Unsupported(
                    "installed Kubernetes version and repository minor do not match".into(),
                ));
            }
            "keyring-missing" => {
                return Err(AdapterError::Unsupported(
                    "Kubernetes APT keyring is missing; repository security cannot be preserved"
                        .into(),
                ));
            }
            "gpgcheck-disabled" => {
                return Err(AdapterError::Unsupported(
                    "Kubernetes RPM repository has gpgcheck disabled".into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Kubernetes package target belongs to another MirrorSwitch format".into(),
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
    command_output(runtime.run("apt-get", &update)?, "Kubernetes APT refresh")?;
    let mut query = Vec::new();
    for option in &options {
        query.extend(["-o".into(), option.clone()]);
    }
    query.extend(["policy".into(), "kubeadm".into()]);
    command_output(runtime.run("apt-cache", &query)?, "Kubernetes APT query")
}

fn verify_rpm(
    runtime: &dyn Runtime,
    target: &Path,
    repo_id: Option<&str>,
) -> Result<String, AdapterError> {
    let repo_id = repo_id.unwrap_or("mirrorswitch-kubernetes");
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
    command_output(runtime.run("dnf", &refresh)?, "Kubernetes RPM refresh")?;
    let mut query = common.to_vec();
    query.extend([
        "-q".into(),
        "list".into(),
        "--showduplicates".into(),
        "kubeadm".into(),
    ]);
    command_output(runtime.run("dnf", &query)?, "Kubernetes RPM query")
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
            "Kubernetes package state must contain one {format} document"
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
            "Kubernetes package state has ambiguous {kind}"
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
            ("minor".into(), vec![source.minor.clone()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("kubernetes-package-snapshot:{value}"),
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
            "Kubernetes package source is missing {key} metadata"
        ))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Kubernetes package source has ambiguous {key} metadata"
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
            "Kubernetes package {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Kubernetes package configuration {} is not UTF-8",
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
