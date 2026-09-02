use std::{
    collections::{BTreeMap, BTreeSet},
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

const UPSTREAM: &str = "ros1-packages--repository-metadata";
const COVERAGE_VERSION: &str = "noetic-focal-final";
const MANAGED_MARKER: &str = "# Managed by MirrorSwitch: ROS 1 package repository v1";
const DEFAULT_KEYRING: &str = "/usr/share/keyrings/ros-archive-keyring.gpg";
const PARSE_ROOTS: &[&str] = &[
    "https://packages.ros.org/ros",
    "https://mirrors.aliyun.com/ros",
    "https://repo.huaweicloud.com/ros",
    "https://mirrors.nju.edu.cn/ros",
    "https://mirror.sjtu.edu.cn/ros",
    "https://mirrors.tuna.tsinghua.edu.cn/ros",
    "https://mirrors.ustc.edu.cn/ros",
];
const ACTIONABLE: &[(&str, &str)] = &[
    ("huaweicloud", "https://repo.huaweicloud.com/ros"),
    ("nju", "https://mirrors.nju.edu.cn/ros"),
    ("sjtug", "https://mirror.sjtu.edu.cn/ros"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/ros"),
    ("ustc", "https://mirrors.ustc.edu.cn/ros"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct RosAdapter;

impl Adapter for RosAdapter {
    fn key(&self) -> &'static str {
        "ros"
    }

    fn tool_id(&self) -> &'static str {
        "ros"
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
        require_apt(runtime)?;
        let platform = platform(context)?;
        let documents = read_documents(runtime)?;
        let configured = documents
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        let ros_distribution =
            ros_distribution(runtime)?.or_else(|| (configured > 0).then(|| "noetic".into()));
        let Some(ros_distribution) = ros_distribution else {
            return Ok(None);
        };
        if ros_distribution != "noetic" {
            return Err(AdapterError::Unsupported(format!(
                "ROS 1 {ros_distribution} is outside final Noetic/Focal mirror coverage"
            )));
        }
        Ok(Some(DetectedTool {
            tool_id: "ros".into(),
            executable: Some(PathBuf::from("apt-get")),
            version: Some(ros_distribution.clone()),
            evidence: vec![
                format!(
                    "Linux distribution is {}/{}",
                    platform.distribution, platform.suite
                ),
                format!("ROS 1 distribution is {ros_distribution}"),
                format!("APT architecture is {}", platform.architecture),
                format!("configured ROS 1 repository files: {configured}"),
                "ROS 1 Noetic reached EOL; only the final Focal snapshot is supported".into(),
                "ROS 2 and rosdep metadata are separate configuration surfaces".into(),
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
        require_apt(runtime)?;
        if detected.tool_id != "ros" || detected.version.as_deref() != Some("noetic") {
            return Err(AdapterError::InvalidConfiguration(
                "ROS 1 read received another tool or distribution".into(),
            ));
        }
        let platform = platform(context)?;
        let documents = read_documents(runtime)?;
        let target = choose_target(&documents);
        let source_count = documents
            .iter()
            .filter(|document| document.source.is_some())
            .count();
        let mut files = Vec::new();
        let mut configs = Vec::new();
        let mut sources = vec![snapshot_source("ros-distribution", "noetic")];
        sources.push(snapshot_source("suite", &platform.suite));
        sources.push(snapshot_source("architecture", &platform.architecture));
        if source_count > 1 {
            sources.push(policy_source("multiple-source-files", Path::new(":repo:")));
        }
        for document in documents {
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
                if source.suite != platform.suite || source.component != "main" {
                    sources.push(policy_source("coverage-mismatch", &document.path));
                }
                let keyring = source.signed_by.as_deref().ok_or_else(|| {
                    AdapterError::Unsupported(
                        "ROS 1 APT source has no explicit Signed-By keyring".into(),
                    )
                })?;
                let keyring = PathBuf::from(keyring);
                validate_path(&keyring, "keyring")?;
                if runtime.read(&keyring)?.is_none() {
                    sources.push(policy_source("keyring-missing", &keyring));
                } else {
                    sources.push(policy_source("keyring-preserved", &keyring));
                }
            }
            if document.path != target && document.exists {
                sources.push(policy_source("other-apt-source-preserved", &document.path));
            }
            configs.push(ConfigurationDocument {
                path: document.path.clone(),
                format: if document.path == target {
                    "ros1-package-target".into()
                } else {
                    "ros1-package-read-only".into()
                },
                contents: document.contents,
            });
        }
        if source_count == 0 {
            let keyring = PathBuf::from(DEFAULT_KEYRING);
            if runtime.read(&keyring)?.is_none() {
                sources.push(policy_source("keyring-missing", &keyring));
            } else {
                sources.push(policy_source("keyring-preserved", &keyring));
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "ros".into(),
            scope,
            files,
            sources,
            documents: configs,
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
        Ok(SelectionRequest {
            tool_id: "ros".into(),
            adapter_key: "ros".into(),
            context: context.clone(),
            tool_version: Some("noetic".into()),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::from([(UPSTREAM.into(), COVERAGE_VERSION.into())]),
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
        let target = find_document(current, "ros1-package-target")?;
        let rendered = if target.contents.is_empty() {
            render_new(&endpoint)
        } else {
            rewrite_existing(
                utf8(&target.path, &target.contents)?,
                &target.path,
                &endpoint,
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
                summary: "map only packages.ros.org/ros/ubuntu Noetic/Focal while preserving keyring and unrelated APT sources".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "ros".into(),
            tool_id: "ros".into(),
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
            let documents = read_documents(runtime)?;
            let target = choose_target(&documents);
            if !receipt
                .changed_targets
                .contains(&rooted(&context.root, &target))
            {
                return Err(AdapterError::Verification(
                    "ROS 1 transaction contains no known target".into(),
                ));
            }
            let source = documents
                .iter()
                .find(|document| document.path == target)
                .and_then(|document| document.source.as_ref())
                .ok_or_else(|| {
                    AdapterError::Verification("ROS 1 repository is not active after apply".into())
                })?;
            let output = verify_apt(runtime, &target)?;
            if !output.contains("ros-noetic-ros-base") || !output.contains("1.5.0") {
                return Err(AdapterError::Verification(
                    "APT did not expose final ros-noetic-ros-base".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "APT refreshed and queried ROS 1 Noetic/Focal through {}",
                    source.uri
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
                "restored {} ROS 1 repository files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

struct Platform {
    distribution: String,
    suite: String,
    architecture: String,
}

struct RepositorySource {
    uri: String,
    suite: String,
    component: String,
    signed_by: Option<String>,
}

struct ObservedDocument {
    path: PathBuf,
    contents: Vec<u8>,
    exists: bool,
    source: Option<RepositorySource>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "ROS 1 adapter supports Linux only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "ROS 1 APT repository requires system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "ros" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 1 operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn require_apt(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    if !runtime.command_exists("apt-get") || !runtime.command_exists("apt-cache") {
        return Err(AdapterError::Unsupported(
            "ROS 1 repository requires apt-get and apt-cache".into(),
        ));
    }
    Ok(())
}

fn platform(context: &SystemContext) -> Result<Platform, AdapterError> {
    let distribution = context.distribution.as_ref().ok_or_else(|| {
        AdapterError::Unsupported("ROS 1 requires a detected distribution".into())
    })?;
    if distribution.id != "ubuntu" || distribution.version_codename.as_deref() != Some("focal") {
        return Err(AdapterError::Unsupported(format!(
            "ROS 1 final mirror coverage is Ubuntu Focal only, not {} {}",
            distribution.id,
            distribution
                .version_codename
                .as_deref()
                .unwrap_or("unknown")
        )));
    }
    Ok(Platform {
        distribution: "ubuntu".into(),
        suite: "focal".into(),
        architecture: match context.architecture {
            Architecture::X86_64 => "amd64".into(),
            Architecture::Arm64 => "arm64".into(),
        },
    })
}

fn read_documents(runtime: &dyn Runtime) -> Result<Vec<ObservedDocument>, AdapterError> {
    let directory = PathBuf::from("/etc/apt/sources.list.d");
    let target = PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-ros1.sources");
    let mut paths = BTreeSet::from([PathBuf::from("/etc/apt/sources.list"), target]);
    for path in runtime.list_files(&directory)? {
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "list" | "sources"))
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
            parse_source(utf8(&path, &contents)?, &path)?
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

fn parse_source(text: &str, path: &Path) -> Result<Option<RepositorySource>, AdapterError> {
    let mut uri = None;
    let mut suite = None;
    let mut component = None;
    let mut signed_by = None;
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or_default().trim();
        if let Some(value) = active.strip_prefix("Signed-By:") {
            signed_by = Some(value.trim().into());
        }
        if let Some(value) = active.strip_prefix("Suites:") {
            suite = value.split_whitespace().next().map(str::to_owned);
        }
        if let Some(value) = active.strip_prefix("Components:") {
            component = value.split_whitespace().next().map(str::to_owned);
        }
        let fields = active.split_whitespace().collect::<Vec<_>>();
        for (index, token) in fields.iter().enumerate() {
            if !is_ros_uri(token) {
                continue;
            }
            if uri.replace(token.trim_end_matches('/').into()).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "multiple ROS 1 URIs exist in {}",
                    path.display()
                )));
            }
            if active.starts_with("deb ") {
                if let Some(option) = fields.iter().find(|field| field.contains("signed-by="))
                    && let Some((_, value)) = option.split_once("signed-by=")
                {
                    signed_by = Some(value.trim_end_matches(']').into());
                }
                suite = fields.get(index + 1).map(|value| (*value).into());
                component = fields.get(index + 2).map(|value| (*value).into());
            }
        }
    }
    let Some(uri) = uri else {
        return Ok(None);
    };
    Ok(Some(RepositorySource {
        uri,
        suite: suite.ok_or_else(|| {
            AdapterError::InvalidConfiguration("ROS 1 source has no suite".into())
        })?,
        component: component.ok_or_else(|| {
            AdapterError::InvalidConfiguration("ROS 1 source has no component".into())
        })?,
        signed_by,
    }))
}

fn is_ros_uri(value: &str) -> bool {
    let value = value.trim_end_matches('/');
    PARSE_ROOTS
        .iter()
        .any(|root| value == format!("{root}/ubuntu"))
}

fn choose_target(documents: &[ObservedDocument]) -> PathBuf {
    documents
        .iter()
        .find(|document| document.source.is_some())
        .map(|document| document.path.clone())
        .unwrap_or_else(|| PathBuf::from("/etc/apt/sources.list.d/mirrorswitch-ros1.sources"))
}

fn is_managed_path(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "mirrorswitch-ros1.sources")
}

fn ros_distribution(runtime: &dyn Runtime) -> Result<Option<String>, AdapterError> {
    if let Some(value) = runtime
        .environment_variable("ROS_DISTRO")
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(Some(value.to_ascii_lowercase()));
    }
    if runtime.command_exists("rosversion") {
        let output = runtime.run("rosversion", &["-d".into()])?;
        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map(|value| Some(value.trim().to_ascii_lowercase()))
                .map_err(|_| AdapterError::Runtime("rosversion output is not UTF-8".into()));
        }
    }
    Ok(None)
}

fn render_new(endpoint: &str) -> String {
    format!(
        "{MANAGED_MARKER}\nTypes: deb\nURIs: {endpoint}/ubuntu\nSuites: focal\nComponents: main\nArchitectures: amd64 arm64\nSigned-By: {DEFAULT_KEYRING}\n"
    )
}

fn rewrite_existing(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    let source = parse_source(text, path)?.ok_or_else(|| {
        AdapterError::InvalidConfiguration("selected ROS 1 source disappeared".into())
    })?;
    let replacement = format!("{endpoint}/ubuntu");
    let mut output = String::with_capacity(text.len());
    let mut replacements = 0;
    for line in text.split_inclusive('\n') {
        let active = line.split('#').next().unwrap_or_default();
        let eligible =
            active.trim_start().starts_with("deb ") || active.trim_start().starts_with("URIs:");
        if eligible {
            replacements += active.matches(&source.uri).count();
            output.push_str(&line.replacen(&source.uri, &replacement, usize::MAX));
        } else {
            output.push_str(line);
        }
    }
    if replacements == 0 {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 1 source URI disappeared".into(),
        ));
    }
    Ok(output)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "ros"
        || selections[0].upstream_id != UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 1 requires one package repository selection".into(),
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
                "ROS 1 selection needs one HTTPS {role:?} endpoint"
            )));
        }
        normalized_endpoint(&endpoints[0].url)
            .ok_or_else(|| AdapterError::InvalidConfiguration("ROS 1 endpoint is unsafe".into()))
    };
    let index = role_url(EndpointRole::Index)?;
    if role_url(EndpointRole::Metadata)? != index || role_url(EndpointRole::Packages)? != index {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 1 index, metadata, and package endpoints differ".into(),
        ));
    }
    if !ACTIONABLE
        .iter()
        .any(|(provider, endpoint)| selection.provider_id == *provider && index == *endpoint)
    {
        return Err(AdapterError::InvalidConfiguration(
            "ROS 1 provider and endpoint are not reviewed".into(),
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
            "multiple-source-files" => {
                return Err(AdapterError::InvalidConfiguration(
                    "multiple ROS 1 source files are active".into(),
                ));
            }
            "managed-target-conflict" => {
                return Err(AdapterError::Unsupported(
                    "managed ROS 1 source target contains user data".into(),
                ));
            }
            "coverage-mismatch" => {
                return Err(AdapterError::Unsupported(
                    "ROS 1 mirror coverage is Noetic/Focal main only".into(),
                ));
            }
            "keyring-missing" => {
                return Err(AdapterError::Unsupported("ROS 1 keyring is missing".into()));
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
    command_output(runtime.run("apt-get", &update)?, "ROS 1 APT refresh")?;
    let mut query = Vec::new();
    for option in &options {
        query.extend(["-o".into(), option.clone()]);
    }
    query.extend(["policy".into(), "ros-noetic-ros-base".into()]);
    command_output(runtime.run("apt-cache", &query)?, "ROS 1 APT query")
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
    current
        .documents
        .iter()
        .find(|document| document.format == format)
        .ok_or_else(|| AdapterError::InvalidConfiguration("ROS 1 target is missing".into()))
}

fn configured_source(source: &RepositorySource, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
        url: source.uri.clone(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["ros1-repository".into()]),
            ("suite".into(), vec![source.suite.clone()]),
            ("component".into(), vec![source.component.clone()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("ros1-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
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
        AdapterError::InvalidConfiguration(format!("ROS 1 source lacks {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "ROS 1 source has ambiguous {key} metadata"
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
            "ROS 1 {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!("ROS 1 source {} is not UTF-8", path.display()))
    })
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{reason}; ROS 1 source restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
