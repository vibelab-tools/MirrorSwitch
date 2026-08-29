use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

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

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const DISTRIBUTION_UPSTREAM: &str = "gradle-distributions--release-artifacts";
const MANAGED_MARKER: &str = "// Managed by MirrorSwitch: Gradle dependency mirror v1";
const MANAGED_FILE: &str = "zz-mirrorswitch.init.gradle";
const VERIFY_PROJECT_MARKER: &str = "// Managed by MirrorSwitch: Gradle verification project v1";
const VERIFY_SETTINGS: &str = "rootProject.name = \"mirrorswitch-verification\"\n";
const VERIFY_TASK: &str = "mirrorSwitchVerify";
const VERIFY_MARKER: &str = "MIRRORSWITCH_GRADLE_OK";
const MAVEN_MIRRORS: &[&str] = &[
    "https://maven.aliyun.com/repository/public",
    "https://repo.huaweicloud.com/repository/maven",
    "https://repo.nju.edu.cn/maven",
];
const DISTRIBUTION_MIRRORS: &[&str] = &[
    "https://repo.huaweicloud.com/gradle",
    "https://mirrors.nju.edu.cn/gradle",
];
const OFFICIAL_DISTRIBUTION: &str = "https://services.gradle.org/distributions";

#[derive(Clone, Copy, Debug, Default)]
pub struct GradleAdapter;

impl Adapter for GradleAdapter {
    fn key(&self) -> &'static str {
        "gradle"
    }

    fn tool_id(&self) -> &'static str {
        "gradle"
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
        let project = project_dir(runtime)?;
        let command = gradle_command(runtime, project.as_deref());
        let layout = config_layout(runtime, project.as_deref())?;
        if command.is_none() && layout.wrapper.is_none() {
            return Ok(None);
        }

        let mut evidence = vec![format!(
            "Gradle user home is {}",
            layout.gradle_user_home.display()
        )];
        let version = if let Some(command) = command.as_deref() {
            let output = run_gradle(runtime, project.as_deref(), command, &["--version"])?;
            let version = gradle_version(&output)?;
            reviewed_version(&version)?;
            evidence.extend(
                output
                    .lines()
                    .map(str::trim)
                    .filter(|line| line.starts_with("Launcher JVM:") || line.starts_with("JVM:"))
                    .map(str::to_owned),
            );
            version
        } else {
            let wrapper = layout.wrapper.as_ref().expect("checked wrapper");
            let contents = runtime.read(wrapper)?.ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Gradle wrapper properties disappeared during detection".into(),
                )
            })?;
            let wrapper = parse_wrapper(wrapper, utf8(wrapper, &contents)?)?;
            reviewed_version(&wrapper.version)?;
            format!("Gradle {} (wrapper configuration)", wrapper.version)
        };

        evidence.push(format!("effective Gradle version is {version}"));
        if let Some(wrapper) = &layout.wrapper {
            let contents = runtime.read(wrapper)?.ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Gradle wrapper properties disappeared during detection".into(),
                )
            })?;
            let wrapper_config = parse_wrapper(wrapper, utf8(wrapper, &contents)?)?;
            reviewed_version(&wrapper_config.version)?;
            evidence.push(format!(
                "wrapper {} requests {} with SHA-256 {}",
                wrapper.display(),
                wrapper_config.file_name,
                if wrapper_config.checksum.is_some() {
                    "configured"
                } else {
                    "missing"
                }
            ));
        }
        evidence.push(format!(
            "found {} user or installation init scripts",
            layout.init_scripts.len()
        ));
        evidence.push(format!(
            "found {} project repository definition files",
            layout.project_files.len()
        ));
        Ok(Some(DetectedTool {
            tool_id: "gradle".into(),
            executable: command.map(PathBuf::from),
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
        reviewed_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Gradle version is missing".into())
        })?)?;
        let project = project_dir(runtime)?;
        let layout = config_layout(runtime, project.as_deref())?;
        if scope == ConfigurationScope::Project {
            if project.is_none() || layout.wrapper.is_none() {
                return Err(AdapterError::Unsupported(
                    "Gradle project scope requires gradle/wrapper/gradle-wrapper.properties".into(),
                ));
            }
            let project = project.as_deref().expect("validated project");
            if gradle_wrapper_command(runtime, project).is_none() {
                return Err(AdapterError::Unsupported(
                    "Gradle project scope requires an executable gradlew wrapper".into(),
                ));
            }
        }

        let selected = match scope {
            ConfigurationScope::User => layout.managed_init.clone(),
            ConfigurationScope::Project => layout.wrapper.clone().expect("validated wrapper"),
            _ => unreachable!("validated Gradle scope"),
        };
        let mut paths = vec![
            (layout.managed_init.clone(), DocumentKind::ManagedInit),
            (
                layout.verification_settings.clone(),
                DocumentKind::VerificationSettings,
            ),
        ];
        paths.extend(
            layout
                .init_scripts
                .iter()
                .filter(|path| **path != layout.managed_init)
                .cloned()
                .map(|path| (path, DocumentKind::InitScript)),
        );
        if let Some(wrapper) = layout.wrapper.clone() {
            paths.push((wrapper, DocumentKind::Wrapper));
        }
        paths.extend(
            layout
                .project_files
                .iter()
                .cloned()
                .map(|path| (path, DocumentKind::ProjectBuild)),
        );
        paths.extend(
            layout
                .properties_files
                .iter()
                .cloned()
                .map(|path| (path, DocumentKind::Properties)),
        );

        let mut sources = environment_sources(runtime);
        let mut files = Vec::new();
        let mut documents = Vec::new();
        let mut seen = BTreeSet::new();
        for (path, kind) in paths {
            validate_path(&path)?;
            if !seen.insert(path.clone()) {
                continue;
            }
            let observed = runtime.read(&path)?;
            let exists = observed.is_some();
            let contents = observed.unwrap_or_default();
            if exists {
                files.push(path.clone());
                let text = utf8(&path, &contents)?;
                match kind {
                    DocumentKind::ManagedInit => {
                        sources.push(managed_init_source(text, &path)?);
                    }
                    DocumentKind::InitScript => {
                        sources.push(policy_source("init-script", &path));
                    }
                    DocumentKind::Wrapper => {
                        sources.push(wrapper_source(parse_wrapper(&path, text)?, &path));
                    }
                    DocumentKind::ProjectBuild => {
                        sources.extend(project_repository_sources(text, &path));
                    }
                    DocumentKind::Properties => {
                        if wrapper_credentials_configured(text)? {
                            sources.push(policy_source("wrapper-credentials", &path));
                        }
                    }
                    DocumentKind::VerificationSettings => {
                        if text != render_verification_settings() {
                            sources.push(policy_source("verification-project-conflict", &path));
                        }
                    }
                }
            }
            documents.push(ConfigurationDocument {
                path: path.clone(),
                format: if path == selected {
                    match kind {
                        DocumentKind::ManagedInit => "gradle-selected-user-init",
                        DocumentKind::Wrapper => "gradle-selected-wrapper",
                        _ => unreachable!("selected Gradle document kind"),
                    }
                } else {
                    match kind {
                        DocumentKind::ManagedInit | DocumentKind::InitScript => {
                            "gradle-init-read-only"
                        }
                        DocumentKind::Wrapper => "gradle-wrapper-read-only",
                        DocumentKind::ProjectBuild => "gradle-project-read-only",
                        DocumentKind::Properties => "gradle-properties-read-only",
                        DocumentKind::VerificationSettings => "gradle-verification-project",
                    }
                }
                .into(),
                contents,
            });
        }
        Ok(CurrentConfiguration {
            tool_id: "gradle".into(),
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
        let (upstream, roles, modes, probe_contexts) = match current.scope {
            ConfigurationScope::User => (
                MAVEN_UPSTREAM,
                vec![EndpointRole::Index, EndpointRole::Artifacts],
                vec![DeliveryMode::Proxy],
                BTreeMap::new(),
            ),
            ConfigurationScope::Project => {
                let wrapper = current_wrapper(current)?;
                let checksum = wrapper.checksum.clone().ok_or_else(|| {
                    AdapterError::Unsupported(
                        "Gradle wrapper distributionSha256Sum is required before changing its URL"
                            .into(),
                    )
                })?;
                let contexts = BTreeMap::from([(
                    DISTRIBUTION_UPSTREAM.into(),
                    vec![BTreeMap::from([
                        ("distribution_file".into(), wrapper.file_name),
                        ("distribution_checksum".into(), checksum),
                    ])],
                )]);
                (
                    DISTRIBUTION_UPSTREAM,
                    vec![EndpointRole::Releases],
                    vec![DeliveryMode::Mirror],
                    contexts,
                )
            }
            _ => unreachable!("validated Gradle scope"),
        };
        Ok(SelectionRequest {
            tool_id: "gradle".into(),
            adapter_key: "gradle".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![upstream.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts,
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: roles,
            allowed_delivery_modes: modes,
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
        let document = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("gradle-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected Gradle document is missing".into())
            })?;
        let new_contents = match current.scope {
            ConfigurationScope::User => {
                let endpoint = selected_maven_endpoint(selections)?;
                render_init_script(endpoint).into_bytes()
            }
            ConfigurationScope::Project => {
                let endpoint = selected_distribution_endpoint(selections)?;
                let wrapper =
                    parse_wrapper(&document.path, utf8(&document.path, &document.contents)?)?;
                validate_wrapper_for_change(current, &wrapper)?;
                rewrite_wrapper(
                    utf8(&document.path, &document.contents)?,
                    &format!("{}/{}", endpoint.trim_end_matches('/'), wrapper.file_name),
                )?
                .into_bytes()
            }
            _ => unreachable!("validated Gradle scope"),
        };
        let mut changes = Vec::new();
        if new_contents != document.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: current
                    .files
                    .contains(&document.path)
                    .then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: match current.scope {
                    ConfigurationScope::User => "install one user init script that rewrites only existing Maven Central repository URLs in place while preserving repository objects, order, content filters, exclusiveContent and all private repositories".into(),
                    ConfigurationScope::Project => "replace only the reviewed Gradle Wrapper distribution URL while preserving distribution version, archive flavor, checksum and every other wrapper property".into(),
                    _ => unreachable!("validated Gradle scope"),
                },
            });
        }
        if current.scope == ConfigurationScope::User {
            let verification = current
                .documents
                .iter()
                .find(|document| document.format == "gradle-verification-project")
                .ok_or_else(|| {
                    AdapterError::InvalidConfiguration(
                        "Gradle verification project document is missing".into(),
                    )
                })?;
            let contents = render_verification_settings().into_bytes();
            if contents != verification.contents {
                changes.push(PlannedFileChange {
                    target: rooted(&context.root, &verification.path),
                    old_contents: current
                        .files
                        .contains(&verification.path)
                        .then(|| verification.contents.clone()),
                    old_mode: None,
                    new_contents: contents,
                    new_mode: None,
                    summary: "create an isolated user-owned Gradle project used only for post-apply dependency resolution".into(),
                });
            }
        }
        Ok(ChangePlan {
            adapter_key: "gradle".into(),
            tool_id: "gradle".into(),
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
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let result = (|| {
            let project = project_dir(runtime)?;
            let layout = config_layout(runtime, project.as_deref())?;
            let managed_target = rooted(&context.root, &layout.managed_init);
            let verification_target = rooted(&context.root, &layout.verification_settings);
            let wrapper_target = layout
                .wrapper
                .as_ref()
                .map(|path| rooted(&context.root, path));
            let changed_user = receipt.changed_targets.contains(&managed_target)
                || receipt.changed_targets.contains(&verification_target);
            let changed_wrapper = wrapper_target
                .as_ref()
                .is_some_and(|target| receipt.changed_targets.contains(target));
            if !changed_user && !changed_wrapper {
                return Err(AdapterError::Verification(
                    "Gradle transaction receipt does not contain a known scope target".into(),
                ));
            }
            let mut summaries = Vec::new();
            if changed_user {
                let contents = runtime.read(&layout.managed_init)?.ok_or_else(|| {
                    AdapterError::Verification("managed Gradle init script disappeared".into())
                })?;
                let source = managed_init_source(
                    utf8(&layout.managed_init, &contents)?,
                    &layout.managed_init,
                )?;
                if metadata(&source, "kind")? != "dependency-default"
                    || !is_maven_mirror(&source.url)
                {
                    return Err(AdapterError::Verification(
                        "managed Gradle init script has no reviewed Maven endpoint".into(),
                    ));
                }
                let verification =
                    runtime
                        .read(&layout.verification_settings)?
                        .ok_or_else(|| {
                            AdapterError::Verification(
                                "managed Gradle verification project disappeared".into(),
                            )
                        })?;
                if utf8(&layout.verification_settings, &verification)?
                    != render_verification_settings()
                {
                    return Err(AdapterError::Verification(
                        "managed Gradle verification project is not canonical".into(),
                    ));
                }
                let command = gradle_command(runtime, project.as_deref()).ok_or_else(|| {
                    AdapterError::Verification("Gradle command disappeared".into())
                })?;
                let verification_dir = layout.verification_settings.parent().ok_or_else(|| {
                    AdapterError::Verification(
                        "managed Gradle verification project has no parent directory".into(),
                    )
                })?;
                let output = run_gradle(
                    runtime,
                    Some(verification_dir),
                    &command,
                    &[
                        "-Dmirrorswitch.verify=true",
                        "--no-daemon",
                        "--refresh-dependencies",
                        "--console=plain",
                        VERIFY_TASK,
                    ],
                )?;
                if !output.contains(VERIFY_MARKER)
                    || !output.contains("commons-lang3-3.14.0.jar")
                    || !output.contains(source.url.trim_end_matches('/'))
                {
                    return Err(AdapterError::Verification(
                        "Gradle did not resolve the verification artifact through the managed Maven endpoint"
                            .into(),
                    ));
                }
                summaries.push(format!("dependency resolution used {}", source.url));
            }
            if changed_wrapper {
                let wrapper_path = layout.wrapper.as_ref().expect("changed wrapper");
                let contents = runtime.read(wrapper_path)?.ok_or_else(|| {
                    AdapterError::Verification("Gradle wrapper properties disappeared".into())
                })?;
                let wrapper = parse_wrapper(wrapper_path, utf8(wrapper_path, &contents)?)?;
                if !is_distribution_mirror(&wrapper.url) || wrapper.checksum.is_none() {
                    return Err(AdapterError::Verification(
                        "Gradle wrapper does not reference a checksummed reviewed mirror".into(),
                    ));
                }
                let project = project.as_deref().ok_or_else(|| {
                    AdapterError::Verification("Gradle project disappeared".into())
                })?;
                let command = gradle_wrapper_command(runtime, project).ok_or_else(|| {
                    AdapterError::Verification("executable Gradle wrapper disappeared".into())
                })?;
                let output = run_gradle(runtime, Some(project), &command, &["--version"])?;
                let observed = gradle_version(&output)?;
                if version_number(&observed)? != wrapper.version {
                    return Err(AdapterError::Verification(format!(
                        "Gradle wrapper launched {} instead of {}",
                        version_number(&observed)?,
                        wrapper.version
                    )));
                }
                summaries.push(format!(
                    "wrapper launched {} from {}",
                    wrapper.version, wrapper.url
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: summaries.join("; "),
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
                "restored {} Gradle configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DocumentKind {
    ManagedInit,
    InitScript,
    Wrapper,
    ProjectBuild,
    Properties,
    VerificationSettings,
}

#[derive(Clone, Debug)]
struct ConfigLayout {
    gradle_user_home: PathBuf,
    managed_init: PathBuf,
    verification_settings: PathBuf,
    init_scripts: Vec<PathBuf>,
    wrapper: Option<PathBuf>,
    project_files: Vec<PathBuf>,
    properties_files: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
struct WrapperConfig {
    url: String,
    file_name: String,
    version: String,
    checksum: Option<String>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "Gradle adapter requires Linux".into(),
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
            "Gradle supports user dependency and explicit project Wrapper scopes".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "gradle" {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle operation received another tool's configuration".into(),
        ));
    }
    require_scope(current.scope)
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
        AdapterError::Unsupported("Gradle user configuration requires a home directory".into())
    })?;
    validate_path(&home)?;
    let gradle_user_home = runtime
        .environment_variable("GRADLE_USER_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".gradle"));
    validate_path(&gradle_user_home)?;
    let managed_init = gradle_user_home.join("init.d").join(MANAGED_FILE);
    let verification_settings = gradle_user_home
        .join("mirrorswitch")
        .join("verification")
        .join("settings.gradle");
    let mut init_scripts = Vec::new();
    for root_script in [
        gradle_user_home.join("init.gradle"),
        gradle_user_home.join("init.gradle.kts"),
    ] {
        if runtime.read(&root_script)?.is_some() {
            init_scripts.push(root_script);
        }
    }
    for path in runtime.list_files(&gradle_user_home.join("init.d"))? {
        if is_init_script(&path) {
            init_scripts.push(path);
        }
    }
    if let Some(gradle_home) = runtime
        .environment_variable("GRADLE_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
    {
        validate_path(&gradle_home)?;
        for path in runtime.list_files(&gradle_home.join("init.d"))? {
            if is_init_script(&path) {
                init_scripts.push(path);
            }
        }
    }
    init_scripts.sort();
    init_scripts.dedup();

    let wrapper = project.map(|project| {
        project
            .join("gradle")
            .join("wrapper")
            .join("gradle-wrapper.properties")
    });
    let wrapper = if let Some(path) = wrapper {
        runtime.read(&path)?.is_some().then_some(path)
    } else {
        None
    };
    let mut project_files = Vec::new();
    let mut properties_files = vec![gradle_user_home.join("gradle.properties")];
    if let Some(project) = project {
        for name in [
            "settings.gradle",
            "settings.gradle.kts",
            "build.gradle",
            "build.gradle.kts",
        ] {
            let path = project.join(name);
            if runtime.read(&path)?.is_some() {
                project_files.push(path);
            }
        }
        properties_files.push(project.join("gradle.properties"));
    }
    let mut existing_properties = Vec::new();
    for path in properties_files {
        if runtime.read(&path)?.is_some() {
            existing_properties.push(path);
        }
    }
    Ok(ConfigLayout {
        gradle_user_home,
        managed_init,
        verification_settings,
        init_scripts,
        wrapper,
        project_files,
        properties_files: existing_properties,
    })
}

fn is_init_script(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".gradle") || name.ends_with(".gradle.kts"))
}

fn gradle_command(runtime: &dyn Runtime, project: Option<&Path>) -> Option<String> {
    project
        .and_then(|project| gradle_wrapper_command(runtime, project))
        .or_else(|| runtime.command_exists("gradle").then(|| "gradle".into()))
}

fn gradle_wrapper_command(runtime: &dyn Runtime, project: &Path) -> Option<String> {
    let path = project.join("gradlew");
    let command = path.to_str()?;
    runtime.command_exists(command).then(|| command.into())
}

fn run_gradle(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    command: &str,
    arguments: &[&str],
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = if let Some(directory) = directory {
        runtime.run_in(directory, command, &arguments)?
    } else {
        runtime.run(command, &arguments)?
    };
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "Gradle command failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("Gradle returned non-UTF-8 stdout".into()))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| AdapterError::Runtime("Gradle returned non-UTF-8 stderr".into()))?;
    Ok(format!("{stdout}\n{stderr}").trim().to_owned())
}

fn gradle_version(output: &str) -> Result<String, AdapterError> {
    output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("Gradle "))
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("Gradle version output is unrecognized".into()))
}

fn reviewed_version(value: &str) -> Result<(), AdapterError> {
    let version = version_number(value)?;
    let mut parts = version.split('.');
    let major = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .ok_or_else(|| AdapterError::Unsupported(format!("unrecognized Gradle version {value}")))?;
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or(0);
    if !((major == 7 && minor >= 6) || matches!(major, 8 | 9)) {
        return Err(AdapterError::Unsupported(format!(
            "Gradle {version} is outside the reviewed 7.6 through 9.x repository model"
        )));
    }
    Ok(())
}

fn version_number(value: &str) -> Result<String, AdapterError> {
    value
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
        })
        .find(|token| {
            token
                .chars()
                .next()
                .is_some_and(|value| value.is_ascii_digit())
        })
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("unrecognized Gradle version {value}")))
}

fn parse_wrapper(path: &Path, text: &str) -> Result<WrapperConfig, AdapterError> {
    let url = property_value(text, "distributionUrl")?.ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "Gradle wrapper {} has no distributionUrl",
            path.display()
        ))
    })?;
    let parsed = reqwest::Url::parse(&url).map_err(|_| {
        AdapterError::InvalidConfiguration("Gradle wrapper distributionUrl is invalid".into())
    })?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AdapterError::Unsupported(
            "Gradle wrapper distributionUrl is not a credential-free default HTTPS URL".into(),
        ));
    }
    let file_name = parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Gradle wrapper distributionUrl has no archive name".into(),
            )
        })?
        .to_owned();
    let archive = file_name
        .strip_prefix("gradle-")
        .and_then(|name| name.strip_suffix(".zip"))
        .ok_or_else(|| {
            AdapterError::Unsupported("Gradle wrapper archive is not a standard Gradle ZIP".into())
        })?;
    let (version, flavor) = archive.rsplit_once('-').ok_or_else(|| {
        AdapterError::Unsupported("Gradle wrapper archive name is unrecognized".into())
    })?;
    if !matches!(flavor, "bin" | "all") || version.is_empty() {
        return Err(AdapterError::Unsupported(
            "Gradle wrapper archive must use the bin or all flavor".into(),
        ));
    }
    reviewed_version(&format!("Gradle {version}"))?;
    let version = version.to_owned();
    let checksum = property_value(text, "distributionSha256Sum")?;
    if checksum.as_ref().is_some_and(|checksum| {
        checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle wrapper distributionSha256Sum is not a SHA-256 digest".into(),
        ));
    }
    Ok(WrapperConfig {
        url,
        file_name,
        version,
        checksum: checksum.map(|checksum| checksum.to_ascii_lowercase()),
    })
}

fn property_value(text: &str, key: &str) -> Result<Option<String>, AdapterError> {
    let mut found = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with(['#', '!']) {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        if !rest.chars().next().is_some_and(|character| {
            character == '=' || character == ':' || character.is_whitespace()
        }) {
            continue;
        }
        if found.is_some() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Gradle properties define {key} more than once"
            )));
        }
        let rest = rest.trim_start();
        let rest = rest.strip_prefix(['=', ':']).unwrap_or(rest).trim_start();
        if has_continuation(rest) {
            return Err(AdapterError::Unsupported(format!(
                "continued Gradle property {key} is not supported"
            )));
        }
        found = Some(unescape_property(rest)?);
    }
    Ok(found)
}

fn has_continuation(value: &str) -> bool {
    value
        .chars()
        .rev()
        .take_while(|character| *character == '\\')
        .count()
        % 2
        == 1
}

fn unescape_property(value: &str) -> Result<String, AdapterError> {
    let mut unescaped = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            unescaped.push(character);
            continue;
        }
        let escaped = characters.next().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Gradle property ends in an escape".into())
        })?;
        if escaped == 'u' {
            return Err(AdapterError::Unsupported(
                "Unicode escapes in Gradle wrapper URLs are not supported".into(),
            ));
        }
        unescaped.push(match escaped {
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            'f' => '\u{000c}',
            value => value,
        });
    }
    Ok(unescaped)
}

fn rewrite_wrapper(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let mut rewritten = String::with_capacity(text.len() + endpoint.len());
    let mut replaced = false;
    for line in text.split_inclusive('\n') {
        let without_newline = line.strip_suffix('\n').unwrap_or(line);
        let without_cr = without_newline
            .strip_suffix('\r')
            .unwrap_or(without_newline);
        if property_line(without_cr, "distributionUrl") {
            if replaced {
                return Err(AdapterError::InvalidConfiguration(
                    "Gradle properties define distributionUrl more than once".into(),
                ));
            }
            let newline = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            rewritten.push_str("distributionUrl=");
            rewritten.push_str(&endpoint.replace(':', "\\:"));
            rewritten.push_str(newline);
            replaced = true;
        } else {
            rewritten.push_str(line);
        }
    }
    if !replaced {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle wrapper distributionUrl disappeared".into(),
        ));
    }
    Ok(rewritten)
}

fn property_line(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with(['#', '!']) {
        return false;
    }
    trimmed.strip_prefix(key).is_some_and(|rest| {
        rest.chars().next().is_some_and(|character| {
            character == '=' || character == ':' || character.is_whitespace()
        })
    })
}

fn render_init_script(endpoint: &str) -> String {
    let endpoint = format!("{}/", endpoint.trim_end_matches('/'));
    format!(
        r#"{MANAGED_MARKER}
import org.gradle.api.artifacts.repositories.MavenArtifactRepository

def mirrorSwitchCentralUrls = [
    "https://repo.maven.apache.org/maven2",
    "https://repo1.maven.org/maven2"
] as Set
def mirrorSwitchEndpoint = uri("{endpoint}")
def mirrorSwitchRewrite = {{ repositories ->
    repositories.configureEach {{ repository ->
        if (repository instanceof MavenArtifactRepository) {{
            def current = repository.url.toString().replaceAll('/+$', '')
            if (mirrorSwitchCentralUrls.contains(current)) {{
                repository.setUrl(mirrorSwitchEndpoint)
            }}
        }}
    }}
}}

gradle.settingsEvaluated {{ settings ->
    mirrorSwitchRewrite(settings.dependencyResolutionManagement.repositories)
}}

gradle.allprojects {{ project ->
    mirrorSwitchRewrite(project.buildscript.repositories)
    mirrorSwitchRewrite(project.repositories)
}}

if (System.getProperty("mirrorswitch.verify") == "true") {{
    gradle.beforeProject {{ project ->
        if (project == project.rootProject && project.tasks.findByName("{VERIFY_TASK}") == null) {{
            project.repositories.maven {{ repository ->
                repository.name = "MirrorSwitchVerification"
                repository.url = mirrorSwitchEndpoint
            }}
            project.tasks.register("{VERIFY_TASK}") {{
                doLast {{
                    def dependency = project.dependencies.create("org.apache.commons:commons-lang3:3.14.0")
                    def configuration = project.configurations.detachedConfiguration(dependency)
                    configuration.transitive = false
                    def artifact = configuration.singleFile
                    println("{VERIFY_MARKER} " + artifact.name + " " + mirrorSwitchEndpoint)
                }}
            }}
        }}
    }}
}}
"#
    )
}

fn render_verification_settings() -> String {
    format!("{VERIFY_PROJECT_MARKER}\n{VERIFY_SETTINGS}")
}

fn managed_init_source(text: &str, path: &Path) -> Result<ConfiguredSource, AdapterError> {
    if !text.contains(MANAGED_MARKER) {
        return Ok(policy_source("managed-file-conflict", path));
    }
    let prefix = "def mirrorSwitchEndpoint = uri(\"";
    let endpoint = text
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(prefix)
                .and_then(|value| value.strip_suffix("\")"))
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "managed Gradle init script has no endpoint declaration".into(),
            )
        })?;
    if !is_maven_mirror(endpoint) {
        return Err(AdapterError::InvalidConfiguration(
            "managed Gradle init script endpoint is not reviewed".into(),
        ));
    }
    Ok(ConfiguredSource {
        upstream_id: Some(MAVEN_UPSTREAM.into()),
        url: format!("{}/", endpoint.trim_end_matches('/')),
        enabled: true,
        metadata: source_metadata("dependency-default", path),
    })
}

fn wrapper_source(wrapper: WrapperConfig, path: &Path) -> ConfiguredSource {
    let public = is_official_distribution(&wrapper.url) || is_distribution_mirror(&wrapper.url);
    ConfiguredSource {
        upstream_id: public.then(|| DISTRIBUTION_UPSTREAM.into()),
        url: if public {
            wrapper.url.clone()
        } else {
            "<redacted>".into()
        },
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["wrapper-distribution".into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("distribution_file".into(), vec![wrapper.file_name]),
            ("distribution_version".into(), vec![wrapper.version]),
            (
                "distribution_checksum".into(),
                vec![wrapper.checksum.unwrap_or_default()],
            ),
        ]),
    }
}

fn current_wrapper(current: &CurrentConfiguration) -> Result<WrapperConfig, AdapterError> {
    let document = current
        .documents
        .iter()
        .find(|document| document.format == "gradle-selected-wrapper")
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("selected Gradle wrapper is missing".into())
        })?;
    parse_wrapper(&document.path, utf8(&document.path, &document.contents)?)
}

fn project_repository_sources(text: &str, path: &Path) -> Vec<ConfiguredSource> {
    [
        ("project-repositories", "repositories"),
        ("content-filter", "content"),
        ("exclusive-content", "exclusiveContent"),
        ("plugin-management", "pluginManagement"),
    ]
    .into_iter()
    .filter(|(_, marker)| text.contains(marker))
    .map(|(kind, _)| policy_source(kind, path))
    .collect()
}

fn environment_sources(runtime: &dyn Runtime) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    for key in ["GRADLE_OPTS", "JAVA_OPTS"] {
        if let Some(value) = runtime.environment_variable(key) {
            if value.contains("gradle.user.home") {
                sources.push(policy_source(
                    "user-home-system-property",
                    Path::new(":env:"),
                ));
            }
            if value.contains("gradle.wrapperUser") || value.contains("gradle.wrapperPassword") {
                sources.push(policy_source("wrapper-credentials", Path::new(":env:")));
            }
        }
    }
    sources
}

fn wrapper_credentials_configured(text: &str) -> Result<bool, AdapterError> {
    for key in [
        "systemProp.gradle.wrapperUser",
        "systemProp.gradle.wrapperPassword",
    ] {
        if property_value(text, key)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn policy_source(kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: source_metadata(kind, path),
    }
}

fn source_metadata(kind: &str, path: &Path) -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([
        ("kind".into(), vec![kind.into()]),
        ("config_path".into(), vec![path.display().to_string()]),
    ])
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        if current.scope == ConfigurationScope::User && kind == "managed-file-conflict" {
            return Err(AdapterError::Unsupported(
                "Gradle managed init target exists without the MirrorSwitch marker".into(),
            ));
        }
        if current.scope == ConfigurationScope::User && kind == "user-home-system-property" {
            return Err(AdapterError::Unsupported(
                "GRADLE_OPTS or JAVA_OPTS overrides Gradle user home precedence".into(),
            ));
        }
        if current.scope == ConfigurationScope::User && kind == "verification-project-conflict" {
            return Err(AdapterError::Unsupported(
                "Gradle verification project target exists without the MirrorSwitch marker".into(),
            ));
        }
        if current.scope == ConfigurationScope::Project && kind == "wrapper-credentials" {
            return Err(AdapterError::Unsupported(
                "Gradle Wrapper credentials must not be retargeted to a public mirror".into(),
            ));
        }
    }
    Ok(())
}

fn validate_wrapper_for_change(
    current: &CurrentConfiguration,
    wrapper: &WrapperConfig,
) -> Result<(), AdapterError> {
    if !is_official_distribution(&wrapper.url) && !is_distribution_mirror(&wrapper.url) {
        return Err(AdapterError::Unsupported(
            "Gradle Wrapper has a private or unmapped distribution URL".into(),
        ));
    }
    if wrapper.checksum.is_none() {
        return Err(AdapterError::Unsupported(
            "Gradle Wrapper distributionSha256Sum is required before changing its URL".into(),
        ));
    }
    if current
        .sources
        .iter()
        .any(|source| metadata(source, "kind").ok() == Some("wrapper-credentials"))
    {
        return Err(AdapterError::Unsupported(
            "Gradle Wrapper credentials must not be retargeted to a public mirror".into(),
        ));
    }
    Ok(())
}

fn selected_maven_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "gradle"
        || selections[0].upstream_id != MAVEN_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle user plan requires exactly one Maven repository selection".into(),
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
                "Gradle selection has no Maven metadata endpoint".into(),
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
                "Gradle selection has no Maven artifact endpoint".into(),
            )
        })?;
    let index = normalized_base(&index.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Gradle Maven endpoint is unsafe".into())
    })?;
    let artifact = normalized_base(&artifact.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Gradle Maven artifact endpoint is unsafe".into())
    })?;
    if index != artifact || !MAVEN_MIRRORS.contains(&index.as_str()) {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle Maven metadata and artifact endpoints are not one reviewed repository".into(),
        ));
    }
    Ok(selections[0]
        .endpoints
        .iter()
        .find(|endpoint| endpoint.role == EndpointRole::Index)
        .expect("validated endpoint")
        .url
        .trim_end_matches('/'))
}

fn selected_distribution_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "gradle"
        || selections[0].upstream_id != DISTRIBUTION_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle project plan requires exactly one distribution selection".into(),
        ));
    }
    let release = selections[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Releases && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Gradle selection has no distribution endpoint".into(),
            )
        })?;
    let endpoint = normalized_base(&release.url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Gradle distribution endpoint is unsafe".into())
    })?;
    if !DISTRIBUTION_MIRRORS.contains(&endpoint.as_str()) {
        return Err(AdapterError::InvalidConfiguration(
            "Gradle distribution endpoint is not reviewed".into(),
        ));
    }
    Ok(release.url.trim_end_matches('/'))
}

fn normalized_base(value: &str) -> Option<String> {
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

fn distribution_base(value: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(value).ok()?;
    let file = parsed.path_segments()?.next_back()?;
    let base = value.strip_suffix(file)?.trim_end_matches('/');
    normalized_base(base)
}

fn is_official_distribution(value: &str) -> bool {
    distribution_base(value).as_deref() == Some(OFFICIAL_DISTRIBUTION)
}

fn is_distribution_mirror(value: &str) -> bool {
    distribution_base(value).is_some_and(|base| DISTRIBUTION_MIRRORS.contains(&base.as_str()))
}

fn is_maven_mirror(value: &str) -> bool {
    normalized_base(value).is_some_and(|base| MAVEN_MIRRORS.contains(&base.as_str()))
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Gradle source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Gradle source has ambiguous {key} metadata"
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
            "Gradle reported unsafe configuration path {}",
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
            "Gradle configuration {} is not UTF-8",
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
