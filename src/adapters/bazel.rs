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

const RELEASE_UPSTREAM: &str = "bazel--release-artifacts";
const APT_UPSTREAM: &str = "bazel-apt--repository-metadata";
const BAZEL_VERSION: &str = "9.2.0";
const HUAWEI: &str = "https://repo.huaweicloud.com/bazel";
const NJU_APT: &str = "https://mirrors.nju.edu.cn/bazel-apt";
const TUNA_APT: &str = "https://mirrors.tuna.tsinghua.edu.cn/bazel-apt";
const OFFICIAL_APT: &str = "https://storage.googleapis.com/bazel-apt";
const OFFICIAL_RELEASE_BASES: &[&str] = &[
    "https://releases.bazel.build",
    "https://github.com/bazelbuild/bazel/releases/download",
];
const X64_SHA256: &str = "7668a95db1250f12c40407251e4e203b4ec8bf39bc495d2f485b2d8c99048694";
const ARM64_SHA256: &str = "049dd21f40ad979db11c3ee68c96a42ce75f1185e69ac61ab20de1501427a410";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch Bazelisk release mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch Bazelisk release mirror <<<";
const APT_SOURCE: &str = "/etc/apt/sources.list.d/bazel.list";

#[derive(Clone, Copy, Debug, Default)]
pub struct BazelAdapter;

impl Adapter for BazelAdapter {
    fn key(&self) -> &'static str {
        "bazel"
    }

    fn tool_id(&self) -> &'static str {
        "bazel"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System, ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::User
    }

    fn default_scope_for(
        &self,
        _context: &SystemContext,
        _runtime: &dyn Runtime,
        detected: &DetectedTool,
    ) -> Result<ConfigurationScope, AdapterError> {
        Ok(
            if detected.executable.as_deref() == Some(Path::new("bazel")) {
                ConfigurationScope::System
            } else {
                ConfigurationScope::User
            },
        )
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
        let method = detect_method(context, runtime)?;
        let Some(method) = method else {
            return Ok(None);
        };
        if !runtime.command_exists("env") {
            return Err(AdapterError::Unsupported(
                "Bazel installation discovery requires the standard env command".into(),
            ));
        }
        let (executable, version, evidence) = match method {
            InstallMethod::Bazelisk => {
                let version = bazelisk_version(runtime)?;
                let project = project_observation(runtime)?;
                (
                    PathBuf::from("bazelisk"),
                    version.clone(),
                    vec![
                        format!("Bazelisk {version}"),
                        "installation method is Bazelisk release download".into(),
                        format!(
                            "project .bazelversion is {}",
                            if project.version { "present" } else { "absent" }
                        ),
                        format!(
                            "project .bazeliskrc is {}",
                            if project.bazelisk_rc {
                                "present"
                            } else {
                                "absent"
                            }
                        ),
                    ],
                )
            }
            InstallMethod::Apt => {
                let version = bazel_version(runtime)?;
                (
                    PathBuf::from("bazel"),
                    version.clone(),
                    vec![
                        format!("Bazel {version}"),
                        "installation method is the signed Bazel APT repository".into(),
                        format!("APT source is {APT_SOURCE}"),
                        "APT repository architecture is amd64 only".into(),
                    ],
                )
            }
        };
        Ok(Some(DetectedTool {
            tool_id: "bazel".into(),
            executable: Some(executable),
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
        let method = detect_method(context, runtime)?.ok_or_else(|| {
            AdapterError::Conflict("Bazel installation method disappeared".into())
        })?;
        let expected_scope = match method {
            InstallMethod::Bazelisk => ConfigurationScope::User,
            InstallMethod::Apt => ConfigurationScope::System,
        };
        if scope != expected_scope {
            return Err(AdapterError::Unsupported(format!(
                "detected Bazel installation requires {expected_scope:?} scope"
            )));
        }
        if detected.tool_id != "bazel" {
            return Err(AdapterError::InvalidConfiguration(
                "Bazel read received another tool's detection result".into(),
            ));
        }
        let version = match method {
            InstallMethod::Bazelisk => bazelisk_version(runtime)?,
            InstallMethod::Apt => bazel_version(runtime)?,
        };
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Bazel launcher or binary version changed after detection".into(),
            ));
        }
        let layout = layout(runtime)?;
        let mut files = Vec::new();
        let mut sources = vec![snapshot_source("installation-method", method.name())];
        sources.push(snapshot_source("detected-version", &version));
        let mut documents = Vec::new();
        match method {
            InstallMethod::Bazelisk => {
                add_bazelisk_state(runtime, &layout, &mut files, &mut sources, &mut documents)?;
            }
            InstallMethod::Apt => {
                let contents = runtime
                    .read(Path::new(APT_SOURCE))?
                    .ok_or_else(|| AdapterError::Conflict("Bazel APT source disappeared".into()))?;
                files.push(PathBuf::from(APT_SOURCE));
                let parsed = parse_apt_source(utf8(Path::new(APT_SOURCE), &contents)?)?;
                sources.push(if is_public_apt(&parsed.url) {
                    configured_source(
                        &parsed.url,
                        APT_UPSTREAM,
                        "apt-source",
                        Path::new(APT_SOURCE),
                    )
                } else {
                    policy_source("private-apt-source", Path::new(APT_SOURCE))
                });
                documents.push(ConfigurationDocument {
                    path: PathBuf::from(APT_SOURCE),
                    format: "bazel-apt-source".into(),
                    contents,
                });
            }
        }
        add_project_documents(runtime, &mut files, &mut sources, &mut documents)?;
        let manifest = runtime.read(&layout.verification_manifest)?;
        let manifest_exists = manifest.is_some();
        let manifest = manifest.unwrap_or_default();
        if manifest_exists {
            files.push(layout.verification_manifest.clone());
            if utf8(&layout.verification_manifest, &manifest)? != render_manifest() {
                sources.push(policy_source(
                    "verification-conflict",
                    &layout.verification_manifest,
                ));
            }
        }
        documents.push(ConfigurationDocument {
            path: layout.verification_manifest,
            format: "bazel-verification-manifest".into(),
            contents: manifest,
        });
        Ok(CurrentConfiguration {
            tool_id: "bazel".into(),
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
        let upstream = match current.scope {
            ConfigurationScope::User => RELEASE_UPSTREAM,
            ConfigurationScope::System => APT_UPSTREAM,
            _ => {
                return Err(AdapterError::Unsupported(
                    "Bazel supports only system APT or user Bazelisk scope".into(),
                ));
            }
        };
        Ok(SelectionRequest {
            tool_id: "bazel".into(),
            adapter_key: "bazel".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![upstream.into()],
            repository_versions: BTreeMap::from([(upstream.into(), BAZEL_VERSION.into())]),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: current.scope == ConfigurationScope::System,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![
                EndpointRole::Index,
                EndpointRole::Metadata,
                EndpointRole::Artifacts,
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
        let endpoint = selected_endpoint(current.scope, selections)?;
        let manifest = find_document(current, "bazel-verification-manifest")?;
        let mut changes = Vec::new();
        match current.scope {
            ConfigurationScope::User => {
                let config = find_document(current, "bazelisk-user-config")?;
                add_change(
                    context,
                    current,
                    config,
                    rewrite_bazelisk_config(
                        utf8(&config.path, &config.contents)?,
                        &config.path,
                        &endpoint,
                    )?
                    .into_bytes(),
                    "add or retarget Bazelisk release base while preserving launcher policy",
                    &mut changes,
                );
            }
            ConfigurationScope::System => {
                let source = find_document(current, "bazel-apt-source")?;
                add_change(
                    context,
                    current,
                    source,
                    rewrite_apt_source(utf8(&source.path, &source.contents)?, &endpoint)?
                        .into_bytes(),
                    "retarget the signed Bazel APT source while preserving options and keyring",
                    &mut changes,
                );
            }
            _ => unreachable!("scope validated"),
        }
        add_change(
            context,
            current,
            manifest,
            render_manifest().into_bytes(),
            "create a fixed Bazel release verification manifest",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "bazel".into(),
            tool_id: "bazel".into(),
            scope: current.scope,
            changes,
            requires_elevation: current.scope == ConfigurationScope::System,
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
            let layout = layout(runtime)?;
            let user_target = rooted(&context.root, &layout.user_config);
            let apt_target = rooted(&context.root, Path::new(APT_SOURCE));
            let manifest_target = rooted(&context.root, &layout.verification_manifest);
            let mode = if receipt.changed_targets.contains(&apt_target) {
                InstallMethod::Apt
            } else if receipt.changed_targets.contains(&user_target) {
                InstallMethod::Bazelisk
            } else if receipt.changed_targets.contains(&manifest_target) {
                detect_method(context, runtime)?.ok_or_else(|| {
                    AdapterError::Verification(
                        "Bazel installation method disappeared after apply".into(),
                    )
                })?
            } else {
                return Err(AdapterError::Verification(
                    "Bazel transaction receipt contains no installation target".into(),
                ));
            };
            let manifest = runtime
                .read(&layout.verification_manifest)?
                .ok_or_else(|| {
                    AdapterError::Verification("Bazel verification manifest disappeared".into())
                })?;
            if utf8(&layout.verification_manifest, &manifest)? != render_manifest() {
                return Err(AdapterError::Verification(
                    "Bazel verification manifest is not canonical".into(),
                ));
            }
            let endpoint = match mode {
                InstallMethod::Bazelisk => {
                    let config = runtime.read(&layout.user_config)?.ok_or_else(|| {
                        AdapterError::Verification("Bazelisk user config disappeared".into())
                    })?;
                    let parsed = parse_bazelisk_config(
                        utf8(&layout.user_config, &config)?,
                        &layout.user_config,
                    )?;
                    let endpoint = parsed.managed.ok_or_else(|| {
                        AdapterError::Verification("managed Bazelisk base URL is missing".into())
                    })?;
                    if endpoint != HUAWEI {
                        return Err(AdapterError::Verification(
                            "managed Bazelisk endpoint is not reviewed".into(),
                        ));
                    }
                    verify_bazelisk(runtime, &layout, context.architecture, &endpoint)?;
                    endpoint
                }
                InstallMethod::Apt => {
                    let source = runtime.read(Path::new(APT_SOURCE))?.ok_or_else(|| {
                        AdapterError::Verification("Bazel APT source disappeared".into())
                    })?;
                    let parsed = parse_apt_source(utf8(Path::new(APT_SOURCE), &source)?)?;
                    if !is_reviewed_apt(&parsed.url) {
                        return Err(AdapterError::Verification(
                            "Bazel APT source is not reviewed".into(),
                        ));
                    }
                    verify_apt(runtime)?;
                    parsed.url
                }
            };
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} verified Bazel {BAZEL_VERSION} through {endpoint}",
                    mode.name()
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
                "restored {} Bazel configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallMethod {
    Bazelisk,
    Apt,
}

impl InstallMethod {
    fn name(self) -> &'static str {
        match self {
            Self::Bazelisk => "Bazelisk",
            Self::Apt => "APT",
        }
    }
}

struct Layout {
    user_config: PathBuf,
    verification_root: PathBuf,
    verification_manifest: PathBuf,
}

#[derive(Default)]
struct ProjectObservation {
    version: bool,
    bazelisk_rc: bool,
}

struct ParsedBazeliskConfig {
    managed: Option<String>,
    unmanaged: Vec<KeyAssignment>,
    format_url: bool,
}

struct KeyAssignment {
    range: Range<usize>,
    value: String,
}

struct AptSource {
    url: String,
    range: Range<usize>,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Bazel v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "bazel"
        || !matches!(
            current.scope,
            ConfigurationScope::System | ConfigurationScope::User
        )
    {
        return Err(AdapterError::InvalidConfiguration(
            "Bazel operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn detect_method(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<Option<InstallMethod>, AdapterError> {
    let bazelisk = runtime.command_exists("bazelisk");
    let apt_contents = runtime.read(Path::new(APT_SOURCE))?;
    let apt = apt_contents
        .as_deref()
        .and_then(|contents| std::str::from_utf8(contents).ok())
        .is_some_and(|text| parse_apt_source(text).is_ok());
    if bazelisk && apt {
        return Err(AdapterError::Unsupported(
            "Bazelisk and Bazel APT installation methods are both active".into(),
        ));
    }
    if bazelisk {
        return Ok(Some(InstallMethod::Bazelisk));
    }
    if apt {
        if context.architecture != Architecture::X86_64 {
            return Err(AdapterError::Unsupported(
                "the Bazel APT repository has no arm64 packages; use Bazelisk".into(),
            ));
        }
        let debian_like = context.distribution.as_ref().is_some_and(|distribution| {
            matches!(distribution.id.as_str(), "debian" | "ubuntu")
                || distribution.id_like.iter().any(|id| id == "debian")
        });
        if !debian_like {
            return Err(AdapterError::Unsupported(
                "the configured Bazel APT source requires Debian or Ubuntu".into(),
            ));
        }
        for command in ["apt-get", "apt-cache", "bazel"] {
            if !runtime.command_exists(command) {
                return Err(AdapterError::Unsupported(format!(
                    "Bazel APT verification requires {command}"
                )));
            }
        }
        return Ok(Some(InstallMethod::Apt));
    }
    if runtime.command_exists("bazel") {
        return Err(AdapterError::Unsupported(
            "the installed Bazel binary has no configurable Bazelisk or APT source".into(),
        ));
    }
    Ok(None)
}

fn bazelisk_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = command_output(
        runtime.run("bazelisk", &["bazeliskVersion".into()])?,
        "bazelisk bazeliskVersion",
    )?;
    parse_version(&output, "Bazelisk")
}

fn bazel_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = command_output(
        runtime.run("bazel", &["--version".into()])?,
        "bazel --version",
    )?;
    parse_version(&output, "Bazel")
}

fn parse_version(output: &str, label: &str) -> Result<String, AdapterError> {
    output
        .split_whitespace()
        .map(|field| {
            field
                .trim_start_matches('v')
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        })
        .find(|field| {
            field.split('.').count() >= 2
                && field
                    .split('.')
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        })
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("{label} version is unrecognized")))
}

fn layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Bazel requires a user home".into()))?;
    validate_path(&home, "home")?;
    let verification_root = home.join(".mirrorswitch/verification/bazel");
    Ok(Layout {
        user_config: home.join(".bazeliskrc"),
        verification_manifest: verification_root.join("release.txt"),
        verification_root,
    })
}

fn add_bazelisk_state(
    runtime: &dyn Runtime,
    layout: &Layout,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let contents = runtime.read(&layout.user_config)?;
    if contents.is_some() {
        files.push(layout.user_config.clone());
    }
    let contents = contents.unwrap_or_default();
    let parsed = parse_bazelisk_config(utf8(&layout.user_config, &contents)?, &layout.user_config)?;
    if let Some(value) = &parsed.managed {
        sources.push(configured_source(
            value,
            RELEASE_UPSTREAM,
            "managed-bazelisk-base",
            &layout.user_config,
        ));
    }
    for assignment in &parsed.unmanaged {
        sources.push(if is_public_release_base(&assignment.value) {
            configured_source(
                &assignment.value,
                RELEASE_UPSTREAM,
                "adoptable-bazelisk-base",
                &layout.user_config,
            )
        } else {
            policy_source("private-bazelisk-base", &layout.user_config)
        });
    }
    if parsed.managed.is_some() && !parsed.unmanaged.is_empty() || parsed.unmanaged.len() > 1 {
        sources.push(policy_source(
            "duplicate-bazelisk-base",
            &layout.user_config,
        ));
    }
    if parsed.format_url {
        sources.push(policy_source("bazelisk-format-url", &layout.user_config));
    }
    if let Some(value) = runtime
        .environment_variable("BAZELISK_FORMAT_URL")
        .filter(|value| !value.trim().is_empty())
    {
        let _ = value;
        sources.push(policy_source("bazelisk-format-url", Path::new(":env:")));
    }
    if let Some(value) = runtime
        .environment_variable("BAZELISK_BASE_URL")
        .filter(|value| !value.trim().is_empty())
        && parsed
            .managed
            .as_deref()
            .into_iter()
            .chain(parsed.unmanaged.iter().map(|item| item.value.as_str()))
            .all(|profile| !same_base(profile, &value))
    {
        sources.push(policy_source(
            "bazelisk-environment-override",
            Path::new(":env:"),
        ));
    }
    documents.push(ConfigurationDocument {
        path: layout.user_config.clone(),
        format: "bazelisk-user-config".into(),
        contents,
    });
    Ok(())
}

fn project_observation(runtime: &dyn Runtime) -> Result<ProjectObservation, AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(ProjectObservation::default());
    };
    validate_path(&project, "project")?;
    Ok(ProjectObservation {
        version: runtime.read(&project.join(".bazelversion"))?.is_some(),
        bazelisk_rc: runtime.read(&project.join(".bazeliskrc"))?.is_some(),
    })
}

fn add_project_documents(
    runtime: &dyn Runtime,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(());
    };
    validate_path(&project, "project")?;
    for (name, format) in [
        (".bazeliskrc", "bazel-project-bazeliskrc-observed"),
        (".bazelversion", "bazel-project-version-observed"),
        (".bazelrc", "bazel-project-bazelrc-observed"),
        ("WORKSPACE", "bazel-project-workspace-observed"),
        ("WORKSPACE.bazel", "bazel-project-workspace-observed"),
        ("MODULE.bazel", "bazel-project-module-observed"),
        ("MODULE.bazel.lock", "bazel-project-module-lock-observed"),
    ] {
        let path = project.join(name);
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        if name == ".bazeliskrc" {
            let text = utf8(&path, &contents)?;
            if text.lines().map(active_line).any(|line| {
                line.starts_with("BAZELISK_BASE_URL=") || line.starts_with("BAZELISK_FORMAT_URL=")
            }) {
                sources.push(policy_source("project-bazelisk-precedence", &path));
            }
        }
        files.push(path.clone());
        sources.push(policy_source("project-file-preserved", &path));
        documents.push(ConfigurationDocument {
            path,
            format: format.into(),
            contents,
        });
    }
    Ok(())
}

fn parse_bazelisk_config(text: &str, path: &Path) -> Result<ParsedBazeliskConfig, AdapterError> {
    let range = managed_range(text, path)?;
    let managed = range
        .as_ref()
        .map(|range| managed_base(&text[range.clone()], path))
        .transpose()?;
    let mut unmanaged = Vec::new();
    let mut format_url = false;
    for (start, line) in line_spans(text) {
        if range.as_ref().is_some_and(|range| range.contains(&start)) {
            continue;
        }
        let active = active_line(line);
        if active.starts_with("BAZELISK_FORMAT_URL=") {
            format_url = true;
        }
        if let Some(value) = active.strip_prefix("BAZELISK_BASE_URL=") {
            let value = rc_value(value)?;
            unmanaged.push(KeyAssignment {
                range: start..start + line.len(),
                value: value.into(),
            });
        }
    }
    Ok(ParsedBazeliskConfig {
        managed,
        unmanaged,
        format_url,
    })
}

fn managed_base(block: &str, path: &Path) -> Result<String, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| {
            active_line(line)
                .strip_prefix("BAZELISK_BASE_URL=")
                .map(rc_value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 || values[0] != HUAWEI {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed Bazelisk block in {} is incomplete or unreviewed",
            path.display()
        )));
    }
    Ok(values[0].into())
}

fn rc_value(value: &str) -> Result<&str, AdapterError> {
    let value = value.trim();
    let quoted = value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')));
    let value = if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if value.is_empty() || value.contains(['\n', '\r', '#', '`', '$', ' ', '\t', '\'', '"']) {
        return Err(AdapterError::InvalidConfiguration(
            "Bazelisk URL configuration is not one literal value".into(),
        ));
    }
    Ok(value)
}

fn rewrite_bazelisk_config(
    text: &str,
    path: &Path,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let parsed = parse_bazelisk_config(text, path)?;
    if parsed.format_url
        || parsed.managed.is_some() && !parsed.unmanaged.is_empty()
        || parsed.unmanaged.len() > 1
    {
        return Err(AdapterError::InvalidConfiguration(
            "Bazelisk config cannot be rewritten safely".into(),
        ));
    }
    if parsed
        .unmanaged
        .iter()
        .any(|item| !is_public_release_base(&item.value))
    {
        return Err(AdapterError::Unsupported(
            "private Bazelisk base URL cannot be replaced".into(),
        ));
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = format!(
        "{MANAGED_BEGIN}{newline}BAZELISK_BASE_URL={endpoint}{newline}{MANAGED_END}{newline}"
    );
    if let Some(range) = managed_range(text, path)? {
        return Ok(format!(
            "{}{}{}",
            &text[..range.start],
            block,
            &text[range.end..]
        ));
    }
    if let Some(assignment) = parsed.unmanaged.first() {
        return Ok(format!(
            "{}{}{}",
            &text[..assignment.range.start],
            block,
            &text[assignment.range.end..]
        ));
    }
    let mut output = text.to_owned();
    if !output.is_empty() && !output.ends_with('\n') {
        output.push_str(newline);
    }
    output.push_str(&block);
    Ok(output)
}

fn managed_range(text: &str, path: &Path) -> Result<Option<Range<usize>>, AdapterError> {
    let begins = line_spans(text)
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == MANAGED_BEGIN)
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let ends = line_spans(text)
        .filter(|(_, line)| line.trim_end_matches(['\r', '\n']) == MANAGED_END)
        .map(|(start, line)| start + line.len())
        .collect::<Vec<_>>();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([begin], [end]) if begin < end => Ok(Some(*begin..*end)),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "Bazelisk managed markers in {} are missing, duplicated, or out of order",
            path.display()
        ))),
    }
}

fn parse_apt_source(text: &str) -> Result<AptSource, AdapterError> {
    let matches = line_spans(text)
        .filter_map(|(start, line)| {
            let active = active_line(line);
            if !active.starts_with("deb ")
                || !active.contains(" stable ")
                || !active.ends_with("jdk1.8")
            {
                return None;
            }
            let relative = line.find("https://")?;
            let end = line[relative..]
                .find(char::is_whitespace)
                .map_or(line.len(), |offset| relative + offset);
            Some((start + relative..start + end, &line[relative..end], active))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Bazel APT source must contain exactly one active binary entry".into(),
        ));
    }
    let (range, url, line) = &matches[0];
    if !line.contains("arch=amd64") || !line.contains("signed-by=") {
        return Err(AdapterError::Unsupported(
            "Bazel APT source must retain amd64 and signed-by policy".into(),
        ));
    }
    Ok(AptSource {
        url: normalized_base(url)
            .ok_or_else(|| AdapterError::InvalidConfiguration("Bazel APT URL is unsafe".into()))?,
        range: range.clone(),
    })
}

fn rewrite_apt_source(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let parsed = parse_apt_source(text)?;
    if !is_public_apt(&parsed.url) {
        return Err(AdapterError::Unsupported(
            "private Bazel APT repository cannot be replaced".into(),
        ));
    }
    let mut output = text.to_owned();
    output.replace_range(parsed.range, endpoint);
    Ok(output)
}

fn selected_endpoint(
    scope: ConfigurationScope,
    selections: &[MirrorSelection],
) -> Result<String, AdapterError> {
    let upstream = if scope == ConfigurationScope::User {
        RELEASE_UPSTREAM
    } else {
        APT_UPSTREAM
    };
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "bazel" && selection.upstream_id == upstream)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Bazel requires exactly one installation source selection".into(),
        ));
    }
    let selection = matches[0];
    let mut bases = BTreeSet::new();
    for role in [
        EndpointRole::Index,
        EndpointRole::Metadata,
        EndpointRole::Artifacts,
    ] {
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if endpoints.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Bazel selection requires one HTTPS {role:?} endpoint"
            )));
        }
        bases.insert(normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Bazel {role:?} endpoint is unsafe"))
        })?);
    }
    if bases.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Bazel installation source endpoints must share one base".into(),
        ));
    }
    let endpoint = bases.into_iter().next().expect("one endpoint");
    let expected = match (scope, endpoint.as_str()) {
        (ConfigurationScope::User, HUAWEI) => "huaweicloud",
        (ConfigurationScope::System, NJU_APT) => "nju",
        (ConfigurationScope::System, TUNA_APT) => "tuna",
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Bazel endpoint is not reviewed for the installation method".into(),
            ));
        }
    };
    if selection.provider_id != expected {
        return Err(AdapterError::InvalidConfiguration(
            "Bazel provider and endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn verify_bazelisk(
    runtime: &dyn Runtime,
    layout: &Layout,
    architecture: Architecture,
    endpoint: &str,
) -> Result<(), AdapterError> {
    let hash = match architecture {
        Architecture::X86_64 => X64_SHA256,
        Architecture::Arm64 => ARM64_SHA256,
    };
    let arguments = vec![
        format!("BAZELISK_BASE_URL={endpoint}"),
        format!(
            "BAZELISK_HOME={}",
            path_text(&layout.verification_root.join("cache"), "cache")?
        ),
        format!("USE_BAZEL_VERSION={BAZEL_VERSION}"),
        format!("BAZELISK_VERIFY_SHA256={hash}"),
        "bazelisk".into(),
        "version".into(),
    ];
    let output = command_output(
        runtime.run("env", &arguments)?,
        "Bazelisk release verification",
    )?;
    if !output.contains(BAZEL_VERSION) {
        return Err(AdapterError::Verification(
            "Bazelisk did not execute Bazel 9.2.0".into(),
        ));
    }
    Ok(())
}

fn verify_apt(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let common = [
        "-o",
        "Dir::Etc::sourcelist=/etc/apt/sources.list.d/bazel.list",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        "APT::Get::List-Cleanup=0",
    ];
    let mut update = common
        .iter()
        .map(|item| (*item).into())
        .collect::<Vec<String>>();
    update.push("update".into());
    command_output(
        runtime.run("apt-get", &update)?,
        "Bazel APT metadata refresh",
    )?;
    let mut policy = common
        .iter()
        .map(|item| (*item).into())
        .collect::<Vec<String>>();
    policy.extend(["policy".into(), "bazel".into()]);
    let output = command_output(runtime.run("apt-cache", &policy)?, "Bazel APT policy query")?;
    if !output.contains(BAZEL_VERSION) {
        return Err(AdapterError::Verification(
            "Bazel APT policy did not report Bazel 9.2.0".into(),
        ));
    }
    bazel_version(runtime)?;
    Ok(())
}

fn render_manifest() -> String {
    format!(
        "version={BAZEL_VERSION}\nx86_64_sha256={X64_SHA256}\narm64_sha256={ARM64_SHA256}\ndeb_amd64_sha256=7c54a526c195f1b1a404372eb05cf1d7a5ede898bf6f8e791febd0f25bff8e0b\n"
    )
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-bazelisk-base" | "private-apt-source" => {
                return Err(AdapterError::Unsupported(
                    "the active Bazel installation source is private or unreviewed".into(),
                ));
            }
            "duplicate-bazelisk-base" => {
                return Err(AdapterError::InvalidConfiguration(
                    "Bazelisk base URL is assigned more than once".into(),
                ));
            }
            "bazelisk-format-url" | "bazelisk-environment-override" => {
                return Err(AdapterError::Unsupported(
                    "Bazelisk format or process environment overrides the user base URL".into(),
                ));
            }
            "project-bazelisk-precedence" => {
                return Err(AdapterError::Unsupported(
                    "project .bazeliskrc overrides the user release source".into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Bazel verification target contains data not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn normalized_base(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_owned())
}

fn same_base(left: &str, right: &str) -> bool {
    normalized_base(left).is_some_and(|left| normalized_base(right).as_deref() == Some(&left))
}

fn is_public_release_base(value: &str) -> bool {
    normalized_base(value)
        .is_some_and(|value| value == HUAWEI || OFFICIAL_RELEASE_BASES.contains(&value.as_str()))
}

fn is_reviewed_apt(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| matches!(value.as_str(), NJU_APT | TUNA_APT))
}

fn is_public_apt(value: &str) -> bool {
    is_reviewed_apt(value) || normalized_base(value).is_some_and(|value| value == OFFICIAL_APT)
}

fn active_line(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim()
}

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
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
            "Bazel current configuration must contain exactly one {format} document"
        )));
    }
    Ok(matches[0])
}

fn add_change(
    context: &SystemContext,
    current: &CurrentConfiguration,
    document: &ConfigurationDocument,
    new_contents: Vec<u8>,
    summary: &str,
    changes: &mut Vec<PlannedFileChange>,
) {
    if document.contents == new_contents {
        return;
    }
    changes.push(PlannedFileChange {
        target: rooted(&context.root, &document.path),
        old_contents: current
            .files
            .contains(&document.path)
            .then(|| document.contents.clone()),
        old_mode: None,
        new_contents,
        new_mode: None,
        summary: summary.into(),
    });
}

fn configured_source(value: &str, upstream: &str, kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(upstream.into()),
        url: normalized_base(value).unwrap_or_else(|| "<preserved>".into()),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
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

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "bazel-snapshot:<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Bazel source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Bazel source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
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

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Bazel reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, kind: &str) -> Result<&'a str, AdapterError> {
    path.to_str()
        .ok_or_else(|| AdapterError::Verification(format!("Bazel {kind} path is not UTF-8")))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Bazel configuration {} is not UTF-8",
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
