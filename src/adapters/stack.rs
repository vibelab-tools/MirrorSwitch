use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
    process::Output,
};

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const STACKAGE_UPSTREAM: &str = "stackage--language-registry";
const HACKAGE_UPSTREAM: &str = "hackage--language-registry";
const VERIFY_SNAPSHOT: &str = "lts-22.43";
const VERIFY_COMPILER: &str = "ghc-9.6.6";
const VERIFY_PACKAGE: &str = "StateVar";
const VERIFY_VERSION: &str = "1.2.2";
const VERIFY_PACKAGE_ID: &str = "StateVar-1.2.2";
const SNAPSHOT_SHA256: &str = "08bd13ce621b41a8f5e51456b38d5b46d7783ce114a50ab604d6bbab0d002146";
const GLOBAL_HINTS_SHA256: &str =
    "c26bcae5f588e370090d946cc79f57666c4cda31bb1f50c8ad4024f058289c96";
const HACKAGE_TARBALL_SHA256: &str =
    "5e4b39da395656a59827b0280508aafdc70335798b50e5d6fd52596026251825";

const REVIEWED_STACKAGE: &[ReviewedStackage] = &[
    ReviewedStackage {
        provider: "nju",
        index: "https://mirrors.nju.edu.cn/stackage/",
        metadata: "https://mirrors.nju.edu.cn/github-raw/fpco/stackage-content/master/stack/",
        artifacts: "https://mirror.nju.edu.cn/stackage/",
    },
    ReviewedStackage {
        provider: "tuna",
        index: "https://mirrors.tuna.tsinghua.edu.cn/stackage/",
        metadata: "https://mirrors.tuna.tsinghua.edu.cn/github-raw/fpco/stackage-content/master/stack/",
        artifacts: "https://mirrors.tuna.tsinghua.edu.cn/stackage/",
    },
    ReviewedStackage {
        provider: "ustc",
        index: "https://mirrors.ustc.edu.cn/stackage/",
        metadata: "https://mirrors.ustc.edu.cn/stackage/stackage-content/stack/",
        artifacts: "https://mirrors.ustc.edu.cn/stackage/",
    },
];

const REVIEWED_HACKAGE: &[(&str, &str)] = &[
    ("nju", "https://mirrors.nju.edu.cn/hackage/"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/hackage/"),
    ("ustc", "https://mirrors.ustc.edu.cn/hackage/"),
];

const OFFICIAL_STACKAGE: &[&str] = &[
    "https://www.stackage.org/snapshots",
    "https://www.stackage.org/snapshots.json",
    "https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master",
    "https://raw.githubusercontent.com/commercialhaskell/stackage-content/master/stack/global-hints.yaml",
    "https://raw.githubusercontent.com/fpco/stackage-content/master/stack/global-hints.yaml",
    "https://raw.githubusercontent.com/commercialhaskell/stackage-content/master/stack/stack-setup-2.yaml",
    "https://raw.githubusercontent.com/commercialhaskell/stackage-content/master/stack/stack-setup.yaml",
    "https://raw.githubusercontent.com/fpco/stackage-content/master/stack/stack-setup-2.yaml",
    "https://raw.githubusercontent.com/fpco/stackage-content/master/stack/stack-setup.yaml",
];

const OFFICIAL_HACKAGE: &[&str] = &[
    "https://hackage.haskell.org",
    "http://hackage.haskell.org",
    "https://hackage.haskell.org/packages/archive",
    "http://hackage.haskell.org/packages/archive",
];

const MANAGED_TOP_LEVEL: &[&str] = &[
    "urls",
    "snapshot-location-base",
    "global-hints-location",
    "setup-info-locations",
    "package-index",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct StackAdapter;

impl Adapter for StackAdapter {
    fn key(&self) -> &'static str {
        "stack"
    }

    fn tool_id(&self) -> &'static str {
        "stack"
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
        require_supported_context(context)?;
        if !runtime.command_exists("stack") {
            return Ok(None);
        }
        let snapshot = stack_snapshot(context, runtime)?;
        let documents = read_documents(runtime, &snapshot)?;
        for document in documents.documents() {
            parse_yaml(&document.path, &document.contents)?;
        }
        let project = documents
            .project
            .as_ref()
            .map(|document| {
                let parsed = parse_yaml(&document.path, &document.contents)?;
                let locator = project_locator(&parsed);
                Ok::<_, AdapterError>(format!(
                    "project configuration is {} ({locator})",
                    document.path.display()
                ))
            })
            .transpose()?;
        let private_count = documents
            .documents()
            .map(|document| parse_yaml(&document.path, &document.contents))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .map(private_reference_count)
            .sum::<usize>();
        let mut evidence = vec![
            format!("Stack {}", snapshot.version),
            format!(
                "native platform is {:?} {:?}",
                context.os, context.architecture
            ),
            format!("selected user home is {}", snapshot.user_home.display()),
            format!("Stack root is {}", snapshot.stack_root.display()),
            snapshot.project_dir.as_ref().map_or_else(
                || "no project directory was selected".into(),
                |path| format!("selected project directory is {}", path.display()),
            ),
            snapshot.system_config.as_ref().map_or_else(
                || "native platform has no system-wide Stack configuration".into(),
                |path| format!("system configuration is {}", path.display()),
            ),
            format!("user configuration is {}", snapshot.user_config.display()),
            project.unwrap_or_else(|| "no active project stack.yaml was detected".into()),
            format!("{private_count} private archive/VCS reference(s) remain opaque and unchanged"),
        ];
        evidence.push(format!(
            "toolchain gate is GHC 9.6.6 {}",
            stack_toolchain(context).0
        ));
        Ok(Some(DetectedTool {
            tool_id: "stack".into(),
            executable: Some(PathBuf::from("stack")),
            version: Some(snapshot.version),
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
        require_supported_context(context)?;
        require_scope(scope)?;
        if detected.tool_id != "stack" {
            return Err(AdapterError::InvalidConfiguration(
                "Stack read received another tool's detection result".into(),
            ));
        }
        let snapshot = stack_snapshot(context, runtime)?;
        if detected.version.as_deref() != Some(snapshot.version.as_str()) {
            return Err(AdapterError::Conflict(
                "Stack version changed after detection".into(),
            ));
        }
        let documents = read_documents(runtime, &snapshot)?;
        let mut sources = Vec::new();
        for document in documents.documents() {
            let parsed = parse_yaml(&document.path, &document.contents)?;
            validate_managed_values(&parsed)?;
            sources.extend(configured_sources(&parsed, &document.path));
        }
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: format!("stack-version:{}", snapshot.version),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["tool-snapshot".into()]),
                ("version".into(), vec![snapshot.version.clone()]),
            ]),
        });

        let verification_config = read_document(
            runtime,
            &snapshot.verification_config,
            "Stack verification config",
        )?;
        let verification_project = read_document(
            runtime,
            &snapshot.verification_project,
            "Stack verification project",
        )?;
        let verification_system = read_document(
            runtime,
            &snapshot.verification_system,
            "Stack verification system config",
        )?;
        let verification_cabal = read_document(
            runtime,
            &snapshot.verification_cabal,
            "Stack verification Cabal package",
        )?;
        let verification_module = read_document(
            runtime,
            &snapshot.verification_module,
            "Stack verification Haskell module",
        )?;
        let mut files = documents
            .documents()
            .filter(|document| document.exists)
            .map(|document| document.path.clone())
            .collect::<Vec<_>>();
        for document in [
            &verification_config,
            &verification_project,
            &verification_system,
            &verification_cabal,
            &verification_module,
        ] {
            if document.exists {
                files.push(document.path.clone());
            }
        }
        let mut configuration_documents = Vec::new();
        if let Some(system) = documents.system {
            configuration_documents.push(ConfigurationDocument {
                path: system.path,
                format: "stack-system-config-read-only".into(),
                contents: system.contents,
            });
        }
        configuration_documents.push(ConfigurationDocument {
            path: documents.user.path,
            format: if scope == ConfigurationScope::User {
                "stack-target-config".into()
            } else {
                "stack-user-config-read-only".into()
            },
            contents: documents.user.contents,
        });
        if let Some(project) = documents.project {
            configuration_documents.push(ConfigurationDocument {
                path: project.path,
                format: if scope == ConfigurationScope::Project {
                    "stack-target-config".into()
                } else {
                    "stack-project-config-read-only".into()
                },
                contents: project.contents,
            });
        }
        configuration_documents.extend([
            ConfigurationDocument {
                path: verification_config.path,
                format: "stack-verification-config".into(),
                contents: verification_config.contents,
            },
            ConfigurationDocument {
                path: verification_project.path,
                format: "stack-verification-project".into(),
                contents: verification_project.contents,
            },
            ConfigurationDocument {
                path: verification_system.path,
                format: "stack-verification-system".into(),
                contents: verification_system.contents,
            },
            ConfigurationDocument {
                path: verification_cabal.path,
                format: "stack-verification-cabal".into(),
                contents: verification_cabal.contents,
            },
            ConfigurationDocument {
                path: verification_module.path,
                format: "stack-verification-module".into(),
                contents: verification_module.contents,
            },
        ]);
        Ok(CurrentConfiguration {
            tool_id: "stack".into(),
            scope,
            sources,
            files,
            documents: configuration_documents,
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context)?;
        require_current(current)?;
        reviewed_stack_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Stack version is missing".into())
        })?)?;
        let (toolchain_file, toolchain_sha) = stack_toolchain(context);
        Ok(SelectionRequest {
            tool_id: "stack".into(),
            adapter_key: "stack".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![STACKAGE_UPSTREAM.into(), HACKAGE_UPSTREAM.into()],
            repository_versions: BTreeMap::from([
                (STACKAGE_UPSTREAM.into(), "lts-22".into()),
                (HACKAGE_UPSTREAM.into(), "secure".into()),
            ]),
            probe_contexts: BTreeMap::from([(
                STACKAGE_UPSTREAM.into(),
                vec![BTreeMap::from([
                    ("toolchain_file".into(), toolchain_file.into()),
                    ("toolchain_sha".into(), toolchain_sha.into()),
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
                EndpointRole::Metadata,
                EndpointRole::Index,
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
        require_supported_context(context)?;
        require_current(current)?;
        let endpoints = selected_endpoints(selections)?;
        let target = current
            .documents
            .iter()
            .find(|document| document.format == "stack-target-config")
            .ok_or_else(|| {
                AdapterError::Unsupported(
                    "project scope requires an active stack.yaml inside the current project".into(),
                )
            })?;
        if current.scope == ConfigurationScope::User {
            if let Some(project) = current
                .documents
                .iter()
                .find(|document| document.format == "stack-project-config-read-only")
            {
                let parsed = parse_yaml(&project.path, &project.contents)?;
                if has_managed_values(&parsed) {
                    return Err(AdapterError::Unsupported(format!(
                        "{} overrides Stack repository settings; select project scope explicitly",
                        project.path.display()
                    )));
                }
            }
        }
        let parsed = parse_yaml(&target.path, &target.contents)?;
        validate_managed_values(&parsed)?;
        let mut rendered = rewrite_config(&parsed, &endpoints)?.into_bytes();
        if target.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let mut changes = Vec::new();
        if rendered != target.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &target.path),
                old_contents: current
                    .files
                    .contains(&target.path)
                    .then(|| target.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: format!(
                    "configure independent Stackage snapshot/global-hints/setup and Hackage download roots in {}; preserve snapshot/resolver, private packages, security policy, comments and unrelated keys",
                    target.path.display()
                ),
            });
        }
        let verification_config = current
            .documents
            .iter()
            .find(|document| document.format == "stack-verification-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Stack verification configuration document is missing".into(),
                )
            })?;
        let verification_project = current
            .documents
            .iter()
            .find(|document| document.format == "stack-verification-project")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Stack verification project document is missing".into(),
                )
            })?;
        let verification_system = current
            .documents
            .iter()
            .find(|document| document.format == "stack-verification-system")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Stack verification system document is missing".into(),
                )
            })?;
        let verification_cabal = current
            .documents
            .iter()
            .find(|document| document.format == "stack-verification-cabal")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Stack verification Cabal document is missing".into(),
                )
            })?;
        let verification_module = current
            .documents
            .iter()
            .find(|document| document.format == "stack-verification-module")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Stack verification module document is missing".into(),
                )
            })?;
        let verification_contents = render_managed_config(&endpoints);
        add_change_if_needed(
            context,
            current,
            &mut changes,
            verification_config,
            verification_contents.into_bytes(),
            "create an isolated credential-free Stack global config for snapshot and Hackage verification",
        );
        add_change_if_needed(
            context,
            current,
            &mut changes,
            verification_project,
            render_verification_project().into_bytes(),
            "create a fixed lts-22.43 Stack project without user packages or private dependencies",
        );
        add_change_if_needed(
            context,
            current,
            &mut changes,
            verification_system,
            b"{}\n".to_vec(),
            "create an empty Stack system config so verification is isolated from host policy",
        );
        add_change_if_needed(
            context,
            current,
            &mut changes,
            verification_cabal,
            render_verification_cabal().into_bytes(),
            "create a minimal local package that requires fixed StateVar 1.2.2",
        );
        add_change_if_needed(
            context,
            current,
            &mut changes,
            verification_module,
            b"module MirrorSwitchVerification where\n".to_vec(),
            "create the minimal module used by Stack dependency resolution",
        );
        Ok(ChangePlan {
            adapter_key: "stack".into(),
            tool_id: "stack".into(),
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
            let snapshot = stack_snapshot(context, runtime)?;
            let known = [
                rooted(&context.root, &snapshot.user_config),
                snapshot
                    .project_config
                    .as_ref()
                    .map(|path| rooted(&context.root, path))
                    .unwrap_or_default(),
                rooted(&context.root, &snapshot.verification_config),
                rooted(&context.root, &snapshot.verification_project),
                rooted(&context.root, &snapshot.verification_system),
                rooted(&context.root, &snapshot.verification_cabal),
                rooted(&context.root, &snapshot.verification_module),
            ];
            if receipt
                .changed_targets
                .iter()
                .all(|target| !known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Stack transaction receipt contains no known target".into(),
                ));
            }
            let verification = read_document(
                runtime,
                &snapshot.verification_config,
                "Stack verification config",
            )?;
            let parsed = parse_yaml(&verification.path, &verification.contents)?;
            let endpoints = reviewed_effective_endpoints(&parsed)?;
            if verification.contents != render_managed_config(&endpoints).as_bytes() {
                return Err(AdapterError::Verification(
                    "Stack verification config is not canonical".into(),
                ));
            }
            let project = read_document(
                runtime,
                &snapshot.verification_project,
                "Stack verification project",
            )?;
            if project.contents != render_verification_project().as_bytes() {
                return Err(AdapterError::Verification(
                    "Stack verification project is not canonical".into(),
                ));
            }
            let system = read_document(
                runtime,
                &snapshot.verification_system,
                "Stack verification system config",
            )?;
            if system.contents != b"{}\n" {
                return Err(AdapterError::Verification(
                    "Stack verification system config is not canonical".into(),
                ));
            }
            let cabal = read_document(
                runtime,
                &snapshot.verification_cabal,
                "Stack verification Cabal package",
            )?;
            if cabal.contents != render_verification_cabal().as_bytes() {
                return Err(AdapterError::Verification(
                    "Stack verification Cabal package is not canonical".into(),
                ));
            }
            let module = read_document(
                runtime,
                &snapshot.verification_module,
                "Stack verification Haskell module",
            )?;
            if module.contents != b"module MirrorSwitchVerification where\n" {
                return Err(AdapterError::Verification(
                    "Stack verification Haskell module is not canonical".into(),
                ));
            }
            let root = snapshot
                .verification_config
                .parent()
                .ok_or_else(|| {
                    AdapterError::Verification("invalid Stack verification path".into())
                })?
                .join("root");
            let environment = stack_verification_environment(
                &root,
                &verification.path,
                &system.path,
                &project.path,
            )?;
            let removed_environment = vec!["STACK_XDG".into()];
            let common = vec!["--no-terminal".into()];
            let mut dependency_arguments = common.clone();
            dependency_arguments.extend([
                "ls".into(),
                "dependencies".into(),
                "--global-hints".into(),
            ]);
            let dependencies = run_program_in(
                runtime,
                &project.path,
                "stack",
                &dependency_arguments,
                &environment,
                &removed_environment,
                "Stack fixed snapshot/global-hints dependency resolution",
            )?;
            for marker in ["StateVar 1.2.2", "base 4.18.2.1"] {
                if !dependencies.contains(marker) {
                    return Err(AdapterError::Verification(format!(
                        "Stack dependency resolution did not report {marker}"
                    )));
                }
            }
            let destination = snapshot
                .verification_config
                .parent()
                .ok_or_else(|| {
                    AdapterError::Verification("invalid Stack verification path".into())
                })?
                .join("source")
                .join(&receipt.transaction_id);
            let mut unpack_arguments = common;
            unpack_arguments.extend([
                "unpack".into(),
                VERIFY_PACKAGE_ID.into(),
                "--to".into(),
                path_string(&destination)?,
            ]);
            run_program_in(
                runtime,
                &project.path,
                "stack",
                &unpack_arguments,
                &environment,
                &removed_environment,
                "Stack fixed Hackage package resolution",
            )?;
            let package_file = destination
                .join(VERIFY_PACKAGE_ID)
                .join(format!("{VERIFY_PACKAGE}.cabal"));
            let package = runtime.read(&package_file)?.ok_or_else(|| {
                AdapterError::Verification(
                    "Stack unpack did not extract the fixed verification package".into(),
                )
            })?;
            let package = utf8(&package_file, &package)?;
            if !package.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case(&format!("name: {VERIFY_PACKAGE}"))
            }) || !package.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case(&format!("version: {VERIFY_VERSION}"))
            }) {
                return Err(AdapterError::Verification(
                    "fixed verification package metadata is inconsistent".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Stack {} resolved {VERIFY_SNAPSHOT}/{VERIFY_COMPILER} and unpacked {VERIFY_PACKAGE_ID}; catalog gates snapshot {SNAPSHOT_SHA256}, global hints {GLOBAL_HINTS_SHA256}, Hackage package {HACKAGE_TARBALL_SHA256}, and the host-architecture GHC bindist",
                    snapshot.version
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
                "restored {} Stack configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy)]
struct ReviewedStackage {
    provider: &'static str,
    index: &'static str,
    metadata: &'static str,
    artifacts: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StackSnapshot {
    version: String,
    user_home: PathBuf,
    project_dir: Option<PathBuf>,
    stack_root: PathBuf,
    system_config: Option<PathBuf>,
    user_config: PathBuf,
    project_config: Option<PathBuf>,
    verification_config: PathBuf,
    verification_project: PathBuf,
    verification_system: PathBuf,
    verification_cabal: PathBuf,
    verification_module: PathBuf,
}

#[derive(Clone, Debug)]
struct TextDocument {
    path: PathBuf,
    exists: bool,
    contents: Vec<u8>,
}

struct StackDocuments {
    system: Option<TextDocument>,
    user: TextDocument,
    project: Option<TextDocument>,
}

impl StackDocuments {
    fn documents(&self) -> impl Iterator<Item = &TextDocument> {
        self.system
            .iter()
            .chain(std::iter::once(&self.user))
            .chain(self.project.iter())
    }
}

#[derive(Clone, Debug)]
struct ParsedYaml {
    contents: String,
    blocks: Vec<YamlBlock>,
    managed: ManagedValues,
}

#[derive(Clone, Debug)]
struct YamlBlock {
    key: String,
    end: usize,
    header_end: usize,
    value: Option<YamlScalar>,
}

#[derive(Clone, Debug, Default)]
struct ManagedValues {
    latest_snapshot: Option<YamlScalar>,
    snapshot_base: Option<YamlScalar>,
    global_hints: Option<YamlScalar>,
    setup_info: Option<YamlScalar>,
    hackage_prefix: Option<YamlScalar>,
}

#[derive(Clone, Debug)]
struct YamlScalar {
    value: String,
    range: Range<usize>,
    quote: Option<char>,
}

#[derive(Clone, Debug)]
struct LineInfo {
    start: usize,
    full_end: usize,
    indent: usize,
    active_end: usize,
    key: Option<String>,
    value: Option<YamlScalar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedEndpoints {
    stackage_index: String,
    global_hints: String,
    setup_info: String,
    hackage: String,
}

fn stack_snapshot(
    context: &SystemContext,
    runtime: &dyn Runtime,
) -> Result<StackSnapshot, AdapterError> {
    let output = run_program(
        runtime,
        "stack",
        &["--numeric-version"],
        "stack --numeric-version",
    )?;
    let version = output
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| AdapterError::Unsupported("Stack returned an empty version".into()))?
        .to_owned();
    reviewed_stack_version(&version)?;
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Stack user home is unavailable".into()))?;
    validate_path(&home, "Stack user home")?;
    let project_dir = runtime.project_dir();
    if let Some(project) = &project_dir {
        validate_path(project, "Stack project directory")?;
    }
    let system_config = if let Some(value) = nonempty_environment(runtime, "STACK_GLOBAL_CONFIG") {
        Some(absolute_environment_path(&value, "STACK_GLOBAL_CONFIG")?)
    } else if context.os == OperatingSystem::Windows {
        None
    } else {
        let legacy = PathBuf::from("/etc/stack/config");
        if runtime.read(&legacy)?.is_some() {
            Some(legacy)
        } else {
            Some(PathBuf::from("/etc/stack/config.yaml"))
        }
    };
    let explicit_root = nonempty_environment(runtime, "STACK_ROOT");
    let use_xdg = explicit_root.is_none() && nonempty_environment(runtime, "STACK_XDG").is_some();
    let stack_root = if let Some(value) = explicit_root.as_deref() {
        environment_user_path(context, runtime, &home, value, "STACK_ROOT")?
    } else if use_xdg {
        let data = match nonempty_environment(runtime, "XDG_DATA_HOME") {
            Some(value) => environment_user_path(context, runtime, &home, &value, "XDG_DATA_HOME")?,
            None if context.os == OperatingSystem::Windows => windows_app_data(runtime)?,
            None => home.join(".local/share"),
        };
        data.join("stack")
    } else if context.os == OperatingSystem::Windows {
        windows_app_data(runtime)?.join("stack")
    } else {
        home.join(".stack")
    };
    let user_config = if let Some(value) = nonempty_environment(runtime, "STACK_CONFIG") {
        environment_user_path(context, runtime, &home, &value, "STACK_CONFIG")?
    } else if explicit_root.is_some() {
        stack_root.join("config.yaml")
    } else if use_xdg {
        let xdg = match nonempty_environment(runtime, "XDG_CONFIG_HOME") {
            Some(value) => {
                environment_user_path(context, runtime, &home, &value, "XDG_CONFIG_HOME")?
            }
            None if context.os == OperatingSystem::Windows => windows_app_data(runtime)?,
            None => home.join(".config"),
        };
        xdg.join("stack/config.yaml")
    } else {
        stack_root.join("config.yaml")
    };
    validate_user_config_path(context, runtime, &home, &user_config)?;
    let project_config = project_config_path(runtime)?;
    let verification = home.join(".mirrorswitch/verification/stack");
    validate_user_path(&home, &verification, "Stack verification root")?;
    Ok(StackSnapshot {
        version,
        user_home: home,
        project_dir,
        stack_root,
        system_config,
        user_config,
        project_config,
        verification_config: verification.join("config.yaml"),
        verification_project: verification.join("stack.yaml"),
        verification_system: verification.join("system.yaml"),
        verification_cabal: verification.join("mirrorswitch-stack-verification.cabal"),
        verification_module: verification.join("src/MirrorSwitchVerification.hs"),
    })
}

fn project_config_path(runtime: &dyn Runtime) -> Result<Option<PathBuf>, AdapterError> {
    let Some(project_dir) = runtime.project_dir() else {
        return Ok(None);
    };
    validate_path(&project_dir, "Stack project directory")?;
    if let Some(value) = nonempty_environment(runtime, "STACK_YAML") {
        let candidate = PathBuf::from(value);
        let path = if candidate.is_absolute() {
            candidate
        } else {
            project_dir.join(candidate)
        };
        validate_project_path(&project_dir, &path, "STACK_YAML")?;
        if runtime.read(&path)?.is_none() {
            return Err(AdapterError::Unsupported(format!(
                "STACK_YAML selects missing file {}",
                path.display()
            )));
        }
        return Ok(Some(path));
    }
    let mut directory = project_dir.clone();
    loop {
        let candidate = directory.join("stack.yaml");
        if runtime.read(&candidate)?.is_some() {
            validate_project_path(&directory, &candidate, "Stack project config")?;
            return Ok(Some(candidate));
        }
        let Some(parent) = directory.parent() else {
            return Ok(None);
        };
        if parent == directory {
            return Ok(None);
        }
        directory = parent.to_path_buf();
    }
}

fn read_documents(
    runtime: &dyn Runtime,
    snapshot: &StackSnapshot,
) -> Result<StackDocuments, AdapterError> {
    Ok(StackDocuments {
        system: snapshot
            .system_config
            .as_ref()
            .map(|path| read_document(runtime, path, "Stack system config"))
            .transpose()?,
        user: read_document(runtime, &snapshot.user_config, "Stack user config")?,
        project: snapshot
            .project_config
            .as_ref()
            .map(|path| read_document(runtime, path, "Stack project config"))
            .transpose()?,
    })
}

fn read_document(
    runtime: &dyn Runtime,
    path: &Path,
    label: &str,
) -> Result<TextDocument, AdapterError> {
    let observed = runtime.read(path)?;
    let exists = observed.is_some();
    let contents = observed.unwrap_or_default();
    if contents.contains(&0) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} {} contains NUL bytes",
            path.display()
        )));
    }
    utf8(path, &contents)?;
    Ok(TextDocument {
        path: path.to_path_buf(),
        exists,
        contents,
    })
}

fn parse_yaml(path: &Path, contents: &[u8]) -> Result<ParsedYaml, AdapterError> {
    let text = utf8(path, contents)?.to_owned();
    if text.contains('\t') {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} contains tabs and cannot be rewritten safely",
            path.display()
        )));
    }
    let lines = yaml_lines(path, &text)?;
    let mut top_lines = Vec::new();
    let mut keys = BTreeSet::new();
    let mut saw_content = false;
    for (index, line) in lines.iter().enumerate() {
        let active = text[line.start..line.active_end].trim();
        if active.is_empty() {
            continue;
        }
        if active == "---" && !saw_content {
            saw_content = true;
            continue;
        }
        if active == "---" || active == "..." || active.starts_with('%') {
            return Err(AdapterError::Unsupported(format!(
                "Stack YAML {} contains multiple documents or directives",
                path.display()
            )));
        }
        saw_content = true;
        if line.indent == 0 {
            let key = line.key.as_ref().ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "Stack YAML {} has a complex top-level value",
                    path.display()
                ))
            })?;
            if !keys.insert(key.clone()) {
                return Err(AdapterError::Unsupported(format!(
                    "Stack YAML {} contains duplicate key {key}",
                    path.display()
                )));
            }
            top_lines.push(index);
        }
    }
    let mut blocks = Vec::new();
    for (position, line_index) in top_lines.iter().enumerate() {
        let line = &lines[*line_index];
        blocks.push(YamlBlock {
            key: line.key.clone().expect("top-level keys were checked"),
            end: top_lines
                .get(position + 1)
                .map_or(text.len(), |next| lines[*next].start),
            header_end: line.full_end,
            value: line.value.clone(),
        });
    }
    validate_unsafe_yaml(path, &text, &lines, &blocks)?;
    let managed = parse_managed(path, &text, &lines, &blocks)?;
    Ok(ParsedYaml {
        contents: text,
        blocks,
        managed,
    })
}

fn yaml_lines(path: &Path, text: &str) -> Result<Vec<LineInfo>, AdapterError> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let newline = text[start..]
            .find('\n')
            .map_or(text.len(), |offset| start + offset);
        let end = if newline > start && text.as_bytes()[newline - 1] == b'\r' {
            newline - 1
        } else {
            newline
        };
        let full_end = if newline < text.len() {
            newline + 1
        } else {
            newline
        };
        let raw = &text[start..end];
        let indent = raw.bytes().take_while(|byte| *byte == b' ').count();
        let comment = yaml_comment_offset(raw);
        let active = raw[..comment].trim_end();
        let active_end = start + active.len();
        let trimmed = active.trim_start();
        let (key, value) = if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            (None, None)
        } else if let Some(colon) = mapping_colon(trimmed) {
            let raw_key = trimmed[..colon].trim();
            if !valid_yaml_key(raw_key) {
                (None, None)
            } else {
                let value_start_in_trimmed = colon
                    + 1
                    + trimmed[colon + 1..]
                        .bytes()
                        .take_while(|byte| *byte == b' ')
                        .count();
                let raw_value = trimmed[value_start_in_trimmed..].trim_end();
                let scalar = if raw_value.is_empty() {
                    None
                } else {
                    let absolute = start + indent + value_start_in_trimmed;
                    Some(parse_scalar(path, raw_key, raw_value, absolute)?)
                };
                (Some(raw_key.to_owned()), scalar)
            }
        } else {
            (None, None)
        };
        lines.push(LineInfo {
            start,
            full_end,
            indent,
            active_end,
            key,
            value,
        });
        if full_end == text.len() {
            break;
        }
        start = full_end;
    }
    Ok(lines)
}

fn yaml_comment_offset(line: &str) -> usize {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if double => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single
                && !double
                && (index == 0 || line.as_bytes()[index - 1].is_ascii_whitespace()) =>
            {
                return index;
            }
            _ => {}
        }
    }
    line.len()
}

fn mapping_colon(value: &str) -> Option<usize> {
    let mut single = false;
    let mut double = false;
    for (index, character) in value.char_indices() {
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            ':' if !single && !double => return Some(index),
            _ => {}
        }
    }
    None
}

fn valid_yaml_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn parse_scalar(
    path: &Path,
    key: &str,
    value: &str,
    start: usize,
) -> Result<YamlScalar, AdapterError> {
    if value.starts_with(['&', '*', '!']) {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} uses a dynamic or complex value for {key}",
            path.display()
        )));
    }
    let quote = value
        .chars()
        .next()
        .filter(|character| matches!(character, '\'' | '"'));
    let decoded = match quote {
        Some(quote) => {
            if value.len() < 2 || !value.ends_with(quote) {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Stack YAML {} has an unterminated scalar for {key}",
                    path.display()
                )));
            }
            let inner = &value[1..value.len() - 1];
            if inner.contains(quote) || inner.contains('\\') {
                return Err(AdapterError::Unsupported(format!(
                    "Stack YAML {} uses escaped syntax for {key}",
                    path.display()
                )));
            }
            inner.to_owned()
        }
        None => value.to_owned(),
    };
    Ok(YamlScalar {
        value: decoded,
        range: start..start + value.len(),
        quote,
    })
}

fn validate_unsafe_yaml(
    path: &Path,
    text: &str,
    lines: &[LineInfo],
    blocks: &[YamlBlock],
) -> Result<(), AdapterError> {
    for line in lines {
        let active = text[line.start..line.active_end].trim();
        if active.starts_with("<<:")
            || active.contains("!include")
            || active
                .split_ascii_whitespace()
                .any(|token| token.starts_with('&'))
        {
            return Err(AdapterError::Unsupported(format!(
                "Stack YAML {} uses include, anchor, tag or merge syntax",
                path.display()
            )));
        }
        if let (Some(key), Some(value)) = (&line.key, &line.value) {
            if matches!(
                key.as_str(),
                "ignore-expiry"
                    | "http-no-tls"
                    | "insecure"
                    | "disable-checksum-validation"
                    | "no-check-certificate"
            ) && value.value.eq_ignore_ascii_case("true")
            {
                return Err(AdapterError::Unsupported(format!(
                    "Stack YAML {} disables transport, expiry or checksum verification",
                    path.display()
                )));
            }
        }
    }
    if blocks.iter().any(|block| block.key == "package-indices") {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} uses deprecated package-indices",
            path.display()
        )));
    }
    if blocks.iter().any(|block| block.key == "setup-info") {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} contains inline setup-info",
            path.display()
        )));
    }
    Ok(())
}

fn parse_managed(
    path: &Path,
    text: &str,
    lines: &[LineInfo],
    blocks: &[YamlBlock],
) -> Result<ManagedValues, AdapterError> {
    let mut managed = ManagedValues::default();
    if let Some(block) = block(blocks, "urls") {
        require_mapping_block(path, block)?;
        managed.latest_snapshot = child_scalar(path, text, lines, block, "latest-snapshot")?;
    }
    if let Some(block) = block(blocks, "snapshot-location-base") {
        managed.snapshot_base = Some(required_block_scalar(path, block)?);
    }
    if let Some(block) = block(blocks, "global-hints-location") {
        require_mapping_block(path, block)?;
        managed.global_hints = child_scalar(path, text, lines, block, "url")?;
    }
    if let Some(block) = block(blocks, "setup-info-locations") {
        require_mapping_block(path, block)?;
        managed.setup_info = sequence_scalar(path, text, lines, block)?;
    }
    if let Some(block) = block(blocks, "package-index") {
        require_mapping_block(path, block)?;
        managed.hackage_prefix = child_scalar(path, text, lines, block, "download-prefix")?;
    }
    Ok(managed)
}

fn block<'a>(blocks: &'a [YamlBlock], key: &str) -> Option<&'a YamlBlock> {
    blocks.iter().find(|block| block.key == key)
}

fn require_mapping_block(path: &Path, block: &YamlBlock) -> Result<(), AdapterError> {
    if block.value.is_some() {
        Err(AdapterError::Unsupported(format!(
            "Stack YAML {} uses inline syntax for {}",
            path.display(),
            block.key
        )))
    } else {
        Ok(())
    }
}

fn required_block_scalar(path: &Path, block: &YamlBlock) -> Result<YamlScalar, AdapterError> {
    block.value.clone().ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "Stack YAML {} has a complex value for {}",
            path.display(),
            block.key
        ))
    })
}

fn child_scalar(
    path: &Path,
    text: &str,
    lines: &[LineInfo],
    block: &YamlBlock,
    key: &str,
) -> Result<Option<YamlScalar>, AdapterError> {
    let children = lines
        .iter()
        .filter(|line| line.start >= block.header_end && line.start < block.end)
        .filter(|line| !text[line.start..line.active_end].trim().is_empty())
        .collect::<Vec<_>>();
    let Some(indent) = children.iter().map(|line| line.indent).min() else {
        return Ok(None);
    };
    let matches = children
        .into_iter()
        .filter(|line| line.indent == indent && line.key.as_deref() == Some(key))
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} contains duplicate {}.{}",
            path.display(),
            block.key,
            key
        )));
    }
    matches
        .first()
        .map(|line| {
            line.value.clone().ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "Stack YAML {} has a complex value for {}.{key}",
                    path.display(),
                    block.key
                ))
            })
        })
        .transpose()
}

fn sequence_scalar(
    path: &Path,
    text: &str,
    lines: &[LineInfo],
    block: &YamlBlock,
) -> Result<Option<YamlScalar>, AdapterError> {
    let entries = lines
        .iter()
        .filter(|line| line.start >= block.header_end && line.start < block.end)
        .filter_map(|line| {
            let active = text[line.start..line.active_end].trim();
            active.strip_prefix("- ").map(|value| (line, value.trim()))
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() != 1 {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} has multiple setup-info locations and cannot preserve priority safely",
            path.display()
        )));
    }
    let (line, value) = entries[0];
    if value.is_empty() || value.starts_with(['{', '[', '&', '*', '!']) {
        return Err(AdapterError::Unsupported(format!(
            "Stack YAML {} contains complex setup-info",
            path.display()
        )));
    }
    let value_start = line.start
        + text[line.start..line.active_end]
            .find(value)
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("setup-info range is invalid".into())
            })?;
    parse_scalar(path, "setup-info-locations", value, value_start).map(Some)
}

fn validate_managed_values(parsed: &ParsedYaml) -> Result<(), AdapterError> {
    for (kind, scalar) in [
        ("latest snapshot", parsed.managed.latest_snapshot.as_ref()),
        ("snapshot base", parsed.managed.snapshot_base.as_ref()),
        ("global hints", parsed.managed.global_hints.as_ref()),
        ("setup info", parsed.managed.setup_info.as_ref()),
        ("Hackage prefix", parsed.managed.hackage_prefix.as_ref()),
    ] {
        if let Some(scalar) = scalar {
            validate_public_url(kind, &scalar.value)?;
        }
    }
    Ok(())
}

fn validate_public_url(kind: &str, value: &str) -> Result<(), AdapterError> {
    let normalized = normalized_url(value).ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "Stack {kind} is credential-bearing, dynamic or not an HTTP(S) URL"
        ))
    })?;
    let reviewed = REVIEWED_STACKAGE.iter().any(|item| {
        [
            normalized_url(item.index).unwrap(),
            normalized_url(item.metadata).unwrap(),
            normalized_url(item.artifacts).unwrap(),
            normalized_url(&format!("{}snapshots.json", item.index)).unwrap(),
            normalized_url(&format!("{}stackage-snapshots", item.index)).unwrap(),
            normalized_url(&format!("{}global-hints.yaml", item.metadata)).unwrap(),
            normalized_url(&format!("{}stack-setup.yaml", item.artifacts)).unwrap(),
        ]
        .contains(&normalized)
    }) || REVIEWED_HACKAGE
        .iter()
        .any(|(_, endpoint)| normalized_url(endpoint).as_deref() == Some(normalized.as_str()))
        || OFFICIAL_STACKAGE.contains(&normalized.as_str())
        || OFFICIAL_HACKAGE.contains(&normalized.as_str());
    if reviewed {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "Stack {kind} points to an unreviewed endpoint"
        )))
    }
}

fn has_managed_values(parsed: &ParsedYaml) -> bool {
    parsed
        .blocks
        .iter()
        .any(|block| MANAGED_TOP_LEVEL.contains(&block.key.as_str()))
}

fn project_locator(parsed: &ParsedYaml) -> &'static str {
    if block(&parsed.blocks, "snapshot").is_some() {
        "snapshot preserved"
    } else if block(&parsed.blocks, "resolver").is_some() {
        "resolver preserved"
    } else {
        "no explicit snapshot/resolver"
    }
}

fn private_reference_count(parsed: &ParsedYaml) -> usize {
    parsed
        .blocks
        .iter()
        .filter(|block| {
            matches!(
                block.key.as_str(),
                "extra-deps" | "packages" | "extra-package-dbs"
            )
        })
        .count()
}

fn configured_sources(parsed: &ParsedYaml, path: &Path) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    for (upstream, kind, scalar) in [
        (
            Some(STACKAGE_UPSTREAM),
            "latest-snapshot",
            parsed.managed.latest_snapshot.as_ref(),
        ),
        (
            Some(STACKAGE_UPSTREAM),
            "snapshot-base",
            parsed.managed.snapshot_base.as_ref(),
        ),
        (
            Some(STACKAGE_UPSTREAM),
            "global-hints",
            parsed.managed.global_hints.as_ref(),
        ),
        (
            Some(STACKAGE_UPSTREAM),
            "setup-info",
            parsed.managed.setup_info.as_ref(),
        ),
        (
            Some(HACKAGE_UPSTREAM),
            "hackage-prefix",
            parsed.managed.hackage_prefix.as_ref(),
        ),
    ] {
        if let Some(scalar) = scalar {
            sources.push(ConfiguredSource {
                upstream_id: upstream.map(str::to_owned),
                url: normalized_url(&scalar.value)
                    .unwrap_or_else(|| "stack-policy:unreviewed".into()),
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec![kind.into()]),
                    ("path".into(), vec![path.display().to_string()]),
                ]),
            });
        }
    }
    if block(&parsed.blocks, "snapshot").is_some() || block(&parsed.blocks, "resolver").is_some() {
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: "stack-project:snapshot-or-resolver-preserved".into(),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["project-snapshot-policy".into()]),
                ("path".into(), vec![path.display().to_string()]),
            ]),
        });
    }
    sources
}

fn rewrite_config(
    parsed: &ParsedYaml,
    endpoints: &SelectedEndpoints,
) -> Result<String, AdapterError> {
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut append = String::new();
    replace_or_insert_child(
        parsed,
        "urls",
        "latest-snapshot",
        &format!("{}snapshots.json", endpoints.stackage_index),
        &mut edits,
        &mut append,
    )?;
    replace_or_append_scalar(
        parsed,
        "snapshot-location-base",
        &format!("{}stackage-snapshots/", endpoints.stackage_index),
        &mut edits,
        &mut append,
    );
    replace_or_insert_child(
        parsed,
        "global-hints-location",
        "url",
        &endpoints.global_hints,
        &mut edits,
        &mut append,
    )?;
    if let Some(scalar) = &parsed.managed.setup_info {
        edits.push((
            scalar.range.clone(),
            quoted_value(&endpoints.setup_info, scalar.quote),
        ));
    } else if block(&parsed.blocks, "setup-info-locations").is_some() {
        let block = block(&parsed.blocks, "setup-info-locations").unwrap();
        edits.push((
            block.end..block.end,
            nested_insertion(
                &parsed.contents,
                block.end,
                &format!("  - {}", endpoints.setup_info),
            ),
        ));
    } else {
        append.push_str(&format!(
            "setup-info-locations:\n  - {}\n",
            endpoints.setup_info
        ));
    }
    replace_or_insert_child(
        parsed,
        "package-index",
        "download-prefix",
        &endpoints.hackage,
        &mut edits,
        &mut append,
    )?;
    let mut rendered = parsed.contents.clone();
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0.start));
    for (range, replacement) in edits {
        if range.end > rendered.len() || range.start > range.end {
            return Err(AdapterError::InvalidConfiguration(
                "Stack YAML replacement range is invalid".into(),
            ));
        }
        rendered.replace_range(range, &replacement);
    }
    if !append.is_empty() {
        if !rendered.is_empty() && !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        if !rendered.is_empty() && !rendered.ends_with("\n\n") {
            rendered.push('\n');
        }
        rendered.push_str(&append);
    }
    if parsed.contents.contains("\r\n") {
        rendered = rendered.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    Ok(rendered)
}

fn replace_or_insert_child(
    parsed: &ParsedYaml,
    parent: &str,
    child: &str,
    value: &str,
    edits: &mut Vec<(Range<usize>, String)>,
    append: &mut String,
) -> Result<(), AdapterError> {
    let scalar = match (parent, child) {
        ("urls", "latest-snapshot") => parsed.managed.latest_snapshot.as_ref(),
        ("global-hints-location", "url") => parsed.managed.global_hints.as_ref(),
        ("package-index", "download-prefix") => parsed.managed.hackage_prefix.as_ref(),
        _ => None,
    };
    if let Some(scalar) = scalar {
        edits.push((scalar.range.clone(), quoted_value(value, scalar.quote)));
    } else if let Some(block) = block(&parsed.blocks, parent) {
        edits.push((
            block.end..block.end,
            nested_insertion(&parsed.contents, block.end, &format!("  {child}: {value}")),
        ));
    } else {
        append.push_str(&format!("{parent}:\n  {child}: {value}\n"));
    }
    Ok(())
}

fn replace_or_append_scalar(
    parsed: &ParsedYaml,
    key: &str,
    value: &str,
    edits: &mut Vec<(Range<usize>, String)>,
    append: &mut String,
) {
    if let Some(scalar) = &parsed.managed.snapshot_base {
        edits.push((scalar.range.clone(), quoted_value(value, scalar.quote)));
    } else {
        append.push_str(&format!("{key}: {value}\n"));
    }
}

fn nested_insertion(text: &str, position: usize, line: &str) -> String {
    let prefix = if position > 0 && !text[..position].ends_with('\n') {
        "\n"
    } else {
        ""
    };
    format!("{prefix}{line}\n")
}

fn quoted_value(value: &str, quote: Option<char>) -> String {
    quote.map_or_else(|| value.into(), |quote| format!("{quote}{value}{quote}"))
}

fn render_managed_config(endpoints: &SelectedEndpoints) -> String {
    format!(
        "urls:\n  latest-snapshot: {index}snapshots.json\nsnapshot-location-base: {index}stackage-snapshots/\nglobal-hints-location:\n  url: {hints}\nsetup-info-locations:\n  - {setup}\npackage-index:\n  download-prefix: {hackage}\n",
        index = endpoints.stackage_index,
        hints = endpoints.global_hints,
        setup = endpoints.setup_info,
        hackage = endpoints.hackage,
    )
}

fn render_verification_project() -> String {
    format!("snapshot: {VERIFY_SNAPSHOT}\npackages:\n  - .\nextra-deps: []\n")
}

fn render_verification_cabal() -> String {
    format!(
        "cabal-version: 2.4\nname: mirrorswitch-stack-verification\nversion: 0.0.0\nlibrary\n  exposed-modules: MirrorSwitchVerification\n  build-depends: base, {VERIFY_PACKAGE} == {VERIFY_VERSION}\n  hs-source-dirs: src\n  default-language: Haskell2010\n"
    )
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<SelectedEndpoints, AdapterError> {
    if selections.len() != 2 {
        return Err(AdapterError::InvalidConfiguration(
            "Stack requires one Stackage selection and one Hackage selection".into(),
        ));
    }
    let stackage = selections
        .iter()
        .find(|selection| {
            selection.tool_id == "stack" && selection.upstream_id == STACKAGE_UPSTREAM
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Stack Stackage selection is missing".into())
        })?;
    let hackage = selections
        .iter()
        .find(|selection| selection.tool_id == "stack" && selection.upstream_id == HACKAGE_UPSTREAM)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Stack Hackage selection is missing".into())
        })?;
    let reviewed = REVIEWED_STACKAGE
        .iter()
        .find(|item| item.provider == stackage.provider_id)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Stack selection uses an unreviewed Stackage provider".into(),
            )
        })?;
    let index = unique_endpoint(stackage, EndpointRole::Index)?;
    let metadata = unique_endpoint(stackage, EndpointRole::Metadata)?;
    let artifacts = unique_endpoint(stackage, EndpointRole::Artifacts)?;
    if normalized_url(index).as_deref() != normalized_url(reviewed.index).as_deref()
        || normalized_url(metadata).as_deref() != normalized_url(reviewed.metadata).as_deref()
        || normalized_url(artifacts).as_deref() != normalized_url(reviewed.artifacts).as_deref()
    {
        return Err(AdapterError::InvalidConfiguration(
            "Stack Stackage roles do not match one reviewed provider layout".into(),
        ));
    }
    let reviewed_hackage = REVIEWED_HACKAGE
        .iter()
        .find(|(provider, _)| *provider == hackage.provider_id)
        .map(|(_, endpoint)| *endpoint)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Stack selection uses an unreviewed Hackage provider".into(),
            )
        })?;
    for role in [
        EndpointRole::Metadata,
        EndpointRole::Index,
        EndpointRole::Artifacts,
    ] {
        if normalized_url(unique_endpoint(hackage, role)?).as_deref()
            != normalized_url(reviewed_hackage).as_deref()
        {
            return Err(AdapterError::InvalidConfiguration(
                "Stack Hackage roles do not match one reviewed secure repository".into(),
            ));
        }
    }
    Ok(SelectedEndpoints {
        stackage_index: ensure_trailing_slash(reviewed.index),
        global_hints: format!(
            "{}global-hints.yaml",
            ensure_trailing_slash(reviewed.metadata)
        ),
        setup_info: format!(
            "{}stack-setup.yaml",
            ensure_trailing_slash(reviewed.artifacts)
        ),
        hackage: ensure_trailing_slash(reviewed_hackage),
    })
}

fn reviewed_effective_endpoints(parsed: &ParsedYaml) -> Result<SelectedEndpoints, AdapterError> {
    let latest = parsed
        .managed
        .latest_snapshot
        .as_ref()
        .ok_or_else(|| AdapterError::Verification("latest snapshot is missing".into()))?;
    let snapshot = parsed
        .managed
        .snapshot_base
        .as_ref()
        .ok_or_else(|| AdapterError::Verification("snapshot base is missing".into()))?;
    let hints = parsed
        .managed
        .global_hints
        .as_ref()
        .ok_or_else(|| AdapterError::Verification("global hints are missing".into()))?;
    let setup = parsed
        .managed
        .setup_info
        .as_ref()
        .ok_or_else(|| AdapterError::Verification("setup info is missing".into()))?;
    let hackage = parsed
        .managed
        .hackage_prefix
        .as_ref()
        .ok_or_else(|| AdapterError::Verification("Hackage prefix is missing".into()))?;
    let stackage = REVIEWED_STACKAGE
        .iter()
        .find(|item| {
            normalized_url(&latest.value)
                == normalized_url(&format!("{}snapshots.json", item.index))
                && normalized_url(&snapshot.value)
                    == normalized_url(&format!("{}stackage-snapshots/", item.index))
                && normalized_url(&hints.value)
                    == normalized_url(&format!("{}global-hints.yaml", item.metadata))
                && normalized_url(&setup.value)
                    == normalized_url(&format!("{}stack-setup.yaml", item.artifacts))
        })
        .ok_or_else(|| {
            AdapterError::Verification(
                "Stack verification config does not use one reviewed Stackage layout".into(),
            )
        })?;
    let hackage = REVIEWED_HACKAGE
        .iter()
        .find(|(_, endpoint)| normalized_url(&hackage.value) == normalized_url(endpoint))
        .map(|(_, endpoint)| *endpoint)
        .ok_or_else(|| {
            AdapterError::Verification(
                "Stack verification config does not use a reviewed Hackage layout".into(),
            )
        })?;
    Ok(SelectedEndpoints {
        stackage_index: ensure_trailing_slash(stackage.index),
        global_hints: format!(
            "{}global-hints.yaml",
            ensure_trailing_slash(stackage.metadata)
        ),
        setup_info: format!(
            "{}stack-setup.yaml",
            ensure_trailing_slash(stackage.artifacts)
        ),
        hackage: ensure_trailing_slash(hackage),
    })
}

fn unique_endpoint(selection: &MirrorSelection, role: EndpointRole) -> Result<&str, AdapterError> {
    let matches = selection
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Stack selection requires exactly one {role:?} HTTPS endpoint"
        )));
    }
    Ok(&matches[0].url)
}

fn stack_toolchain(context: &SystemContext) -> (&'static str, &'static str) {
    match (context.os, context.architecture) {
        (OperatingSystem::Linux, Architecture::X86_64) => (
            "ghc-9.6.6-x86_64-deb9-linux.tar.xz",
            "ff5b4929a4e89c536e7badb3b142e353dc4bda1f31d3ee446406ad88c3bebddf",
        ),
        (OperatingSystem::Linux, Architecture::Arm64) => (
            "ghc-9.6.6-aarch64-deb10-linux.tar.xz",
            "58d5ce65758ec5179b448e4e1a2f835924b4ada96cf56af80d011bed87d91fef",
        ),
        (OperatingSystem::Macos, Architecture::X86_64) => (
            "ghc-9.6.6-x86_64-apple-darwin.tar.bz2",
            "951d1b5ed47fc25a782014befccb82699fcbe585265bd2c6c1a4e0163a2a6dff",
        ),
        (OperatingSystem::Macos, Architecture::Arm64) => (
            "ghc-9.6.6-aarch64-apple-darwin.tar.bz2",
            "c812e10db846185ea576619b3454151604531b0c14791ac1d368439e755be613",
        ),
        (OperatingSystem::Windows, Architecture::X86_64) => (
            "ghc-9.6.6-x86_64-unknown-mingw32.tar.xz",
            "fc12b7bfc78e69c8c7ebcb9f874f868665e5744df1af73e71cf5224c32d9c6e4",
        ),
        (OperatingSystem::Windows, Architecture::Arm64) => {
            unreachable!("Windows arm64 is rejected before Stack candidate selection")
        }
    }
}

fn stack_verification_environment(
    root: &Path,
    config: &Path,
    system: &Path,
    project: &Path,
) -> Result<BTreeMap<String, String>, AdapterError> {
    Ok(BTreeMap::from([
        ("STACK_ROOT".into(), path_string(root)?),
        ("STACK_CONFIG".into(), path_string(config)?),
        ("STACK_GLOBAL_CONFIG".into(), path_string(system)?),
        ("STACK_YAML".into(), path_string(project)?),
        ("NO_COLOR".into(), "1".into()),
    ]))
}

fn add_change_if_needed(
    context: &SystemContext,
    current: &CurrentConfiguration,
    changes: &mut Vec<PlannedFileChange>,
    document: &ConfigurationDocument,
    contents: Vec<u8>,
    summary: &str,
) {
    if !current.files.contains(&document.path) || document.contents != contents {
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

fn reviewed_stack_version(version: &str) -> Result<(), AdapterError> {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    let patch = parts.next().and_then(|part| part.parse::<u64>().ok());
    if major == Some(3) && minor.is_some_and(|minor| (1..=11).contains(&minor)) && patch.is_some() {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "Stack {version} is outside the reviewed 3.1.1 through 3.11.x range"
        )))
    }
}

fn run_program(
    runtime: &dyn Runtime,
    program: &str,
    arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    output_text(runtime.run(program, &arguments)?, operation)
}

fn run_program_in(
    runtime: &dyn Runtime,
    project: &Path,
    program: &str,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    removed_environment: &[String],
    operation: &str,
) -> Result<String, AdapterError> {
    let directory = project
        .parent()
        .ok_or_else(|| AdapterError::Runtime("Stack project has no parent directory".into()))?;
    output_text(
        runtime.run_in_with_environment(
            directory,
            program,
            arguments,
            environment,
            removed_environment,
        )?,
        operation,
    )
}

fn output_text(output: Output, operation: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|output| output.trim().to_owned())
        .map_err(|error| {
            AdapterError::Runtime(format!("{operation} returned non-UTF-8 output: {error}"))
        })
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    message: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Err(AdapterError::Verification(format!(
        "{message}; configuration restored: {}",
        restored.verified
    )))
}

fn nonempty_environment(runtime: &dyn Runtime, name: &str) -> Option<String> {
    runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
}

fn absolute_environment_path(value: &str, variable: &str) -> Result<PathBuf, AdapterError> {
    let path = PathBuf::from(value);
    validate_path(&path, variable)?;
    if !path.is_absolute() {
        return Err(AdapterError::Unsupported(format!(
            "{variable} must be an absolute path"
        )));
    }
    Ok(path)
}

fn windows_app_data(runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    let value = nonempty_environment(runtime, "APPDATA")
        .ok_or_else(|| AdapterError::Unsupported("Stack APPDATA is unavailable".into()))?;
    absolute_environment_path(&value, "APPDATA")
}

fn environment_user_path(
    context: &SystemContext,
    _runtime: &dyn Runtime,
    home: &Path,
    value: &str,
    variable: &str,
) -> Result<PathBuf, AdapterError> {
    let path = absolute_environment_path(value, variable)?;
    if context.os == OperatingSystem::Windows {
        if path.parent().is_some() {
            return Ok(path);
        }
        return Err(AdapterError::Unsupported(format!(
            "{variable} must not select a Windows filesystem root"
        )));
    }
    if path.starts_with(home) && path != home {
        return Ok(path);
    }
    Err(AdapterError::Unsupported(format!(
        "{variable} must select a path inside {}",
        home.display()
    )))
}

fn validate_user_config_path(
    context: &SystemContext,
    _runtime: &dyn Runtime,
    home: &Path,
    path: &Path,
) -> Result<(), AdapterError> {
    validate_path(path, "Stack user config")?;
    if !path.is_absolute() || path == home {
        return Err(AdapterError::Unsupported(
            "Stack user config must be an absolute user file".into(),
        ));
    }
    if path.starts_with(home) {
        return Ok(());
    }
    if context.os == OperatingSystem::Windows {
        if path.parent().is_some() {
            return Ok(());
        }
        return Err(AdapterError::Unsupported(
            "Stack user config must not be a Windows filesystem root".into(),
        ));
    }
    Err(AdapterError::Unsupported(format!(
        "Stack user config must select a path inside {}",
        home.display()
    )))
}

fn validate_user_path(home: &Path, path: &Path, label: &str) -> Result<(), AdapterError> {
    validate_path(path, label)?;
    if !path.is_absolute() || !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "{label} must select a path inside {}",
            home.display()
        )));
    }
    Ok(())
}

fn validate_project_path(project: &Path, path: &Path, label: &str) -> Result<(), AdapterError> {
    validate_path(path, label)?;
    let parent = path.parent();
    if !path.is_absolute()
        || path == project
        || !(path.starts_with(project) || parent.is_some_and(|parent| project.starts_with(parent)))
    {
        return Err(AdapterError::Unsupported(format!(
            "{label} must select a file inside {}",
            project.display()
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, label: &str) -> Result<(), AdapterError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        Err(AdapterError::Unsupported(format!(
            "{label} has an unsafe path"
        )))
    } else {
        Ok(())
    }
}

fn normalized_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.contains(['?', '#']) || value.contains(char::is_whitespace) {
        return None;
    }
    let (scheme, remainder) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, ""), |parts| parts);
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let path = path.trim_matches('/');
    Some(if path.is_empty() {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}/{path}")
    })
}

fn ensure_trailing_slash(value: &str) -> String {
    format!("{}/", value.trim_end_matches('/'))
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Stack on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "Stack on Windows arm64 is unavailable because the reviewed setup metadata has no native Windows arm64 GHC toolchain"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Stack requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if matches!(
        scope,
        ConfigurationScope::User | ConfigurationScope::Project
    ) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(
            "Stack adapter supports user and project scope".into(),
        ))
    }
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "stack"
        && matches!(
            current.scope,
            ConfigurationScope::User | ConfigurationScope::Project
        )
    {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "Stack operation received another tool or scope".into(),
        ))
    }
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("{} is not UTF-8: {error}", path.display()))
    })
}

fn path_string(path: &Path) -> Result<String, AdapterError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Runtime(format!("{} is not UTF-8", path.display())))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
