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

const RUBYGEMS_UPSTREAM: &str = "rubygems--language-registry";
const DEFAULT_SOURCE: &str = "https://rubygems.org/";
const VERIFY_GEM: &str = "net-protocol";
const VERIFY_VERSION: &str = "0.3.0";
const VERIFY_GEM_ID: &str = "net-protocol-0.3.0";
const VERIFY_GEM_SHA256: &str = "ba310c3d4f1cad46bb1ab20336b06669b1ff8f7c568d9cb9342b32a718547472";
const REVIEWED_ENDPOINTS: &[(&str, &str)] = &[
    ("aliyun", "https://mirrors.aliyun.com/rubygems/"),
    ("nju", "https://mirrors.nju.edu.cn/rubygems/"),
    ("tuna", "https://mirrors.tuna.tsinghua.edu.cn/rubygems/"),
    ("ustc", "https://mirrors.ustc.edu.cn/rubygems/"),
];
const RECOGNIZED_PUBLIC_SOURCES: &[&str] = &[
    DEFAULT_SOURCE,
    "http://rubygems.org/",
    "https://mirrors.aliyun.com/rubygems/",
    "https://repo.huaweicloud.com/repository/rubygems/",
    "https://mirrors.nju.edu.cn/rubygems/",
    "https://mirrors.tuna.tsinghua.edu.cn/rubygems/",
    "https://mirrors.ustc.edu.cn/rubygems/",
];
const VERIFICATION_UNSET_ENVIRONMENT: &[&str] = &[
    "BUNDLE_IGNORE_CONFIG",
    "BUNDLE_FROZEN",
    "BUNDLE_DEPLOYMENT",
    "BUNDLE_WITHOUT",
    "BUNDLE_ONLY",
    "BUNDLE_LOCKFILE",
    "BUNDLE_DISABLE_CHECKSUM_VALIDATION",
    "BUNDLE_SSL_VERIFY_MODE",
    "BUNDLE_MIRROR__ALL",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct BundlerAdapter;

impl Adapter for BundlerAdapter {
    fn key(&self) -> &'static str {
        "bundler"
    }

    fn tool_id(&self) -> &'static str {
        "bundler"
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
        if !runtime.command_exists("bundle") || !runtime.command_exists("ruby") {
            return Ok(None);
        }
        let snapshot = bundler_snapshot(runtime)?;
        let state = read_state(runtime, &snapshot)?;
        let analysis = analyze_state(runtime, &snapshot, &state)?;
        let mut evidence = vec![
            format!("Bundler {}", snapshot.bundler_version),
            format!("Ruby {}", snapshot.ruby_version),
            format!(
                "native platform is {:?} {:?}; bundle resolved through native PATH semantics",
                context.os, context.architecture
            ),
            format!("selected user home is {}", snapshot.home.display()),
            format!(
                "global configuration is {}",
                snapshot.global_config.display()
            ),
            format!("public Gem source identity is {}", analysis.source_identity),
            format!(
                "{} private source/mirror definition(s) remain opaque",
                analysis.private_count
            ),
        ];
        evidence.push(if analysis.credential_origins.is_empty() {
            "no credential-bearing source setting was detected".into()
        } else {
            format!(
                "credential-bearing source settings were detected in {}; values remain opaque",
                analysis.credential_origins.join(", ")
            )
        });
        evidence.push(snapshot.project.as_ref().map_or_else(
            || "no active Bundler project was detected".into(),
            |project| {
                format!(
                    "project Gemfile and lockfile are read-only; local configuration is {}",
                    project.local_config.display()
                )
            },
        ));
        evidence.push(match analysis.effective_mirror.as_ref() {
            Some((endpoint, origin)) => {
                format!("effective source mirror is {endpoint} from {origin}")
            }
            None => "no source-specific Bundler mirror is currently configured".into(),
        });
        Ok(Some(DetectedTool {
            tool_id: "bundler".into(),
            executable: Some(PathBuf::from("bundle")),
            version: Some(snapshot.bundler_version),
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
        if detected.tool_id != "bundler" {
            return Err(AdapterError::InvalidConfiguration(
                "Bundler read received another tool's detection result".into(),
            ));
        }
        let snapshot = bundler_snapshot(runtime)?;
        if detected.version.as_deref() != Some(snapshot.bundler_version.as_str()) {
            return Err(AdapterError::Conflict(
                "Bundler version changed after detection".into(),
            ));
        }
        let state = read_state(runtime, &snapshot)?;
        let analysis = analyze_state(runtime, &snapshot, &state)?;
        validate_scope_policy(scope, &snapshot, &analysis)?;
        let target_path = target_config_path(scope, &snapshot)?;
        let target = document_for_path(&state, &target_path).unwrap_or_else(|| TextDocument {
            path: target_path.clone(),
            exists: false,
            contents: Vec::new(),
        });

        let mut sources = vec![ConfiguredSource {
            upstream_id: Some(RUBYGEMS_UPSTREAM.into()),
            url: analysis.source_identity.clone(),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["bundler-public-source".into()]),
                ("scope".into(), vec![scope_label(scope).into()]),
            ]),
        }];
        if let Some((endpoint, origin)) = &analysis.effective_mirror {
            sources.push(ConfiguredSource {
                upstream_id: Some(RUBYGEMS_UPSTREAM.into()),
                url: endpoint.clone(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["effective-source-mirror".into()]),
                    ("origin".into(), vec![origin.clone()]),
                ]),
            });
        }
        for position in 0..analysis.private_count {
            sources.push(ConfiguredSource {
                upstream_id: None,
                url: format!("bundler-private-source:{}", position + 1),
                enabled: true,
                metadata: BTreeMap::from([(
                    "kind".into(),
                    vec!["private-source-or-mirror".into()],
                )]),
            });
        }
        if analysis.credential_count > 0 {
            sources.push(ConfiguredSource {
                upstream_id: None,
                url: "bundler-policy:credentials-redacted".into(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("kind".into(), vec!["credential-policy".into()]),
                    ("count".into(), vec![analysis.credential_count.to_string()]),
                ]),
            });
        }
        sources.push(ConfiguredSource {
            upstream_id: None,
            url: format!("bundler-version:{}", snapshot.bundler_version),
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec!["tool-snapshot".into()]),
                (
                    "bundler_version".into(),
                    vec![snapshot.bundler_version.clone()],
                ),
                ("ruby_version".into(), vec![snapshot.ruby_version.clone()]),
            ]),
        });

        let mut files = state
            .documents()
            .filter(|document| document.exists)
            .map(|document| document.path.clone())
            .collect::<Vec<_>>();
        let verification_config = read_text_document(
            runtime,
            &snapshot.verification_config,
            "Bundler verification config",
        )?;
        let verification_gemfile = read_text_document(
            runtime,
            &snapshot.verification_gemfile,
            "Bundler verification Gemfile",
        )?;
        for document in [&verification_config, &verification_gemfile] {
            if document.exists {
                files.push(document.path.clone());
            }
        }
        files.sort();
        files.dedup();

        let mut documents = vec![ConfigurationDocument {
            path: target.path.clone(),
            format: "bundler-target-config".into(),
            contents: target.contents.clone(),
        }];
        for document in state.documents() {
            if document.path != target.path {
                documents.push(ConfigurationDocument {
                    path: document.path.clone(),
                    format: read_only_format(&snapshot, &document.path).into(),
                    contents: document.contents.clone(),
                });
            }
        }
        documents.push(ConfigurationDocument {
            path: verification_config.path,
            format: "bundler-verification-config".into(),
            contents: verification_config.contents,
        });
        documents.push(ConfigurationDocument {
            path: verification_gemfile.path,
            format: "bundler-verification-gemfile".into(),
            contents: verification_gemfile.contents,
        });
        Ok(CurrentConfiguration {
            tool_id: "bundler".into(),
            scope,
            sources,
            files,
            documents,
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
        reviewed_bundler_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Bundler version is missing".into())
        })?)?;
        public_source(current)?;
        Ok(SelectionRequest {
            tool_id: "bundler".into(),
            adapter_key: "bundler".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![RUBYGEMS_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
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
        let source = public_source(current)?;
        let endpoint = selected_endpoint(selections)?;
        let target = current
            .documents
            .iter()
            .find(|document| document.format == "bundler-target-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Bundler target configuration document is missing".into(),
                )
            })?;
        let parsed = parse_bundler_config(&target.path, &target.contents)?;
        validate_config_policy(&parsed, &target.path)?;
        let mut rendered = rewrite_mirror_config(
            utf8(&target.path, &target.contents)?,
            &parsed,
            source,
            endpoint,
        )?;
        if target.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.insert(0, '\u{feff}');
        }
        let mut changes = Vec::new();
        if rendered.as_bytes() != target.contents {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &target.path),
                old_contents: current
                    .files
                    .contains(&target.path)
                    .then(|| target.contents.clone()),
                old_mode: None,
                new_contents: rendered.into_bytes(),
                new_mode: None,
                summary: format!(
                    "set only the source-specific Bundler mirror for {source} in {}; preserve private mirrors, credentials, fallback policy and unrelated settings",
                    target.path.display()
                ),
            });
        }
        let verification_config = current
            .documents
            .iter()
            .find(|document| document.format == "bundler-verification-config")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Bundler verification config document is missing".into(),
                )
            })?;
        let expected_config = render_verification_config(source, endpoint);
        if verification_config.contents != expected_config.as_bytes() {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &verification_config.path),
                old_contents: current
                    .files
                    .contains(&verification_config.path)
                    .then(|| verification_config.contents.clone()),
                old_mode: None,
                new_contents: expected_config.into_bytes(),
                new_mode: None,
                summary: "create an isolated credential-free Bundler mirror config".into(),
            });
        }
        let verification_gemfile = current
            .documents
            .iter()
            .find(|document| document.format == "bundler-verification-gemfile")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Bundler verification Gemfile document is missing".into(),
                )
            })?;
        let expected_gemfile = render_verification_gemfile(source);
        if verification_gemfile.contents != expected_gemfile.as_bytes() {
            changes.push(PlannedFileChange {
                target: rooted(&context.root, &verification_gemfile.path),
                old_contents: current
                    .files
                    .contains(&verification_gemfile.path)
                    .then(|| verification_gemfile.contents.clone()),
                old_mode: None,
                new_contents: expected_gemfile.into_bytes(),
                new_mode: None,
                summary: format!(
                    "create an isolated fixed-package Gemfile for {source}; never edit the project Gemfile or lockfile"
                ),
            });
        }
        Ok(ChangePlan {
            adapter_key: "bundler".into(),
            tool_id: "bundler".into(),
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
            let snapshot = bundler_snapshot(runtime)?;
            let known_targets = [
                rooted(&context.root, &snapshot.global_config),
                snapshot
                    .project
                    .as_ref()
                    .map(|project| rooted(&context.root, &project.local_config))
                    .unwrap_or_default(),
                rooted(&context.root, &snapshot.verification_config),
                rooted(&context.root, &snapshot.verification_gemfile),
            ];
            if receipt
                .changed_targets
                .iter()
                .all(|target| !known_targets.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Bundler transaction receipt contains no known target".into(),
                ));
            }
            let state = read_state(runtime, &snapshot)?;
            let analysis = analyze_state(runtime, &snapshot, &state)?;
            let verification_config =
                runtime
                    .read(&snapshot.verification_config)?
                    .ok_or_else(|| {
                        AdapterError::Verification("Bundler verification config disappeared".into())
                    })?;
            let parsed_verification =
                parse_bundler_config(&snapshot.verification_config, &verification_config)?;
            let endpoint = mirror_value(
                &parsed_verification,
                &analysis.source_identity,
                &snapshot.verification_config,
            )?
            .filter(|value| is_reviewed_endpoint(value))
            .ok_or_else(|| {
                AdapterError::Verification(
                    "Bundler verification config has no reviewed source mirror".into(),
                )
            })?;
            if verification_config
                != render_verification_config(&analysis.source_identity, &endpoint).as_bytes()
            {
                return Err(AdapterError::Verification(
                    "Bundler verification config is not canonical".into(),
                ));
            }
            let verification_gemfile =
                runtime
                    .read(&snapshot.verification_gemfile)?
                    .ok_or_else(|| {
                        AdapterError::Verification(
                            "Bundler verification Gemfile disappeared".into(),
                        )
                    })?;
            if verification_gemfile
                != render_verification_gemfile(&analysis.source_identity).as_bytes()
            {
                return Err(AdapterError::Verification(
                    "Bundler verification Gemfile is not canonical".into(),
                ));
            }
            if analysis
                .effective_mirror
                .as_ref()
                .map(|value| value.0.as_str())
                != Some(endpoint.as_str())
            {
                return Err(AdapterError::Verification(
                    "effective Bundler config did not load the selected mirror".into(),
                ));
            }
            let verification_dir = snapshot.verification_dir.as_path();
            let key = canonical_mirror_name(&analysis.source_identity);
            let config_output = run_isolated_bundle(
                runtime,
                &snapshot,
                &["config", "get", &key],
                "bundle config get mirror verification",
            )?;
            let reported_config = config_output.replace('\\', "/");
            let expected_config = snapshot
                .verification_config
                .display()
                .to_string()
                .replace('\\', "/");
            let path_matches = if context.os == OperatingSystem::Windows {
                reported_config
                    .to_ascii_lowercase()
                    .contains(&expected_config.to_ascii_lowercase())
            } else {
                reported_config.contains(&expected_config)
            };
            if !config_output.contains(&endpoint) || !path_matches {
                return Err(AdapterError::Verification(
                    "bundle config get did not report the isolated selected mirror".into(),
                ));
            }
            let lock = run_isolated_bundle(
                runtime,
                &snapshot,
                &["lock", "--print"],
                "bundle lock fixed dependency verification",
            )?;
            for marker in [
                format!("remote: {}", analysis.source_identity),
                format!("{VERIFY_GEM} ({VERIFY_VERSION})"),
                "timeout (".into(),
            ] {
                if !lock.contains(&marker) {
                    return Err(AdapterError::Verification(format!(
                        "bundle lock output is missing reviewed marker {marker}"
                    )));
                }
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Bundler {} loaded source-specific mirror {endpoint}; bundle lock resolved {VERIFY_GEM_ID} and timeout from an isolated Gemfile; the catalog gate separately enforces gem SHA-256 {VERIFY_GEM_SHA256} in {}",
                    snapshot.bundler_version,
                    verification_dir.display()
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
                "restored {} Bundler configuration file(s) from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BundlerSnapshot {
    bundler_version: String,
    ruby_version: String,
    home: PathBuf,
    global_config: PathBuf,
    project: Option<ProjectSnapshot>,
    verification_dir: PathBuf,
    verification_config: PathBuf,
    verification_gemfile: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectSnapshot {
    root: PathBuf,
    gemfile: PathBuf,
    lockfile: PathBuf,
    local_config: PathBuf,
}

#[derive(Clone, Debug)]
struct BundlerState {
    global: TextDocument,
    local: Option<TextDocument>,
    gemfile: Option<TextDocument>,
    lockfile: Option<TextDocument>,
    global_parsed: ParsedConfig,
    local_parsed: Option<ParsedConfig>,
}

impl BundlerState {
    fn documents(&self) -> impl Iterator<Item = &TextDocument> {
        std::iter::once(&self.global)
            .chain(self.local.iter())
            .chain(self.gemfile.iter())
            .chain(self.lockfile.iter())
    }
}

#[derive(Clone, Debug)]
struct TextDocument {
    path: PathBuf,
    exists: bool,
    contents: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct ParsedConfig {
    entries: Vec<ConfigEntry>,
}

#[derive(Clone, Debug)]
struct ConfigEntry {
    key: String,
    value: String,
    value_range: Range<usize>,
}

#[derive(Clone, Debug)]
struct StateAnalysis {
    source_identity: String,
    private_count: usize,
    credential_count: usize,
    credential_origins: Vec<String>,
    local_mirror: Option<String>,
    effective_mirror: Option<(String, String)>,
}

#[derive(Clone, Debug, Default)]
struct ProjectSourceAnalysis {
    public_sources: BTreeSet<String>,
    private_count: usize,
    credential_count: usize,
}

fn bundler_snapshot(runtime: &dyn Runtime) -> Result<BundlerSnapshot, AdapterError> {
    let bundle = run_program(runtime, None, "bundle", &["--version"], "bundle --version")?;
    let bundler_version = bundle
        .strip_prefix("Bundler version ")
        .or_else(|| bundle.strip_prefix("Bundler "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AdapterError::Unsupported(format!("unrecognized Bundler version output {bundle}"))
        })?
        .to_owned();
    reviewed_bundler_version(&bundler_version)?;
    let ruby = run_program(runtime, None, "ruby", &["--version"], "ruby --version")?;
    let ruby_version = ruby
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| AdapterError::Unsupported("Ruby version output is malformed".into()))?
        .to_owned();
    reviewed_ruby_version(&ruby_version)?;
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Bundler user home is unavailable".into()))?;
    validate_absolute_path(&home, "Bundler user home")?;
    let global_config = global_config_path(runtime, &home)?;
    validate_user_path(&home, &global_config, "Bundler global config")?;
    let project = project_snapshot(runtime)?;
    let verification_dir = home.join(".mirrorswitch/verification/bundler");
    let verification_config = verification_dir.join(".bundle/config");
    let verification_gemfile = verification_dir.join("Gemfile");
    for (path, label) in [
        (&verification_dir, "Bundler verification directory"),
        (&verification_config, "Bundler verification config"),
        (&verification_gemfile, "Bundler verification Gemfile"),
    ] {
        validate_user_path(&home, path, label)?;
    }
    if global_config == verification_config {
        return Err(AdapterError::Unsupported(
            "Bundler global config collides with the verification config".into(),
        ));
    }
    Ok(BundlerSnapshot {
        bundler_version,
        ruby_version,
        home,
        global_config,
        project,
        verification_dir,
        verification_config,
        verification_gemfile,
    })
}

fn global_config_path(runtime: &dyn Runtime, home: &Path) -> Result<PathBuf, AdapterError> {
    if let Some(value) = nonempty_environment(runtime, "BUNDLE_USER_CONFIG") {
        return environment_path(home, &value, "BUNDLE_USER_CONFIG", false);
    }
    if let Some(value) = nonempty_environment(runtime, "BUNDLE_USER_HOME") {
        return Ok(environment_path(home, &value, "BUNDLE_USER_HOME", false)?.join("config"));
    }
    Ok(home.join(".bundle/config"))
}

fn project_snapshot(runtime: &dyn Runtime) -> Result<Option<ProjectSnapshot>, AdapterError> {
    let Some(start) = runtime.project_dir() else {
        if nonempty_environment(runtime, "BUNDLE_GEMFILE").is_some()
            || nonempty_environment(runtime, "BUNDLE_APP_CONFIG").is_some()
        {
            return Err(AdapterError::Unsupported(
                "Bundler project environment is set without a selected project directory".into(),
            ));
        }
        return Ok(None);
    };
    validate_absolute_path(&start, "Bundler project directory")?;
    let gemfile = if let Some(value) = nonempty_environment(runtime, "BUNDLE_GEMFILE") {
        let candidate = PathBuf::from(value);
        let candidate = if candidate.is_absolute() {
            candidate
        } else {
            start.join(candidate)
        };
        validate_project_path(&start, &candidate, "BUNDLE_GEMFILE")?;
        if runtime.read(&candidate)?.is_none() {
            return Err(AdapterError::Unsupported(format!(
                "BUNDLE_GEMFILE selects missing file {}",
                candidate.display()
            )));
        }
        Some(candidate)
    } else {
        find_project_gemfile(runtime, &start)?
    };
    let Some(gemfile) = gemfile else {
        if nonempty_environment(runtime, "BUNDLE_APP_CONFIG").is_some() {
            return Err(AdapterError::Unsupported(
                "BUNDLE_APP_CONFIG is set but no active Gemfile was found".into(),
            ));
        }
        return Ok(None);
    };
    let root = gemfile
        .parent()
        .ok_or_else(|| AdapterError::InvalidConfiguration("Gemfile has no parent".into()))?
        .to_path_buf();
    let file_name = gemfile.file_name().and_then(|name| name.to_str());
    let lockfile = if file_name == Some("gems.rb") {
        root.join("gems.locked")
    } else {
        root.join("Gemfile.lock")
    };
    let local_config = if let Some(value) = nonempty_environment(runtime, "BUNDLE_APP_CONFIG") {
        let candidate = PathBuf::from(value);
        let directory = if candidate.is_absolute() {
            candidate
        } else {
            root.join(candidate)
        };
        validate_project_path(&root, &directory, "BUNDLE_APP_CONFIG")?;
        directory.join("config")
    } else {
        root.join(".bundle/config")
    };
    validate_project_path(&root, &local_config, "Bundler local config")?;
    Ok(Some(ProjectSnapshot {
        root,
        gemfile,
        lockfile,
        local_config,
    }))
}

fn find_project_gemfile(
    runtime: &dyn Runtime,
    start: &Path,
) -> Result<Option<PathBuf>, AdapterError> {
    let mut directory = start.to_path_buf();
    loop {
        for name in ["Gemfile", "gems.rb"] {
            let candidate = directory.join(name);
            if runtime.read(&candidate)?.is_some() {
                return Ok(Some(candidate));
            }
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

fn read_state(
    runtime: &dyn Runtime,
    snapshot: &BundlerSnapshot,
) -> Result<BundlerState, AdapterError> {
    let global = read_text_document(runtime, &snapshot.global_config, "Bundler global config")?;
    let global_parsed = parse_bundler_config(&global.path, &global.contents)?;
    validate_config_policy(&global_parsed, &global.path)?;
    let (local, gemfile, lockfile, local_parsed) = match &snapshot.project {
        Some(project) => {
            let local = read_text_document(runtime, &project.local_config, "Bundler local config")?;
            let parsed = parse_bundler_config(&local.path, &local.contents)?;
            validate_config_policy(&parsed, &local.path)?;
            let gemfile = read_text_document(runtime, &project.gemfile, "Bundler Gemfile")?;
            if !gemfile.exists {
                return Err(AdapterError::Conflict(
                    "Bundler Gemfile disappeared after discovery".into(),
                ));
            }
            let lockfile = read_text_document(runtime, &project.lockfile, "Bundler lockfile")?;
            (Some(local), Some(gemfile), Some(lockfile), Some(parsed))
        }
        None => (None, None, None, None),
    };
    Ok(BundlerState {
        global,
        local,
        gemfile,
        lockfile,
        global_parsed,
        local_parsed,
    })
}

fn analyze_state(
    runtime: &dyn Runtime,
    snapshot: &BundlerSnapshot,
    state: &BundlerState,
) -> Result<StateAnalysis, AdapterError> {
    validate_environment_policy(runtime)?;
    let project = match (&state.gemfile, &state.lockfile) {
        (Some(gemfile), Some(lockfile)) => {
            let mut analysis = analyze_gemfile(&gemfile.path, &gemfile.contents)?;
            analyze_lockfile(&lockfile.path, &lockfile.contents, &mut analysis)?;
            analysis
        }
        _ => ProjectSourceAnalysis {
            public_sources: BTreeSet::from([DEFAULT_SOURCE.into()]),
            ..ProjectSourceAnalysis::default()
        },
    };
    if project.public_sources.len() != 1 {
        return Err(AdapterError::Unsupported(format!(
            "Bundler requires exactly one static public Gem source identity, found {}",
            project.public_sources.len()
        )));
    }
    let source_identity = project
        .public_sources
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("public source analysis failed".into())
        })?;
    let mirror_env = bundler_mirror_key(&source_identity);
    if nonempty_environment(runtime, &mirror_env).is_some() {
        return Err(AdapterError::Unsupported(format!(
            "environment variable for {} overrides Bundler configuration",
            canonical_mirror_name(&source_identity)
        )));
    }
    let global_mirror = mirror_value(
        &state.global_parsed,
        &source_identity,
        &snapshot.global_config,
    )?;
    let local_mirror = match (&state.local_parsed, &snapshot.project) {
        (Some(parsed), Some(project)) => {
            mirror_value(parsed, &source_identity, &project.local_config)?
        }
        _ => None,
    };
    let effective_mirror = local_mirror
        .as_ref()
        .map(|value| (value.clone(), "local config".into()))
        .or_else(|| {
            global_mirror
                .as_ref()
                .map(|value| (value.clone(), "global config".into()))
        });
    let config_private = private_mirror_count(&state.global_parsed)
        + state.local_parsed.as_ref().map_or(0, private_mirror_count);
    let global_credentials = credential_setting_count(&state.global_parsed);
    let local_credentials = state
        .local_parsed
        .as_ref()
        .map_or(0, credential_setting_count);
    let mut credential_origins = Vec::new();
    if project.credential_count > 0 {
        credential_origins.push("Gemfile or lockfile private sources".into());
    }
    if global_credentials > 0 {
        credential_origins.push("global config".into());
    }
    if local_credentials > 0 {
        credential_origins.push("local config".into());
    }
    let credential_count = project.credential_count + global_credentials + local_credentials;
    Ok(StateAnalysis {
        source_identity,
        private_count: project.private_count + config_private,
        credential_count,
        credential_origins,
        local_mirror,
        effective_mirror,
    })
}

fn validate_scope_policy(
    scope: ConfigurationScope,
    snapshot: &BundlerSnapshot,
    analysis: &StateAnalysis,
) -> Result<(), AdapterError> {
    match scope {
        ConfigurationScope::User => {
            if analysis.local_mirror.is_some() {
                return Err(AdapterError::Unsupported(
                    "project-local Bundler mirror overrides user scope; select project scope explicitly"
                        .into(),
                ));
            }
        }
        ConfigurationScope::Project => {
            if snapshot.project.is_none() {
                return Err(AdapterError::Unsupported(
                    "Bundler project scope requires an active Gemfile".into(),
                ));
            }
        }
        _ => return require_scope(scope),
    }
    Ok(())
}

fn target_config_path(
    scope: ConfigurationScope,
    snapshot: &BundlerSnapshot,
) -> Result<PathBuf, AdapterError> {
    match scope {
        ConfigurationScope::User => Ok(snapshot.global_config.clone()),
        ConfigurationScope::Project => snapshot
            .project
            .as_ref()
            .map(|project| project.local_config.clone())
            .ok_or_else(|| {
                AdapterError::Unsupported("Bundler project scope requires an active Gemfile".into())
            }),
        _ => Err(AdapterError::Unsupported(
            "Bundler supports only user and explicit project scopes".into(),
        )),
    }
}

fn document_for_path(state: &BundlerState, path: &Path) -> Option<TextDocument> {
    state
        .documents()
        .find(|document| document.path == path)
        .cloned()
}

fn read_only_format(snapshot: &BundlerSnapshot, path: &Path) -> &'static str {
    if snapshot
        .project
        .as_ref()
        .is_some_and(|project| path == project.gemfile)
    {
        "bundler-gemfile-read-only"
    } else if snapshot
        .project
        .as_ref()
        .is_some_and(|project| path == project.lockfile)
    {
        "bundler-lockfile-read-only"
    } else {
        "bundler-config-read-only"
    }
}

fn read_text_document(
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

fn parse_bundler_config(path: &Path, contents: &[u8]) -> Result<ParsedConfig, AdapterError> {
    let text = utf8(path, contents)?;
    let mut entries = Vec::new();
    let mut keys = BTreeSet::new();
    let mut offset = 0;
    for raw in text.split_inclusive('\n') {
        let line = raw
            .strip_suffix('\n')
            .unwrap_or(raw)
            .strip_suffix('\r')
            .unwrap_or(raw.strip_suffix('\n').unwrap_or(raw));
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            offset += raw.len();
            continue;
        }
        if line.len() != line.trim_start().len()
            || trimmed.starts_with(['-', '&', '*', '!', '{', '['])
        {
            return Err(AdapterError::Unsupported(format!(
                "Bundler config {} is not a flat scalar mapping",
                path.display()
            )));
        }
        let delimiter = line
            .char_indices()
            .find_map(|(position, character)| {
                if character == ':'
                    && line[position + 1..]
                        .chars()
                        .next()
                        .is_none_or(char::is_whitespace)
                {
                    Some(position)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "Bundler config {} contains a non-scalar entry",
                    path.display()
                ))
            })?;
        let key = line[..delimiter].trim();
        if key.is_empty() || !keys.insert(key.to_owned()) {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Bundler config {} contains an empty or duplicate key",
                path.display()
            )));
        }
        let raw_value = &line[delimiter + 1..];
        let value_start = offset + delimiter + 1;
        let (value, relative_start, relative_end) = parse_yaml_scalar(raw_value, path, key)?;
        entries.push(ConfigEntry {
            key: key.to_owned(),
            value,
            value_range: value_start + relative_start..value_start + relative_end,
        });
        offset += raw.len();
    }
    Ok(ParsedConfig { entries })
}

fn parse_yaml_scalar(
    raw: &str,
    path: &Path,
    key: &str,
) -> Result<(String, usize, usize), AdapterError> {
    let value = raw.trim_start();
    if value.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "Bundler config key {key} has no scalar value in {}",
            path.display()
        )));
    }
    let leading = raw.len() - value.len();
    if let Some(quote @ ('\'' | '"')) = value.chars().next() {
        let tail = &value[quote.len_utf8()..];
        let close = quoted_scalar_end(tail, quote).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Bundler config key {key} has an unterminated quote in {}",
                path.display()
            ))
        })?;
        let remainder = tail[close + quote.len_utf8()..].trim();
        if !remainder.is_empty() && !remainder.starts_with('#') {
            return Err(AdapterError::Unsupported(format!(
                "Bundler config key {key} has a complex YAML value in {}",
                path.display()
            )));
        }
        let start = leading + quote.len_utf8();
        let end = start + close;
        return Ok((tail[..close].to_owned(), start, end));
    }
    let without_comment = value
        .find(" #")
        .map_or(value, |position| &value[..position])
        .trim_end();
    if without_comment.is_empty()
        || without_comment.contains(char::is_whitespace)
        || without_comment.starts_with(['{', '[', '&', '*', '!', '|', '>'])
    {
        return Err(AdapterError::Unsupported(format!(
            "Bundler config key {key} has a complex YAML value in {}",
            path.display()
        )));
    }
    Ok((
        without_comment.to_owned(),
        leading,
        leading + without_comment.len(),
    ))
}

fn quoted_scalar_end(value: &str, quote: char) -> Option<usize> {
    let mut characters = value.char_indices().peekable();
    let mut escaped = false;
    while let Some((position, character)) = characters.next() {
        if quote == '"' {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == quote {
                return Some(position);
            }
        } else if character == quote {
            if characters.peek().is_some_and(|(_, next)| *next == quote) {
                characters.next();
            } else {
                return Some(position);
            }
        }
    }
    None
}

fn validate_config_policy(parsed: &ParsedConfig, path: &Path) -> Result<(), AdapterError> {
    if parsed
        .entries
        .iter()
        .any(|entry| entry.key == "BUNDLE_MIRROR__ALL")
    {
        return Err(AdapterError::Unsupported(format!(
            "Bundler catch-all mirror in {} could redirect private sources",
            path.display()
        )));
    }
    if parsed.entries.iter().any(|entry| {
        entry.key == "BUNDLE_DISABLE_CHECKSUM_VALIDATION"
            && !matches!(entry.value.to_ascii_lowercase().as_str(), "false" | "0")
    }) {
        return Err(AdapterError::Unsupported(format!(
            "Bundler checksum validation is disabled in {}",
            path.display()
        )));
    }
    if parsed
        .entries
        .iter()
        .any(|entry| entry.key == "BUNDLE_SSL_VERIFY_MODE")
    {
        return Err(AdapterError::Unsupported(format!(
            "Bundler SSL verification override in {} is not changed automatically",
            path.display()
        )));
    }
    Ok(())
}

fn mirror_value(
    parsed: &ParsedConfig,
    source: &str,
    path: &Path,
) -> Result<Option<String>, AdapterError> {
    let key = bundler_mirror_key(source);
    let Some(entry) = parsed.entries.iter().find(|entry| entry.key == key) else {
        return Ok(None);
    };
    let endpoint = normalized_public_source(&entry.value).ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "source-specific Bundler mirror in {} points to an unreviewed or credential-bearing endpoint",
            path.display()
        ))
    })?;
    Ok(Some(endpoint))
}

fn private_mirror_count(parsed: &ParsedConfig) -> usize {
    parsed
        .entries
        .iter()
        .filter(|entry| {
            entry.key.starts_with("BUNDLE_MIRROR__")
                && entry.key != "BUNDLE_MIRROR__ALL"
                && !RECOGNIZED_PUBLIC_SOURCES.iter().any(|source| {
                    let key = bundler_mirror_key(source);
                    entry.key == key || entry.key == format!("{key}__FALLBACK_TIMEOUT")
                })
        })
        .count()
}

fn credential_setting_count(parsed: &ParsedConfig) -> usize {
    parsed
        .entries
        .iter()
        .filter(|entry| {
            !entry.key.starts_with("BUNDLE_MIRROR__")
                && !entry.key.starts_with("BUNDLE_BUILD__")
                && !entry.key.starts_with("BUNDLE_LOCAL__")
                && entry.key.starts_with("BUNDLE_")
                && entry.key.contains("__")
                && entry.value.contains(':')
        })
        .count()
}

fn analyze_gemfile(path: &Path, contents: &[u8]) -> Result<ProjectSourceAnalysis, AdapterError> {
    let text = utf8(path, contents)?;
    let mut analysis = ProjectSourceAnalysis::default();
    for raw in text.lines() {
        let line = strip_ruby_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if contains_ruby_call(trimmed, "eval_gemfile") {
            return Err(AdapterError::Unsupported(format!(
                "eval_gemfile in {} makes source identity non-local",
                path.display()
            )));
        }
        if starts_ruby_call(trimmed, "source") {
            let (value, _) = first_ruby_string(&trimmed["source".len()..]).ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "dynamic Bundler source in {} cannot be evaluated safely",
                    path.display()
                ))
            })?;
            record_project_source(path, &value, &mut analysis)?;
        }
        let mut remainder = trimmed;
        while let Some(position) = find_source_option(remainder) {
            let after = &remainder[position + "source:".len()..];
            let (value, consumed) = first_ruby_string(after).ok_or_else(|| {
                AdapterError::Unsupported(format!(
                    "dynamic Bundler source option in {} cannot be evaluated safely",
                    path.display()
                ))
            })?;
            record_project_source(path, &value, &mut analysis)?;
            remainder = &after[consumed..];
        }
    }
    Ok(analysis)
}

fn analyze_lockfile(
    path: &Path,
    contents: &[u8],
    analysis: &mut ProjectSourceAnalysis,
) -> Result<(), AdapterError> {
    let text = utf8(path, contents)?;
    if text.is_empty() {
        return Ok(());
    }
    let mut lock_public = BTreeSet::new();
    for line in text.lines() {
        let Some(raw) = line.trim().strip_prefix("remote:") else {
            continue;
        };
        let value = raw.trim();
        if value.is_empty() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "empty remote in {}",
                path.display()
            )));
        }
        if looks_like_public_host(value) && has_url_credentials(value) {
            return Err(AdapterError::Unsupported(format!(
                "credential-bearing public source in {} is not rewritten",
                path.display()
            )));
        }
        if let Some(source) = normalized_public_source(value) {
            lock_public.insert(source);
        } else if has_url_credentials(value) {
            analysis.credential_count += 1;
        }
    }
    if lock_public.len() > 1
        || lock_public
            .iter()
            .any(|source| !analysis.public_sources.contains(source))
    {
        return Err(AdapterError::Unsupported(format!(
            "public source identity in {} conflicts with the Gemfile",
            path.display()
        )));
    }
    Ok(())
}

fn record_project_source(
    path: &Path,
    value: &str,
    analysis: &mut ProjectSourceAnalysis,
) -> Result<(), AdapterError> {
    if value.trim().is_empty() {
        return Err(AdapterError::InvalidConfiguration(format!(
            "empty Bundler source in {}",
            path.display()
        )));
    }
    if value.contains("#{") {
        return Err(AdapterError::Unsupported(format!(
            "interpolated Bundler source in {} cannot be evaluated safely",
            path.display()
        )));
    }
    if looks_like_public_host(value) && has_url_credentials(value) {
        return Err(AdapterError::Unsupported(format!(
            "credential-bearing public source in {} is not rewritten",
            path.display()
        )));
    }
    if let Some(source) = normalized_public_source(value) {
        analysis.public_sources.insert(source);
    } else {
        analysis.private_count += 1;
        if has_url_credentials(value) {
            analysis.credential_count += 1;
        }
    }
    Ok(())
}

fn strip_ruby_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (position, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(active), current) if active == current => quote = None,
            (None, '#') => return &line[..position],
            _ => {}
        }
    }
    line
}

fn starts_ruby_call(line: &str, name: &str) -> bool {
    line.strip_prefix(name).is_some_and(|remainder| {
        remainder
            .chars()
            .next()
            .is_some_and(|character| character.is_whitespace() || character == '(')
    })
}

fn contains_ruby_call(line: &str, name: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for (position, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        match (quote, character) {
            (None, '\'' | '"') => {
                quote = Some(character);
                continue;
            }
            (Some(active), current) if active == current => {
                quote = None;
                continue;
            }
            (Some(_), _) => continue,
            _ => {}
        }
        if !line[position..].starts_with(name) {
            continue;
        }
        let before = line[..position].chars().next_back();
        let after = line[position + name.len()..].chars().next();
        if before.is_none_or(|character| !is_ruby_identifier(character))
            && after.is_some_and(|character| character.is_whitespace() || character == '(')
        {
            return true;
        }
    }
    false
}

fn is_ruby_identifier(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn find_source_option(line: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (position, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        match (quote, character) {
            (None, '\'' | '"') => {
                quote = Some(character);
                continue;
            }
            (Some(active), current) if active == current => {
                quote = None;
                continue;
            }
            (Some(_), _) => continue,
            _ => {}
        }
        if !line[position..].starts_with("source:") {
            continue;
        }
        let before = line[..position].chars().next_back();
        if before.is_none_or(|character| !is_ruby_identifier(character)) {
            return Some(position);
        }
    }
    None
}

fn first_ruby_string(value: &str) -> Option<(String, usize)> {
    let trimmed = value.trim_start_matches(|character: char| {
        character.is_whitespace() || character == '(' || character == ','
    });
    let leading = value.len() - trimmed.len();
    let quote @ ('\'' | '"') = trimmed.chars().next()? else {
        return None;
    };
    let mut escaped = false;
    let mut rendered = String::new();
    for (position, character) in trimmed[quote.len_utf8()..].char_indices() {
        if escaped {
            rendered.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote {
            return Some((
                rendered,
                leading + quote.len_utf8() + position + character.len_utf8(),
            ));
        } else {
            rendered.push(character);
        }
    }
    None
}

fn rewrite_mirror_config(
    text: &str,
    parsed: &ParsedConfig,
    source: &str,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let key = bundler_mirror_key(source);
    if let Some(entry) = parsed.entries.iter().find(|entry| entry.key == key) {
        if entry.value_range.end > text.len() || entry.value_range.start > entry.value_range.end {
            return Err(AdapterError::InvalidConfiguration(
                "Bundler mirror replacement range is invalid".into(),
            ));
        }
        return Ok(replace_range(text, entry.value_range.clone(), endpoint));
    }
    let line = format!("{key}: \"{endpoint}\"");
    if text.is_empty() {
        Ok(format!("---\n{line}\n"))
    } else {
        let newline = newline(text);
        let mut rendered = text.to_owned();
        if !rendered.ends_with('\n') {
            rendered.push_str(newline);
        }
        rendered.push_str(&line);
        rendered.push_str(newline);
        Ok(rendered)
    }
}

fn render_verification_config(source: &str, endpoint: &str) -> String {
    format!("---\n{}: \"{endpoint}\"\n", bundler_mirror_key(source))
}

fn render_verification_gemfile(source: &str) -> String {
    format!("source \"{source}\"\n\ngem \"{VERIFY_GEM}\", \"= {VERIFY_VERSION}\"\n")
}

fn run_isolated_bundle(
    runtime: &dyn Runtime,
    snapshot: &BundlerSnapshot,
    bundle_arguments: &[&str],
    operation: &str,
) -> Result<String, AdapterError> {
    let isolated_home = snapshot.verification_dir.join("home");
    let environment = BTreeMap::from([
        ("HOME".into(), path_string(&isolated_home)?),
        ("USERPROFILE".into(), path_string(&isolated_home)?),
        (
            "BUNDLE_USER_HOME".into(),
            path_string(&isolated_home.join(".bundle"))?,
        ),
        (
            "BUNDLE_USER_CONFIG".into(),
            path_string(&isolated_home.join(".bundle/config"))?,
        ),
        (
            "BUNDLE_APP_CONFIG".into(),
            path_string(&snapshot.verification_dir.join(".bundle"))?,
        ),
        (
            "BUNDLE_GEMFILE".into(),
            path_string(&snapshot.verification_gemfile)?,
        ),
        (
            "BUNDLE_PATH".into(),
            path_string(&snapshot.verification_dir.join("bundle"))?,
        ),
        (
            "BUNDLE_CACHE_PATH".into(),
            path_string(&snapshot.verification_dir.join("cache"))?,
        ),
    ]);
    let removed_environment = VERIFICATION_UNSET_ENVIRONMENT
        .iter()
        .map(|variable| (*variable).to_owned())
        .collect::<Vec<_>>();
    let arguments = bundle_arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let output = runtime.run_in_with_environment(
        &snapshot.verification_dir,
        "bundle",
        &arguments,
        &environment,
        &removed_environment,
    )?;
    output_text(output, operation)
}

fn public_source(current: &CurrentConfiguration) -> Result<&str, AdapterError> {
    let sources = current
        .sources
        .iter()
        .filter(|source| {
            source.upstream_id.as_deref() == Some(RUBYGEMS_UPSTREAM)
                && source
                    .metadata
                    .get("kind")
                    .is_some_and(|values| values == &["bundler-public-source"])
        })
        .collect::<Vec<_>>();
    if sources.len() != 1 || normalized_public_source(&sources[0].url).is_none() {
        return Err(AdapterError::InvalidConfiguration(
            "Bundler current configuration lacks one public source identity".into(),
        ));
    }
    Ok(&sources[0].url)
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&'static str, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "bundler"
        || selections[0].upstream_id != RUBYGEMS_UPSTREAM
    {
        return Err(AdapterError::InvalidConfiguration(
            "Bundler requires exactly one RubyGems mirror selection".into(),
        ));
    }
    let selection = &selections[0];
    let index = unique_endpoint(selection, EndpointRole::Index)?;
    let metadata = unique_endpoint(selection, EndpointRole::Metadata)?;
    let artifacts = unique_endpoint(selection, EndpointRole::Artifacts)?;
    let expected = REVIEWED_ENDPOINTS
        .iter()
        .find(|(provider, _)| *provider == selection.provider_id)
        .map(|(_, endpoint)| *endpoint)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Bundler selection uses an unreviewed provider".into(),
            )
        })?;
    if [index, metadata, artifacts]
        .iter()
        .any(|endpoint| normalized_public_source(endpoint).as_deref() != Some(expected))
    {
        return Err(AdapterError::InvalidConfiguration(
            "Bundler index, dependency metadata and artifact endpoints must share one reviewed root"
                .into(),
        ));
    }
    Ok(expected)
}

fn unique_endpoint(selection: &MirrorSelection, role: EndpointRole) -> Result<&str, AdapterError> {
    let endpoints = selection
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
        .collect::<Vec<_>>();
    if endpoints.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Bundler selection requires exactly one {role:?} HTTPS endpoint"
        )));
    }
    Ok(&endpoints[0].url)
}

fn normalized_public_source(value: &str) -> Option<String> {
    let normalized = normalize_url(value)?;
    RECOGNIZED_PUBLIC_SOURCES
        .iter()
        .find(|source| **source == normalized)
        .map(|source| (*source).to_owned())
}

fn normalize_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.contains(['?', '#']) || value.contains(char::is_whitespace) {
        return None;
    }
    let (scheme, remainder) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, ""), |(authority, path)| (authority, path));
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let path = path.trim_matches('/');
    Some(if path.is_empty() {
        format!("{scheme}://{authority}/")
    } else {
        format!("{scheme}://{authority}/{path}/")
    })
}

fn looks_like_public_host(value: &str) -> bool {
    let Some((_, remainder)) = value.trim().split_once("://") else {
        return false;
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    RECOGNIZED_PUBLIC_SOURCES.iter().any(|source| {
        source
            .split_once("://")
            .and_then(|(_, remainder)| remainder.split('/').next())
            .is_some_and(|public_host| public_host.eq_ignore_ascii_case(host))
    })
}

fn has_url_credentials(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split('/').next())
        .is_some_and(|authority| authority.contains('@'))
}

fn is_reviewed_endpoint(value: &str) -> bool {
    REVIEWED_ENDPOINTS
        .iter()
        .any(|(_, endpoint)| *endpoint == value)
}

fn bundler_mirror_key(source: &str) -> String {
    format!(
        "BUNDLE_MIRROR__{}",
        source.to_ascii_uppercase().replace('.', "__")
    )
}

fn canonical_mirror_name(source: &str) -> String {
    format!("mirror.{source}")
}

fn validate_environment_policy(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    if nonempty_environment(runtime, "BUNDLE_IGNORE_CONFIG").is_some() {
        return Err(AdapterError::Unsupported(
            "BUNDLE_IGNORE_CONFIG prevents persisted Bundler mirror settings from loading".into(),
        ));
    }
    if nonempty_environment(runtime, "BUNDLE_MIRROR__ALL").is_some() {
        return Err(AdapterError::Unsupported(
            "BUNDLE_MIRROR__ALL could redirect private Gem sources".into(),
        ));
    }
    if nonempty_environment(runtime, "BUNDLE_SSL_VERIFY_MODE").is_some() {
        return Err(AdapterError::Unsupported(
            "BUNDLE_SSL_VERIFY_MODE overrides Bundler transport verification".into(),
        ));
    }
    if nonempty_environment(runtime, "BUNDLE_DISABLE_CHECKSUM_VALIDATION")
        .is_some_and(|value| !matches!(value.to_ascii_lowercase().as_str(), "false" | "0"))
    {
        return Err(AdapterError::Unsupported(
            "BUNDLE_DISABLE_CHECKSUM_VALIDATION disables Bundler artifact validation".into(),
        ));
    }
    Ok(())
}

fn nonempty_environment(runtime: &dyn Runtime, name: &str) -> Option<String> {
    runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
}

fn environment_path(
    home: &Path,
    value: &str,
    variable: &str,
    allow_home: bool,
) -> Result<PathBuf, AdapterError> {
    let path = PathBuf::from(value);
    validate_absolute_path(&path, variable)?;
    if !path.starts_with(home) || (!allow_home && path == home) {
        return Err(AdapterError::Unsupported(format!(
            "{variable} must select a path inside {}",
            home.display()
        )));
    }
    Ok(path)
}

fn validate_user_path(home: &Path, path: &Path, label: &str) -> Result<(), AdapterError> {
    validate_absolute_path(path, label)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "{label} {} is outside user home {}",
            path.display(),
            home.display()
        )));
    }
    Ok(())
}

fn validate_project_path(root: &Path, path: &Path, label: &str) -> Result<(), AdapterError> {
    validate_absolute_path(path, label)?;
    if !path.starts_with(root) || path == root {
        return Err(AdapterError::Unsupported(format!(
            "{label} {} is outside project {}",
            path.display(),
            root.display()
        )));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{label} path {} is not absolute and normalized",
            path.display()
        )));
    }
    Ok(())
}

fn reviewed_bundler_version(value: &str) -> Result<(), AdapterError> {
    let (major, _, _) = version_components(value).ok_or_else(|| {
        AdapterError::Unsupported(format!("Bundler version {value} is unrecognized"))
    })?;
    if matches!(major, 2..=4) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "Bundler {value} is outside the reviewed 2.x through 4.x range"
        )))
    }
}

fn reviewed_ruby_version(value: &str) -> Result<(), AdapterError> {
    let (major, minor, _) = version_components(value).ok_or_else(|| {
        AdapterError::Unsupported(format!("Ruby version {value} is unrecognized"))
    })?;
    if (major == 2 && minor >= 6) || matches!(major, 3 | 4) {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "Ruby {value} is outside the reviewed 2.6 through 4.x range"
        )))
    }
}

fn version_components(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch_digits = parts
        .next()
        .unwrap_or("0")
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    let patch = patch_digits.parse().ok()?;
    Some((major, minor, patch))
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
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AdapterError::Runtime(format!(
            "{operation} failed with {}: {}{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
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

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Bundler on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Bundler requires x86_64 or arm64".into(),
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
            "Bundler supports only user and explicit project scopes".into(),
        ))
    }
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    require_scope(current.scope)?;
    if current.tool_id == "bundler" {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "Bundler operation received another tool's configuration".into(),
        ))
    }
}

fn scope_label(scope: ConfigurationScope) -> &'static str {
    match scope {
        ConfigurationScope::User => "user",
        ConfigurationScope::Project => "project",
        _ => "unsupported",
    }
}

fn path_string(path: &Path) -> Result<String, AdapterError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported(format!("non-UTF-8 path {}", path.display())))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!("{} is not UTF-8: {error}", path.display()))
    })
}

fn replace_range(text: &str, range: Range<usize>, replacement: &str) -> String {
    let mut rendered = String::with_capacity(text.len() - range.len() + replacement.len());
    rendered.push_str(&text[..range.start]);
    rendered.push_str(replacement);
    rendered.push_str(&text[range.end..]);
    rendered
}

fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        return path.to_path_buf();
    }
    root.join(path.strip_prefix("/").unwrap_or(path))
}
