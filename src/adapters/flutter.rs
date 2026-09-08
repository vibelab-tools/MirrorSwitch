use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

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

const STORAGE_UPSTREAM: &str = "flutter--release-artifacts";
const PUB_UPSTREAM: &str = "dart-pub--language-registry";
const NJU_STORAGE: &str = "https://mirrors.nju.edu.cn/flutter";
const SJTUG_STORAGE: &str = "https://mirror.sjtu.edu.cn";
const TUNA_PUB: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub";
const SJTUG_PUB: &str = "https://mirror.sjtu.edu.cn/dart-pub";
const TUNA_PUB_ARTIFACTS: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub/packages";
const SJTUG_PUB_ARTIFACTS: &str =
    "https://storage.flutter-io.cn/dartlang-pub-exported-api/latest/api/archives";
const OFFICIAL_STORAGE: &[&str] = &[
    "https://storage.googleapis.com",
    "https://storage.flutter-io.cn",
];
const OFFICIAL_PUB: &[&str] = &["https://pub.dev", "https://pub.dartlang.org"];
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch Flutter mirrors >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch Flutter mirrors <<<";
const FOREIGN_DART_BEGIN: &str = "# >>> MirrorSwitch Dart Pub mirror >>>";
const VERIFY_MARKER: &str = "# Managed by MirrorSwitch: Flutter verification project v1";
const STORAGE_VARIABLE: &str = "FLUTTER_STORAGE_BASE_URL";
const PUB_VARIABLE: &str = "PUB_HOSTED_URL";

#[derive(Clone, Copy, Debug, Default)]
pub struct FlutterAdapter;

impl Adapter for FlutterAdapter {
    fn key(&self) -> &'static str {
        "flutter"
    }

    fn tool_id(&self) -> &'static str {
        "flutter"
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
        require_supported_context(context)?;
        if !runtime.command_exists("flutter") {
            return Ok(None);
        }
        if context.os == OperatingSystem::Windows && !runtime.command_exists("reg.exe") {
            return Err(AdapterError::Unsupported(
                "Flutter Windows persistence requires reg.exe".into(),
            ));
        }
        let version = flutter_version(runtime, None, None)?;
        validate_version(&version)?;
        let help = run_flutter(
            runtime,
            None,
            None,
            None,
            None,
            &["--verbose", "precache", "--help"],
            "flutter precache --help",
        )?;
        let artifact_flag = platform_artifact_flag(context);
        if !help.lines().any(|line| line.contains(artifact_flag)) {
            return Err(AdapterError::Unsupported(format!(
                "Flutter precache does not expose {artifact_flag} artifacts"
            )));
        }
        let layout = config_layout(context, runtime)?;
        let project = inspect_project(runtime)?;
        let token_files = token_file_count(runtime, &layout.token_dir)?;
        Ok(Some(DetectedTool {
            tool_id: "flutter".into(),
            executable: Some(PathBuf::from("flutter")),
            version: Some(version.framework_version.clone()),
            evidence: vec![
                format!("Flutter {}", version.framework_version),
                format!("Flutter channel is {}", version.channel),
                format!(
                    "Flutter framework revision is {}",
                    version.framework_revision
                ),
                format!(
                    "Flutter engine artifact revision is {}",
                    version.engine_revision
                ),
                format!(
                    "Flutter engine content hash is {}",
                    version
                        .engine_content_hash
                        .as_deref()
                        .unwrap_or("unavailable")
                ),
                format!("Dart SDK is {}", version.dart_sdk_version),
                format!(
                    "Flutter SDK repository is {}",
                    repository_state(&version.repository_url)
                ),
                format!(
                    "Flutter bootstrap cache and {artifact_flag} precache command are operable"
                ),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                format!("selected persistence is {}", layout.shell.name()),
                format!(
                    "selected persistence target is {}",
                    layout.profile.display()
                ),
                format!(
                    "FLUTTER_STORAGE_BASE_URL is {}",
                    environment_state(runtime, "FLUTTER_STORAGE_BASE_URL", ManagedKey::Storage)
                ),
                format!(
                    "PUB_HOSTED_URL is {}",
                    environment_state(runtime, "PUB_HOSTED_URL", ManagedKey::Pub)
                ),
                format!("project hosted declaration(s): {}", project.hosted),
                format!("project publish target(s): {}", project.publish_targets),
                format!("project lock hosted source(s): {}", project.lock_hosted),
                format!("Pub token store file(s): {token_files} (contents not read)"),
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
        require_supported_context(context)?;
        require_scope(scope)?;
        if detected.tool_id != "flutter" {
            return Err(AdapterError::InvalidConfiguration(
                "Flutter read received another tool's detection result".into(),
            ));
        }
        let version = flutter_version(runtime, None, None)?;
        validate_version(&version)?;
        if detected.version.as_deref() != Some(version.framework_version.as_str()) {
            return Err(AdapterError::Conflict(
                "Flutter version changed after detection".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        if layout.shell == ShellKind::WindowsRegistry {
            return windows_current(runtime, &layout, &version);
        }
        let profile_contents = runtime.read(&layout.profile)?;
        let profile_exists = profile_contents.is_some();
        let profile_contents = profile_contents.unwrap_or_default();
        let profile_text = utf8(&layout.profile, &profile_contents)?;
        let parsed = parse_profile(profile_text, &layout.profile, layout.shell)?;
        let mut sources = profile_sources(&parsed, &layout.profile, layout.shell);
        sources.push(snapshot_source(
            "release-identity",
            &version.release_identity(),
        ));
        sources.push(snapshot_source(
            "framework-version",
            &version.framework_version,
        ));
        sources.push(snapshot_source("flutter-channel", &version.channel));
        sources.push(snapshot_source(
            "engine-artifact-version",
            &version.engine_revision,
        ));
        for key in [ManagedKey::Storage, ManagedKey::Pub] {
            if let Some(value) = runtime
                .environment_variable(key.environment_name())
                .filter(|value| !value.trim().is_empty())
            {
                let represented = parsed
                    .value_for(key)
                    .is_some_and(|profile_value| same_base(profile_value, &value))
                    || parsed
                        .unmanaged
                        .iter()
                        .filter(|assignment| assignment.key == key)
                        .any(|assignment| same_base(&assignment.value, &value));
                if !represented {
                    sources.push(policy_source(
                        &format!("{}-environment-override", key.policy_name()),
                        Path::new(":env:"),
                        layout.shell,
                    ));
                }
            }
        }
        if profile_text.contains(FOREIGN_DART_BEGIN) {
            sources.push(policy_source(
                "foreign-dart-managed-block",
                &layout.profile,
                layout.shell,
            ));
        }
        if token_file_count(runtime, &layout.token_dir)? > 0 {
            sources.push(policy_source(
                "credentials-detected",
                &layout.token_dir,
                layout.shell,
            ));
        }

        let mut files = profile_exists
            .then_some(layout.profile.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let mut documents = vec![ConfigurationDocument {
            path: layout.profile.clone(),
            format: format!("flutter-selected-{}-profile", layout.shell.name()),
            contents: profile_contents,
        }];
        append_shared_current(runtime, &layout, &mut files, &mut sources, &mut documents)?;
        Ok(CurrentConfiguration {
            tool_id: "flutter".into(),
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
        require_supported_context(context)?;
        require_current(current)?;
        let version = detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Flutter version is missing".into())
        })?;
        reviewed_framework_version(version)?;
        let release_identity = snapshot_value(current, "release-identity")?;
        Ok(SelectionRequest {
            tool_id: "flutter".into(),
            adapter_key: "flutter".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![STORAGE_UPSTREAM.into(), PUB_UPSTREAM.into()],
            repository_versions: BTreeMap::from([(
                STORAGE_UPSTREAM.into(),
                release_identity.into(),
            )]),
            probe_contexts: BTreeMap::from([(
                STORAGE_UPSTREAM.into(),
                vec![storage_probe_context(context)],
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
                EndpointRole::Artifacts,
            ],
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
        require_supported_context(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let selected = selected_endpoints(selections)?;
        if context.os == OperatingSystem::Windows {
            return windows_plan(context, current, &selected);
        }
        let profile = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("flutter-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "selected Flutter shell profile is missing".into(),
                )
            })?;
        let shell = shell_from_format(&profile.format)?;
        let mut rendered = rewrite_profile(
            utf8(&profile.path, &profile.contents)?,
            &profile.path,
            shell,
            &selected.storage,
            &selected.hosted,
        )?
        .into_bytes();
        if profile.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let fixture = find_document(current, "flutter-verification-pubspec")?;
        let lock = find_document(current, "flutter-verification-lock")?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            profile,
            rendered,
            "add or retarget one managed Flutter storage and Pub block while preserving unrelated shell policy",
            &mut changes,
        );
        add_change(
            context,
            current,
            fixture,
            render_verification_pubspec().into_bytes(),
            "create an isolated Flutter Pub dependency fixture",
            &mut changes,
        );
        if !changes.is_empty() || !current.files.contains(&lock.path) {
            add_change(
                context,
                current,
                lock,
                render_verification_lock().into_bytes(),
                "snapshot the isolated Flutter Pub lockfile inside the configuration transaction",
                &mut changes,
            );
        }
        Ok(ChangePlan {
            adapter_key: "flutter".into(),
            tool_id: "flutter".into(),
            scope: ConfigurationScope::User,
            changes,
            requires_elevation: false,
            service_impact: ServiceImpact::None,
        })
    }

    fn apply(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        if context.os == OperatingSystem::Windows {
            windows_apply(runtime, plan)
        } else {
            runtime.apply_plan(plan)
        }
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        if context.os == OperatingSystem::Windows {
            return windows_verify(context, runtime, receipt);
        }
        let result = (|| {
            let layout = config_layout(context, runtime)?;
            let known = [
                rooted(&context.root, &layout.profile),
                rooted(&context.root, &layout.verification_pubspec),
                rooted(&context.root, &layout.verification_lock),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Flutter transaction receipt contains no known target".into(),
                ));
            }
            let profile = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("Flutter shell profile disappeared".into())
            })?;
            let parsed = parse_profile(
                utf8(&layout.profile, &profile)?,
                &layout.profile,
                layout.shell,
            )?;
            if parsed.dynamic || !parsed.unmanaged.is_empty() {
                return Err(AdapterError::Verification(
                    "Flutter profile gained conflicting mirror policy".into(),
                ));
            }
            let managed = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed Flutter mirror block is missing".into())
            })?;
            if !is_reviewed_storage(&managed.storage) || !is_reviewed_pub(&managed.hosted) {
                return Err(AdapterError::Verification(
                    "managed Flutter endpoints are not reviewed".into(),
                ));
            }
            let pubspec = runtime.read(&layout.verification_pubspec)?.ok_or_else(|| {
                AdapterError::Verification("Flutter verification pubspec disappeared".into())
            })?;
            if utf8(&layout.verification_pubspec, &pubspec)? != render_verification_pubspec() {
                return Err(AdapterError::Verification(
                    "Flutter verification pubspec is not canonical".into(),
                ));
            }

            let version = flutter_version(runtime, Some(&managed.storage), Some(&managed.hosted))?;
            validate_version(&version)?;
            run_flutter(
                runtime,
                None,
                Some(&managed.storage),
                Some(&managed.hosted),
                None,
                &[
                    "--suppress-analytics",
                    "precache",
                    platform_artifact_flag(context),
                ],
                "Flutter platform precache verification",
            )?;
            let doctor = run_flutter(
                runtime,
                None,
                Some(&managed.storage),
                Some(&managed.hosted),
                None,
                &["--suppress-analytics", "doctor", "--verbose"],
                "Flutter doctor verification",
            )?;
            if !doctor.contains("Flutter") {
                return Err(AdapterError::Verification(
                    "flutter doctor did not report the Flutter installation".into(),
                ));
            }
            run_flutter(
                runtime,
                Some(&layout.verification_root),
                Some(&managed.storage),
                Some(&managed.hosted),
                Some(&layout.verification_cache),
                &["--suppress-analytics", "pub", "get"],
                "Flutter Pub dependency verification",
            )?;
            let deps = run_flutter(
                runtime,
                Some(&layout.verification_root),
                Some(&managed.storage),
                Some(&managed.hosted),
                Some(&layout.verification_cache),
                &["--suppress-analytics", "pub", "deps", "--style=compact"],
                "Flutter Pub dependency query",
            )?;
            if !deps.contains("retry 3.1.2") {
                return Err(AdapterError::Verification(
                    "Flutter Pub query did not resolve retry 3.1.2".into(),
                ));
            }
            let lock = runtime.read(&layout.verification_lock)?.ok_or_else(|| {
                AdapterError::Verification("Flutter verification lockfile was not created".into())
            })?;
            let lock = utf8(&layout.verification_lock, &lock)?;
            if !lock.contains("retry:")
                || !lock.contains("version: \"3.1.2\"")
                || !lock.contains(managed.hosted.trim_end_matches('/'))
            {
                return Err(AdapterError::Verification(
                    "Flutter lockfile does not bind retry 3.1.2 to the selected Pub endpoint"
                        .into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Flutter {} {} verified {:?} artifacts through {} and Pub through {}",
                    version.framework_version,
                    version.channel,
                    context.os,
                    managed.storage,
                    managed.hosted
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
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        if context.os == OperatingSystem::Windows {
            return windows_restore(context, runtime, receipt);
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: format!(
                "restored {} Flutter configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ManagedKey {
    Storage,
    Pub,
}

impl ManagedKey {
    fn environment_name(self) -> &'static str {
        match self {
            Self::Storage => "FLUTTER_STORAGE_BASE_URL",
            Self::Pub => "PUB_HOSTED_URL",
        }
    }

    fn policy_name(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Pub => "pub",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellKind {
    Bash,
    Zsh,
    Fish,
    WindowsRegistry,
}

impl ShellKind {
    fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::WindowsRegistry => "Windows user environment",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlutterVersion {
    framework_version: String,
    channel: String,
    repository_url: String,
    framework_revision: String,
    engine_revision: String,
    engine_content_hash: Option<String>,
    dart_sdk_version: String,
}

impl FlutterVersion {
    fn release_identity(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.channel, self.framework_version, self.framework_revision, self.engine_revision
        )
    }
}

#[derive(Debug)]
struct Layout {
    shell: ShellKind,
    profile: PathBuf,
    token_dir: PathBuf,
    verification_root: PathBuf,
    verification_pubspec: PathBuf,
    verification_lock: PathBuf,
    verification_cache: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsRecoveryState {
    schema_version: u32,
    original_storage: Option<String>,
    original_pub: Option<String>,
    selected_storage: String,
    selected_pub: String,
}

impl WindowsRecoveryState {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != 1
            || !is_reviewed_storage(&self.selected_storage)
            || !is_reviewed_pub(&self.selected_pub)
        {
            return Err(AdapterError::InvalidConfiguration(
                "Flutter Windows recovery state has an invalid selected endpoint pair".into(),
            ));
        }
        for original in [
            self.original_storage.as_deref(),
            self.original_pub.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !valid_registry_url(original) {
                return Err(AdapterError::InvalidConfiguration(
                    "Flutter Windows recovery state has an invalid original endpoint".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Assignment {
    range: Range<usize>,
    key: ManagedKey,
    value: String,
}

#[derive(Clone, Debug)]
struct ManagedValues {
    storage: String,
    hosted: String,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<ManagedValues>,
    unmanaged: Vec<Assignment>,
    dynamic: bool,
}

impl ParsedProfile {
    fn value_for(&self, key: ManagedKey) -> Option<&str> {
        self.managed.as_ref().map(|managed| match key {
            ManagedKey::Storage => managed.storage.as_str(),
            ManagedKey::Pub => managed.hosted.as_str(),
        })
    }
}

#[derive(Default)]
struct ProjectObservation {
    hosted: usize,
    publish_targets: usize,
    lock_hosted: usize,
}

struct SelectedEndpoints {
    storage: String,
    hosted: String,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Flutter on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "Flutter on Windows arm64 is unavailable because the reviewed SDK channel has no native Windows arm64 archive"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Flutter requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn platform_artifact_flag(context: &SystemContext) -> &'static str {
    match context.os {
        OperatingSystem::Linux => "--linux",
        OperatingSystem::Macos => "--macos",
        OperatingSystem::Windows => "--windows",
    }
}

fn storage_probe_context(context: &SystemContext) -> BTreeMap<String, String> {
    let (manifest, platform, provenance) = match (context.os, context.architecture) {
        (OperatingSystem::Linux, Architecture::X86_64) => (
            "releases_linux.json",
            "linux-x64",
            "233a40905c350398edeb1eacad7ef43b68a8b84f0cf520201c27071dc3a70124",
        ),
        (OperatingSystem::Linux, Architecture::Arm64) => (
            "releases_linux.json",
            "linux-arm64",
            "d06ce9d4f7f1907523507c082e4511a0ce1d45a0853bde8e0aa0ab86b2d446cc",
        ),
        (OperatingSystem::Macos, Architecture::X86_64) => (
            "releases_macos.json",
            "darwin-x64",
            "6b3a832033f2c8e2a5d77bf96bbd61c549a1125e2fa6f47f8997880ef3191beb",
        ),
        (OperatingSystem::Macos, Architecture::Arm64) => (
            "releases_macos.json",
            "darwin-arm64",
            "b8175594873362eaec01a6bb880b0267179974f40c2cfd151d1de8b83c4041eb",
        ),
        (OperatingSystem::Windows, Architecture::X86_64) => (
            "releases_windows.json",
            "windows-x64",
            "c7d27a8ce0bb6bd69a661e231b7b88cb89d1011c205b8573068022ead8e9deb9",
        ),
        (OperatingSystem::Windows, Architecture::Arm64) => {
            unreachable!("Windows arm64 is rejected before candidate selection")
        }
    };
    BTreeMap::from([
        ("flutter_release_manifest".into(), manifest.into()),
        ("flutter_engine_platform".into(), platform.into()),
        ("flutter_engine_provenance_sha".into(), provenance.into()),
    ])
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Flutter adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "flutter" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Flutter requires a user home".into()))?;
    validate_path(&home, "home")?;
    let verification_root = home.join(".mirrorswitch/verification/flutter");
    if context.os == OperatingSystem::Windows {
        let local_app_data = required_environment_path(runtime, "LOCALAPPDATA")?;
        let app_data = required_environment_path(runtime, "APPDATA")?;
        return Ok(Layout {
            shell: ShellKind::WindowsRegistry,
            profile: local_app_data.join("MirrorSwitch/flutter/environment-recovery.json"),
            token_dir: app_data.join("dart"),
            verification_pubspec: verification_root.join("pubspec.yaml"),
            verification_lock: verification_root.join("pubspec.lock"),
            verification_cache: verification_root.join("cache"),
            verification_root,
        });
    }
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().and_then(parse_shell))
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "Flutter requires SHELL to select bash, zsh, or fish initialization".into(),
            )
        })?;
    let profile = selected_profile(context, runtime, &home, shell)?;
    let token_dir = match context.os {
        OperatingSystem::Macos => home.join("Library/Application Support/dart"),
        OperatingSystem::Linux => match runtime
            .environment_variable("XDG_CONFIG_HOME")
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) => {
                let path = PathBuf::from(value);
                validate_path(&path, "XDG_CONFIG_HOME")?;
                path.join("dart")
            }
            None => home.join(".config/dart"),
        },
        OperatingSystem::Windows => unreachable!("Windows layout returned above"),
    };
    Ok(Layout {
        shell,
        profile,
        token_dir,
        verification_pubspec: verification_root.join("pubspec.yaml"),
        verification_lock: verification_root.join("pubspec.lock"),
        verification_cache: verification_root.join("cache"),
        verification_root,
    })
}

fn required_environment_path(
    runtime: &dyn Runtime,
    variable: &str,
) -> Result<PathBuf, AdapterError> {
    let path = runtime
        .environment_variable(variable)
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            AdapterError::Unsupported(format!("Flutter Windows persistence requires {variable}"))
        })?;
    validate_path(&path, variable)?;
    Ok(path)
}

fn append_shared_current(
    runtime: &dyn Runtime,
    layout: &Layout,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    for (path, format) in project_paths(runtime)? {
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        files.push(path.clone());
        sources.extend(project_sources(utf8(&path, &contents)?, &path, format));
        documents.push(ConfigurationDocument {
            path,
            format: format.into(),
            contents,
        });
    }
    let fixture = runtime.read(&layout.verification_pubspec)?;
    let fixture_exists = fixture.is_some();
    let fixture = fixture.unwrap_or_default();
    if fixture_exists
        && utf8(&layout.verification_pubspec, &fixture)? != render_verification_pubspec()
    {
        sources.push(policy_source(
            "verification-conflict",
            &layout.verification_pubspec,
            layout.shell,
        ));
    }
    if fixture_exists {
        files.push(layout.verification_pubspec.clone());
    }
    documents.push(ConfigurationDocument {
        path: layout.verification_pubspec.clone(),
        format: "flutter-verification-pubspec".into(),
        contents: fixture,
    });
    let lock = runtime.read(&layout.verification_lock)?;
    let lock_exists = lock.is_some();
    let lock = lock.unwrap_or_default();
    if lock_exists && !fixture_exists {
        sources.push(policy_source(
            "verification-conflict",
            &layout.verification_lock,
            layout.shell,
        ));
    }
    if lock_exists {
        files.push(layout.verification_lock.clone());
    }
    documents.push(ConfigurationDocument {
        path: layout.verification_lock.clone(),
        format: "flutter-verification-lock".into(),
        contents: lock,
    });
    Ok(())
}

fn windows_current(
    runtime: &dyn Runtime,
    layout: &Layout,
    version: &FlutterVersion,
) -> Result<CurrentConfiguration, AdapterError> {
    let observed = runtime.read(&layout.profile)?;
    let recovery_exists = observed.is_some();
    let recovery_contents = observed.unwrap_or_default();
    let recovery = if recovery_exists {
        let state: WindowsRecoveryState =
            serde_json::from_slice(&recovery_contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "Flutter Windows recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        Some(state)
    } else {
        None
    };
    let storage = query_windows_variable(runtime, STORAGE_VARIABLE)?;
    let hosted = query_windows_variable(runtime, PUB_VARIABLE)?;
    let mut sources = vec![
        snapshot_source("release-identity", &version.release_identity()),
        snapshot_source("framework-version", &version.framework_version),
        snapshot_source("flutter-channel", &version.channel),
        snapshot_source("engine-artifact-version", &version.engine_revision),
    ];
    if recovery.is_some() {
        sources.push(policy_source(
            "windows-recovery-active",
            &layout.profile,
            ShellKind::WindowsRegistry,
        ));
    }
    for (key, value, upstream) in [
        (ManagedKey::Storage, storage.as_deref(), STORAGE_UPSTREAM),
        (ManagedKey::Pub, hosted.as_deref(), PUB_UPSTREAM),
    ] {
        if let Some(value) = value {
            let managed = recovery.as_ref().is_some_and(|state| match key {
                ManagedKey::Storage => same_base(&state.selected_storage, value),
                ManagedKey::Pub => same_base(&state.selected_pub, value),
            });
            let kind = if managed {
                format!("{}-managed-shell-profile", key.policy_name())
            } else if is_public(key, value) {
                format!("{}-adoptable-shell-profile", key.policy_name())
            } else {
                format!("{}-private-shell-profile", key.policy_name())
            };
            sources.push(configured_source(
                value,
                upstream,
                &kind,
                Path::new(r"HKCU\Environment"),
                ShellKind::WindowsRegistry,
            ));
        }
    }
    for (key, persistent) in [
        (ManagedKey::Storage, storage.as_deref()),
        (ManagedKey::Pub, hosted.as_deref()),
    ] {
        if let Some(value) = runtime
            .environment_variable(key.environment_name())
            .filter(|value| !value.trim().is_empty())
        {
            let stale_original = recovery.as_ref().is_some_and(|state| {
                let original = match key {
                    ManagedKey::Storage => state.original_storage.as_deref(),
                    ManagedKey::Pub => state.original_pub.as_deref(),
                };
                original.is_some_and(|original| same_base(original, &value))
            });
            if !persistent.is_some_and(|persistent| same_base(persistent, &value))
                && !stale_original
            {
                sources.push(policy_source(
                    &format!("{}-environment-override", key.policy_name()),
                    Path::new(":env:"),
                    ShellKind::WindowsRegistry,
                ));
            }
        }
    }
    if token_file_count(runtime, &layout.token_dir)? > 0 {
        sources.push(policy_source(
            "credentials-detected",
            &layout.token_dir,
            ShellKind::WindowsRegistry,
        ));
    }

    let mut files = recovery_exists
        .then_some(layout.profile.clone())
        .into_iter()
        .collect::<Vec<_>>();
    let mut documents = vec![
        ConfigurationDocument {
            path: layout.profile.clone(),
            format: "flutter-windows-recovery".into(),
            contents: recovery_contents,
        },
        ConfigurationDocument {
            path: PathBuf::from(r"HKCU\Environment\FLUTTER_STORAGE_BASE_URL"),
            format: "flutter-windows-storage-snapshot".into(),
            contents: storage.as_deref().unwrap_or_default().as_bytes().to_vec(),
        },
        ConfigurationDocument {
            path: PathBuf::from(r"HKCU\Environment\PUB_HOSTED_URL"),
            format: "flutter-windows-pub-snapshot".into(),
            contents: hosted.as_deref().unwrap_or_default().as_bytes().to_vec(),
        },
    ];
    append_shared_current(runtime, layout, &mut files, &mut sources, &mut documents)?;
    Ok(CurrentConfiguration {
        tool_id: "flutter".into(),
        scope: ConfigurationScope::User,
        files,
        sources,
        documents,
    })
}

fn windows_plan(
    context: &SystemContext,
    current: &CurrentConfiguration,
    selected: &SelectedEndpoints,
) -> Result<ChangePlan, AdapterError> {
    let recovery = find_document(current, "flutter-windows-recovery")?;
    let fixture = find_document(current, "flutter-verification-pubspec")?;
    let lock = find_document(current, "flutter-verification-lock")?;
    if !recovery.contents.is_empty() {
        let state: WindowsRecoveryState =
            serde_json::from_slice(&recovery.contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "Flutter Windows recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        if !same_base(&state.selected_storage, &selected.storage)
            || !same_base(&state.selected_pub, &selected.hosted)
        {
            return Err(AdapterError::Unsupported(
                "a previous Flutter Windows recovery state is active; restore it before selecting another endpoint pair"
                    .into(),
            ));
        }
        if fixture.contents != render_verification_pubspec().as_bytes()
            || !current.files.contains(&lock.path)
        {
            return Err(AdapterError::Unsupported(
                "active Flutter Windows recovery state has incomplete verification files; restore it first"
                    .into(),
            ));
        }
        return Ok(ChangePlan {
            adapter_key: "flutter".into(),
            tool_id: "flutter".into(),
            scope: ConfigurationScope::User,
            changes: Vec::new(),
            requires_elevation: false,
            service_impact: ServiceImpact::None,
        });
    }
    let state = WindowsRecoveryState {
        schema_version: 1,
        original_storage: snapshot_document_value(current, "flutter-windows-storage-snapshot")?,
        original_pub: snapshot_document_value(current, "flutter-windows-pub-snapshot")?,
        selected_storage: selected.storage.clone(),
        selected_pub: selected.hosted.clone(),
    };
    state.validate()?;
    let mut recovery_contents = serde_json::to_vec_pretty(&state).map_err(|error| {
        AdapterError::Runtime(format!(
            "could not serialize Flutter Windows recovery state: {error}"
        ))
    })?;
    recovery_contents.push(b'\n');
    let mut changes = Vec::new();
    add_change(
        context,
        current,
        recovery,
        recovery_contents,
        "record private Flutter Windows user-environment recovery state before updating the storage and Pub pair",
        &mut changes,
    );
    add_change(
        context,
        current,
        fixture,
        render_verification_pubspec().into_bytes(),
        "create an isolated Flutter Pub dependency fixture",
        &mut changes,
    );
    add_change(
        context,
        current,
        lock,
        render_verification_lock().into_bytes(),
        "snapshot the isolated Flutter Pub lockfile inside the configuration transaction",
        &mut changes,
    );
    Ok(ChangePlan {
        adapter_key: "flutter".into(),
        tool_id: "flutter".into(),
        scope: ConfigurationScope::User,
        changes,
        requires_elevation: false,
        service_impact: ServiceImpact::None,
    })
}

fn snapshot_document_value(
    current: &CurrentConfiguration,
    format: &str,
) -> Result<Option<String>, AdapterError> {
    let document = find_document(current, format)?;
    if document.contents.is_empty() {
        return Ok(None);
    }
    String::from_utf8(document.contents.clone())
        .map(Some)
        .map_err(|_| AdapterError::InvalidConfiguration(format!("{format} is not UTF-8")))
}

fn windows_apply(
    runtime: &mut dyn Runtime,
    plan: &ChangePlan,
) -> Result<ApplyOutcome, AdapterError> {
    if plan.adapter_key != "flutter" || plan.tool_id != "flutter" {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter Windows apply received another tool's plan".into(),
        ));
    }
    let state = plan.changes.iter().find_map(|change| {
        serde_json::from_slice::<WindowsRecoveryState>(&change.new_contents).ok()
    });
    let Some(state) = state else {
        return runtime.apply_plan(plan);
    };
    state.validate()?;
    let outcome = runtime.apply_plan(plan)?;
    let ApplyOutcome::Applied(receipt) = &outcome else {
        return Ok(outcome);
    };
    if let Err(error) = set_windows_pair(runtime, &state.selected_storage, &state.selected_pub) {
        let registry_restored = restore_windows_pair(runtime, &state).is_ok();
        let state_restored =
            registry_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
        return Err(AdapterError::Runtime(format!(
            "Flutter Windows environment update failed: {error}; registry restored: {registry_restored}; recovery files restored: {state_restored}"
        )));
    }
    Ok(outcome)
}

fn windows_verify(
    context: &SystemContext,
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
) -> Result<VerificationResult, AdapterError> {
    let layout = config_layout(context, runtime)?;
    let state = read_windows_recovery(runtime, &layout)?;
    let known = [
        rooted(&context.root, &layout.profile),
        rooted(&context.root, &layout.verification_pubspec),
        rooted(&context.root, &layout.verification_lock),
    ];
    if receipt
        .changed_targets
        .iter()
        .all(|target| !known.contains(target))
    {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter Windows receipt contains no known target".into(),
        ));
    }
    let result = (|| {
        if query_windows_variable(runtime, STORAGE_VARIABLE)?.as_deref()
            != Some(state.selected_storage.as_str())
            || query_windows_variable(runtime, PUB_VARIABLE)?.as_deref()
                != Some(state.selected_pub.as_str())
        {
            return Err(AdapterError::Verification(
                "Flutter Windows user environment did not retain the selected endpoint pair".into(),
            ));
        }
        let pubspec = runtime.read(&layout.verification_pubspec)?.ok_or_else(|| {
            AdapterError::Verification("Flutter verification pubspec disappeared".into())
        })?;
        if utf8(&layout.verification_pubspec, &pubspec)? != render_verification_pubspec() {
            return Err(AdapterError::Verification(
                "Flutter verification pubspec is not canonical".into(),
            ));
        }
        let version = flutter_version(
            runtime,
            Some(&state.selected_storage),
            Some(&state.selected_pub),
        )?;
        validate_version(&version)?;
        run_flutter(
            runtime,
            None,
            Some(&state.selected_storage),
            Some(&state.selected_pub),
            None,
            &[
                "--suppress-analytics",
                "precache",
                platform_artifact_flag(context),
            ],
            "Flutter Windows precache verification",
        )?;
        let doctor = run_flutter(
            runtime,
            None,
            Some(&state.selected_storage),
            Some(&state.selected_pub),
            None,
            &["--suppress-analytics", "doctor", "--verbose"],
            "Flutter doctor verification",
        )?;
        if !doctor.contains("Flutter") {
            return Err(AdapterError::Verification(
                "flutter doctor did not report the Flutter installation".into(),
            ));
        }
        run_flutter(
            runtime,
            Some(&layout.verification_root),
            Some(&state.selected_storage),
            Some(&state.selected_pub),
            Some(&layout.verification_cache),
            &["--suppress-analytics", "pub", "get"],
            "Flutter Pub dependency verification",
        )?;
        let deps = run_flutter(
            runtime,
            Some(&layout.verification_root),
            Some(&state.selected_storage),
            Some(&state.selected_pub),
            Some(&layout.verification_cache),
            &["--suppress-analytics", "pub", "deps", "--style=compact"],
            "Flutter Pub dependency query",
        )?;
        if !deps.contains("retry 3.1.2") {
            return Err(AdapterError::Verification(
                "Flutter Pub query did not resolve retry 3.1.2".into(),
            ));
        }
        let lock = runtime.read(&layout.verification_lock)?.ok_or_else(|| {
            AdapterError::Verification("Flutter verification lockfile was not created".into())
        })?;
        let lock = utf8(&layout.verification_lock, &lock)?;
        if !lock.contains("retry:")
            || !lock.contains("version: \"3.1.2\"")
            || !lock.contains(state.selected_pub.trim_end_matches('/'))
        {
            return Err(AdapterError::Verification(
                "Flutter lockfile does not bind retry 3.1.2 to the selected Pub endpoint".into(),
            ));
        }
        Ok(VerificationResult {
            valid: true,
            summary: format!(
                "Flutter {} {} verified Windows artifacts through {} and Pub through {}",
                version.framework_version,
                version.channel,
                state.selected_storage,
                state.selected_pub
            ),
        })
    })();
    if let Err(error) = result {
        let registry_restored = restore_windows_pair(runtime, &state).is_ok();
        let state_restored =
            registry_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
        return Err(AdapterError::Verification(format!(
            "{error}; registry restored: {registry_restored}; recovery files restored: {state_restored}"
        )));
    }
    result
}

fn windows_restore(
    context: &SystemContext,
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
) -> Result<RestoreResult, AdapterError> {
    let layout = config_layout(context, runtime)?;
    let state = read_windows_recovery(runtime, &layout)?;
    restore_windows_pair(runtime, &state)?;
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Ok(RestoreResult {
        restored: restored.verified,
        summary: "restored the previous Flutter Windows user environment and recovery files".into(),
    })
}

fn read_windows_recovery(
    runtime: &dyn Runtime,
    layout: &Layout,
) -> Result<WindowsRecoveryState, AdapterError> {
    let contents = runtime
        .read(&layout.profile)?
        .ok_or_else(|| AdapterError::Runtime("Flutter Windows recovery state is missing".into()))?;
    let state: WindowsRecoveryState = serde_json::from_slice(&contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Flutter Windows recovery state is invalid: {error}"
        ))
    })?;
    state.validate()?;
    Ok(state)
}

fn query_windows_variable(
    runtime: &dyn Runtime,
    variable: &str,
) -> Result<Option<String>, AdapterError> {
    let output = runtime.run(
        "reg.exe",
        &[
            "query".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            variable.into(),
        ],
    )?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "reg.exe query {variable} failed with status {}",
            output.status
        )));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("reg.exe returned non-UTF-8 output".into()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(variable))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("reg.exe returned no {variable} value"))
        })?;
    let rest = line[variable.len()..].trim_start();
    let split = rest.find(char::is_whitespace).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("reg.exe returned malformed {variable} state"))
    })?;
    let kind = &rest[..split];
    let value = rest[split..].trim();
    if kind != "REG_SZ" || !valid_registry_url(value) {
        return Err(AdapterError::Unsupported(format!(
            "Flutter Windows {variable} must be a non-empty HTTPS REG_SZ URL"
        )));
    }
    Ok(Some(value.into()))
}

fn set_windows_pair(
    runtime: &dyn Runtime,
    storage: &str,
    hosted: &str,
) -> Result<(), AdapterError> {
    set_windows_variable(runtime, STORAGE_VARIABLE, storage)?;
    set_windows_variable(runtime, PUB_VARIABLE, hosted)
}

fn restore_windows_pair(
    runtime: &dyn Runtime,
    state: &WindowsRecoveryState,
) -> Result<(), AdapterError> {
    restore_windows_variable(runtime, STORAGE_VARIABLE, state.original_storage.as_deref())?;
    restore_windows_variable(runtime, PUB_VARIABLE, state.original_pub.as_deref())
}

fn restore_windows_variable(
    runtime: &dyn Runtime,
    variable: &str,
    original: Option<&str>,
) -> Result<(), AdapterError> {
    match original {
        Some(value) => set_windows_variable(runtime, variable, value),
        None => delete_windows_variable(runtime, variable),
    }
}

fn set_windows_variable(
    runtime: &dyn Runtime,
    variable: &str,
    value: &str,
) -> Result<(), AdapterError> {
    if !valid_registry_url(value) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flutter Windows {variable} endpoint is not a valid HTTPS URL"
        )));
    }
    let output = runtime.run(
        "reg.exe",
        &[
            "add".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            variable.into(),
            "/t".into(),
            "REG_SZ".into(),
            "/d".into(),
            value.into(),
            "/f".into(),
        ],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "reg.exe add {variable} failed with status {}",
            output.status
        )))
    }
}

fn delete_windows_variable(runtime: &dyn Runtime, variable: &str) -> Result<(), AdapterError> {
    let output = runtime.run(
        "reg.exe",
        &[
            "delete".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            variable.into(),
            "/f".into(),
        ],
    )?;
    if output.status.success() || output.status.code() == Some(1) {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "reg.exe delete {variable} failed with status {}",
            output.status
        )))
    }
}

fn valid_registry_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && !value.chars().any(char::is_whitespace)
    })
}

fn parse_shell(value: &str) -> Option<ShellKind> {
    match value {
        "bash" => Some(ShellKind::Bash),
        "zsh" => Some(ShellKind::Zsh),
        "fish" => Some(ShellKind::Fish),
        _ => None,
    }
}

fn selected_profile(
    context: &SystemContext,
    runtime: &dyn Runtime,
    home: &Path,
    shell: ShellKind,
) -> Result<PathBuf, AdapterError> {
    if let Some(value) = runtime
        .environment_variable("PROFILE")
        .filter(|value| !value.trim().is_empty())
    {
        if value == "/dev/null" {
            return Err(AdapterError::Unsupported(
                "PROFILE=/dev/null disables persistent Flutter configuration".into(),
            ));
        }
        let path = PathBuf::from(value);
        validate_user_path(&path, home, "shell profile")?;
        return Ok(path);
    }
    if context.environment == ExecutionEnvironment::Container
        && shell == ShellKind::Bash
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.trim().is_empty())
    {
        let path = PathBuf::from(value);
        validate_user_path(&path, home, "BASH_ENV")?;
        return Ok(path);
    }
    let path = match shell {
        ShellKind::Bash => home.join(".bashrc"),
        ShellKind::Zsh => match runtime
            .environment_variable("ZDOTDIR")
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) => {
                let path = PathBuf::from(value).join(".zshrc");
                validate_user_path(&path, home, "ZDOTDIR profile")?;
                path
            }
            None => home.join(".zshrc"),
        },
        ShellKind::Fish => home.join(".config/fish/conf.d/mirrorswitch-flutter.fish"),
        ShellKind::WindowsRegistry => {
            unreachable!("Windows layout returned before shell selection")
        }
    };
    validate_user_path(&path, home, "shell profile")?;
    Ok(path)
}

fn project_paths(runtime: &dyn Runtime) -> Result<Vec<(PathBuf, &'static str)>, AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(Vec::new());
    };
    validate_path(&project, "project")?;
    Ok(vec![
        (project.join("pubspec.yaml"), "flutter-project-pubspec"),
        (project.join("pubspec.lock"), "flutter-project-lock"),
    ])
}

fn inspect_project(runtime: &dyn Runtime) -> Result<ProjectObservation, AdapterError> {
    let mut observation = ProjectObservation::default();
    for (path, format) in project_paths(runtime)? {
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        let text = utf8(&path, &contents)?;
        if format == "flutter-project-pubspec" {
            observation.hosted += text.matches("hosted:").count();
            observation.publish_targets += text
                .lines()
                .filter(|line| active_yaml_line(line).starts_with("publish_to:"))
                .count();
        } else {
            observation.lock_hosted += text
                .lines()
                .filter(|line| active_yaml_line(line) == "source: hosted")
                .count();
        }
    }
    Ok(observation)
}

fn token_file_count(runtime: &dyn Runtime, directory: &Path) -> Result<usize, AdapterError> {
    Ok(runtime
        .list_files(directory)?
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "pub-tokens.json" || name == "pub-credentials.json")
        })
        .count())
}

fn project_sources(text: &str, path: &Path, format: &str) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if format == "flutter-project-pubspec" {
        for line in text.lines().map(active_yaml_line) {
            if line.starts_with("hosted:") {
                sources.push(project_source("project-hosted-preserved", path));
            } else if line.starts_with("publish_to:") {
                sources.push(project_source("publish-target-preserved", path));
            } else if line.starts_with("git:")
                || line.starts_with("path:")
                || line.starts_with("sdk:")
            {
                sources.push(project_source("non-hosted-source-preserved", path));
            }
        }
    } else {
        for line in text.lines().map(active_yaml_line) {
            if line == "source: hosted" {
                sources.push(project_source("project-lock-preserved", path));
            }
        }
    }
    sources
}

fn active_yaml_line(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim()
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let managed_range = managed_range(text, path)?;
    let managed = managed_range
        .as_ref()
        .map(|range| managed_values(&text[range.clone()], path, shell))
        .transpose()?;
    let mut unmanaged = Vec::new();
    let mut dynamic = false;
    for (start, line) in line_spans(text) {
        if managed_range
            .as_ref()
            .is_some_and(|range| range.contains(&start))
        {
            continue;
        }
        let active = line.trim();
        if active.is_empty()
            || active.starts_with('#')
            || (!active.contains(ManagedKey::Storage.environment_name())
                && !active.contains(ManagedKey::Pub.environment_name()))
        {
            continue;
        }
        match assignment(active, shell)? {
            Some((key, value)) => unmanaged.push(Assignment {
                range: start..start + line.len(),
                key,
                value: value.into(),
            }),
            None => dynamic = true,
        }
    }
    Ok(ParsedProfile {
        managed,
        unmanaged,
        dynamic,
    })
}

fn managed_values(
    block: &str,
    path: &Path,
    shell: ShellKind,
) -> Result<ManagedValues, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| assignment(line.trim(), shell).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let storage = unique_assignment(&values, ManagedKey::Storage, path)?;
    let hosted = unique_assignment(&values, ManagedKey::Pub, path)?;
    if values.len() != 2 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed Flutter block in {} must assign only both mirror variables",
            path.display()
        )));
    }
    if !is_reviewed_storage(storage) || !is_reviewed_pub(hosted) {
        return Err(AdapterError::Unsupported(
            "managed Flutter block is bound to an unreviewed endpoint".into(),
        ));
    }
    Ok(ManagedValues {
        storage: storage.into(),
        hosted: hosted.into(),
    })
}

fn unique_assignment<'a>(
    values: &[(ManagedKey, &'a str)],
    key: ManagedKey,
    path: &Path,
) -> Result<&'a str, AdapterError> {
    let matches = values
        .iter()
        .filter(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed Flutter block in {} must assign {} exactly once",
            path.display(),
            key.environment_name()
        )));
    }
    Ok(matches[0])
}

fn assignment(line: &str, shell: ShellKind) -> Result<Option<(ManagedKey, &str)>, AdapterError> {
    let (key, raw) = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            let Some(key) = parse_key(key.trim()) else {
                return Ok(None);
            };
            (key, value.trim())
        }
        ShellKind::Fish => {
            let Some(rest) = line.strip_prefix("set ") else {
                return Ok(None);
            };
            let mut fields = rest.split_whitespace();
            let Some(flags) = fields.next() else {
                return Ok(None);
            };
            let Some(key) = fields.next().and_then(parse_key) else {
                return Ok(None);
            };
            let Some(value) = fields.next() else {
                return Ok(None);
            };
            if !flags.contains('x') || fields.next().is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "fish {} assignment is not a literal exported value",
                    key.environment_name()
                )));
            }
            (key, value)
        }
        ShellKind::WindowsRegistry => {
            return Err(AdapterError::InvalidConfiguration(
                "Flutter Windows registry is not a shell profile".into(),
            ));
        }
    };
    Ok(Some((key, literal_value(raw, key)?)))
}

fn parse_key(value: &str) -> Option<ManagedKey> {
    match value {
        "FLUTTER_STORAGE_BASE_URL" => Some(ManagedKey::Storage),
        "PUB_HOSTED_URL" => Some(ManagedKey::Pub),
        _ => None,
    }
}

fn literal_value(raw: &str, key: ManagedKey) -> Result<&str, AdapterError> {
    let single = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    let value = if single || double {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.is_empty()
        || value.contains([';', '`', '$', '\n', '\r'])
        || (single && value.contains('\''))
        || (double && value.contains('"'))
        || (!single
            && !double
            && raw
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '\'' | '"')))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "{} assignment is not a literal value",
            key.environment_name()
        )));
    }
    Ok(value)
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
            "Flutter managed markers in {} are missing, duplicated, or out of order",
            path.display()
        ))),
    }
}

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
}

fn profile_sources(parsed: &ParsedProfile, path: &Path, shell: ShellKind) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(managed) = &parsed.managed {
        sources.push(configured_source(
            &managed.storage,
            STORAGE_UPSTREAM,
            "storage-managed-shell-profile",
            path,
            shell,
        ));
        sources.push(configured_source(
            &managed.hosted,
            PUB_UPSTREAM,
            "pub-managed-shell-profile",
            path,
            shell,
        ));
    }
    for assignment in &parsed.unmanaged {
        let public = is_public(assignment.key, &assignment.value);
        let kind = format!(
            "{}-{}-shell-profile",
            assignment.key.policy_name(),
            if public { "adoptable" } else { "private" }
        );
        sources.push(if public {
            configured_source(
                &assignment.value,
                match assignment.key {
                    ManagedKey::Storage => STORAGE_UPSTREAM,
                    ManagedKey::Pub => PUB_UPSTREAM,
                },
                &kind,
                path,
                shell,
            )
        } else {
            policy_source(&kind, path, shell)
        });
    }
    for key in [ManagedKey::Storage, ManagedKey::Pub] {
        let count = usize::from(parsed.managed.is_some())
            + parsed
                .unmanaged
                .iter()
                .filter(|assignment| assignment.key == key)
                .count();
        if count > 1 {
            sources.push(policy_source(
                &format!("{}-duplicate-shell-profile", key.policy_name()),
                path,
                shell,
            ));
        }
    }
    if parsed.dynamic {
        sources.push(policy_source("dynamic-shell-profile", path, shell));
    }
    sources
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        let kind = metadata(source, "kind")?;
        if kind.ends_with("-private-shell-profile") {
            return Err(AdapterError::Unsupported(
                "existing Flutter mirror variable points to a private, authenticated, or unreviewed endpoint"
                    .into(),
            ));
        }
        if kind.ends_with("-duplicate-shell-profile") {
            return Err(AdapterError::InvalidConfiguration(
                "selected shell profile assigns a Flutter mirror variable more than once".into(),
            ));
        }
        match kind {
            "dynamic-shell-profile" => {
                return Err(AdapterError::Unsupported(
                    "selected shell profile computes a Flutter mirror variable dynamically".into(),
                ));
            }
            "storage-environment-override" | "pub-environment-override" => {
                return Err(AdapterError::Unsupported(
                    "current Flutter mirror environment is not represented by the selected persistent profile"
                        .into(),
                ));
            }
            "foreign-dart-managed-block" => {
                return Err(AdapterError::Conflict(
                    "the selected profile is already managed by the Dart Pub adapter".into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Flutter verification target contains data not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_profile(
    text: &str,
    path: &Path,
    shell: ShellKind,
    storage: &str,
    hosted: &str,
) -> Result<String, AdapterError> {
    let parsed = parse_profile(text, path, shell)?;
    if parsed.dynamic {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter profile cannot be rewritten safely".into(),
        ));
    }
    for key in [ManagedKey::Storage, ManagedKey::Pub] {
        if parsed
            .unmanaged
            .iter()
            .filter(|assignment| assignment.key == key)
            .count()
            > 1
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Flutter profile assigns {} more than once",
                key.environment_name()
            )));
        }
    }
    if parsed
        .unmanaged
        .iter()
        .any(|assignment| !is_public(assignment.key, &assignment.value))
    {
        return Err(AdapterError::Unsupported(
            "private or unreviewed Flutter endpoints cannot be replaced".into(),
        ));
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(storage, hosted, newline, shell);
    if let Some(range) = managed_range(text, path)? {
        return Ok(format!(
            "{}{}{}",
            &text[..range.start],
            block,
            &text[range.end..]
        ));
    }
    if !parsed.unmanaged.is_empty() {
        let insertion = parsed
            .unmanaged
            .iter()
            .map(|assignment| assignment.range.start)
            .min()
            .expect("non-empty assignments");
        let mut output = text.to_owned();
        let mut ranges = parsed
            .unmanaged
            .iter()
            .map(|assignment| assignment.range.clone())
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
        for range in ranges {
            output.replace_range(range, "");
        }
        output.insert_str(insertion, &block);
        return Ok(output);
    }
    let mut output = text.to_owned();
    if !output.is_empty() {
        if !output.ends_with('\n') {
            output.push_str(newline);
        }
        if !output.ends_with(&format!("{newline}{newline}")) {
            output.push_str(newline);
        }
    }
    output.push_str(&block);
    Ok(output)
}

fn render_managed(storage: &str, hosted: &str, newline: &str, shell: ShellKind) -> String {
    let (storage, hosted) = match shell {
        ShellKind::Bash | ShellKind::Zsh => (
            format!("export FLUTTER_STORAGE_BASE_URL='{storage}'"),
            format!("export PUB_HOSTED_URL='{hosted}'"),
        ),
        ShellKind::Fish => (
            format!("set -gx FLUTTER_STORAGE_BASE_URL '{storage}'"),
            format!("set -gx PUB_HOSTED_URL '{hosted}'"),
        ),
        ShellKind::WindowsRegistry => {
            unreachable!("Flutter Windows persistence does not render a shell block")
        }
    };
    format!("{MANAGED_BEGIN}{newline}{storage}{newline}{hosted}{newline}{MANAGED_END}{newline}")
}

fn render_verification_pubspec() -> String {
    format!(
        "{VERIFY_MARKER}\nname: mirrorswitch_flutter_verification\npublish_to: none\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  retry: 3.1.2\n"
    )
}

fn render_verification_lock() -> String {
    format!("{VERIFY_MARKER}\npackages: {{}}\nsdks:\n  dart: \">=3.0.0 <4.0.0\"\n")
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish]
        .into_iter()
        .find(|shell| format == format!("flutter-selected-{}-profile", shell.name()))
        .ok_or_else(|| AdapterError::InvalidConfiguration("unknown Flutter profile format".into()))
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<SelectedEndpoints, AdapterError> {
    let storage = selected_storage(selections)?;
    let hosted = selected_pub(selections)?;
    Ok(SelectedEndpoints { storage, hosted })
}

fn selected_storage(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "flutter" && selection.upstream_id == STORAGE_UPSTREAM
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter requires exactly one storage selection".into(),
        ));
    }
    let selection = matches[0];
    let endpoints = role_endpoints(selection, "Flutter storage")?;
    if endpoints.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter storage index, metadata, and artifacts must share one base URL".into(),
        ));
    }
    let endpoint = endpoints.into_iter().next().expect("one endpoint");
    let provider = match endpoint.as_str() {
        NJU_STORAGE => "nju",
        SJTUG_STORAGE => "sjtug",
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Flutter storage endpoint is not reviewed".into(),
            ));
        }
    };
    if selection.provider_id != provider {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter storage provider and endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn selected_pub(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "flutter" && selection.upstream_id == PUB_UPSTREAM)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter requires exactly one Pub selection".into(),
        ));
    }
    let selection = matches[0];
    let role = |role| -> Result<String, AdapterError> {
        let endpoints = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if endpoints.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Flutter Pub selection requires one HTTPS {role:?} endpoint"
            )));
        }
        normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Flutter Pub {role:?} endpoint is unsafe"))
        })
    };
    let index = role(EndpointRole::Index)?;
    let metadata = role(EndpointRole::Metadata)?;
    let artifacts = role(EndpointRole::Artifacts)?;
    if index != metadata {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter Pub index and metadata endpoints must share one hosted URL".into(),
        ));
    }
    let (provider, expected_artifacts) = match index.as_str() {
        TUNA_PUB => ("tuna", TUNA_PUB_ARTIFACTS),
        SJTUG_PUB => ("sjtug", SJTUG_PUB_ARTIFACTS),
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Flutter Pub hosted endpoint is not reviewed".into(),
            ));
        }
    };
    if selection.provider_id != provider || artifacts != expected_artifacts {
        return Err(AdapterError::InvalidConfiguration(
            "Flutter Pub provider, hosted endpoint, and artifact endpoint do not match".into(),
        ));
    }
    Ok(index)
}

fn role_endpoints(
    selection: &MirrorSelection,
    label: &str,
) -> Result<BTreeSet<String>, AdapterError> {
    let mut values = BTreeSet::new();
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
                "{label} selection requires one HTTPS {role:?} endpoint"
            )));
        }
        values.insert(normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("{label} {role:?} endpoint is unsafe"))
        })?);
    }
    Ok(values)
}

fn flutter_version(
    runtime: &dyn Runtime,
    storage: Option<&str>,
    hosted: Option<&str>,
) -> Result<FlutterVersion, AdapterError> {
    let output = run_flutter_stdout(
        runtime,
        None,
        storage,
        hosted,
        None,
        &["--version", "--machine"],
        "flutter --version --machine",
    )?;
    serde_json::from_str(output.trim()).map_err(|error| {
        AdapterError::Unsupported(format!(
            "Flutter machine version output is invalid: {error}"
        ))
    })
}

fn validate_version(version: &FlutterVersion) -> Result<(), AdapterError> {
    reviewed_framework_version(&version.framework_version)?;
    if !matches!(version.channel.as_str(), "stable" | "beta") {
        return Err(AdapterError::Unsupported(format!(
            "Flutter channel {} is not reviewed for release mirrors",
            version.channel
        )));
    }
    if !valid_revision(&version.framework_revision)
        || !valid_revision(&version.engine_revision)
        || version
            .engine_content_hash
            .as_deref()
            .is_some_and(|hash| !valid_revision(hash))
    {
        return Err(AdapterError::Unsupported(
            "Flutter framework or engine revision is unrecognized".into(),
        ));
    }
    if version.dart_sdk_version.trim().is_empty() {
        return Err(AdapterError::Unsupported(
            "Flutter did not report its Dart SDK version".into(),
        ));
    }
    if !reviewed_repository(&version.repository_url) {
        return Err(AdapterError::Unsupported(
            "Flutter SDK repository is custom or unreviewed".into(),
        ));
    }
    Ok(())
}

fn reviewed_framework_version(value: &str) -> Result<(), AdapterError> {
    if !valid_version(value) {
        return Err(AdapterError::Unsupported(
            "Flutter framework version is unrecognized".into(),
        ));
    }
    let mut parts = value.split(['.', '-']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    if !matches!((major, minor), (Some(3), Some(22..))) {
        return Err(AdapterError::Unsupported(format!(
            "Flutter {value} is outside the reviewed 3.22+ mirror model"
        )));
    }
    Ok(())
}

fn valid_version(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
        && value.split(['.', '-', '+']).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn reviewed_repository(value: &str) -> bool {
    if matches!(
        value.trim_end_matches('/'),
        "git@github.com:flutter/flutter.git" | "ssh://git@github.com/flutter/flutter.git"
    ) {
        return true;
    }
    normalized_base(value).is_some_and(|value| {
        matches!(
            value.as_str(),
            "https://github.com/flutter/flutter"
                | "https://github.com/flutter/flutter.git"
                | "https://mirrors.nju.edu.cn/git/flutter-sdk.git"
                | "https://mirrors.nju.edu.cn/flutter-sdk.git"
                | "https://mirrors.tuna.tsinghua.edu.cn/flutter-sdk.git"
                | "https://mirror.sjtu.edu.cn/git%2fflutter-sdk.git"
        )
    })
}

fn repository_state(value: &str) -> &'static str {
    if reviewed_repository(value) {
        "reviewed"
    } else {
        "custom"
    }
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

fn same_base(left: &str, right: &str) -> bool {
    normalized_base(left).is_some_and(|left| normalized_base(right).as_deref() == Some(&left))
}

fn is_reviewed_storage(value: &str) -> bool {
    normalized_base(value)
        .is_some_and(|value| matches!(value.as_str(), NJU_STORAGE | SJTUG_STORAGE))
}

fn is_reviewed_pub(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| matches!(value.as_str(), TUNA_PUB | SJTUG_PUB))
}

fn is_public(key: ManagedKey, value: &str) -> bool {
    normalized_base(value).is_some_and(|value| match key {
        ManagedKey::Storage => {
            is_reviewed_storage(&value) || OFFICIAL_STORAGE.contains(&value.as_str())
        }
        ManagedKey::Pub => is_reviewed_pub(&value) || OFFICIAL_PUB.contains(&value.as_str()),
    })
}

fn environment_state(runtime: &dyn Runtime, name: &str, key: ManagedKey) -> &'static str {
    match runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
    {
        None => "unset",
        Some(value) if is_public(key, &value) => "public",
        Some(_) => "custom",
    }
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
            "Flutter current configuration must contain exactly one {format} document"
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

fn run_flutter(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    storage: Option<&str>,
    hosted: Option<&str>,
    cache: Option<&Path>,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let output = run_flutter_output(runtime, directory, storage, hosted, cache, arguments)?;
    command_output(output, label)
}

fn run_flutter_stdout(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    storage: Option<&str>,
    hosted: Option<&str>,
    cache: Option<&Path>,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let output = run_flutter_output(runtime, directory, storage, hosted, cache, arguments)?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "{label} failed with status {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stdout")))
}

fn run_flutter_output(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    storage: Option<&str>,
    hosted: Option<&str>,
    cache: Option<&Path>,
    arguments: &[&str],
) -> Result<std::process::Output, AdapterError> {
    let mut environment = BTreeMap::from([
        ("CI".into(), "true".into()),
        ("DART_SUPPRESS_ANALYTICS".into(), "1".into()),
        ("FLUTTER_SUPPRESS_ANALYTICS".into(), "true".into()),
    ]);
    if let Some(storage) = storage {
        environment.insert(STORAGE_VARIABLE.into(), storage.into());
    }
    if let Some(hosted) = hosted {
        environment.insert(PUB_VARIABLE.into(), hosted.into());
    }
    if let Some(cache) = cache {
        let cache = cache.to_str().ok_or_else(|| {
            AdapterError::Verification("Flutter verification cache path is not UTF-8".into())
        })?;
        environment.insert("PUB_CACHE".into(), cache.into());
    }
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    match directory {
        Some(directory) => {
            runtime.run_in_with_environment(directory, "flutter", &arguments, &environment, &[])
        }
        None => runtime.run_with_environment("flutter", &arguments, &environment, &[]),
    }
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

fn configured_source(
    value: &str,
    upstream: &str,
    kind: &str,
    path: &Path,
    shell: ShellKind,
) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(upstream.into()),
        url: normalized_base(value).unwrap_or_else(|| "<preserved>".into()),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("shell".into(), vec![shell.name().into()]),
        ]),
    }
}

fn project_source(kind: &str, path: &Path) -> ConfiguredSource {
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

fn policy_source(kind: &str, path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("shell".into(), vec![shell.name().into()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "flutter-snapshot:<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
    }
}

fn snapshot_value<'a>(
    current: &'a CurrentConfiguration,
    kind: &str,
) -> Result<&'a str, AdapterError> {
    let matches = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some(kind))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flutter current configuration must contain one {kind} snapshot"
        )));
    }
    metadata(matches[0], "value")
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Flutter source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flutter source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "Flutter {kind} {} is outside the user home",
            path.display()
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Flutter reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Flutter configuration {} is not UTF-8",
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
