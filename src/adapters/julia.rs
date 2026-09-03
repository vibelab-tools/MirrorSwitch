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

const PKG_UPSTREAM: &str = "julia--language-registry";
const NJU_PKG_SERVER: &str = "https://mirrors.nju.edu.cn/julia";
const OFFICIAL_PKG_SERVER: &str = "https://pkg.julialang.org";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch Julia Pkg server >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch Julia Pkg server <<<";
const PKG_VARIABLE: &str = "JULIA_PKG_SERVER";
const EXAMPLE_TREE: &str = "e1f0e1a832ccd8e97d6d0348dec33ee139a5aeaf";
const HELLO_TREE: &str = "370059fde9f8b780a2335dcbcf05ba224053d45f";

const DISCOVERY_SCRIPT: &str = r#"
using Pkg
pkg_version = isdefined(Base, :pkgversion) ? Base.pkgversion(Pkg) : Pkg.VERSION
registry_root = isempty(DEPOT_PATH) ? "" : joinpath(first(DEPOT_PATH), "registries")
registry_entries = isdir(registry_root) ? filter(name -> !startswith(name, "."), readdir(registry_root)) : String[]
registries = isdefined(Pkg.Registry, :reachable_registries) ?
    getfield(Pkg.Registry, :reachable_registries)() : nothing
registry_count = isnothing(registries) ? length(registry_entries) : length(registries)
non_general_count = isnothing(registries) ?
    count(name -> splitext(name)[1] != "General", registry_entries) :
    count(reg -> reg.name != "General", registries)
println("MIRRORSWITCH_PKG_VERSION=", isnothing(pkg_version) ? VERSION : pkg_version)
println("MIRRORSWITCH_DEPOT_COUNT=", length(DEPOT_PATH))
println("MIRRORSWITCH_FIRST_DEPOT=", isempty(DEPOT_PATH) ? "" : first(DEPOT_PATH))
println("MIRRORSWITCH_ACTIVE_PROJECT=", something(Base.active_project(), ""))
println("MIRRORSWITCH_REGISTRY_COUNT=", registry_count)
println("MIRRORSWITCH_NON_GENERAL_REGISTRY_COUNT=", non_general_count)
Pkg.Registry.status()
"#;

const VERIFY_SCRIPT: &str = r#"
using Pkg, UUIDs
registry_root = joinpath(first(DEPOT_PATH), "registries")
general_exists = isdir(joinpath(registry_root, "General")) || isfile(joinpath(registry_root, "General.toml"))
general_exists || Pkg.Registry.add("General")
Pkg.Registry.update()
Pkg.Registry.status()
mktempdir() do environment
    Pkg.activate(environment)
    Pkg.add([
        Pkg.PackageSpec(name="Example", version=v"0.5.5"),
        Pkg.PackageSpec(name="HelloWorldC_jll", version=v"1.4.4+0"),
    ])
    dependencies = Pkg.dependencies()
    example = dependencies[UUID("7876af07-990d-54b4-ab0e-23690620f79a")]
    hello = dependencies[UUID("dca1746e-5efc-54fc-8249-22745bc95a49")]
    @assert string(example.tree_hash) == "e1f0e1a832ccd8e97d6d0348dec33ee139a5aeaf"
    @assert string(hello.tree_hash) == "370059fde9f8b780a2335dcbcf05ba224053d45f"
    artifact = ENV["MIRRORSWITCH_EXPECTED_ARTIFACT"]
    @assert isdir(joinpath(first(DEPOT_PATH), "artifacts", artifact))
    println("MIRRORSWITCH_JULIA_VERIFY=registry:General example:", example.tree_hash,
        " hello:", hello.tree_hash, " artifact:ready:", artifact)
end
"#;

#[derive(Clone, Copy, Debug, Default)]
pub struct JuliaAdapter;

impl Adapter for JuliaAdapter {
    fn key(&self) -> &'static str {
        "julia"
    }

    fn tool_id(&self) -> &'static str {
        "julia"
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
        if !runtime.command_exists("julia") {
            return Ok(None);
        }
        if context.os == OperatingSystem::Windows && !runtime.command_exists("reg.exe") {
            return Err(AdapterError::Unsupported(
                "Julia Pkg Windows persistence requires reg.exe".into(),
            ));
        }
        let version = julia_version(runtime)?;
        reviewed_version(&version, "Julia")?;
        let discovery = discover_pkg(runtime)?;
        reviewed_version(&discovery.pkg_version, "Pkg")?;
        let layout = config_layout(context, runtime)?;
        Ok(Some(DetectedTool {
            tool_id: "julia".into(),
            executable: Some(PathBuf::from("julia")),
            version: Some(version.clone()),
            evidence: vec![
                format!("Julia {version}"),
                format!("Pkg {}", discovery.pkg_version),
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
                    "JULIA_PKG_SERVER is {}",
                    environment_state(runtime, "JULIA_PKG_SERVER", true)
                ),
                format!(
                    "JULIA_DEPOT_PATH is {}",
                    environment_state(runtime, "JULIA_DEPOT_PATH", false)
                ),
                format!("effective DEPOT_PATH entries: {}", discovery.depot_count),
                format!(
                    "active project is {}",
                    if discovery.active_project.is_empty() {
                        "unset"
                    } else {
                        "detected"
                    }
                ),
                format!("reachable registries: {}", discovery.registry_count),
                format!(
                    "non-General registries preserved: {}",
                    discovery.non_general_registry_count
                ),
                "Pkg server authentication directory is preserved without inspection".into(),
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
        if detected.tool_id != "julia" {
            return Err(AdapterError::InvalidConfiguration(
                "Julia Pkg read received another tool's detection result".into(),
            ));
        }
        let version = julia_version(runtime)?;
        reviewed_version(&version, "Julia")?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Julia version changed after detection".into(),
            ));
        }
        let discovery = discover_pkg(runtime)?;
        reviewed_version(&discovery.pkg_version, "Pkg")?;
        let layout = config_layout(context, runtime)?;
        if layout.shell == ShellKind::WindowsRegistry {
            return windows_current(runtime, &layout, &version, &discovery);
        }
        let profile_contents = runtime.read(&layout.profile)?;
        let profile_exists = profile_contents.is_some();
        let profile_contents = profile_contents.unwrap_or_default();
        let parsed = parse_profile(
            utf8(&layout.profile, &profile_contents)?,
            &layout.profile,
            layout.shell,
        )?;
        let mut sources = profile_sources(&parsed, &layout.profile, layout.shell);
        sources.push(snapshot_source("julia-version", &version));
        sources.push(snapshot_source("pkg-version", &discovery.pkg_version));
        sources.push(snapshot_source(
            "depot-count",
            &discovery.depot_count.to_string(),
        ));
        if discovery.non_general_registry_count > 0 {
            sources.push(policy_source(
                "non-general-registries-preserved",
                Path::new(":julia-registry:"),
                layout.shell,
            ));
        }
        if discovery.first_depot.is_some() {
            sources.push(policy_source(
                "authentication-directory-preserved",
                Path::new(":julia-auth:"),
                layout.shell,
            ));
        }
        add_environment_policy(runtime, &parsed, &mut sources, layout.shell);

        let mut files = profile_exists
            .then_some(layout.profile.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let mut documents = vec![ConfigurationDocument {
            path: layout.profile.clone(),
            format: format!("julia-selected-{}-profile", layout.shell.name()),
            contents: profile_contents,
        }];
        add_project_documents(
            runtime,
            &discovery,
            &mut files,
            &mut sources,
            &mut documents,
        )?;
        Ok(CurrentConfiguration {
            tool_id: "julia".into(),
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
        reviewed_version(
            detected.version.as_deref().ok_or_else(|| {
                AdapterError::InvalidConfiguration("Julia version is missing".into())
            })?,
            "Julia",
        )?;
        Ok(SelectionRequest {
            tool_id: "julia".into(),
            adapter_key: "julia".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![PKG_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                PKG_UPSTREAM.into(),
                vec![artifact_probe_context(context)],
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
        require_supported_context(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let endpoint = selected_pkg_server(selections)?;
        if context.os == OperatingSystem::Windows {
            return windows_plan(context, current, &endpoint);
        }
        let profile = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("julia-selected-"))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("selected Julia shell profile is missing".into())
            })?;
        let shell = shell_from_format(&profile.format)?;
        let mut rendered = rewrite_profile(
            utf8(&profile.path, &profile.contents)?,
            &profile.path,
            shell,
            &endpoint,
        )?
        .into_bytes();
        if profile.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let changes = if profile.contents == rendered {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &profile.path),
                old_contents: current
                    .files
                    .contains(&profile.path)
                    .then(|| profile.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: "add or retarget one managed JULIA_PKG_SERVER assignment while preserving depot, registries, authentication, and project files".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "julia".into(),
            tool_id: "julia".into(),
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
            let profile_target = rooted(&context.root, &layout.profile);
            if !receipt.changed_targets.contains(&profile_target) {
                return Err(AdapterError::Verification(
                    "Julia transaction receipt contains no known target".into(),
                ));
            }
            let profile = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("Julia shell profile disappeared".into())
            })?;
            let parsed = parse_profile(
                utf8(&layout.profile, &profile)?,
                &layout.profile,
                layout.shell,
            )?;
            if parsed.dynamic || !parsed.unmanaged.is_empty() {
                return Err(AdapterError::Verification(
                    "Julia shell profile gained conflicting JULIA_PKG_SERVER policy".into(),
                ));
            }
            let endpoint = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed JULIA_PKG_SERVER is missing".into())
            })?;
            if normalized_pkg_server(&endpoint).as_deref() != Some(NJU_PKG_SERVER) {
                return Err(AdapterError::Verification(
                    "managed JULIA_PKG_SERVER is not the reviewed Pkg server".into(),
                ));
            }
            let output = run_verification(context, runtime, &layout, &endpoint)?;
            for marker in [
                "registry:General",
                EXAMPLE_TREE,
                HELLO_TREE,
                "artifact:ready",
            ] {
                if !output.contains(marker) {
                    return Err(AdapterError::Verification(format!(
                        "Julia Pkg verification output is missing {marker}"
                    )));
                }
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Julia Pkg resolved General, Example source, and a native artifact through {endpoint} in an isolated depot"
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
                "restored {} Julia Pkg configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
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

#[derive(Debug)]
struct Layout {
    shell: ShellKind,
    profile: PathBuf,
    verification_depot: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsRecoveryState {
    schema_version: u32,
    original: Option<String>,
    selected: String,
}

impl WindowsRecoveryState {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != 1
            || normalized_pkg_server(&self.selected).as_deref() != Some(NJU_PKG_SERVER)
        {
            return Err(AdapterError::InvalidConfiguration(
                "Julia Windows recovery state has an invalid selected Pkg server".into(),
            ));
        }
        if self
            .original
            .as_deref()
            .is_some_and(|value| !valid_registry_url(value))
        {
            return Err(AdapterError::InvalidConfiguration(
                "Julia Windows recovery state has an invalid original Pkg server".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Discovery {
    pkg_version: String,
    depot_count: usize,
    first_depot: Option<PathBuf>,
    active_project: String,
    registry_count: usize,
    non_general_registry_count: usize,
}

#[derive(Clone, Debug)]
struct Assignment {
    range: Range<usize>,
    value: String,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<String>,
    unmanaged: Vec<Assignment>,
    dynamic: bool,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Julia Pkg on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "Julia Pkg on Windows arm64 is unavailable because Julia has no reviewed native Windows arm64 runtime"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Julia Pkg requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn artifact_probe_context(context: &SystemContext) -> BTreeMap<String, String> {
    let (tree, digest) = match (context.os, context.architecture) {
        (OperatingSystem::Linux, Architecture::X86_64) => (
            "c8aa41cab66118db2387696eba33856344935ce3",
            "ba2e68bc72a3e6cadefb8ff892bc7c76289b06b7606cc4d1f2613ce917c5425f",
        ),
        (OperatingSystem::Linux, Architecture::Arm64) => (
            "a2368a2caae8074bdda6e71d51acb43553fcd076",
            "7b56d8aa960fe3e540f945126c942f4be1bcb1da66f4fd530450a70efcd76955",
        ),
        (OperatingSystem::Macos, Architecture::X86_64) => (
            "3122acd9ac102f55d7aed639ebb869f4cc9c00eb",
            "fb43e27e8052fbfa753d8052f7bf22ccba99acefeb6f6eb89b19e04d0dd4d035",
        ),
        (OperatingSystem::Macos, Architecture::Arm64) => (
            "14e7b6ef22f415365b443e7c66bbb3cee64a8ebd",
            "e4ff76831994b2d214892ab9877f8ca5ac63e18867e14913c1f8fa1ec1523e64",
        ),
        (OperatingSystem::Windows, Architecture::X86_64) => (
            "6e1eb164b0651aa44621eac4dfa340d6e60295ef",
            "1f10e46f7b073136f7f668de89096d631ae8bb8903547d588f6817f0b780b2fc",
        ),
        (OperatingSystem::Windows, Architecture::Arm64) => {
            unreachable!("Windows arm64 is rejected before candidate selection")
        }
    };
    BTreeMap::from([
        ("julia_artifact_tree".into(), tree.into()),
        ("julia_artifact_sha".into(), digest.into()),
    ])
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Julia Pkg adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "julia" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Pkg operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Julia Pkg requires a user home".into()))?;
    validate_path(&home, "home")?;
    if context.os == OperatingSystem::Windows {
        let local_app_data = runtime
            .environment_variable("LOCALAPPDATA")
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                AdapterError::Unsupported(
                    "Julia Pkg Windows persistence requires LOCALAPPDATA".into(),
                )
            })?;
        validate_path(&local_app_data, "LOCALAPPDATA")?;
        return Ok(Layout {
            shell: ShellKind::WindowsRegistry,
            profile: local_app_data.join("MirrorSwitch/julia/environment-recovery.json"),
            verification_depot: home.join(".mirrorswitch/verification/julia/depot"),
        });
    }
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().and_then(parse_shell))
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "Julia Pkg requires SHELL to select bash, zsh, or fish initialization".into(),
            )
        })?;
    let profile = selected_profile(context, runtime, &home, shell)?;
    Ok(Layout {
        shell,
        profile,
        verification_depot: home.join(".mirrorswitch/verification/julia/depot"),
    })
}

fn windows_current(
    runtime: &dyn Runtime,
    layout: &Layout,
    version: &str,
    discovery: &Discovery,
) -> Result<CurrentConfiguration, AdapterError> {
    let observed = runtime.read(&layout.profile)?;
    let recovery_exists = observed.is_some();
    let recovery_contents = observed.unwrap_or_default();
    let recovery = if recovery_exists {
        let state: WindowsRecoveryState =
            serde_json::from_slice(&recovery_contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "Julia Windows recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        Some(state)
    } else {
        None
    };
    let registry = query_windows_variable(runtime)?;
    let mut sources = vec![
        snapshot_source("julia-version", version),
        snapshot_source("pkg-version", &discovery.pkg_version),
        snapshot_source("depot-count", &discovery.depot_count.to_string()),
    ];
    if discovery.non_general_registry_count > 0 {
        sources.push(policy_source(
            "non-general-registries-preserved",
            Path::new(":julia-registry:"),
            ShellKind::WindowsRegistry,
        ));
    }
    if discovery.first_depot.is_some() {
        sources.push(policy_source(
            "authentication-directory-preserved",
            Path::new(":julia-auth:"),
            ShellKind::WindowsRegistry,
        ));
    }
    if recovery.is_some() {
        sources.push(policy_source(
            "windows-recovery-active",
            &layout.profile,
            ShellKind::WindowsRegistry,
        ));
    }
    if let Some(value) = &registry {
        let kind = if recovery
            .as_ref()
            .is_some_and(|state| same_server(&state.selected, value))
        {
            "managed-shell-profile"
        } else if is_public(value) {
            "adoptable-shell-profile"
        } else {
            "private-shell-profile"
        };
        sources.push(configured_source(
            value,
            kind,
            Path::new(r"HKCU\Environment"),
            ShellKind::WindowsRegistry,
        ));
    }
    if let Some(value) = runtime.environment_variable(PKG_VARIABLE) {
        let stale_original = recovery
            .as_ref()
            .and_then(|state| state.original.as_deref())
            .is_some_and(|original| same_server(original, &value));
        if value.is_empty() {
            sources.push(policy_source(
                "package-server-disabled",
                Path::new(":env:"),
                ShellKind::WindowsRegistry,
            ));
        } else if !registry
            .as_deref()
            .is_some_and(|persistent| same_server(persistent, &value))
            && !stale_original
        {
            sources.push(policy_source(
                if is_public(&value) {
                    "environment-override"
                } else {
                    "private-environment-override"
                },
                Path::new(":env:"),
                ShellKind::WindowsRegistry,
            ));
        }
    }
    let mut files = recovery_exists
        .then_some(layout.profile.clone())
        .into_iter()
        .collect::<Vec<_>>();
    let mut documents = vec![
        ConfigurationDocument {
            path: layout.profile.clone(),
            format: "julia-windows-recovery".into(),
            contents: recovery_contents,
        },
        ConfigurationDocument {
            path: PathBuf::from(r"HKCU\Environment\JULIA_PKG_SERVER"),
            format: "julia-windows-registry-snapshot".into(),
            contents: registry.as_deref().unwrap_or_default().as_bytes().to_vec(),
        },
    ];
    add_project_documents(runtime, discovery, &mut files, &mut sources, &mut documents)?;
    Ok(CurrentConfiguration {
        tool_id: "julia".into(),
        scope: ConfigurationScope::User,
        sources,
        files,
        documents,
    })
}

fn windows_plan(
    context: &SystemContext,
    current: &CurrentConfiguration,
    endpoint: &str,
) -> Result<ChangePlan, AdapterError> {
    let recovery = current
        .documents
        .iter()
        .find(|document| document.format == "julia-windows-recovery")
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Julia Windows recovery document is missing".into())
        })?;
    if !recovery.contents.is_empty() {
        let state: WindowsRecoveryState =
            serde_json::from_slice(&recovery.contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "Julia Windows recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        if !same_server(&state.selected, endpoint) {
            return Err(AdapterError::Unsupported(
                "a previous Julia Windows recovery state is active; restore it before selecting another Pkg server"
                    .into(),
            ));
        }
        return Ok(ChangePlan {
            adapter_key: "julia".into(),
            tool_id: "julia".into(),
            scope: ConfigurationScope::User,
            changes: Vec::new(),
            requires_elevation: false,
            service_impact: ServiceImpact::None,
        });
    }
    let snapshot = current
        .documents
        .iter()
        .find(|document| document.format == "julia-windows-registry-snapshot")
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Julia Windows registry snapshot is missing".into())
        })?;
    let original = if snapshot.contents.is_empty() {
        None
    } else {
        Some(String::from_utf8(snapshot.contents.clone()).map_err(|_| {
            AdapterError::InvalidConfiguration(
                "Julia Windows registry snapshot is not UTF-8".into(),
            )
        })?)
    };
    let state = WindowsRecoveryState {
        schema_version: 1,
        original,
        selected: endpoint.into(),
    };
    state.validate()?;
    let mut contents = serde_json::to_vec_pretty(&state).map_err(|error| {
        AdapterError::Runtime(format!(
            "could not serialize Julia Windows recovery state: {error}"
        ))
    })?;
    contents.push(b'\n');
    Ok(ChangePlan {
        adapter_key: "julia".into(),
        tool_id: "julia".into(),
        scope: ConfigurationScope::User,
        changes: vec![PlannedFileChange {
            target: rooted(&context.root, &recovery.path),
            old_contents: current
                .files
                .contains(&recovery.path)
                .then(|| recovery.contents.clone()),
            old_mode: None,
            new_contents: contents,
            new_mode: None,
            summary: "record private Julia Windows user-environment recovery state before updating JULIA_PKG_SERVER".into(),
        }],
        requires_elevation: false,
        service_impact: ServiceImpact::None,
    })
}

fn windows_apply(
    runtime: &mut dyn Runtime,
    plan: &ChangePlan,
) -> Result<ApplyOutcome, AdapterError> {
    if plan.adapter_key != "julia" || plan.tool_id != "julia" {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Windows apply received another tool's plan".into(),
        ));
    }
    if plan.changes.is_empty() {
        return runtime.apply_plan(plan);
    }
    let state: WindowsRecoveryState = serde_json::from_slice(&plan.changes[0].new_contents)
        .map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "Julia Windows recovery state is invalid: {error}"
            ))
        })?;
    state.validate()?;
    let outcome = runtime.apply_plan(plan)?;
    let ApplyOutcome::Applied(receipt) = &outcome else {
        return Ok(outcome);
    };
    if let Err(error) = set_windows_variable(runtime, &state.selected) {
        let registry_restored =
            restore_windows_variable(runtime, state.original.as_deref()).is_ok();
        let state_restored =
            registry_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
        return Err(AdapterError::Runtime(format!(
            "Julia Windows environment update failed: {error}; registry restored: {registry_restored}; recovery file restored: {state_restored}"
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
    let target = rooted(&context.root, &layout.profile);
    if !receipt.changed_targets.contains(&target) {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Windows receipt does not contain the recovery state".into(),
        ));
    }
    let result = (|| {
        if query_windows_variable(runtime)?.as_deref() != Some(state.selected.as_str()) {
            return Err(AdapterError::Verification(
                "Julia Windows user environment did not retain JULIA_PKG_SERVER".into(),
            ));
        }
        let output = run_verification(context, runtime, &layout, &state.selected)?;
        for marker in [
            "registry:General",
            EXAMPLE_TREE,
            HELLO_TREE,
            "artifact:ready",
        ] {
            if !output.contains(marker) {
                return Err(AdapterError::Verification(format!(
                    "Julia Pkg verification output is missing {marker}"
                )));
            }
        }
        Ok(VerificationResult {
            valid: true,
            summary: format!(
                "Julia Pkg resolved General, Example source, and a native Windows artifact through {} in an isolated depot",
                state.selected
            ),
        })
    })();
    if let Err(error) = result {
        let registry_restored =
            restore_windows_variable(runtime, state.original.as_deref()).is_ok();
        let state_restored =
            registry_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
        return Err(AdapterError::Verification(format!(
            "{error}; registry restored: {registry_restored}; recovery file restored: {state_restored}"
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
    restore_windows_variable(runtime, state.original.as_deref())?;
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Ok(RestoreResult {
        restored: restored.verified,
        summary: "restored the previous Julia Windows user environment and recovery file".into(),
    })
}

fn read_windows_recovery(
    runtime: &dyn Runtime,
    layout: &Layout,
) -> Result<WindowsRecoveryState, AdapterError> {
    let contents = runtime
        .read(&layout.profile)?
        .ok_or_else(|| AdapterError::Runtime("Julia Windows recovery state is missing".into()))?;
    let state: WindowsRecoveryState = serde_json::from_slice(&contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Julia Windows recovery state is invalid: {error}"
        ))
    })?;
    state.validate()?;
    Ok(state)
}

fn query_windows_variable(runtime: &dyn Runtime) -> Result<Option<String>, AdapterError> {
    let output = runtime.run(
        "reg.exe",
        &[
            "query".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            PKG_VARIABLE.into(),
        ],
    )?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "reg.exe query {PKG_VARIABLE} failed with status {}",
            output.status
        )));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("reg.exe returned non-UTF-8 output".into()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(PKG_VARIABLE))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("reg.exe returned no {PKG_VARIABLE} value"))
        })?;
    let rest = line[PKG_VARIABLE.len()..].trim_start();
    let split = rest.find(char::is_whitespace).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "reg.exe returned malformed {PKG_VARIABLE} state"
        ))
    })?;
    let kind = &rest[..split];
    let value = rest[split..].trim();
    if kind != "REG_SZ" || !valid_registry_url(value) {
        return Err(AdapterError::Unsupported(format!(
            "Julia Windows {PKG_VARIABLE} must be a non-empty HTTPS REG_SZ URL"
        )));
    }
    Ok(Some(value.into()))
}

fn set_windows_variable(runtime: &dyn Runtime, value: &str) -> Result<(), AdapterError> {
    if !valid_registry_url(value) {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Windows Pkg server is not a valid HTTPS URL".into(),
        ));
    }
    let output = runtime.run(
        "reg.exe",
        &[
            "add".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            PKG_VARIABLE.into(),
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
            "reg.exe add {PKG_VARIABLE} failed with status {}",
            output.status
        )))
    }
}

fn restore_windows_variable(
    runtime: &dyn Runtime,
    original: Option<&str>,
) -> Result<(), AdapterError> {
    match original {
        Some(value) => set_windows_variable(runtime, value),
        None => delete_windows_variable(runtime),
    }
}

fn delete_windows_variable(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let output = runtime.run(
        "reg.exe",
        &[
            "delete".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            PKG_VARIABLE.into(),
            "/f".into(),
        ],
    )?;
    if output.status.success() || output.status.code() == Some(1) {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "reg.exe delete {PKG_VARIABLE} failed with status {}",
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
                "PROFILE=/dev/null disables persistent Julia Pkg configuration".into(),
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
        ShellKind::Fish => home.join(".config/fish/conf.d/mirrorswitch-julia.fish"),
        ShellKind::WindowsRegistry => {
            unreachable!("Windows layout returned before shell selection")
        }
    };
    validate_user_path(&path, home, "shell profile")?;
    Ok(path)
}

fn julia_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = run_julia(runtime, &["--version"], "julia --version")?;
    let version = output
        .split_whitespace()
        .find(|token| valid_version(token))
        .ok_or_else(|| AdapterError::Unsupported("Julia version output is unrecognized".into()))?;
    Ok(version.into())
}

fn discover_pkg(runtime: &dyn Runtime) -> Result<Discovery, AdapterError> {
    let output = run_julia(
        runtime,
        &[
            "--startup-file=no",
            "--history-file=no",
            "-e",
            DISCOVERY_SCRIPT,
        ],
        "Julia Pkg discovery",
    )?;
    let pkg_version = marker(&output, "MIRRORSWITCH_PKG_VERSION=")?.to_owned();
    let depot_count = numeric_marker(&output, "MIRRORSWITCH_DEPOT_COUNT=")?;
    let first_depot = marker(&output, "MIRRORSWITCH_FIRST_DEPOT=")?;
    let first_depot = if first_depot.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(first_depot))
    };
    if let Some(path) = &first_depot {
        validate_path(path, "first depot")?;
    }
    Ok(Discovery {
        pkg_version,
        depot_count,
        first_depot,
        active_project: marker(&output, "MIRRORSWITCH_ACTIVE_PROJECT=")?.to_owned(),
        registry_count: numeric_marker(&output, "MIRRORSWITCH_REGISTRY_COUNT=")?,
        non_general_registry_count: numeric_marker(
            &output,
            "MIRRORSWITCH_NON_GENERAL_REGISTRY_COUNT=",
        )?,
    })
}

fn marker<'a>(output: &'a str, prefix: &str) -> Result<&'a str, AdapterError> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "Julia Pkg discovery did not report {}",
                prefix.trim_end_matches('=')
            ))
        })
}

fn numeric_marker(output: &str, prefix: &str) -> Result<usize, AdapterError> {
    marker(output, prefix)?.parse().map_err(|_| {
        AdapterError::Unsupported(format!(
            "Julia Pkg discovery reported an invalid {}",
            prefix.trim_end_matches('=')
        ))
    })
}

fn reviewed_version(version: &str, component: &str) -> Result<(), AdapterError> {
    let mut parts = version.split(['.', '-', '+']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    if !matches!((major, minor), (Some(1), Some(6..))) {
        return Err(AdapterError::Unsupported(format!(
            "{component} {version} is outside the reviewed Julia 1.6 through 1.x Pkg model"
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

fn run_julia(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    command_output(runtime.run("julia", &arguments)?, label)
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

fn add_project_documents(
    runtime: &dyn Runtime,
    discovery: &Discovery,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let mut candidates = BTreeSet::new();
    if let Some(project) = runtime.project_dir() {
        validate_path(&project, "project directory")?;
        candidates.insert(project.join("Project.toml"));
        candidates.insert(project.join("Manifest.toml"));
    }
    if !discovery.active_project.is_empty() {
        let active = PathBuf::from(&discovery.active_project);
        validate_path(&active, "active project")?;
        candidates.insert(active.clone());
        candidates.insert(active.with_file_name("Manifest.toml"));
    }
    for path in candidates {
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        files.push(path.clone());
        sources.push(project_source(&path));
        documents.push(ConfigurationDocument {
            path,
            format: "julia-project-file-preserved".into(),
            contents,
        });
    }
    Ok(())
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let managed_range = managed_range(text, path)?;
    let managed = managed_range
        .as_ref()
        .map(|range| managed_value(&text[range.clone()], path, shell))
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
        if active.is_empty() || active.starts_with('#') || !active.contains("JULIA_PKG_SERVER") {
            continue;
        }
        match assignment(active, shell)? {
            Some(value) => unmanaged.push(Assignment {
                range: start..start + line.len(),
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

fn managed_value(block: &str, path: &Path, shell: ShellKind) -> Result<String, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| assignment(line.trim(), shell).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed Julia Pkg block in {} must assign JULIA_PKG_SERVER exactly once",
            path.display()
        )));
    }
    let value = values[0];
    if normalized_pkg_server(value).as_deref() != Some(NJU_PKG_SERVER) {
        return Err(AdapterError::Unsupported(
            "managed JULIA_PKG_SERVER is bound to an unreviewed endpoint".into(),
        ));
    }
    Ok(value.into())
}

fn assignment(line: &str, shell: ShellKind) -> Result<Option<&str>, AdapterError> {
    let raw = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            if key.trim() != "JULIA_PKG_SERVER" {
                return Ok(None);
            }
            value.trim()
        }
        ShellKind::Fish => {
            let Some(rest) = line.strip_prefix("set ") else {
                return Ok(None);
            };
            let mut fields = rest.split_whitespace();
            let Some(flags) = fields.next() else {
                return Ok(None);
            };
            let Some(key) = fields.next() else {
                return Ok(None);
            };
            let value = fields.next().unwrap_or("");
            if !flags.contains('x') || key != "JULIA_PKG_SERVER" {
                return Ok(None);
            }
            if fields.next().is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "fish JULIA_PKG_SERVER assignment is not a literal value".into(),
                ));
            }
            value
        }
        ShellKind::WindowsRegistry => {
            return Err(AdapterError::InvalidConfiguration(
                "Julia Windows registry is not a shell profile".into(),
            ));
        }
    };
    literal_value(raw).map(Some)
}

fn literal_value(raw: &str) -> Result<&str, AdapterError> {
    let single = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    let value = if single || double {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.contains([';', '`', '$', '\n', '\r'])
        || (single && value.contains('\''))
        || (double && value.contains('"'))
        || (!single
            && !double
            && raw
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '\'' | '"')))
    {
        return Err(AdapterError::InvalidConfiguration(
            "JULIA_PKG_SERVER assignment is not a literal value".into(),
        ));
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
            "Julia Pkg managed markers in {} are missing, duplicated, or out of order",
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
    if let Some(value) = &parsed.managed {
        sources.push(configured_source(
            value,
            "managed-shell-profile",
            path,
            shell,
        ));
    }
    for item in &parsed.unmanaged {
        let kind = if item.value.is_empty() {
            "package-server-disabled"
        } else if is_public(&item.value) {
            "adoptable-shell-profile"
        } else {
            "private-shell-profile"
        };
        sources.push(if kind == "adoptable-shell-profile" {
            configured_source(&item.value, kind, path, shell)
        } else {
            policy_source(kind, path, shell)
        });
    }
    if parsed.unmanaged.len() + usize::from(parsed.managed.is_some()) > 1 {
        sources.push(policy_source("duplicate-shell-profile", path, shell));
    }
    if parsed.dynamic {
        sources.push(policy_source("dynamic-shell-profile", path, shell));
    }
    sources
}

fn add_environment_policy(
    runtime: &dyn Runtime,
    parsed: &ParsedProfile,
    sources: &mut Vec<ConfiguredSource>,
    shell: ShellKind,
) {
    let Some(value) = runtime.environment_variable("JULIA_PKG_SERVER") else {
        return;
    };
    if value.is_empty() {
        sources.push(policy_source(
            "package-server-disabled",
            Path::new(":env:"),
            shell,
        ));
        return;
    }
    if !is_public(&value) {
        sources.push(policy_source(
            "private-environment-override",
            Path::new(":env:"),
            shell,
        ));
        return;
    }
    let represented = parsed
        .managed
        .as_deref()
        .into_iter()
        .chain(parsed.unmanaged.iter().map(|item| item.value.as_str()))
        .any(|profile_value| same_server(profile_value, &value));
    if !represented {
        sources.push(policy_source(
            "environment-override",
            Path::new(":env:"),
            shell,
        ));
    }
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "package-server-disabled" => {
                return Err(AdapterError::Unsupported(
                    "JULIA_PKG_SERVER is explicitly empty, which disables Pkg servers; the user's opt-out is preserved"
                        .into(),
                ));
            }
            "private-shell-profile" | "private-environment-override" => {
                return Err(AdapterError::Unsupported(
                    "existing JULIA_PKG_SERVER is private, authenticated, or unreviewed and will not be replaced"
                        .into(),
                ));
            }
            "duplicate-shell-profile" => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected shell profile assigns JULIA_PKG_SERVER more than once".into(),
                ));
            }
            "dynamic-shell-profile" => {
                return Err(AdapterError::Unsupported(
                    "selected shell profile computes JULIA_PKG_SERVER dynamically".into(),
                ));
            }
            "environment-override" => {
                return Err(AdapterError::Unsupported(
                    "current JULIA_PKG_SERVER is not represented by the selected persistent profile"
                        .into(),
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
    endpoint: &str,
) -> Result<String, AdapterError> {
    let parsed = parse_profile(text, path, shell)?;
    if parsed.dynamic || parsed.unmanaged.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Pkg profile cannot be rewritten safely".into(),
        ));
    }
    if parsed
        .unmanaged
        .iter()
        .any(|item| item.value.is_empty() || !is_public(&item.value))
    {
        return Err(AdapterError::Unsupported(
            "disabled, private, or unreviewed JULIA_PKG_SERVER cannot be replaced".into(),
        ));
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(endpoint, newline, shell);
    if let Some(range) = managed_range(text, path)? {
        return Ok(format!(
            "{}{}{}",
            &text[..range.start],
            block,
            &text[range.end..]
        ));
    }
    if let Some(item) = parsed.unmanaged.first() {
        return Ok(format!(
            "{}{}{}",
            &text[..item.range.start],
            block,
            &text[item.range.end..]
        ));
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

fn render_managed(endpoint: &str, newline: &str, shell: ShellKind) -> String {
    let assignment = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            format!("export JULIA_PKG_SERVER='{endpoint}'")
        }
        ShellKind::Fish => format!("set -gx JULIA_PKG_SERVER '{endpoint}'"),
        ShellKind::WindowsRegistry => {
            unreachable!("Julia Windows persistence does not render a shell block")
        }
    };
    format!("{MANAGED_BEGIN}{newline}{assignment}{newline}{MANAGED_END}{newline}")
}

fn selected_pkg_server(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "julia" && selection.upstream_id == PKG_UPSTREAM)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Pkg requires exactly one package server selection".into(),
        ));
    }
    let selection = matches[0];
    if selection.provider_id != "nju" {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Pkg provider is not reviewed".into(),
        ));
    }
    let mut values = Vec::new();
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
                "Julia Pkg selection requires one HTTPS {role:?} endpoint"
            )));
        }
        values.push(normalized_pkg_server(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Julia Pkg {role:?} endpoint is unsafe"))
        })?);
    }
    if values.iter().any(|value| value != NJU_PKG_SERVER) {
        return Err(AdapterError::InvalidConfiguration(
            "Julia Pkg registry, package source, and artifact roles must share the reviewed Pkg server"
                .into(),
        ));
    }
    Ok(NJU_PKG_SERVER.into())
}

fn normalized_pkg_server(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let parsed = reqwest::Url::parse(&candidate).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(candidate.trim_end_matches('/').to_ascii_lowercase())
}

fn is_public(value: &str) -> bool {
    normalized_pkg_server(value)
        .is_some_and(|value| matches!(value.as_str(), NJU_PKG_SERVER | OFFICIAL_PKG_SERVER))
}

fn same_server(left: &str, right: &str) -> bool {
    normalized_pkg_server(left)
        .is_some_and(|left| normalized_pkg_server(right).as_deref() == Some(&left))
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish]
        .into_iter()
        .find(|shell| format == format!("julia-selected-{}-profile", shell.name()))
        .ok_or_else(|| AdapterError::InvalidConfiguration("unknown Julia profile format".into()))
}

fn run_verification(
    context: &SystemContext,
    runtime: &dyn Runtime,
    layout: &Layout,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let depot = layout.verification_depot.to_str().ok_or_else(|| {
        AdapterError::Verification("Julia verification depot path is not UTF-8".into())
    })?;
    let depot_separator = if context.os == OperatingSystem::Windows {
        ';'
    } else {
        ':'
    };
    let probe = artifact_probe_context(context);
    let environment = BTreeMap::from([
        (PKG_VARIABLE.into(), endpoint.into()),
        (
            "JULIA_DEPOT_PATH".into(),
            format!("{depot}{depot_separator}"),
        ),
        ("JULIA_PKG_PRECOMPILE_AUTO".into(), "0".into()),
        (
            "JULIA_PKG_SERVER_REGISTRY_PREFERENCE".into(),
            "conservative".into(),
        ),
        (
            "MIRRORSWITCH_EXPECTED_ARTIFACT".into(),
            probe["julia_artifact_tree"].clone(),
        ),
    ]);
    let arguments = vec![
        "--startup-file=no".into(),
        "--history-file=no".into(),
        "-e".into(),
        VERIFY_SCRIPT.into(),
    ];
    command_output(
        runtime.run_with_environment("julia", &arguments, &environment, &[])?,
        "Julia Pkg registry, package, and artifact verification",
    )
}

fn configured_source(value: &str, kind: &str, path: &Path, shell: ShellKind) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(PKG_UPSTREAM.into()),
        url: normalized_pkg_server(value).unwrap_or_else(|| "<preserved>".into()),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
            ("shell".into(), vec![shell.name().into()]),
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

fn project_source(path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["project-file-preserved".into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("julia-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Julia source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Julia source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn environment_state(
    runtime: &dyn Runtime,
    variable: &str,
    empty_is_disabled: bool,
) -> &'static str {
    match runtime.environment_variable(variable) {
        Some(value) if value.is_empty() && empty_is_disabled => "explicitly empty (disabled)",
        Some(value) if value.is_empty() => "explicitly empty",
        Some(_) => "set",
        None => "unset",
    }
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "Julia Pkg {kind} {} is outside the user home",
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
            "Julia reported unsafe {kind} path {}",
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
            "Julia configuration {} is not UTF-8",
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
