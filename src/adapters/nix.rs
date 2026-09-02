use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
};

use serde_json::Value;

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

const SYSTEM_CONFIG: &str = "/etc/nix/nix.conf";
const NIXOS_DAEMON_PLIST: &str = "/Library/LaunchDaemons/org.nixos.nix-daemon.plist";
const DETERMINATE_DAEMON_PLIST: &str =
    "/Library/LaunchDaemons/systems.determinate.nix-daemon.plist";
const NIXOS_DAEMON_LABEL: &str = "org.nixos.nix-daemon";
const DETERMINATE_DAEMON_LABEL: &str = "systems.determinate.nix-daemon";
const CACHE_UPSTREAM: &str = "nix-channels--binary-cache";
const OFFICIAL_CACHE: &str = "https://cache.nixos.org";
const OFFICIAL_CACHE_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
const CACHE_MIRRORS: &[&str] = &[
    "https://mirrors.nju.edu.cn/nix-channels/store",
    "https://mirror.sjtu.edu.cn/nix-channels/store",
    "https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store",
    "https://mirrors.ustc.edu.cn/nix-channels/store",
];
const DARWIN_CACHE_MIRRORS: &[&str] = &[
    "https://mirrors.nju.edu.cn/nix-channels/store",
    "https://mirrors.tuna.tsinghua.edu.cn/nix-channels/store",
];

#[derive(Clone, Copy, Debug)]
struct DarwinProbe {
    store_hash: &'static str,
    store_name: &'static str,
    store_path: &'static str,
    nar_file: &'static str,
    nar_sha256: &'static str,
}

const DARWIN_X86_64_PROBE: DarwinProbe = DarwinProbe {
    store_hash: "4sv8vd71y21gic34irbqr4pp1xgdhqck",
    store_name: "hello-2.12.2",
    store_path: "/nix/store/4sv8vd71y21gic34irbqr4pp1xgdhqck-hello-2.12.2",
    nar_file: "1yhq10d543mxsmsjn3kf2lv7pakw9401as6vp9si6sljimp1f7cd.nar.xz",
    nar_sha256: "8d1d176e8d926a1375badb681500497caa7b36156e0e2b75d5bd0e521a0818fa",
};
const DARWIN_ARM64_PROBE: DarwinProbe = DarwinProbe {
    store_hash: "mxawknsavjm2cfw3imi3g58497nkfiky",
    store_name: "hello-2.12.2",
    store_path: "/nix/store/mxawknsavjm2cfw3imi3g58497nkfiky-hello-2.12.2",
    nar_file: "0mf6jiwbrgiimzjp63bbh5d73x848ynbx79ijbxhxqs42bp5nkbv.nar.xz",
    nar_sha256: "7b4d5bee1244e30efb92319dbeac4704f5715a816b0d73e5af31bebc7894c655",
};

#[derive(Clone, Copy, Debug, Default)]
pub struct NixAdapter;

#[derive(Clone, Copy, Debug, Default)]
pub struct NixMacosAdapter;

#[derive(Clone, Copy, Debug)]
struct NixBackend {
    adapter_key: &'static str,
    tool_id: &'static str,
    operating_system: OperatingSystem,
}

const LINUX_BACKEND: NixBackend = NixBackend {
    adapter_key: "nix",
    tool_id: "nix",
    operating_system: OperatingSystem::Linux,
};
const MACOS_BACKEND: NixBackend = NixBackend {
    adapter_key: "nix-macos",
    tool_id: "nix-macos",
    operating_system: OperatingSystem::Macos,
};

impl Adapter for NixBackend {
    fn key(&self) -> &'static str {
        self.adapter_key
    }

    fn tool_id(&self) -> &'static str {
        self.tool_id
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System, ConfigurationScope::User]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
    }

    fn default_scope_for(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
    ) -> Result<ConfigurationScope, AdapterError> {
        require_supported_context(context, self.operating_system)?;
        Ok(if is_multi_user(context, runtime)? {
            ConfigurationScope::System
        } else {
            ConfigurationScope::User
        })
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        require_supported_context(context, self.operating_system)?;
        let has_nix = runtime.command_exists("nix");
        let system_config = runtime.read(Path::new(SYSTEM_CONFIG))?.is_some();
        let user_config = match user_config_path(runtime)? {
            Some(path) => runtime.read(&path)?.is_some(),
            None => false,
        };
        if !has_nix && !system_config && !user_config {
            return Ok(None);
        }

        let mut evidence = Vec::new();
        let mut version = None;
        if has_nix {
            let output = runtime.run("nix", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "nix --version failed with status {}",
                    output.status
                )));
            }
            let observed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            version = (!observed.is_empty()).then_some(observed.clone());
            evidence.push(format!("Nix command {observed}"));
        }
        evidence.push(if is_multi_user(context, runtime)? {
            if context.os == OperatingSystem::Macos {
                format!(
                    "Nix multi-user launchd installation ({})",
                    darwin_daemon_label(runtime)?.ok_or_else(|| {
                        AdapterError::Unsupported(
                            "macOS Nix daemon has no supported launchd service".into(),
                        )
                    })?
                )
            } else {
                "Nix multi-user daemon installation".into()
            }
        } else {
            "Nix single-user local-store installation".into()
        });
        if system_config {
            evidence.push(format!("Nix system configuration {SYSTEM_CONFIG}"));
        }
        if user_config {
            evidence.push("Nix user configuration under the detected home directory".into());
        }
        Ok(Some(DetectedTool {
            tool_id: self.tool_id.into(),
            executable: has_nix.then(|| PathBuf::from("nix")),
            version,
            evidence,
        }))
    }

    fn read_current(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
        _detected: &DetectedTool,
        scope: ConfigurationScope,
    ) -> Result<CurrentConfiguration, AdapterError> {
        require_supported_context(context, self.operating_system)?;
        validate_scope(context, runtime, scope)?;
        let path = configuration_path(runtime, scope)?;
        if scope == ConfigurationScope::System
            && context
                .distribution
                .as_ref()
                .is_some_and(|distribution| distribution.id == "nixos")
        {
            return Err(AdapterError::Unsupported(
                "NixOS generates nix.conf declaratively; configure nix.settings instead".into(),
            ));
        }

        let existing = runtime.read(&path)?;
        let contents = existing.clone().unwrap_or_default();
        let text = utf8(&path, &contents)?;
        parse_configuration(text)?;

        validate_environment_policy(runtime, scope)?;
        let effective = read_effective_config(runtime)?;
        validate_effective_config(context, &effective)?;
        let store_path = discover_store_path(runtime)?;
        let narinfo_hash = store_path_hash(&store_path)?;
        let mut sources = effective
            .substituters
            .iter()
            .map(|url| ConfiguredSource {
                upstream_id: is_official_or_mirror(url).then(|| CACHE_UPSTREAM.into()),
                url: url.clone(),
                enabled: true,
                metadata: cache_metadata(context, &effective, &narinfo_hash, &store_path),
            })
            .collect::<Vec<_>>();
        sources.extend(channel_sources(runtime)?);
        if let Some(registry) = effective.flake_registry {
            if !registry.trim().is_empty() {
                sources.push(ConfiguredSource {
                    upstream_id: None,
                    url: registry,
                    enabled: true,
                    metadata: BTreeMap::from([(
                        "configuration_surface".into(),
                        vec!["flake-registry".into()],
                    )]),
                });
            }
        }

        Ok(CurrentConfiguration {
            tool_id: self.tool_id.into(),
            scope,
            files: existing
                .is_some()
                .then(|| path.clone())
                .into_iter()
                .collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path,
                format: match scope {
                    ConfigurationScope::System => "nix-system",
                    ConfigurationScope::User => "nix-user",
                    _ => unreachable!("configuration_path accepts only system and user"),
                }
                .into(),
                contents,
            }],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context, self.operating_system)?;
        if current.tool_id != self.tool_id
            || !matches!(
                current.scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
        {
            return Err(AdapterError::InvalidConfiguration(
                "Nix selection requires a system or user configuration".into(),
            ));
        }
        let mut contexts = current
            .sources
            .iter()
            .filter(|source| source.upstream_id.as_deref() == Some(CACHE_UPSTREAM))
            .map(|source| probe_context(context, source))
            .collect::<Result<Vec<_>, AdapterError>>()?;
        contexts.sort();
        contexts.dedup();
        if contexts.len() != 1 {
            return Err(AdapterError::Unsupported(
                "no unambiguous signed nixpkgs binary cache is configured".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: self.tool_id.into(),
            adapter_key: self.adapter_key.into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![CACHE_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(CACHE_UPSTREAM.into(), contexts)]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Artifacts],
            allowed_delivery_modes: vec![DeliveryMode::Mirror],
            composition_policy: CompositionPolicy::Single,
            overrides: BTreeMap::new(),
        })
    }

    fn plan(
        &self,
        context: &SystemContext,
        current: &CurrentConfiguration,
        selection: &[MirrorSelection],
    ) -> Result<ChangePlan, AdapterError> {
        require_supported_context(context, self.operating_system)?;
        if current.tool_id != self.tool_id
            || !matches!(
                current.scope,
                ConfigurationScope::System | ConfigurationScope::User
            )
            || current.documents.len() != 1
        {
            return Err(AdapterError::InvalidConfiguration(
                "Nix plan requires exactly one system or user nix.conf document".into(),
            ));
        }
        let endpoint = selected_endpoint(selection, self.tool_id)?;
        let document = &current.documents[0];
        let text = utf8(&document.path, &document.contents)?;
        let new_contents = rewrite_configuration(text, endpoint)?.into_bytes();
        let existed = current.files.contains(&document.path);
        let changes = (new_contents != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: existed.then(|| document.contents.clone()),
                old_mode: None,
                new_contents,
                new_mode: None,
                summary: "prefer the selected signed nixpkgs cache without changing keys or custom caches"
                    .into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: self.adapter_key.into(),
            tool_id: self.tool_id.into(),
            scope: current.scope,
            changes,
            requires_elevation: current.scope == ConfigurationScope::System,
            service_impact: if current.scope == ConfigurationScope::System {
                ServiceImpact::RestartRequired
            } else {
                ServiceImpact::None
            },
        })
    }

    fn apply(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        require_supported_context(context, self.operating_system)?;
        if plan.adapter_key != self.adapter_key || plan.tool_id != self.tool_id {
            return Err(AdapterError::InvalidConfiguration(
                "Nix apply received another adapter's plan".into(),
            ));
        }
        let outcome = runtime.apply_plan(plan)?;
        if context.os == OperatingSystem::Macos
            && plan.scope == ConfigurationScope::System
            && matches!(outcome, ApplyOutcome::Applied(_))
        {
            let ApplyOutcome::Applied(receipt) = &outcome else {
                unreachable!()
            };
            if let Err(error) = reload_darwin_daemon(runtime) {
                let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
                let reloaded = restored && reload_darwin_daemon(runtime).is_ok();
                return Err(AdapterError::Runtime(format!(
                    "could not reload the macOS Nix daemon: {error}; configuration restored: {restored}; restored daemon reloaded: {reloaded}"
                )));
            }
        }
        Ok(outcome)
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let effective = match read_effective_config(runtime) {
            Ok(effective) => effective,
            Err(error) => {
                return verification_failure(
                    self,
                    context,
                    runtime,
                    receipt,
                    format!("Nix could not read applied config: {error}"),
                );
            }
        };
        if let Err(error) = validate_effective_config(context, &effective) {
            return verification_failure(self, context, runtime, receipt, error.to_string());
        }
        let mirrors = effective
            .substituters
            .iter()
            .filter(|url| is_supported_mirror(url, self.tool_id))
            .collect::<BTreeSet<_>>();
        if mirrors.len() != 1 {
            return verification_failure(
                self,
                context,
                runtime,
                receipt,
                "effective Nix configuration does not contain exactly one selected mirror".into(),
            );
        }
        let endpoint = mirrors.into_iter().next().unwrap();
        let store_path = if context.os == OperatingSystem::Macos {
            darwin_probe(context.architecture).store_path.into()
        } else {
            match discover_store_path(runtime) {
                Ok(path) => path,
                Err(error) => {
                    return verification_failure(
                        self,
                        context,
                        runtime,
                        receipt,
                        format!("Nix store path discovery failed: {error}"),
                    );
                }
            }
        };
        for arguments in [
            vec![
                "--extra-experimental-features".into(),
                "nix-command".into(),
                "store".into(),
                "ping".into(),
                "--store".into(),
                endpoint.clone(),
            ],
            vec![
                "--extra-experimental-features".into(),
                "nix-command".into(),
                "path-info".into(),
                "--store".into(),
                endpoint.clone(),
                store_path.clone(),
            ],
        ] {
            let output = match runtime.run("nix", &arguments) {
                Ok(output) => output,
                Err(error) => {
                    return verification_failure(
                        self,
                        context,
                        runtime,
                        receipt,
                        format!("nix remote cache query could not run: {error}"),
                    );
                }
            };
            if !output.status.success() {
                return verification_failure(
                    self,
                    context,
                    runtime,
                    receipt,
                    format!(
                        "nix remote cache query failed with status {}",
                        output.status
                    ),
                );
            }
        }
        if context.os == OperatingSystem::Macos {
            let probe = darwin_probe(context.architecture);
            let output = match runtime.run(
                "nix",
                &[
                    "--extra-experimental-features".into(),
                    "nix-command".into(),
                    "store".into(),
                    "ls".into(),
                    "--store".into(),
                    endpoint.clone(),
                    "--long".into(),
                    "--recursive".into(),
                    probe.store_path.into(),
                ],
            ) {
                Ok(output) => output,
                Err(error) => {
                    return verification_failure(
                        self,
                        context,
                        runtime,
                        receipt,
                        format!(
                            "Nix could not read the Darwin NAR from the selected cache: {error}"
                        ),
                    );
                }
            };
            if !output.status.success() {
                return verification_failure(
                    self,
                    context,
                    runtime,
                    receipt,
                    format!(
                        "Nix could not validate the Darwin NAR from the selected cache: status {}",
                        output.status
                    ),
                );
            }
        }
        Ok(VerificationResult {
            valid: true,
            summary: if context.os == OperatingSystem::Macos {
                "Nix reloaded the signed cache configuration, queried a current-system store path, and validated a Darwin NAR"
                    .into()
            } else {
                "Nix read the signed cache configuration and queried a current-system store path"
                    .into()
            },
        })
    }

    fn restore(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<RestoreResult, AdapterError> {
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        if context.os == OperatingSystem::Macos && is_multi_user(context, runtime)? {
            reload_darwin_daemon(runtime)?;
        }
        Ok(RestoreResult {
            restored: restored.verified,
            summary: format!(
                "restored {} Nix configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

macro_rules! delegate_nix_adapter {
    ($adapter:ty, $backend:expr) => {
        impl Adapter for $adapter {
            fn key(&self) -> &'static str {
                $backend.key()
            }

            fn tool_id(&self) -> &'static str {
                $backend.tool_id()
            }

            fn supported_scopes(&self) -> &'static [ConfigurationScope] {
                $backend.supported_scopes()
            }

            fn default_scope(&self) -> ConfigurationScope {
                $backend.default_scope()
            }

            fn default_scope_for(
                &self,
                context: &SystemContext,
                runtime: &dyn Runtime,
                detected: &DetectedTool,
            ) -> Result<ConfigurationScope, AdapterError> {
                $backend.default_scope_for(context, runtime, detected)
            }

            fn composition_policy(&self) -> CompositionPolicy {
                $backend.composition_policy()
            }

            fn detect(
                &self,
                context: &SystemContext,
                runtime: &dyn Runtime,
            ) -> Result<Option<DetectedTool>, AdapterError> {
                $backend.detect(context, runtime)
            }

            fn read_current(
                &self,
                context: &SystemContext,
                runtime: &dyn Runtime,
                detected: &DetectedTool,
                scope: ConfigurationScope,
            ) -> Result<CurrentConfiguration, AdapterError> {
                $backend.read_current(context, runtime, detected, scope)
            }

            fn selection_request(
                &self,
                context: &SystemContext,
                detected: &DetectedTool,
                current: &CurrentConfiguration,
            ) -> Result<SelectionRequest, AdapterError> {
                $backend.selection_request(context, detected, current)
            }

            fn plan(
                &self,
                context: &SystemContext,
                current: &CurrentConfiguration,
                selection: &[MirrorSelection],
            ) -> Result<ChangePlan, AdapterError> {
                $backend.plan(context, current, selection)
            }

            fn apply(
                &self,
                context: &SystemContext,
                runtime: &mut dyn Runtime,
                plan: &ChangePlan,
            ) -> Result<ApplyOutcome, AdapterError> {
                $backend.apply(context, runtime, plan)
            }

            fn verify(
                &self,
                context: &SystemContext,
                runtime: &mut dyn Runtime,
                receipt: &TransactionReceipt,
            ) -> Result<VerificationResult, AdapterError> {
                $backend.verify(context, runtime, receipt)
            }

            fn restore(
                &self,
                context: &SystemContext,
                runtime: &mut dyn Runtime,
                receipt: &TransactionReceipt,
            ) -> Result<RestoreResult, AdapterError> {
                $backend.restore(context, runtime, receipt)
            }
        }
    };
}

delegate_nix_adapter!(NixAdapter, LINUX_BACKEND);
delegate_nix_adapter!(NixMacosAdapter, MACOS_BACKEND);

#[derive(Clone, Debug)]
struct EffectiveConfig {
    substituters: Vec<String>,
    trusted_public_keys: Vec<String>,
    require_sigs: bool,
    system: String,
    flake_registry: Option<String>,
}

#[derive(Clone, Debug)]
struct SettingLine {
    value_range: Range<usize>,
    values: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ParsedConfiguration {
    base: Option<SettingLine>,
    extra: Option<SettingLine>,
}

fn require_supported_context(
    context: &SystemContext,
    operating_system: OperatingSystem,
) -> Result<(), AdapterError> {
    if context.os != operating_system {
        return Err(AdapterError::Unsupported(format!(
            "Nix adapter requires {operating_system:?}"
        )));
    }
    if operating_system == OperatingSystem::Macos
        && context.environment != crate::context::ExecutionEnvironment::Host
    {
        return Err(AdapterError::Unsupported(
            "macOS Nix adapter requires a native host".into(),
        ));
    }
    Ok(())
}

fn validate_scope(
    context: &SystemContext,
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<(), AdapterError> {
    if !matches!(scope, ConfigurationScope::System | ConfigurationScope::User) {
        return Err(AdapterError::Unsupported(
            "Nix supports only system and user nix.conf scopes".into(),
        ));
    }
    if context.os == OperatingSystem::Macos && scope == ConfigurationScope::System {
        if !is_multi_user(context, runtime)? {
            return Err(AdapterError::Unsupported(
                "macOS system scope requires a multi-user Nix installation".into(),
            ));
        }
        darwin_daemon_label(runtime)?.ok_or_else(|| {
            AdapterError::Unsupported("macOS Nix daemon has no supported launchd service".into())
        })?;
        if !runtime.command_exists("launchctl") {
            return Err(AdapterError::Unsupported(
                "macOS system scope requires launchctl to reload the Nix daemon".into(),
            ));
        }
    }
    Ok(())
}

fn configuration_path(
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<PathBuf, AdapterError> {
    match scope {
        ConfigurationScope::System => Ok(PathBuf::from(SYSTEM_CONFIG)),
        ConfigurationScope::User => user_config_path(runtime)?.ok_or_else(|| {
            AdapterError::Unsupported("Nix user scope requires a detected home directory".into())
        }),
        _ => Err(AdapterError::Unsupported(
            "Nix supports only system and user nix.conf scopes".into(),
        )),
    }
}

fn user_config_path(runtime: &dyn Runtime) -> Result<Option<PathBuf>, AdapterError> {
    let Some(home) = runtime.home_dir() else {
        return Ok(None);
    };
    let config_home = runtime
        .environment_variable("XDG_CONFIG_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    if !config_home.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "XDG_CONFIG_HOME must be an absolute path for Nix user scope".into(),
        ));
    }
    Ok(Some(config_home.join("nix/nix.conf")))
}

fn validate_environment_policy(
    runtime: &dyn Runtime,
    scope: ConfigurationScope,
) -> Result<(), AdapterError> {
    if nonempty_environment(runtime, "NIX_CONFIG").is_some() {
        return Err(AdapterError::Unsupported(
            "NIX_CONFIG overrides file-backed Nix settings and must be handled explicitly".into(),
        ));
    }
    let override_name = match scope {
        ConfigurationScope::System => "NIX_CONF_DIR",
        ConfigurationScope::User => "NIX_USER_CONF_FILES",
        _ => unreachable!("Nix scope was validated before environment policy"),
    };
    if nonempty_environment(runtime, override_name).is_some() {
        return Err(AdapterError::Unsupported(format!(
            "{override_name} selects an alternate Nix configuration layout"
        )));
    }
    Ok(())
}

fn nonempty_environment(runtime: &dyn Runtime, name: &str) -> Option<String> {
    runtime
        .environment_variable(name)
        .filter(|value| !value.trim().is_empty())
}

fn is_multi_user(context: &SystemContext, runtime: &dyn Runtime) -> Result<bool, AdapterError> {
    if context.os == OperatingSystem::Macos && darwin_daemon_label(runtime)?.is_some() {
        return Ok(true);
    }
    let daemon_socket = runtime
        .list_files(Path::new("/nix/var/nix/daemon-socket"))?
        .into_iter()
        .any(|path| path.file_name().is_some_and(|name| name == "socket"));
    let daemon_profile = runtime
        .read(Path::new(
            "/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh",
        ))?
        .is_some();
    Ok(daemon_socket || daemon_profile)
}

fn darwin_daemon_label(runtime: &dyn Runtime) -> Result<Option<&'static str>, AdapterError> {
    let nixos = runtime.read(Path::new(NIXOS_DAEMON_PLIST))?.is_some();
    let determinate = runtime.read(Path::new(DETERMINATE_DAEMON_PLIST))?.is_some();
    match (nixos, determinate) {
        (true, false) => Ok(Some(NIXOS_DAEMON_LABEL)),
        (false, true) => Ok(Some(DETERMINATE_DAEMON_LABEL)),
        (false, false) => Ok(None),
        (true, true) => Err(AdapterError::InvalidConfiguration(
            "both upstream and Determinate Nix launchd services are installed".into(),
        )),
    }
}

fn reload_darwin_daemon(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let label = darwin_daemon_label(runtime)?.ok_or_else(|| {
        AdapterError::Unsupported("macOS Nix daemon has no supported launchd service".into())
    })?;
    if !runtime.command_exists("launchctl") {
        return Err(AdapterError::Unsupported(
            "launchctl is required to reload the macOS Nix daemon".into(),
        ));
    }
    let output = runtime.run(
        "launchctl",
        &["kickstart".into(), "-k".into(), format!("system/{label}")],
    )?;
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "launchctl kickstart failed with status {}",
            output.status
        )));
    }
    Ok(())
}

fn read_effective_config(runtime: &dyn Runtime) -> Result<EffectiveConfig, AdapterError> {
    if !runtime.command_exists("nix") {
        return Err(AdapterError::Unsupported(
            "Nix command is required to read effective settings".into(),
        ));
    }
    let mut failures = Vec::new();
    for arguments in [
        vec![
            "--extra-experimental-features".into(),
            "nix-command".into(),
            "config".into(),
            "show".into(),
            "--json".into(),
        ],
        vec!["show-config".into(), "--json".into()],
    ] {
        let output = runtime.run("nix", &arguments)?;
        if !output.status.success() {
            failures.push(output.status.to_string());
            continue;
        }
        let root: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
            AdapterError::InvalidConfiguration(format!(
                "nix config show returned invalid JSON: {error}"
            ))
        })?;
        return Ok(EffectiveConfig {
            substituters: setting_strings(&root, "substituters")?,
            trusted_public_keys: setting_strings(&root, "trusted-public-keys")?,
            require_sigs: setting_bool(&root, "require-sigs")?,
            system: setting_string(&root, "system")?,
            flake_registry: optional_setting_string(&root, "flake-registry")?,
        });
    }
    Err(AdapterError::Runtime(format!(
        "both Nix config commands failed with statuses {}",
        failures.join(", ")
    )))
}

fn setting_value<'a>(root: &'a Value, name: &str) -> Result<&'a Value, AdapterError> {
    let value = root.get(name).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix effective config is missing {name}"))
    })?;
    Ok(value.get("value").unwrap_or(value))
}

fn setting_strings(root: &Value, name: &str) -> Result<Vec<String>, AdapterError> {
    match setting_value(root, name)? {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Nix setting {name} contains a non-string value"
                    ))
                })
            })
            .collect(),
        Value::String(value) => Ok(value.split_whitespace().map(str::to_owned).collect()),
        _ => Err(AdapterError::InvalidConfiguration(format!(
            "Nix setting {name} is not a string list"
        ))),
    }
}

fn setting_string(root: &Value, name: &str) -> Result<String, AdapterError> {
    setting_value(root, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Nix setting {name} is not a string"))
        })
}

fn optional_setting_string(root: &Value, name: &str) -> Result<Option<String>, AdapterError> {
    let Some(value) = root.get(name) else {
        return Ok(None);
    };
    value
        .get("value")
        .unwrap_or(value)
        .as_str()
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Nix setting {name} is not a string"))
        })
}

fn setting_bool(root: &Value, name: &str) -> Result<bool, AdapterError> {
    setting_value(root, name)?.as_bool().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix setting {name} is not boolean"))
    })
}

fn validate_effective_config(
    context: &SystemContext,
    effective: &EffectiveConfig,
) -> Result<(), AdapterError> {
    let expected = match (context.os, context.architecture) {
        (OperatingSystem::Linux, Architecture::X86_64) => "x86_64-linux",
        (OperatingSystem::Linux, Architecture::Arm64) => "aarch64-linux",
        (OperatingSystem::Macos, Architecture::X86_64) => "x86_64-darwin",
        (OperatingSystem::Macos, Architecture::Arm64) => "aarch64-darwin",
        (OperatingSystem::Windows, _) => {
            return Err(AdapterError::Unsupported(
                "Nix effective configuration is not supported on Windows".into(),
            ));
        }
    };
    if effective.system != expected {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Nix system {} conflicts with detected architecture {expected}",
            effective.system
        )));
    }
    if !effective.require_sigs {
        return Err(AdapterError::InvalidConfiguration(
            "Nix require-sigs is disabled".into(),
        ));
    }
    if !effective
        .trusted_public_keys
        .iter()
        .any(|key| key == OFFICIAL_CACHE_KEY)
    {
        return Err(AdapterError::InvalidConfiguration(
            "Nix does not trust the canonical cache.nixos.org signing key".into(),
        ));
    }
    Ok(())
}

fn cache_metadata(
    context: &SystemContext,
    effective: &EffectiveConfig,
    narinfo_hash: &str,
    store_path: &str,
) -> BTreeMap<String, Vec<String>> {
    let mut metadata = BTreeMap::from([
        ("configuration_surface".into(), vec!["binary-cache".into()]),
        ("nix_system".into(), vec![effective.system.clone()]),
        ("narinfo_hash".into(), vec![narinfo_hash.into()]),
        ("store_path".into(), vec![store_path.into()]),
        ("signature_key".into(), vec![OFFICIAL_CACHE_KEY.into()]),
    ]);
    if context.os == OperatingSystem::Macos {
        let probe = darwin_probe(context.architecture);
        metadata.extend([
            ("darwin_probe_hash".into(), vec![probe.store_hash.into()]),
            ("darwin_probe_name".into(), vec![probe.store_name.into()]),
            ("darwin_nar_file".into(), vec![probe.nar_file.into()]),
            ("darwin_nar_digest".into(), vec![probe.nar_sha256.into()]),
        ]);
    }
    metadata
}

fn probe_context(
    context: &SystemContext,
    source: &ConfiguredSource,
) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut values = BTreeMap::from([(
        "narinfo_hash".into(),
        single_metadata(source, "narinfo_hash")?.to_owned(),
    )]);
    if context.os == OperatingSystem::Macos {
        for key in [
            "darwin_probe_hash",
            "darwin_probe_name",
            "darwin_nar_file",
            "darwin_nar_digest",
        ] {
            values.insert(key.into(), single_metadata(source, key)?.to_owned());
        }
    }
    Ok(values)
}

fn darwin_probe(architecture: Architecture) -> DarwinProbe {
    match architecture {
        Architecture::X86_64 => DARWIN_X86_64_PROBE,
        Architecture::Arm64 => DARWIN_ARM64_PROBE,
    }
}

fn discover_store_path(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    if !runtime.command_exists("nix-store") {
        return Err(AdapterError::Unsupported(
            "nix-store is required to discover an architecture-specific narinfo".into(),
        ));
    }
    let mut roots = vec![
        "/proc/self/exe".to_owned(),
        "/nix/var/nix/profiles/default".into(),
    ];
    if let Some(home) = runtime.home_dir() {
        roots.push(home.join(".nix-profile").display().to_string());
    }
    for root in roots {
        let output = runtime.run(
            "nix-store",
            &["--query".into(), "--requisites".into(), root],
        )?;
        if !output.status.success() {
            continue;
        }
        if let Some(path) = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .find(|value| store_path_hash(value).is_ok())
        {
            return Ok(path.to_owned());
        }
    }
    Err(AdapterError::Unsupported(
        "no current-system Nix store path was available for narinfo probing".into(),
    ))
}

fn store_path_hash(path: &str) -> Result<String, AdapterError> {
    let name = path.strip_prefix("/nix/store/").ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix store path is outside /nix/store: {path}"))
    })?;
    let (hash, package) = name.split_once('-').ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix store path has no package name: {path}"))
    })?;
    const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    if hash.len() != 32
        || package.is_empty()
        || !hash.chars().all(|character| NIX_BASE32.contains(character))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Nix store path has an invalid hash: {path}"
        )));
    }
    Ok(hash.into())
}

fn channel_sources(runtime: &dyn Runtime) -> Result<Vec<ConfiguredSource>, AdapterError> {
    if !runtime.command_exists("nix-channel") {
        return Ok(Vec::new());
    }
    let output = runtime.run("nix-channel", &["--list".into()])?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let url = fields.next()?;
            Some(ConfiguredSource {
                upstream_id: None,
                url: url.into(),
                enabled: true,
                metadata: BTreeMap::from([
                    ("configuration_surface".into(), vec!["channel".into()]),
                    ("channel_name".into(), vec![name.into()]),
                ]),
            })
        })
        .collect())
}

fn parse_configuration(text: &str) -> Result<ParsedConfiguration, AdapterError> {
    let mut parsed = ParsedConfiguration::default();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\n', '\r']);
        let content_end = line.find('#').unwrap_or(line.len());
        let active = &line[..content_end];
        let trimmed = active.trim();
        if trimmed.is_empty() {
            offset += inclusive.len();
            continue;
        }
        if trimmed.starts_with("include ") || trimmed.starts_with("!include ") {
            return Err(AdapterError::Unsupported(
                "Nix include directives require declarative owner-aware editing".into(),
            ));
        }
        let Some(equals) = active.find('=') else {
            offset += inclusive.len();
            continue;
        };
        let key = active[..equals].trim();
        let value_part = &active[equals + 1..];
        let leading = value_part.len() - value_part.trim_start().len();
        let trailing = value_part.len() - value_part.trim_end().len();
        let start = offset + equals + 1 + leading;
        let end = offset + active.len() - trailing;
        let setting = SettingLine {
            value_range: start..end,
            values: value_part.split_whitespace().map(str::to_owned).collect(),
        };
        let target = match key {
            "substituters" | "binary-caches" => Some(&mut parsed.base),
            "extra-substituters" | "extra-binary-caches" => Some(&mut parsed.extra),
            _ => None,
        };
        if let Some(target) = target {
            if target.replace(setting).is_some() {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Nix configuration has multiple active {key} assignments"
                )));
            }
        }
        offset += inclusive.len();
    }
    Ok(parsed)
}

fn rewrite_configuration(text: &str, endpoint: &str) -> Result<String, AdapterError> {
    let parsed = parse_configuration(text)?;
    let mut replacements = Vec::new();
    let extra_has_mirror = parsed
        .extra
        .as_ref()
        .is_some_and(|line| line.values.iter().any(|value| is_known_mirror(value)));

    if let Some(base) = &parsed.base {
        let values = rewrite_cache_values(&base.values, endpoint, true);
        replacements.push((base.value_range.clone(), values.join(" ")));
        if let Some(extra) = &parsed.extra {
            let values = extra
                .values
                .iter()
                .filter(|value| !is_known_mirror(value))
                .cloned()
                .collect::<Vec<_>>();
            replacements.push((extra.value_range.clone(), values.join(" ")));
        }
    } else if !extra_has_mirror {
        let mut output = text.to_owned();
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&format!("substituters = {endpoint} {OFFICIAL_CACHE}/\n"));
        return Ok(output);
    } else if let Some(extra) = &parsed.extra {
        let values = rewrite_cache_values(&extra.values, endpoint, false);
        replacements.push((extra.value_range.clone(), values.join(" ")));
    }
    replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0.start));
    let mut output = text.to_owned();
    for (range, value) in replacements {
        output.replace_range(range, &value);
    }
    Ok(output)
}

fn rewrite_cache_values(values: &[String], endpoint: &str, ensure_mirror: bool) -> Vec<String> {
    let mut output = Vec::new();
    let mut inserted = false;
    for value in values {
        if is_known_mirror(value) {
            if !inserted {
                output.push(endpoint.into());
                inserted = true;
            }
            continue;
        }
        if ensure_mirror && is_official_cache(value) && !inserted {
            output.push(endpoint.into());
            inserted = true;
        }
        output.push(value.clone());
    }
    if ensure_mirror && !inserted {
        output.push(endpoint.into());
    }
    output
}

fn selected_endpoint<'a>(
    selections: &'a [MirrorSelection],
    tool_id: &str,
) -> Result<&'a str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == tool_id && selection.upstream_id == CACHE_UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Nix plan requires exactly one binary cache selection".into(),
        ));
    }
    let endpoint = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "Nix selection has no HTTPS artifacts endpoint".into(),
            )
        })?;
    if !is_supported_mirror(&endpoint.url, tool_id) {
        return Err(AdapterError::InvalidConfiguration(
            "Nix selection is not a reviewed signed nixpkgs cache endpoint".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn is_official_or_mirror(url: &str) -> bool {
    is_official_cache(url) || is_known_mirror(url)
}

fn is_official_cache(url: &str) -> bool {
    url.trim_end_matches('/') == OFFICIAL_CACHE
}

fn is_known_mirror(url: &str) -> bool {
    let normalized = url.trim_end_matches('/');
    CACHE_MIRRORS.contains(&normalized)
}

fn is_supported_mirror(url: &str, tool_id: &str) -> bool {
    let normalized = url.trim_end_matches('/');
    if tool_id == "nix-macos" {
        DARWIN_CACHE_MIRRORS.contains(&normalized)
    } else {
        CACHE_MIRRORS.contains(&normalized)
    }
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Nix source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Nix source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn verification_failure<T>(
    backend: &NixBackend,
    context: &SystemContext,
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    let daemon_reloaded = if restored
        && backend.operating_system == OperatingSystem::Macos
        && is_multi_user(context, runtime).unwrap_or(false)
    {
        reload_darwin_daemon(runtime).is_ok()
    } else {
        true
    };
    Err(AdapterError::Verification(format!(
        "{reason}; configuration restored: {restored}; restored daemon reloaded: {daemon_reloaded}"
    )))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Nix configuration {} is not UTF-8",
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
