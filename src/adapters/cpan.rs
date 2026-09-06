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

const UPSTREAM: &str = "cpan--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/CPAN";
const NJU: &str = "https://mirrors.nju.edu.cn/CPAN";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/CPAN";
const USTC: &str = "https://mirrors.ustc.edu.cn/CPAN";
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch cpanm mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch cpanm mirror <<<";
const CPANM_ENV: &str = "PERL_CPANM_OPT";
const TRY_TINY_PATH: &str = "E/ET/ETHER/Try-Tiny-0.32.tar.gz";

const DISCOVERY_SCRIPT: &str = r#"
# MIRRORSWITCH_CPAN_DISCOVERY_V1
my %result = (
  perlVersion => sprintf('%vd', $^V),
  archname => $Config::Config{archname},
);
if (eval { require CPAN; require CPAN::HandleConfig; 1 }) {
  my $home = CPAN::HandleConfig::cpan_home();
  my $system;
  for my $inc (@INC) {
    my $path = "$inc/CPAN/Config.pm";
    if (-f $path) { $system = $path; last }
  }
  $result{cpanVersion} = $CPAN::VERSION;
  $result{cpanHome} = $home;
  $result{myConfig} = "$home/CPAN/MyConfig.pm";
  $result{systemConfig} = $system if defined $system;
}
print JSON::PP->new->canonical->encode(\%result);
"#;

const CPAN_QUERY_SCRIPT: &str = r#"
# MIRRORSWITCH_CPAN_QUERY_V1
CPAN::HandleConfig->load;
my $root = $ENV{MIRRORSWITCH_CPAN_VERIFY_ROOT};
die "verification root is missing" unless defined $root && length $root;
$CPAN::Config->{cpan_home} = "$root/cpan-pm";
$CPAN::Config->{build_dir} = "$root/cpan-pm/build";
$CPAN::Config->{keep_source_where} = "$root/cpan-pm/sources";
$CPAN::Config->{histfile} = "$root/cpan-pm/histfile";
$CPAN::Config->{prefs_dir} = "$root/cpan-pm/prefs";
$CPAN::Config->{connect_to_internet_ok} = 1;
$CPAN::Config->{index_expire} = 0;
$CPAN::Config->{inhibit_startup_message} = 1;
my $module = CPAN::Shell->expand('Module', 'Try::Tiny');
die "Try::Tiny was not found" unless $module;
my $file = $module->cpan_file || '';
print "\nMIRRORSWITCH_CPAN_FILE=$file\n";
"#;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpanAdapter;

impl Adapter for CpanAdapter {
    fn key(&self) -> &'static str {
        "cpan"
    }

    fn tool_id(&self) -> &'static str {
        "cpan"
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
        if !runtime.command_exists("perl") {
            return Ok(None);
        }
        if context.os == OperatingSystem::Windows
            && runtime.command_exists("cpanm")
            && !runtime.command_exists("reg.exe")
        {
            return Err(AdapterError::Unsupported(
                "cpanm Windows persistence requires reg.exe".into(),
            ));
        }
        let home = user_home(runtime)?;
        let discovery = perl_discovery(runtime, &home)?;
        validate_discovery(context, runtime, &discovery, &home)?;
        let (cpanm, cpanm_discovery_failed) = match cpanm_version(runtime, &home) {
            Ok(version) => (version, false),
            Err(error) if discovery.cpan_version.is_none() => return Err(error),
            Err(_) => (None, true),
        };
        if discovery.cpan_version.is_none() && cpanm.is_none() {
            return Ok(None);
        }

        let mut evidence = vec![
            format!("Perl {}", discovery.perl_version),
            format!("Perl architecture is {}", discovery.archname),
            format!(
                "native platform is {:?} {:?}",
                context.os, context.architecture
            ),
            format!("selected user home is {}", home.display()),
            runtime.project_dir().map_or_else(
                || "no project directory was selected".into(),
                |path| format!("project directory {} remains read-only", path.display()),
            ),
        ];
        if let Some(version) = &discovery.cpan_version {
            evidence.push(format!("CPAN.pm {version}"));
            if let Some(path) = &discovery.cpan_home {
                evidence.push(format!("CPAN home is {}", path.display()));
            }
            if let Some(path) = &discovery.my_config {
                evidence.push(format!("CPAN.pm user configuration is {}", path.display()));
            }
            if let Some(path) = &discovery.system_config {
                evidence.push(format!(
                    "CPAN.pm system configuration {} remains read-only",
                    path.display()
                ));
            }
            evidence.push(format!(
                "CPAN.pm configuration is {}",
                cpan_config_state(runtime, &discovery)?
            ));
        } else {
            evidence.push("CPAN.pm is not installed".into());
        }
        if let Some(version) = &cpanm {
            evidence.push(format!("cpanm {version}"));
            match profile_layout(context, runtime, &home) {
                Ok(layout) => evidence.push(format!(
                    "cpanm selected profile is {}",
                    layout.profile.display()
                )),
                Err(_) => evidence.push("cpanm persistent profile is unavailable".into()),
            }
            evidence.push(format!(
                "PERL_CPANM_OPT is {}",
                if context.os == OperatingSystem::Windows {
                    match query_windows_cpanm_options(runtime) {
                        Ok(Some(_)) => "configured in the Windows user environment",
                        Ok(None) => "not configured in the Windows user environment",
                        Err(_) => "unavailable in the Windows user environment",
                    }
                } else {
                    cpanm_environment_state(runtime)
                }
            ));
        } else {
            evidence.push(
                if cpanm_discovery_failed {
                    "cpanm is present but version discovery failed"
                } else {
                    "cpanm is not installed"
                }
                .into(),
            );
        }
        evidence.push(format!(
            "project cpanfile is {}",
            if project_cpanfile(runtime)?.is_some() {
                "present and preserved"
            } else {
                "absent"
            }
        ));
        Ok(Some(DetectedTool {
            tool_id: "cpan".into(),
            executable: Some(PathBuf::from("perl")),
            version: Some(discovery.perl_version),
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
        if detected.tool_id != "cpan" {
            return Err(AdapterError::InvalidConfiguration(
                "CPAN read received another tool's detection result".into(),
            ));
        }
        let home = user_home(runtime)?;
        let discovery = perl_discovery(runtime, &home)?;
        validate_discovery(context, runtime, &discovery, &home)?;
        if detected.version.as_deref() != Some(discovery.perl_version.as_str()) {
            return Err(AdapterError::Conflict(
                "Perl version changed after CPAN client detection".into(),
            ));
        }

        let mut files = Vec::new();
        let mut sources = vec![snapshot_source("perl-version", &discovery.perl_version)];
        let mut documents = Vec::new();

        if discovery.cpan_version.is_some() {
            add_cpan_pm_state(
                runtime,
                &discovery,
                &mut files,
                &mut sources,
                &mut documents,
            )?;
        }
        if matches!(cpanm_version(runtime, &home), Ok(Some(_))) {
            add_cpanm_state(
                context,
                runtime,
                &home,
                &mut files,
                &mut sources,
                &mut documents,
            )?;
        } else if runtime.command_exists("cpanm") {
            sources.push(policy_source(
                "cpanm-version-unavailable",
                Path::new(":command:"),
                "cpanm",
            ));
        }
        if let Some((path, contents)) = project_cpanfile(runtime)? {
            files.push(path.clone());
            match utf8(&path, &contents) {
                Ok(text) => sources.extend(project_sources(text, &path)),
                Err(_) => sources.push(policy_source(
                    "project-cpanfile-non-utf8-preserved",
                    &path,
                    "project",
                )),
            }
            documents.push(ConfigurationDocument {
                path,
                format: "cpan-project-cpanfile-observed".into(),
                contents,
            });
        }

        Ok(CurrentConfiguration {
            tool_id: "cpan".into(),
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
        require_supported_context(context)?;
        require_current(current)?;
        if !has_actionable_client(current) {
            return Err(AdapterError::Unsupported(
                "no initialized CPAN.pm or safely configurable cpanm client is available".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "cpan".into(),
            adapter_key: "cpan".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![UPSTREAM.into()],
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
        let selected = selected_endpoint(selections)?;
        let mut changes = Vec::new();

        if let Some(document) = find_document(current, "cpan-pm-user-config")? {
            let rendered = rewrite_cpan_config(
                utf8(&document.path, &document.contents)?,
                &document.path,
                &selected,
            )?
            .into_bytes();
            add_change(
                context,
                current,
                document,
                preserve_bom(&document.contents, rendered),
                "retarget CPAN.pm urllist while preserving private mirrors and non-mirror policy",
                &mut changes,
            );
        }
        if context.os == OperatingSystem::Windows {
            add_windows_cpanm_plan(context, current, &selected, &mut changes)?;
        } else if let Some(document) = current
            .documents
            .iter()
            .find(|document| document.format.starts_with("cpanm-selected-"))
        {
            let shell = shell_from_format(&document.format)?;
            let rendered = rewrite_profile(
                utf8(&document.path, &document.contents)?,
                &document.path,
                shell,
                &selected,
            )?
            .into_bytes();
            add_change(
                context,
                current,
                document,
                preserve_bom(&document.contents, rendered),
                "add or retarget one managed cpanm mirror option while preserving unrelated options",
                &mut changes,
            );
        }
        if !has_actionable_client(current) {
            return Err(AdapterError::Unsupported(
                "no initialized CPAN.pm or safely configurable cpanm client is available".into(),
            ));
        }

        Ok(ChangePlan {
            adapter_key: "cpan".into(),
            tool_id: "cpan".into(),
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
            windows_cpanm_apply(runtime, plan)
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
        let result = (|| {
            require_supported_context(context)?;
            let home = user_home(runtime)?;
            let discovery = perl_discovery(runtime, &home)?;
            validate_discovery(context, runtime, &discovery, &home)?;
            let my_config_target = discovery
                .my_config
                .as_ref()
                .map(|path| rooted(&context.root, path));
            let cpanm_available = matches!(cpanm_version(runtime, &home), Ok(Some(_)));
            if !cpanm_available
                && receipt
                    .changed_targets
                    .iter()
                    .any(|target| Some(target) != my_config_target.as_ref())
            {
                return Err(AdapterError::Verification(
                    "cpanm became unavailable after its profile was changed".into(),
                ));
            }
            let layout = if cpanm_available {
                match profile_layout(context, runtime, &home) {
                    Ok(layout) => Some(layout),
                    Err(error)
                        if receipt
                            .changed_targets
                            .iter()
                            .any(|target| Some(target) != my_config_target.as_ref()) =>
                    {
                        return Err(error);
                    }
                    Err(_) => None,
                }
            } else {
                None
            };
            let mut known = BTreeSet::new();
            if let Some(path) = my_config_target {
                known.insert(path);
            }
            if let Some(layout) = &layout {
                known.insert(rooted(&context.root, &layout.profile));
            }
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "CPAN transaction receipt contains no known client target".into(),
                ));
            }

            let mut verified = Vec::new();
            let mut selected = BTreeSet::new();
            if let Some(path) = &discovery.my_config
                && let Some(contents) = runtime.read(path)?
                && let Ok(config) = parse_cpan_config(utf8(path, &contents)?, path)
            {
                if config.pushy.as_ref().map(|value| value.value.as_str()) != Some("0")
                    || config.randomize.as_ref().map(|value| value.value.as_str()) != Some("0")
                {
                    return Err(AdapterError::Verification(
                        "CPAN.pm mirror ordering controls are not pinned to zero".into(),
                    ));
                }
                let endpoint = unique_reviewed(&config.urls, "CPAN.pm urllist")?;
                selected.insert(endpoint.clone());
                verify_cpan_pm(runtime, &home, &verification_root(&home))?;
                verified.push("CPAN.pm");
            }
            if let Some(layout) = &layout {
                if layout.shell == ShellKind::WindowsRegistry {
                    if let Some(contents) = runtime.read(&layout.profile)? {
                        let state: WindowsCpanmRecoveryState = serde_json::from_slice(&contents)
                            .map_err(|error| {
                                AdapterError::InvalidConfiguration(format!(
                                    "cpanm Windows recovery state is invalid: {error}"
                                ))
                            })?;
                        state.validate()?;
                        if !query_windows_cpanm_options(runtime)?
                            .as_deref()
                            .is_some_and(|value| {
                                option_tokens(value) == option_tokens(&state.selected)
                            })
                        {
                            return Err(AdapterError::Verification(
                                "cpanm Windows user environment did not retain PERL_CPANM_OPT"
                                    .into(),
                            ));
                        }
                        let options = parse_cpanm_options(&state.selected)?;
                        let endpoint = unique_reviewed(&options.urls(), "cpanm Windows options")?;
                        selected.insert(endpoint);
                        verify_cpanm(runtime, &home, &verification_root(&home), &state.selected)?;
                        verified.push("cpanm");
                    }
                } else if let Some(contents) = runtime.read(&layout.profile)?
                    && let Ok(profile) = parse_profile(
                        utf8(&layout.profile, &contents)?,
                        &layout.profile,
                        layout.shell,
                    )
                    && let Some(value) = profile.value()
                {
                    let options = parse_cpanm_options(value)?;
                    let endpoint = unique_reviewed(&options.urls(), "cpanm options")?;
                    if option_tokens(&rewrite_cpanm_options(value, &endpoint)?)
                        != option_tokens(value)
                    {
                        return Err(AdapterError::Verification(
                            "cpanm mirror resolver options are not canonical".into(),
                        ));
                    }
                    selected.insert(endpoint);
                    verify_cpanm(runtime, &home, &verification_root(&home), value)?;
                    verified.push("cpanm");
                }
            }
            if verified.is_empty() {
                return Err(AdapterError::Verification(
                    "no CPAN client retained a verifiable mirror configuration".into(),
                ));
            }
            if selected.len() != 1 {
                return Err(AdapterError::Verification(
                    "CPAN.pm and cpanm are not bound to the same selected mirror".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "{} verified Try::Tiny through {}",
                    verified.join(" and "),
                    selected.into_iter().next().expect("one selected endpoint")
                ),
            })
        })();
        match result {
            Ok(result) => Ok(result),
            Err(error) if context.os == OperatingSystem::Windows => {
                windows_cpanm_verification_failure(runtime, receipt, error.to_string())
            }
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
            return windows_cpanm_restore(runtime, receipt);
        }
        let restored = runtime.restore_transaction(&receipt.transaction_id)?;
        Ok(RestoreResult {
            restored: restored.verified,
            summary: format!(
                "restored {} CPAN client configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PerlDiscovery {
    perl_version: String,
    archname: String,
    cpan_version: Option<String>,
    cpan_home: Option<PathBuf>,
    my_config: Option<PathBuf>,
    system_config: Option<PathBuf>,
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

struct ProfileLayout {
    shell: ShellKind,
    profile: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsCpanmRecoveryState {
    schema_version: u32,
    original: Option<String>,
    selected: String,
}

impl WindowsCpanmRecoveryState {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != 1 || !canonical_cpanm_options(&self.selected) {
            return Err(AdapterError::InvalidConfiguration(
                "cpanm Windows recovery state has invalid selected options".into(),
            ));
        }
        if self
            .original
            .as_deref()
            .is_some_and(|value| rewrite_cpanm_options(value, ALIYUN).is_err())
        {
            return Err(AdapterError::InvalidConfiguration(
                "cpanm Windows recovery state has unsafe original options".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CpanConfig {
    urllist_range: Range<usize>,
    urls: Vec<String>,
    indent: String,
    pushy: Option<ScalarAssignment>,
    randomize: Option<ScalarAssignment>,
}

#[derive(Debug)]
struct ScalarAssignment {
    range: Range<usize>,
    indent: String,
    value: String,
}

#[derive(Debug)]
struct ProfileAssignment {
    range: Range<usize>,
    value: String,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<String>,
    unmanaged: Vec<ProfileAssignment>,
    dynamic: bool,
}

impl ParsedProfile {
    fn value(&self) -> Option<&str> {
        self.managed
            .as_deref()
            .or_else(|| (self.unmanaged.len() == 1).then(|| self.unmanaged[0].value.as_str()))
    }

    fn safe(&self) -> bool {
        !self.dynamic
            && self.unmanaged.len() <= 1
            && (self.managed.is_none() || self.unmanaged.is_empty())
            && self
                .value()
                .is_none_or(|value| rewrite_cpanm_options(value, ALIYUN).is_ok())
    }
}

#[derive(Clone, Debug)]
enum OptionGroup {
    Mirror { tokens: Vec<String>, url: String },
    From { tokens: Vec<String>, url: String },
    MirrorOnly(Vec<String>),
    NoMirrorOnly(Vec<String>),
    ResolverConflict(Vec<String>),
    Other(Vec<String>),
}

#[derive(Debug)]
struct CpanmOptions {
    groups: Vec<OptionGroup>,
}

impl CpanmOptions {
    fn urls(&self) -> Vec<String> {
        self.groups
            .iter()
            .filter_map(|group| match group {
                OptionGroup::Mirror { url, .. } | OptionGroup::From { url, .. } => {
                    Some(url.clone())
                }
                _ => None,
            })
            .collect()
    }
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "CPAN clients on macOS and Windows require a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "CPAN clients on Windows arm64 are unavailable because the reviewed Perl distribution has no native Windows arm64 runtime"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "CPAN clients require x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "CPAN clients support user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "cpan" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "CPAN operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn user_home(runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("CPAN clients require a user home".into()))?;
    validate_path(&home, "home")?;
    Ok(home)
}

fn perl_discovery(runtime: &dyn Runtime, home: &Path) -> Result<PerlDiscovery, AdapterError> {
    let environment = BTreeMap::from([("HOME".into(), path_text(home, "home")?.into())]);
    let output = run_isolated(
        runtime,
        None,
        "perl",
        &[
            "-MConfig".into(),
            "-MJSON::PP".into(),
            "-e".into(),
            DISCOVERY_SCRIPT.into(),
        ],
        &environment,
        &[],
        "Perl and CPAN.pm discovery",
    )?;
    serde_json::from_str(output.trim()).map_err(|error| {
        AdapterError::Unsupported(format!("Perl CPAN discovery output is invalid: {error}"))
    })
}

fn validate_discovery(
    context: &SystemContext,
    runtime: &dyn Runtime,
    discovery: &PerlDiscovery,
    home: &Path,
) -> Result<(), AdapterError> {
    if !valid_version(&discovery.perl_version) || discovery.archname.trim().is_empty() {
        return Err(AdapterError::Unsupported(
            "Perl version or architecture is unrecognized".into(),
        ));
    }
    if let Some(version) = &discovery.cpan_version {
        if !valid_version(version) {
            return Err(AdapterError::Unsupported(
                "CPAN.pm version is unrecognized".into(),
            ));
        }
        let cpan_home = discovery.cpan_home.as_ref().ok_or_else(|| {
            AdapterError::Unsupported("CPAN.pm did not report its CPAN home".into())
        })?;
        let my_config = discovery.my_config.as_ref().ok_or_else(|| {
            AdapterError::Unsupported("CPAN.pm did not report its user config path".into())
        })?;
        validate_cpan_user_path(context, runtime, cpan_home, home, "CPAN home")?;
        validate_cpan_user_path(context, runtime, my_config, home, "CPAN user config")?;
        if let Some(system) = &discovery.system_config {
            validate_path(system, "CPAN system config")?;
        }
    }
    Ok(())
}

fn cpanm_version(runtime: &dyn Runtime, home: &Path) -> Result<Option<String>, AdapterError> {
    if !runtime.command_exists("cpanm") {
        return Ok(None);
    }
    let detection_home = verification_root(home).join("detection-cpanm");
    let environment = BTreeMap::from([
        ("HOME".into(), path_text(home, "home")?.into()),
        (
            "PERL_CPANM_HOME".into(),
            path_text(&detection_home, "cpanm detection home")?.into(),
        ),
    ]);
    let output = run_isolated(
        runtime,
        None,
        "cpanm",
        &["--version".into()],
        &environment,
        &[],
        "cpanm --version",
    )?;
    let version = output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields
            .windows(2)
            .find(|pair| pair[0] == "version")
            .map(|pair| {
                pair[1].trim_matches(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '.'
                })
            })
    });
    let version = version
        .filter(|value| valid_version(value))
        .ok_or_else(|| {
            AdapterError::Unsupported("cpanm did not report a recognized version".into())
        })?;
    Ok(Some(version.into()))
}

fn cpan_config_state(
    runtime: &dyn Runtime,
    discovery: &PerlDiscovery,
) -> Result<&'static str, AdapterError> {
    if let Some(path) = &discovery.my_config
        && runtime.read(path)?.is_some()
    {
        return Ok("initialized in user config");
    }
    if let Some(path) = &discovery.system_config
        && runtime.read(path)?.is_some()
    {
        return Ok("initialized in system config and eligible for user override");
    }
    Ok("uninitialized")
}

fn add_cpan_pm_state(
    runtime: &dyn Runtime,
    discovery: &PerlDiscovery,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let my_config = discovery.my_config.as_ref().ok_or_else(|| {
        AdapterError::InvalidConfiguration("CPAN user config path is missing".into())
    })?;
    let user_contents = runtime.read(my_config)?;
    if user_contents.is_some() {
        files.push(my_config.clone());
    }
    let (source_path, contents, source_kind) = if let Some(contents) = user_contents {
        (my_config.clone(), contents, "cpan-pm-user-source")
    } else if let Some(system) = &discovery.system_config {
        let Some(contents) = runtime.read(system)? else {
            sources.push(policy_source("cpan-pm-uninitialized", my_config, "CPAN.pm"));
            return Ok(());
        };
        files.push(system.clone());
        (system.clone(), contents, "cpan-pm-system-source")
    } else {
        sources.push(policy_source("cpan-pm-uninitialized", my_config, "CPAN.pm"));
        return Ok(());
    };
    match utf8(&source_path, &contents).and_then(|text| parse_cpan_config(text, &source_path)) {
        Ok(config) => {
            for url in &config.urls {
                sources.push(if is_public_cpan(url) {
                    configured_source(url, "cpan-pm-public-mirror", &source_path, "CPAN.pm")
                } else {
                    policy_source("cpan-pm-private-preserved", &source_path, "CPAN.pm")
                });
            }
            sources.push(policy_source(source_kind, &source_path, "CPAN.pm"));
            documents.push(ConfigurationDocument {
                path: my_config.clone(),
                format: "cpan-pm-user-config".into(),
                contents,
            });
        }
        Err(_) => {
            sources.push(policy_source(
                "cpan-pm-unsafe-static-config",
                &source_path,
                "CPAN.pm",
            ));
        }
    }
    Ok(())
}

fn add_cpanm_state(
    context: &SystemContext,
    runtime: &dyn Runtime,
    home: &Path,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    if context.os == OperatingSystem::Windows {
        return add_windows_cpanm_state(runtime, files, sources, documents);
    }
    let layout = match profile_layout(context, runtime, home) {
        Ok(layout) => layout,
        Err(_) => {
            sources.push(policy_source(
                "cpanm-profile-unavailable",
                Path::new(":shell:"),
                "cpanm",
            ));
            return Ok(());
        }
    };
    let contents = runtime.read(&layout.profile)?;
    if contents.is_some() {
        files.push(layout.profile.clone());
    }
    let contents = contents.unwrap_or_default();
    let parsed = match utf8(&layout.profile, &contents)
        .and_then(|text| parse_profile(text, &layout.profile, layout.shell))
    {
        Ok(parsed) if parsed.safe() => parsed,
        _ => {
            sources.push(policy_source(
                "cpanm-unsafe-profile",
                &layout.profile,
                "cpanm",
            ));
            return Ok(());
        }
    };
    if let Some(environment) = runtime
        .environment_variable(CPANM_ENV)
        .filter(|value| !value.trim().is_empty())
        && parsed
            .value()
            .is_none_or(|profile| option_tokens(profile) != option_tokens(&environment))
    {
        sources.push(policy_source(
            "cpanm-environment-override",
            Path::new(":env:"),
            "cpanm",
        ));
        return Ok(());
    }
    if let Some(value) = parsed.value() {
        let options = parse_cpanm_options(value)?;
        for url in options.urls() {
            sources.push(if is_public_cpan(&url) {
                configured_source(&url, "cpanm-public-mirror", &layout.profile, "cpanm")
            } else {
                policy_source("cpanm-private-preserved", &layout.profile, "cpanm")
            });
        }
    }
    documents.push(ConfigurationDocument {
        path: layout.profile,
        format: format!("cpanm-selected-{}-profile", layout.shell.name()),
        contents,
    });
    Ok(())
}

fn add_windows_cpanm_state(
    runtime: &dyn Runtime,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let layout = ProfileLayout {
        shell: ShellKind::WindowsRegistry,
        profile: windows_cpanm_recovery_path(runtime)?,
    };
    let observed = runtime.read(&layout.profile)?;
    let recovery_exists = observed.is_some();
    let recovery_contents = observed.unwrap_or_default();
    let recovery = if recovery_exists {
        let state: WindowsCpanmRecoveryState =
            serde_json::from_slice(&recovery_contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "cpanm Windows recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        Some(state)
    } else {
        None
    };
    let registry = match query_windows_cpanm_options(runtime) {
        Ok(value) => value,
        Err(AdapterError::Unsupported(_)) if recovery.is_none() => {
            sources.push(policy_source(
                "cpanm-unsafe-windows-registry",
                Path::new(r"HKCU\Environment"),
                "cpanm",
            ));
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if let Some(state) = &recovery
        && registry
            .as_deref()
            .is_none_or(|value| option_tokens(value) != option_tokens(&state.selected))
    {
        return Err(AdapterError::Conflict(
            "cpanm Windows recovery state does not match HKCU PERL_CPANM_OPT".into(),
        ));
    }
    if let Some(value) = &registry {
        let options = match parse_cpanm_options(value) {
            Ok(options) if rewrite_cpanm_options(value, ALIYUN).is_ok() => options,
            _ => {
                sources.push(policy_source(
                    "cpanm-unsafe-windows-registry",
                    Path::new(r"HKCU\Environment"),
                    "cpanm",
                ));
                return Ok(());
            }
        };
        for url in options.urls() {
            sources.push(if is_public_cpan(&url) {
                configured_source(
                    &url,
                    "cpanm-public-mirror",
                    Path::new(r"HKCU\Environment"),
                    "cpanm",
                )
            } else {
                policy_source(
                    "cpanm-private-preserved",
                    Path::new(r"HKCU\Environment"),
                    "cpanm",
                )
            });
        }
    }
    if let Some(value) = runtime
        .environment_variable(CPANM_ENV)
        .filter(|value| !value.trim().is_empty())
    {
        let stale_original = recovery
            .as_ref()
            .and_then(|state| state.original.as_deref())
            .is_some_and(|original| option_tokens(original) == option_tokens(&value));
        if registry
            .as_deref()
            .is_none_or(|persistent| option_tokens(persistent) != option_tokens(&value))
            && !stale_original
        {
            sources.push(policy_source(
                "cpanm-environment-override",
                Path::new(":env:"),
                "cpanm",
            ));
            return Ok(());
        }
    }
    if recovery_exists {
        files.push(layout.profile.clone());
        sources.push(policy_source(
            "cpanm-windows-recovery-active",
            &layout.profile,
            "cpanm",
        ));
    }
    documents.push(ConfigurationDocument {
        path: layout.profile,
        format: "cpanm-windows-recovery".into(),
        contents: recovery_contents,
    });
    documents.push(ConfigurationDocument {
        path: PathBuf::from(r"HKCU\Environment\PERL_CPANM_OPT"),
        format: "cpanm-windows-registry-snapshot".into(),
        contents: registry.as_deref().unwrap_or_default().as_bytes().to_vec(),
    });
    Ok(())
}

fn add_windows_cpanm_plan(
    context: &SystemContext,
    current: &CurrentConfiguration,
    endpoint: &str,
    changes: &mut Vec<PlannedFileChange>,
) -> Result<(), AdapterError> {
    let Some(recovery) = find_document(current, "cpanm-windows-recovery")? else {
        return Ok(());
    };
    if !recovery.contents.is_empty() {
        let state: WindowsCpanmRecoveryState =
            serde_json::from_slice(&recovery.contents).map_err(|error| {
                AdapterError::InvalidConfiguration(format!(
                    "cpanm Windows recovery state is invalid: {error}"
                ))
            })?;
        state.validate()?;
        let options = parse_cpanm_options(&state.selected)?;
        if unique_reviewed(&options.urls(), "cpanm Windows options")? != endpoint {
            return Err(AdapterError::Unsupported(
                "a previous cpanm Windows recovery state is active; restore it before selecting another mirror"
                    .into(),
            ));
        }
        return Ok(());
    }
    let registry = find_document(current, "cpanm-windows-registry-snapshot")?.ok_or_else(|| {
        AdapterError::InvalidConfiguration("cpanm Windows registry snapshot is missing".into())
    })?;
    let original = if registry.contents.is_empty() {
        None
    } else {
        Some(
            std::str::from_utf8(&registry.contents)
                .map_err(|_| {
                    AdapterError::InvalidConfiguration(
                        "cpanm Windows registry snapshot is not UTF-8".into(),
                    )
                })?
                .to_owned(),
        )
    };
    let selected = rewrite_cpanm_options(original.as_deref().unwrap_or_default(), endpoint)?;
    let state = WindowsCpanmRecoveryState {
        schema_version: 1,
        original,
        selected,
    };
    state.validate()?;
    let mut contents = serde_json::to_vec_pretty(&state).map_err(|error| {
        AdapterError::Runtime(format!(
            "could not serialize cpanm Windows recovery state: {error}"
        ))
    })?;
    contents.push(b'\n');
    add_change(
        context,
        current,
        recovery,
        contents,
        "record private cpanm Windows user-environment recovery state before updating PERL_CPANM_OPT",
        changes,
    );
    Ok(())
}

fn windows_cpanm_apply(
    runtime: &mut dyn Runtime,
    plan: &ChangePlan,
) -> Result<ApplyOutcome, AdapterError> {
    if plan.adapter_key != "cpan" || plan.tool_id != "cpan" {
        return Err(AdapterError::InvalidConfiguration(
            "cpanm Windows apply received another tool's plan".into(),
        ));
    }
    let state = plan.changes.iter().find_map(|change| {
        serde_json::from_slice::<WindowsCpanmRecoveryState>(&change.new_contents).ok()
    });
    let Some(state) = state else {
        return runtime.apply_plan(plan);
    };
    state.validate()?;
    let outcome = runtime.apply_plan(plan)?;
    let ApplyOutcome::Applied(receipt) = &outcome else {
        return Ok(outcome);
    };
    if let Err(error) = set_windows_cpanm_options(runtime, &state.selected) {
        let registry_restored =
            restore_windows_cpanm_options(runtime, state.original.as_deref()).is_ok();
        let files_restored =
            registry_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
        return Err(AdapterError::Runtime(format!(
            "cpanm Windows environment update failed: {error}; registry restored: {registry_restored}; recovery files restored: {files_restored}"
        )));
    }
    Ok(outcome)
}

fn windows_cpanm_verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let registry_restored = if !receipt_changed_cpanm_recovery(receipt) {
        true
    } else {
        match windows_cpanm_recovery_path(runtime) {
            Ok(path) => match runtime.read(&path) {
                Ok(None) => true,
                Ok(Some(_)) => read_windows_cpanm_recovery(runtime).is_ok_and(|state| {
                    restore_windows_cpanm_options(runtime, state.original.as_deref()).is_ok()
                }),
                Err(_) => false,
            },
            Err(_) => false,
        }
    };
    let files_restored =
        registry_restored && runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{reason}; registry restored: {registry_restored}; configuration restored: {files_restored}"
    )))
}

fn windows_cpanm_restore(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
) -> Result<RestoreResult, AdapterError> {
    if receipt_changed_cpanm_recovery(receipt) {
        let state = read_windows_cpanm_recovery(runtime)?;
        restore_windows_cpanm_options(runtime, state.original.as_deref())?;
    }
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Ok(RestoreResult {
        restored: restored.verified,
        summary: "restored CPAN.pm configuration, the previous cpanm Windows user environment, and recovery state"
            .into(),
    })
}

fn receipt_changed_cpanm_recovery(receipt: &TransactionReceipt) -> bool {
    receipt
        .changed_targets
        .iter()
        .any(|path| path.ends_with("MirrorSwitch/cpanm/environment-recovery.json"))
}

fn read_windows_cpanm_recovery(
    runtime: &dyn Runtime,
) -> Result<WindowsCpanmRecoveryState, AdapterError> {
    let path = windows_cpanm_recovery_path(runtime)?;
    let contents = runtime
        .read(&path)?
        .ok_or_else(|| AdapterError::Runtime("cpanm Windows recovery state is missing".into()))?;
    let state: WindowsCpanmRecoveryState = serde_json::from_slice(&contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "cpanm Windows recovery state is invalid: {error}"
        ))
    })?;
    state.validate()?;
    Ok(state)
}

fn query_windows_cpanm_options(runtime: &dyn Runtime) -> Result<Option<String>, AdapterError> {
    let output = runtime.run(
        "reg.exe",
        &[
            "query".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            CPANM_ENV.into(),
        ],
    )?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(AdapterError::Runtime(format!(
            "reg.exe query {CPANM_ENV} failed with status {}",
            output.status
        )));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime("reg.exe returned non-UTF-8 output".into()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(CPANM_ENV))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("reg.exe returned no {CPANM_ENV} value"))
        })?;
    let rest = line[CPANM_ENV.len()..].trim_start();
    let split = rest.find(char::is_whitespace).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("reg.exe returned malformed {CPANM_ENV} state"))
    })?;
    let kind = &rest[..split];
    let value = rest[split..].trim();
    if kind != "REG_SZ" || rewrite_cpanm_options(value, ALIYUN).is_err() {
        return Err(AdapterError::Unsupported(format!(
            "cpanm Windows {CPANM_ENV} must be a safe REG_SZ option string"
        )));
    }
    Ok(Some(value.into()))
}

fn set_windows_cpanm_options(runtime: &dyn Runtime, value: &str) -> Result<(), AdapterError> {
    if !canonical_cpanm_options(value) {
        return Err(AdapterError::InvalidConfiguration(
            "cpanm Windows selected options are not canonical".into(),
        ));
    }
    let output = runtime.run(
        "reg.exe",
        &[
            "add".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            CPANM_ENV.into(),
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
            "reg.exe add {CPANM_ENV} failed with status {}",
            output.status
        )))
    }
}

fn restore_windows_cpanm_options(
    runtime: &dyn Runtime,
    original: Option<&str>,
) -> Result<(), AdapterError> {
    match original {
        Some(value) => {
            if rewrite_cpanm_options(value, ALIYUN).is_err() {
                return Err(AdapterError::InvalidConfiguration(
                    "cpanm Windows original options are unsafe".into(),
                ));
            }
            let output = runtime.run(
                "reg.exe",
                &[
                    "add".into(),
                    r"HKCU\Environment".into(),
                    "/v".into(),
                    CPANM_ENV.into(),
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
                    "reg.exe restore {CPANM_ENV} failed with status {}",
                    output.status
                )))
            }
        }
        None => delete_windows_cpanm_options(runtime),
    }
}

fn delete_windows_cpanm_options(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let output = runtime.run(
        "reg.exe",
        &[
            "delete".into(),
            r"HKCU\Environment".into(),
            "/v".into(),
            CPANM_ENV.into(),
            "/f".into(),
        ],
    )?;
    if output.status.success() || output.status.code() == Some(1) {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "reg.exe delete {CPANM_ENV} failed with status {}",
            output.status
        )))
    }
}

fn profile_layout(
    context: &SystemContext,
    runtime: &dyn Runtime,
    home: &Path,
) -> Result<ProfileLayout, AdapterError> {
    if context.os == OperatingSystem::Windows {
        return Ok(ProfileLayout {
            shell: ShellKind::WindowsRegistry,
            profile: windows_cpanm_recovery_path(runtime)?,
        });
    }
    let shell = runtime
        .environment_variable("SHELL")
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().and_then(parse_shell))
        .ok_or_else(|| {
            AdapterError::Unsupported(
                "cpanm requires SHELL to select bash, zsh, or fish initialization".into(),
            )
        })?;
    let profile = if let Some(value) = runtime
        .environment_variable("PROFILE")
        .filter(|value| !value.trim().is_empty())
    {
        if value == "/dev/null" {
            return Err(AdapterError::Unsupported(
                "PROFILE=/dev/null disables persistent cpanm configuration".into(),
            ));
        }
        PathBuf::from(value)
    } else if context.environment == ExecutionEnvironment::Container
        && shell == ShellKind::Bash
        && let Some(value) = runtime
            .environment_variable("BASH_ENV")
            .filter(|value| !value.trim().is_empty())
    {
        PathBuf::from(value)
    } else {
        match shell {
            ShellKind::Bash => home.join(".bashrc"),
            ShellKind::Zsh => runtime
                .environment_variable("ZDOTDIR")
                .filter(|value| !value.trim().is_empty())
                .map_or_else(
                    || home.join(".zshrc"),
                    |value| PathBuf::from(value).join(".zshrc"),
                ),
            ShellKind::Fish => home.join(".config/fish/conf.d/mirrorswitch-cpanm.fish"),
            ShellKind::WindowsRegistry => {
                unreachable!("Windows cpanm layout returned before shell selection")
            }
        }
    };
    validate_user_path(&profile, home, "cpanm shell profile")?;
    Ok(ProfileLayout { shell, profile })
}

fn windows_cpanm_recovery_path(runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    Ok(required_environment_path(runtime, "LOCALAPPDATA")?
        .join("MirrorSwitch/cpanm/environment-recovery.json"))
}

fn required_environment_path(
    runtime: &dyn Runtime,
    variable: &str,
) -> Result<PathBuf, AdapterError> {
    let value = runtime
        .environment_variable(variable)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AdapterError::Unsupported(format!("cpanm Windows persistence requires {variable}"))
        })?;
    let path = PathBuf::from(value);
    validate_path(&path, variable)?;
    Ok(path)
}

fn parse_shell(value: &str) -> Option<ShellKind> {
    match value {
        "bash" => Some(ShellKind::Bash),
        "zsh" => Some(ShellKind::Zsh),
        "fish" => Some(ShellKind::Fish),
        _ => None,
    }
}

fn project_cpanfile(runtime: &dyn Runtime) -> Result<Option<(PathBuf, Vec<u8>)>, AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(None);
    };
    validate_path(&project, "project")?;
    let path = project.join("cpanfile");
    Ok(runtime.read(&path)?.map(|contents| (path, contents)))
}

fn project_sources(text: &str, path: &Path) -> Vec<ConfiguredSource> {
    text.lines()
        .filter_map(|line| {
            let active = line.split('#').next().unwrap_or_default().trim();
            let kind = if active.starts_with("mirror ") {
                "project-mirror-preserved"
            } else if active.contains("url =>") || active.contains("dist =>") {
                "project-distribution-pin-preserved"
            } else if active.contains("path =>") {
                "project-local-path-preserved"
            } else {
                return None;
            };
            Some(policy_source(kind, path, "project"))
        })
        .collect()
}

fn parse_cpan_config(text: &str, path: &Path) -> Result<CpanConfig, AdapterError> {
    if text.matches("$CPAN::Config").count() != 1
        || !text.contains("$CPAN::Config = {")
        || !text.contains("\n};")
        || !text.contains("\n1;")
    {
        return Err(AdapterError::Unsupported(format!(
            "CPAN config {} is not a static generated configuration",
            path.display()
        )));
    }
    let (urllist_range, indent) = block_assignment(text, "urllist", path)?;
    let block = &text[urllist_range.clone()];
    let urls = q_values(block, "urllist", path)?;
    if urls.is_empty() {
        return Err(AdapterError::Unsupported(
            "CPAN urllist is empty or uninitialized".into(),
        ));
    }
    let expected = format!(
        "'urllist'=>[{}],",
        urls.iter()
            .map(|url| format!("q[{url}]"))
            .collect::<Vec<_>>()
            .join(",")
    );
    if without_whitespace(block) != expected {
        return Err(AdapterError::Unsupported(
            "CPAN urllist is dynamic or uses an unsupported Perl expression".into(),
        ));
    }
    for url in &urls {
        validate_cpan_url(url)?;
    }
    Ok(CpanConfig {
        urllist_range,
        urls,
        indent,
        pushy: scalar_assignment(text, "pushy_https", path)?,
        randomize: scalar_assignment(text, "randomize_urllist", path)?,
    })
}

fn block_assignment(
    text: &str,
    key: &str,
    path: &Path,
) -> Result<(Range<usize>, String), AdapterError> {
    let starts = line_spans(text)
        .filter(|(_, line)| line.trim_start().starts_with(&format!("'{key}'")))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "CPAN config {} must assign {key} exactly once",
            path.display()
        )));
    }
    let (start, first) = starts[0];
    let indent = first[..first.len() - first.trim_start().len()].to_owned();
    let mut end = None;
    for (line_start, line) in line_spans(&text[start..]) {
        if line
            .trim_end_matches(['\r', '\n'])
            .trim_end()
            .ends_with("],")
        {
            end = Some(start + line_start + line.len());
            break;
        }
    }
    let end = end.ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!(
            "CPAN {key} array in {} is not terminated",
            path.display()
        ))
    })?;
    Ok((start..end, indent))
}

fn scalar_assignment(
    text: &str,
    key: &str,
    path: &Path,
) -> Result<Option<ScalarAssignment>, AdapterError> {
    let matches = line_spans(text)
        .filter(|(_, line)| line.trim_start().starts_with(&format!("'{key}'")))
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "CPAN config {} assigns {key} more than once",
            path.display()
        )));
    }
    let Some((start, line)) = matches.first().copied() else {
        return Ok(None);
    };
    let compact = without_whitespace(line.trim_end_matches(['\r', '\n']));
    let prefix = format!("'{key}'=>q[");
    if !compact.starts_with(&prefix) || !compact.ends_with("],") {
        return Err(AdapterError::Unsupported(format!(
            "CPAN {key} is dynamic or uses an unsupported Perl expression"
        )));
    }
    let value = &compact[prefix.len()..compact.len() - 2];
    if value.contains(']') {
        return Err(AdapterError::Unsupported(format!(
            "CPAN {key} contains a non-literal value"
        )));
    }
    let indent = line[..line.len() - line.trim_start().len()].to_owned();
    Ok(Some(ScalarAssignment {
        range: start..start + line.len(),
        indent,
        value: value.into(),
    }))
}

fn q_values(block: &str, key: &str, path: &Path) -> Result<Vec<String>, AdapterError> {
    let mut values = Vec::new();
    let mut remainder = block;
    while let Some(start) = remainder.find("q[") {
        let value = &remainder[start + 2..];
        let end = value.find(']').ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "CPAN {key} q[] value in {} is not terminated",
                path.display()
            ))
        })?;
        let value = &value[..end];
        if value.is_empty() || value.contains(['\n', '\r', '\\']) {
            return Err(AdapterError::Unsupported(format!(
                "CPAN {key} contains a non-literal value"
            )));
        }
        values.push(value.into());
        remainder = &remainder[start + 2 + end + 1..];
    }
    Ok(values)
}

fn rewrite_cpan_config(text: &str, path: &Path, selected: &str) -> Result<String, AdapterError> {
    let config = parse_cpan_config(text, path)?;
    let urls = replace_public_urls(&config.urls, selected);
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut urllist = String::new();
    if config.pushy.is_none() {
        urllist.push_str(&format!("{}'pushy_https' => q[0],{newline}", config.indent));
    }
    if config.randomize.is_none() {
        urllist.push_str(&format!(
            "{}'randomize_urllist' => q[0],{newline}",
            config.indent
        ));
    }
    urllist.push_str(&format!(
        "{}'urllist' => [{}],{newline}",
        config.indent,
        urls.iter()
            .map(|url| format!("q[{url}]"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut replacements = vec![(config.urllist_range, urllist)];
    if let Some(pushy) = config.pushy {
        replacements.push((
            pushy.range,
            format!("{}'pushy_https' => q[0],{newline}", pushy.indent),
        ));
    }
    if let Some(randomize) = config.randomize {
        replacements.push((
            randomize.range,
            format!("{}'randomize_urllist' => q[0],{newline}", randomize.indent),
        ));
    }
    replacements.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut output = text.to_owned();
    for (range, replacement) in replacements {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn replace_public_urls(urls: &[String], selected: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut inserted = false;
    for url in urls {
        if is_public_cpan(url) {
            if !inserted {
                output.push(selected.into());
                inserted = true;
            }
        } else {
            output.push(url.clone());
        }
    }
    if !inserted {
        output.push(selected.into());
    }
    output
}

fn parse_profile(text: &str, path: &Path, shell: ShellKind) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let managed = range
        .as_ref()
        .map(|range| managed_value(&text[range.clone()], path, shell))
        .transpose()?;
    let mut unmanaged = Vec::new();
    let mut dynamic = false;
    for (start, line) in line_spans(text) {
        if range.as_ref().is_some_and(|range| range.contains(&start)) {
            continue;
        }
        let active = line.trim();
        if active.is_empty() || active.starts_with('#') || !active.contains(CPANM_ENV) {
            continue;
        }
        match profile_assignment(active, shell)? {
            Some(value) => unmanaged.push(ProfileAssignment {
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
        .filter_map(|line| profile_assignment(line.trim(), shell).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed cpanm block in {} must assign PERL_CPANM_OPT exactly once",
            path.display()
        )));
    }
    Ok(values[0].into())
}

fn profile_assignment(line: &str, shell: ShellKind) -> Result<Option<&str>, AdapterError> {
    let raw = match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                return Ok(None);
            };
            if key.trim() != CPANM_ENV {
                return Ok(None);
            }
            value.trim()
        }
        ShellKind::Fish => {
            let Some(rest) = line.strip_prefix("set ") else {
                return Ok(None);
            };
            let Some((flags, rest)) = take_field(rest) else {
                return Ok(None);
            };
            let Some((key, value)) = take_field(rest) else {
                return Ok(None);
            };
            if key != CPANM_ENV {
                return Ok(None);
            }
            if !flags.contains('x') || value.trim().is_empty() {
                return Err(AdapterError::InvalidConfiguration(
                    "fish PERL_CPANM_OPT assignment is not one exported literal".into(),
                ));
            }
            value.trim()
        }
        ShellKind::WindowsRegistry => {
            return Err(AdapterError::InvalidConfiguration(
                "cpanm Windows registry is not a shell profile".into(),
            ));
        }
    };
    literal_value(raw).map(Some)
}

fn take_field(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let end = value.find(char::is_whitespace).unwrap_or(value.len());
    (end > 0).then(|| (&value[..end], &value[end..]))
}

fn literal_value(raw: &str) -> Result<&str, AdapterError> {
    let single = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    let value = if single || double {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.contains(['\n', '\r', '`', '$'])
        || (single && value.contains('\''))
        || (double && value.contains(['"', '\\']))
        || (!single
            && !double
            && raw
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '\'' | '"')))
    {
        return Err(AdapterError::InvalidConfiguration(
            "PERL_CPANM_OPT is not a literal shell value".into(),
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
            "cpanm managed markers in {} are missing, duplicated, or out of order",
            path.display()
        ))),
    }
}

fn rewrite_profile(
    text: &str,
    path: &Path,
    shell: ShellKind,
    selected: &str,
) -> Result<String, AdapterError> {
    let parsed = parse_profile(text, path, shell)?;
    if !parsed.safe() {
        return Err(AdapterError::Unsupported(
            "cpanm profile or resolver policy cannot be rewritten safely".into(),
        ));
    }
    let value = rewrite_cpanm_options(parsed.value().unwrap_or_default(), selected)?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(&value, newline, shell);
    if let Some(range) = managed_range(text, path)? {
        return Ok(format!(
            "{}{}{}",
            &text[..range.start],
            block,
            &text[range.end..]
        ));
    }
    if let Some(assignment) = parsed.unmanaged.first() {
        let mut output = text.to_owned();
        output.replace_range(assignment.range.clone(), &block);
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

fn render_managed(value: &str, newline: &str, shell: ShellKind) -> String {
    let assignment = match shell {
        ShellKind::Bash | ShellKind::Zsh => format!("export {CPANM_ENV}='{value}'"),
        ShellKind::Fish => format!("set -gx {CPANM_ENV} '{value}'"),
        ShellKind::WindowsRegistry => {
            unreachable!("cpanm Windows persistence does not render a shell block")
        }
    };
    format!("{MANAGED_BEGIN}{newline}{assignment}{newline}{MANAGED_END}{newline}")
}

fn parse_cpanm_options(value: &str) -> Result<CpanmOptions, AdapterError> {
    if value.contains(['\'', '\n', '\r', '\0']) {
        return Err(AdapterError::Unsupported(
            "PERL_CPANM_OPT contains quoting or control characters that cpanm cannot preserve"
                .into(),
        ));
    }
    let tokens = option_tokens(value);
    let mut groups = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        let paired = |kind: fn(Vec<String>, String) -> OptionGroup,
                      groups: &mut Vec<OptionGroup>,
                      index: &mut usize|
         -> Result<(), AdapterError> {
            let value = tokens.get(*index + 1).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "cpanm option {token} is missing its value"
                ))
            })?;
            groups.push(kind(vec![token.clone(), value.clone()], value.clone()));
            *index += 2;
            Ok(())
        };
        if token == "--mirror" {
            paired(
                |tokens, url| OptionGroup::Mirror { tokens, url },
                &mut groups,
                &mut index,
            )?;
        } else if let Some(url) = token.strip_prefix("--mirror=") {
            groups.push(OptionGroup::Mirror {
                tokens: vec![token.clone()],
                url: url.into(),
            });
            index += 1;
        } else if matches!(token.as_str(), "-M" | "--from") {
            paired(
                |tokens, url| OptionGroup::From { tokens, url },
                &mut groups,
                &mut index,
            )?;
        } else if let Some(url) = token.strip_prefix("--from=") {
            groups.push(OptionGroup::From {
                tokens: vec![token.clone()],
                url: url.into(),
            });
            index += 1;
        } else if token.starts_with("-M") && token.len() > 2 {
            groups.push(OptionGroup::From {
                tokens: vec![token.clone()],
                url: token[2..].into(),
            });
            index += 1;
        } else if token == "--mirror-only" {
            groups.push(OptionGroup::MirrorOnly(vec![token.clone()]));
            index += 1;
        } else if token == "--no-mirror-only" {
            groups.push(OptionGroup::NoMirrorOnly(vec![token.clone()]));
            index += 1;
        } else if matches!(
            token.as_str(),
            "--mirror-index" | "--cpanmetadb" | "--metacpan"
        ) || token.starts_with("--mirror-index=")
            || token.starts_with("--cpanmetadb=")
            || token == "--no-metacpan"
        {
            let mut group = vec![token.clone()];
            if matches!(token.as_str(), "--mirror-index" | "--cpanmetadb") {
                let value = tokens.get(index + 1).ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "cpanm option {token} is missing its value"
                    ))
                })?;
                group.push(value.clone());
                index += 1;
            }
            groups.push(OptionGroup::ResolverConflict(group));
            index += 1;
        } else {
            groups.push(OptionGroup::Other(vec![token.clone()]));
            index += 1;
        }
    }
    for group in &groups {
        match group {
            OptionGroup::Mirror { url, .. } | OptionGroup::From { url, .. } => {
                validate_cpan_url(url)?;
            }
            _ => {}
        }
    }
    Ok(CpanmOptions { groups })
}

fn rewrite_cpanm_options(value: &str, selected: &str) -> Result<String, AdapterError> {
    let options = parse_cpanm_options(value)?;
    if options
        .groups
        .iter()
        .any(|group| matches!(group, OptionGroup::ResolverConflict(_)))
    {
        return Err(AdapterError::Unsupported(
            "cpanm uses a custom index or metadata resolver".into(),
        ));
    }
    if options
        .groups
        .iter()
        .any(|group| matches!(group, OptionGroup::NoMirrorOnly(_)))
    {
        return Err(AdapterError::Unsupported(
            "cpanm explicitly disables mirror-only index resolution".into(),
        ));
    }
    let from = options
        .groups
        .iter()
        .filter(|group| matches!(group, OptionGroup::From { .. }))
        .count();
    let mirrors = options
        .groups
        .iter()
        .filter(|group| matches!(group, OptionGroup::Mirror { .. }))
        .count();
    if from > 1 || (from > 0 && mirrors > 0) {
        return Err(AdapterError::InvalidConfiguration(
            "cpanm resolver options are ambiguous".into(),
        ));
    }
    let mut output = Vec::new();
    if from == 1 {
        for group in options.groups {
            match group {
                OptionGroup::From { url, .. } => {
                    if !is_public_cpan(&url) {
                        return Err(AdapterError::Unsupported(
                            "cpanm uses an exclusive private --from resolver".into(),
                        ));
                    }
                    output.extend(["--from".into(), selected.into()]);
                }
                group => output.extend(group_tokens(group)),
            }
        }
    } else if mirrors > 0 {
        let has_mirror_only = options
            .groups
            .iter()
            .any(|group| matches!(group, OptionGroup::MirrorOnly(_)));
        let mut inserted = false;
        for group in options.groups {
            match group {
                OptionGroup::Mirror { url, .. } if is_public_cpan(&url) => {
                    if !inserted {
                        output.extend(["--mirror".into(), selected.into()]);
                        inserted = true;
                    }
                }
                group => output.extend(group_tokens(group)),
            }
        }
        if !inserted {
            output.extend(["--mirror".into(), selected.into()]);
        }
        if !has_mirror_only {
            output.push("--mirror-only".into());
        }
    } else {
        for group in options.groups {
            output.extend(group_tokens(group));
        }
        output.extend(["--from".into(), selected.into()]);
    }
    Ok(output.join(" "))
}

fn group_tokens(group: OptionGroup) -> Vec<String> {
    match group {
        OptionGroup::Mirror { tokens, .. }
        | OptionGroup::From { tokens, .. }
        | OptionGroup::MirrorOnly(tokens)
        | OptionGroup::NoMirrorOnly(tokens)
        | OptionGroup::ResolverConflict(tokens)
        | OptionGroup::Other(tokens) => tokens,
    }
}

fn option_tokens(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

fn canonical_cpanm_options(value: &str) -> bool {
    let Ok(options) = parse_cpanm_options(value) else {
        return false;
    };
    let Ok(endpoint) = unique_reviewed(&options.urls(), "cpanm Windows options") else {
        return false;
    };
    rewrite_cpanm_options(value, &endpoint)
        .is_ok_and(|rendered| option_tokens(&rendered) == option_tokens(value))
}

fn cpanm_environment_state(runtime: &dyn Runtime) -> &'static str {
    match runtime
        .environment_variable(CPANM_ENV)
        .filter(|value| !value.trim().is_empty())
    {
        None => "unset",
        Some(value) if rewrite_cpanm_options(&value, ALIYUN).is_ok() => "static",
        Some(_) => "custom or unsafe",
    }
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "cpan" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "CPAN clients require exactly one repository selection".into(),
        ));
    }
    let selection = matches[0];
    let mut urls = BTreeSet::new();
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
                "CPAN selection requires one HTTPS {role:?} endpoint"
            )));
        }
        urls.insert(normalized_http_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("CPAN {role:?} endpoint is unsafe"))
        })?);
    }
    if urls.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "CPAN index, metadata, and artifacts must share one mirror base".into(),
        ));
    }
    let endpoint = urls.into_iter().next().expect("one endpoint");
    let provider = reviewed_provider(&endpoint).ok_or_else(|| {
        AdapterError::InvalidConfiguration("CPAN endpoint is not reviewed".into())
    })?;
    if selection.provider_id != provider {
        return Err(AdapterError::InvalidConfiguration(
            "CPAN provider and endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn reviewed_provider(value: &str) -> Option<&'static str> {
    match normalized_http_base(value)?.as_str() {
        ALIYUN => Some("aliyun"),
        NJU => Some("nju"),
        TUNA => Some("tuna"),
        USTC => Some("ustc"),
        _ => None,
    }
}

fn is_reviewed_cpan(value: &str) -> bool {
    reviewed_provider(value).is_some()
}

fn is_public_cpan(value: &str) -> bool {
    if is_reviewed_cpan(value) {
        return true;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| {
            matches!(
                host.to_ascii_lowercase().as_str(),
                "cpan.org" | "www.cpan.org" | "cpan.metacpan.org"
            )
        })
        && matches!(url.path(), "" | "/")
}

fn unique_reviewed(urls: &[String], label: &str) -> Result<String, AdapterError> {
    let matches = urls
        .iter()
        .filter_map(|url| {
            is_reviewed_cpan(url)
                .then(|| normalized_http_base(url))
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::Verification(format!(
            "{label} does not contain exactly one reviewed public mirror"
        )));
    }
    Ok(matches.into_iter().next().expect("one reviewed endpoint"))
}

fn validate_cpan_url(value: &str) -> Result<(), AdapterError> {
    if value.starts_with('/') {
        return Ok(());
    }
    let url = reqwest::Url::parse(value).map_err(|_| {
        AdapterError::Unsupported("CPAN client contains an invalid mirror URL".into())
    })?;
    if !matches!(url.scheme(), "http" | "https" | "ftp" | "file")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AdapterError::Unsupported(
            "CPAN client contains an unsupported mirror URL".into(),
        ));
    }
    Ok(())
}

fn normalized_http_base(value: &str) -> Option<String> {
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

fn verify_cpan_pm(runtime: &dyn Runtime, home: &Path, root: &Path) -> Result<(), AdapterError> {
    let environment = BTreeMap::from([
        ("HOME".into(), path_text(home, "home")?.into()),
        ("PERL_MM_USE_DEFAULT".into(), "1".into()),
        (
            "MIRRORSWITCH_CPAN_VERIFY_ROOT".into(),
            path_text(root, "CPAN verification root")?.into(),
        ),
    ]);
    let output = run_isolated(
        runtime,
        None,
        "perl",
        &["-MCPAN".into(), "-e".into(), CPAN_QUERY_SCRIPT.into()],
        &environment,
        &[],
        "CPAN.pm Try::Tiny query",
    )?;
    if !output.contains(&format!("MIRRORSWITCH_CPAN_FILE={TRY_TINY_PATH}")) {
        return Err(AdapterError::Verification(
            "CPAN.pm did not resolve the pinned Try::Tiny distribution".into(),
        ));
    }
    Ok(())
}

fn verify_cpanm(
    runtime: &dyn Runtime,
    home: &Path,
    root: &Path,
    options: &str,
) -> Result<(), AdapterError> {
    let environment = BTreeMap::from([
        ("HOME".into(), path_text(home, "home")?.into()),
        (
            "PERL_CPANM_HOME".into(),
            path_text(&root.join("cpanm"), "cpanm verification home")?.into(),
        ),
        ("PERL_CPANM_OPT".into(), options.into()),
    ]);
    let output = run_isolated(
        runtime,
        None,
        "cpanm",
        &["--info".into(), "Try::Tiny".into()],
        &environment,
        &[],
        "cpanm Try::Tiny query",
    )?;
    if !output.contains("Try-Tiny-0.32.tar.gz") {
        return Err(AdapterError::Verification(
            "cpanm did not resolve the pinned Try::Tiny distribution".into(),
        ));
    }
    Ok(())
}

fn run_isolated(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    program: &str,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    removed_environment: &[String],
    label: &str,
) -> Result<String, AdapterError> {
    let output = match directory {
        Some(directory) => runtime.run_in_with_environment(
            directory,
            program,
            arguments,
            environment,
            removed_environment,
        ),
        None => runtime.run_with_environment(program, arguments, environment, removed_environment),
    }?;
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

fn has_actionable_client(current: &CurrentConfiguration) -> bool {
    current.documents.iter().any(|document| {
        document.format == "cpan-pm-user-config"
            || document.format.starts_with("cpanm-selected-")
            || document.format == "cpanm-windows-recovery"
    })
}

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<Option<&'a ConfigurationDocument>, AdapterError> {
    let matches = current
        .documents
        .iter()
        .filter(|document| document.format == format)
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "CPAN current configuration contains duplicate {format} documents"
        )));
    }
    Ok(matches.into_iter().next())
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

fn configured_source(value: &str, kind: &str, path: &Path, client: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
        url: normalized_http_base(value).unwrap_or_else(|| "<preserved>".into()),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("client".into(), vec![client.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn policy_source(kind: &str, path: &Path, client: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "<preserved>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("client".into(), vec![client.into()]),
            ("config_path".into(), vec![path.display().to_string()]),
        ]),
    }
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: "cpan-snapshot:<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
    }
}

fn shell_from_format(format: &str) -> Result<ShellKind, AdapterError> {
    [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish]
        .into_iter()
        .find(|shell| format == format!("cpanm-selected-{}-profile", shell.name()))
        .ok_or_else(|| AdapterError::InvalidConfiguration("unknown cpanm profile format".into()))
}

fn valid_version(value: &str) -> bool {
    value
        .trim_start_matches('v')
        .split(['.', '_'])
        .all(|part| !part.is_empty() && part.chars().all(|character| character.is_ascii_digit()))
}

fn without_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
}

fn verification_root(home: &Path) -> PathBuf {
    home.join(".mirrorswitch/verification/cpan")
}

fn validate_cpan_user_path(
    context: &SystemContext,
    runtime: &dyn Runtime,
    path: &Path,
    home: &Path,
    kind: &str,
) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if path.starts_with(home) && path != home {
        return Ok(());
    }
    if context.os == OperatingSystem::Windows {
        for variable in ["APPDATA", "LOCALAPPDATA"] {
            let Some(root) = runtime
                .environment_variable(variable)
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
            else {
                continue;
            };
            validate_path(&root, variable)?;
            if path.starts_with(&root) && path != root {
                return Ok(());
            }
        }
    }
    Err(AdapterError::Unsupported(format!(
        "CPAN {kind} {} is outside the selected user directories",
        path.display()
    )))
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "CPAN {kind} {} is outside the user home",
            path.display()
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "CPAN reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, kind: &str) -> Result<&'a str, AdapterError> {
    path.to_str()
        .ok_or_else(|| AdapterError::Unsupported(format!("CPAN {kind} path is not valid UTF-8")))
}

fn preserve_bom(original: &[u8], mut rendered: Vec<u8>) -> Vec<u8> {
    if original.starts_with(&[0xef, 0xbb, 0xbf]) {
        rendered.splice(..0, [0xef, 0xbb, 0xbf]);
    }
    rendered
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "CPAN configuration {} is not UTF-8",
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
