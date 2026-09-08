use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Component, Path, PathBuf},
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

const UPSTREAM: &str = "cran--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/CRAN";
const NJU: &str = "https://mirrors.nju.edu.cn/CRAN";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/CRAN";
const USTC: &str = "https://mirrors.ustc.edu.cn/CRAN";
const OFFICIAL: &[&str] = &[
    "https://cloud.r-project.org",
    "https://cran.r-project.org",
    "https://cran.rstudio.com",
];
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch CRAN mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch CRAN mirror <<<";
const VERIFY_MARKER: &str = "# Managed by MirrorSwitch: CRAN verification script v1";
const DIGEST_VERSION: &str = "0.6.39";
const DIGEST_SHA256: &str = "8bf048b49b2d17077138fae758bda56bbd53278d9437f2fdeaedf979c90a13c9";

const INSPECT_SCRIPT: &str = r#"
cat("R_VERSION\t", as.character(getRversion()), "\n", sep = "")
cat("R_PLATFORM\t", R.version$platform, "\n", sep = "")
cat("R_ARCH\t", Sys.getenv("R_ARCH", unset = ""), "\n", sep = "")
site_env <- Sys.getenv("R_PROFILE", unset = "")
site <- if (nzchar(site_env)) path.expand(site_env) else file.path(R.home("etc"), "Rprofile.site")
cat("SITE_PROFILE\t", site, "\t", if (file.exists(site)) "present" else "absent", "\n", sep = "")
cat("R_PROFILE_USER\t", Sys.getenv("R_PROFILE_USER", unset = ""), "\n", sep = "")
cat("R_REPOSITORIES\t", if (nzchar(Sys.getenv("R_REPOSITORIES", unset = ""))) "set" else "unset", "\n", sep = "")
repos <- getOption("repos")
repo_names <- names(repos)
if (is.null(repo_names)) repo_names <- rep("", length(repos))
for (index in seq_along(repos)) cat("REPOSITORY\t", index, "\t", repo_names[[index]], "\t", unname(repos[[index]]), "\n", sep = "")
"#;

#[derive(Clone, Copy, Debug, Default)]
pub struct CranAdapter;

impl Adapter for CranAdapter {
    fn key(&self) -> &'static str {
        "cran"
    }

    fn tool_id(&self) -> &'static str {
        "cran"
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
        if !runtime.command_exists("Rscript") {
            return Ok(None);
        }
        let digest_command = match context.os {
            OperatingSystem::Linux => "sha256sum",
            OperatingSystem::Macos => "shasum",
            OperatingSystem::Windows => "certutil.exe",
        };
        if !runtime.command_exists(digest_command) {
            return Err(AdapterError::Unsupported(format!(
                "CRAN verification requires native {digest_command}"
            )));
        }
        let snapshot = inspect_runtime(runtime)?;
        review_snapshot(&snapshot)?;
        review_platform(context, &snapshot)?;
        let layout = config_layout(context, runtime)?;
        let cran = effective_cran(&snapshot)?;
        Ok(Some(DetectedTool {
            tool_id: "cran".into(),
            executable: Some(PathBuf::from("Rscript")),
            version: Some(snapshot.r_version.clone()),
            evidence: vec![
                format!("R {}", snapshot.r_version),
                format!("R platform is {}", snapshot.platform),
                format!(
                    "R_ARCH is {}",
                    if snapshot.r_arch.is_empty() {
                        "unset"
                    } else {
                        &snapshot.r_arch
                    }
                ),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                format!(
                    "R reports {} effective repositories",
                    snapshot.repositories.len()
                ),
                format!(
                    "effective CRAN is {}",
                    cran.map_or("unset", |value| public_state(value))
                ),
                format!(
                    "site profile {} is {}",
                    snapshot.site_profile.display(),
                    snapshot.site_state
                ),
                format!(
                    "R_PROFILE_USER is {}",
                    if snapshot.profile_env.is_empty() {
                        "unset"
                    } else {
                        "set"
                    }
                ),
                format!("R_REPOSITORIES is {}", snapshot.repositories_env),
                format!("selected user profile is {}", layout.profile.display()),
                format!(
                    "RStudio CRAN mirror preference is {}",
                    rstudio_preference_state(runtime, &layout.rstudio_preferences)?
                ),
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
        if detected.tool_id != "cran" {
            return Err(AdapterError::InvalidConfiguration(
                "CRAN read received another tool's detection result".into(),
            ));
        }
        let snapshot = inspect_runtime(runtime)?;
        review_snapshot(&snapshot)?;
        review_platform(context, &snapshot)?;
        if detected.version.as_deref() != Some(snapshot.r_version.as_str()) {
            return Err(AdapterError::Conflict(
                "R version changed after CRAN detection".into(),
            ));
        }
        let layout = config_layout(context, runtime)?;
        let profile = runtime.read(&layout.profile)?;
        let profile_exists = profile.is_some();
        let profile = profile.unwrap_or_default();
        let parsed = parse_profile(utf8(&layout.profile, &profile)?, &layout.profile)?;
        let mut sources = profile_sources(&parsed, &layout.profile);
        sources.push(snapshot_source("r-version", &snapshot.r_version));
        sources.push(snapshot_source("r-platform", &snapshot.platform));
        sources.push(policy_source(
            if snapshot.site_state == "present" {
                "site-profile-present"
            } else {
                "site-profile-absent"
            },
            &snapshot.site_profile,
        ));
        for repository in &snapshot.repositories {
            sources.push(repository_source(repository));
        }
        if snapshot.repositories_env == "set" {
            sources.push(policy_source(
                "r-repositories-environment-preserved",
                Path::new(":env:"),
            ));
        }
        let cran = effective_cran(&snapshot)?;
        if cran.is_some_and(|value| !is_public(value)) {
            sources.push(policy_source(
                "private-effective-cran",
                Path::new(":runtime:"),
            ));
        }
        if let Some(managed) = &parsed.managed
            && cran.is_none_or(|value| !same_base(value, managed))
        {
            sources.push(policy_source(
                "effective-cran-override",
                Path::new(":runtime:"),
            ));
        }
        if project_profile_precedes_user(runtime, &layout)? {
            sources.push(policy_source(
                "project-profile-precedence",
                &runtime.project_dir().expect("checked project directory"),
            ));
        }

        let mut files = profile_exists
            .then_some(layout.profile.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let mut documents = vec![ConfigurationDocument {
            path: layout.profile.clone(),
            format: "cran-user-rprofile".into(),
            contents: profile,
        }];
        add_observed_file(
            runtime,
            &layout.rstudio_preferences,
            "cran-rstudio-preferences-observed",
            "rstudio-preferences-preserved",
            &mut files,
            &mut sources,
            &mut documents,
        )?;
        if let Some(project) = runtime.project_dir() {
            validate_path(&project, "project")?;
            add_observed_file(
                runtime,
                &project.join(".Rprofile"),
                "cran-project-rprofile-observed",
                "project-rprofile-preserved",
                &mut files,
                &mut sources,
                &mut documents,
            )?;
            add_observed_file(
                runtime,
                &project.join("renv.lock"),
                "cran-project-renv-lock-observed",
                "renv-lock-preserved",
                &mut files,
                &mut sources,
                &mut documents,
            )?;
        }
        let script = runtime.read(&layout.verification_script)?;
        let script_exists = script.is_some();
        let script = script.unwrap_or_default();
        if script_exists {
            files.push(layout.verification_script.clone());
            if utf8(&layout.verification_script, &script)? != render_verification_script() {
                sources.push(policy_source(
                    "verification-conflict",
                    &layout.verification_script,
                ));
            }
        }
        documents.push(ConfigurationDocument {
            path: layout.verification_script,
            format: "cran-verification-script".into(),
            contents: script,
        });

        Ok(CurrentConfiguration {
            tool_id: "cran".into(),
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
        review_r_version(
            detected
                .version
                .as_deref()
                .ok_or_else(|| AdapterError::InvalidConfiguration("R version is missing".into()))?,
        )?;
        Ok(SelectionRequest {
            tool_id: "cran".into(),
            adapter_key: "cran".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(
                UPSTREAM.into(),
                vec![cran_probe_context(
                    context,
                    detected.version.as_deref().unwrap_or_default(),
                )?],
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
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let profile = find_document(current, "cran-user-rprofile")?;
        let script = find_document(current, "cran-verification-script")?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            profile,
            preserve_bom(
                &profile.contents,
                rewrite_profile(
                    utf8(&profile.path, &profile.contents)?,
                    &profile.path,
                    &endpoint,
                )?
                .into_bytes(),
            ),
            "add or retarget one CRAN entry while preserving named R repositories and profile policy",
            &mut changes,
        );
        add_change(
            context,
            current,
            script,
            render_verification_script().into_bytes(),
            "create an isolated platform-specific CRAN repository verification script",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "cran".into(),
            tool_id: "cran".into(),
            scope: ConfigurationScope::User,
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
            let layout = config_layout(context, runtime)?;
            let known = [
                rooted(&context.root, &layout.profile),
                rooted(&context.root, &layout.verification_script),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "CRAN transaction receipt contains no known target".into(),
                ));
            }
            let profile = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("CRAN user profile disappeared".into())
            })?;
            let parsed = parse_profile(utf8(&layout.profile, &profile)?, &layout.profile)?;
            let endpoint = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed CRAN mirror is missing".into())
            })?;
            if !is_reviewed(&endpoint) {
                return Err(AdapterError::Verification(
                    "managed CRAN mirror is not reviewed".into(),
                ));
            }
            let script = runtime.read(&layout.verification_script)?.ok_or_else(|| {
                AdapterError::Verification("CRAN verification script disappeared".into())
            })?;
            if utf8(&layout.verification_script, &script)? != render_verification_script() {
                return Err(AdapterError::Verification(
                    "CRAN verification script is not canonical".into(),
                ));
            }
            let snapshot = inspect_runtime(runtime)?;
            review_snapshot(&snapshot)?;
            review_platform(context, &snapshot)?;
            let fixture = cran_fixture(context, &snapshot.r_version)?;
            let output = run_verification(runtime, &layout, &endpoint, fixture.package_type)?;
            validate_verification_output(context, runtime, &layout, &output, &endpoint, &fixture)?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "R resolved digest {DIGEST_VERSION} {} metadata and archive through {endpoint}",
                    fixture.package_type
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
                "restored {} CRAN configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug)]
struct Layout {
    profile: PathBuf,
    rstudio_preferences: PathBuf,
    verification_root: PathBuf,
    verification_script: PathBuf,
    verification_library: PathBuf,
    verification_downloads: PathBuf,
}

#[derive(Debug)]
struct Snapshot {
    r_version: String,
    platform: String,
    r_arch: String,
    site_profile: PathBuf,
    site_state: String,
    profile_env: String,
    repositories_env: String,
    repositories: Vec<Repository>,
}

#[derive(Debug)]
struct Repository {
    index: usize,
    name: String,
    url: String,
}

#[derive(Debug)]
struct ParsedProfile {
    managed: Option<String>,
}

struct CranFixture {
    package_type: &'static str,
    index_path: &'static str,
    archive_path: &'static str,
    archive_sha256: &'static str,
}

fn cran_fixture(context: &SystemContext, r_version: &str) -> Result<CranFixture, AdapterError> {
    if context.os != OperatingSystem::Linux && !r_version.starts_with("4.6.") {
        return Err(AdapterError::Unsupported(format!(
            "R {r_version} has no reviewed macOS/Windows 4.6 binary fixture"
        )));
    }
    Ok(match (context.os, context.architecture) {
        (OperatingSystem::Linux, _) => CranFixture {
            package_type: "source",
            index_path: "src/contrib/PACKAGES.gz",
            archive_path: "src/contrib/digest_0.6.39.tar.gz",
            archive_sha256: DIGEST_SHA256,
        },
        (OperatingSystem::Macos, Architecture::X86_64) => CranFixture {
            package_type: "binary",
            index_path: "bin/macosx/big-sur-x86_64/contrib/4.6/PACKAGES.gz",
            archive_path: "bin/macosx/big-sur-x86_64/contrib/4.6/digest_0.6.39.tgz",
            archive_sha256: "302eafa4c89452ad1a5975624b66fa473cb0ac55c61e59f15556a21e00713956",
        },
        (OperatingSystem::Macos, Architecture::Arm64) => CranFixture {
            package_type: "binary",
            index_path: "bin/macosx/sonoma-arm64/contrib/4.6/PACKAGES.gz",
            archive_path: "bin/macosx/sonoma-arm64/contrib/4.6/digest_0.6.39.tgz",
            archive_sha256: "3a2a694c9d1ab8abf7829af29c851b5c82238e2f032b7d6c34a7c85a00c6a698",
        },
        (OperatingSystem::Windows, Architecture::X86_64) => CranFixture {
            package_type: "binary",
            index_path: "bin/windows/contrib/4.6/PACKAGES.gz",
            archive_path: "bin/windows/contrib/4.6/digest_0.6.39.zip",
            archive_sha256: "87fb005dbe912caeab037ae0da169a614a2392673a518302b125537ef2bc36e0",
        },
        (OperatingSystem::Windows, Architecture::Arm64) => {
            unreachable!("Windows arm64 is rejected before CRAN fixture selection")
        }
    })
}

fn cran_probe_context(
    context: &SystemContext,
    r_version: &str,
) -> Result<BTreeMap<String, String>, AdapterError> {
    let fixture = cran_fixture(context, r_version)?;
    Ok(BTreeMap::from([
        ("cran_index_path".into(), fixture.index_path.into()),
        ("cran_archive_path".into(), fixture.archive_path.into()),
        ("cran_archive_sha".into(), fixture.archive_sha256.into()),
    ]))
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "CRAN on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "CRAN on Windows arm64 is unavailable because R has no reviewed native Windows arm64 runtime"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "CRAN requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "CRAN adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "cran" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "CRAN operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("CRAN requires a user home".into()))?;
    validate_path(&home, "home")?;
    let profile = match runtime
        .environment_variable("R_PROFILE_USER")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => {
            if value == "/dev/null" {
                return Err(AdapterError::Unsupported(
                    "R_PROFILE_USER=/dev/null disables persistent CRAN configuration".into(),
                ));
            }
            let path = expand_user_path(&value, &home)?;
            validate_user_path(&path, &home, "R_PROFILE_USER")?;
            path
        }
        None => home.join(".Rprofile"),
    };
    let configured_rstudio = runtime
        .environment_variable("RSTUDIO_CONFIG_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let rstudio_root = configured_rstudio.unwrap_or_else(|| match context.os {
        OperatingSystem::Windows => runtime
            .environment_variable("APPDATA")
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Roaming"))
            .join("RStudio"),
        OperatingSystem::Linux | OperatingSystem::Macos => runtime
            .environment_variable("XDG_CONFIG_HOME")
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("rstudio"),
    });
    validate_path(&rstudio_root, "RStudio config directory")?;
    let verification_root = home.join(".mirrorswitch/verification/cran");
    Ok(Layout {
        profile,
        rstudio_preferences: rstudio_root.join("rstudio-prefs.json"),
        verification_script: verification_root.join("verify.R"),
        verification_library: verification_root.join("library"),
        verification_downloads: verification_root.join("downloads"),
        verification_root,
    })
}

fn expand_user_path(value: &str, home: &Path) -> Result<PathBuf, AdapterError> {
    if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        if relative.is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "R_PROFILE_USER does not identify a file".into(),
            ));
        }
        Ok(home.join(relative))
    } else {
        Ok(PathBuf::from(value))
    }
}

fn project_profile_precedes_user(
    runtime: &dyn Runtime,
    layout: &Layout,
) -> Result<bool, AdapterError> {
    if runtime
        .environment_variable("R_PROFILE_USER")
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Ok(false);
    }
    let Some(project) = runtime.project_dir() else {
        return Ok(false);
    };
    validate_path(&project, "project")?;
    let profile = project.join(".Rprofile");
    if profile == layout.profile {
        return Ok(false);
    }
    Ok(runtime.read(&profile)?.is_some())
}

fn rstudio_preference_state(
    runtime: &dyn Runtime,
    path: &Path,
) -> Result<&'static str, AdapterError> {
    let Some(contents) = runtime.read(path)? else {
        return Ok("absent");
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&contents) else {
        return Ok("unreadable and preserved");
    };
    Ok(
        if value
            .pointer("/cran_mirror/url")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            "present and preserved"
        } else {
            "unset in preserved preferences"
        },
    )
}

fn inspect_runtime(runtime: &dyn Runtime) -> Result<Snapshot, AdapterError> {
    #[cfg(windows)]
    let script = INSPECT_SCRIPT
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(";");
    #[cfg(not(windows))]
    let script = INSPECT_SCRIPT.to_owned();
    let arguments = vec!["-e".into(), script];
    let output = match runtime.project_dir() {
        Some(directory) => {
            validate_path(&directory, "project")?;
            runtime.run_in(&directory, "Rscript", &arguments)?
        }
        None => runtime.run("Rscript", &arguments)?,
    };
    parse_snapshot(&command_output(output, "R CRAN inspection")?)
}

fn parse_snapshot(output: &str) -> Result<Snapshot, AdapterError> {
    let mut scalars = BTreeMap::new();
    let mut repositories = Vec::new();
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            ["REPOSITORY", index, name, url] => {
                let index = index.parse::<usize>().map_err(|_| {
                    AdapterError::Unsupported("R reported an invalid repository index".into())
                })?;
                if url.is_empty() || url.contains(['\n', '\r']) {
                    return Err(AdapterError::Unsupported(
                        "R reported an invalid repository URL".into(),
                    ));
                }
                repositories.push(Repository {
                    index,
                    name: (*name).into(),
                    url: (*url).into(),
                });
            }
            [key, value] if !key.is_empty() => {
                insert_snapshot_scalar(&mut scalars, key, value)?;
            }
            ["SITE_PROFILE", path, state] => {
                insert_snapshot_scalar(&mut scalars, "SITE_PROFILE", path)?;
                insert_snapshot_scalar(&mut scalars, "SITE_PROFILE_STATE", state)?;
            }
            _ => {}
        }
    }
    repositories.sort_by_key(|repository| repository.index);
    if repositories
        .iter()
        .enumerate()
        .any(|(offset, repository)| repository.index != offset + 1)
    {
        return Err(AdapterError::Unsupported(
            "R repository order is incomplete or duplicated".into(),
        ));
    }
    let field = |key| {
        scalars
            .get(key)
            .map(|value| (*value).to_owned())
            .ok_or_else(|| AdapterError::Unsupported(format!("R did not report {key}")))
    };
    Ok(Snapshot {
        r_version: field("R_VERSION")?,
        platform: field("R_PLATFORM")?,
        r_arch: field("R_ARCH")?,
        site_profile: PathBuf::from(field("SITE_PROFILE")?),
        site_state: field("SITE_PROFILE_STATE")?,
        profile_env: field("R_PROFILE_USER")?,
        repositories_env: field("R_REPOSITORIES")?,
        repositories,
    })
}

fn insert_snapshot_scalar<'a>(
    scalars: &mut BTreeMap<&'a str, &'a str>,
    key: &'a str,
    value: &'a str,
) -> Result<(), AdapterError> {
    if scalars.insert(key, value).is_some() {
        return Err(AdapterError::Unsupported(format!(
            "R CRAN inspection duplicated {key}"
        )));
    }
    Ok(())
}

fn review_snapshot(snapshot: &Snapshot) -> Result<(), AdapterError> {
    review_r_version(&snapshot.r_version)?;
    if snapshot.platform.trim().is_empty() {
        return Err(AdapterError::Unsupported(
            "R did not report its platform".into(),
        ));
    }
    validate_path(&snapshot.site_profile, "site profile")?;
    if !matches!(snapshot.site_state.as_str(), "present" | "absent")
        || !matches!(snapshot.repositories_env.as_str(), "set" | "unset")
    {
        return Err(AdapterError::Unsupported(
            "R startup source state is unrecognized".into(),
        ));
    }
    effective_cran(snapshot)?;
    Ok(())
}

fn review_platform(context: &SystemContext, snapshot: &Snapshot) -> Result<(), AdapterError> {
    let platform = snapshot.platform.to_ascii_lowercase();
    let os_matches = match context.os {
        OperatingSystem::Linux => platform.contains("linux"),
        OperatingSystem::Macos => platform.contains("darwin") || platform.contains("apple"),
        OperatingSystem::Windows => platform.contains("mingw") || platform.contains("windows"),
    };
    let architecture_matches = match context.architecture {
        Architecture::X86_64 => platform.contains("x86_64") || snapshot.r_arch == "/x64",
        Architecture::Arm64 => platform.contains("aarch64") || platform.contains("arm64"),
    };
    if !os_matches || !architecture_matches {
        return Err(AdapterError::Unsupported(format!(
            "R platform {} and R_ARCH {} do not match {:?} {:?}",
            snapshot.platform, snapshot.r_arch, context.os, context.architecture
        )));
    }
    Ok(())
}

fn review_r_version(value: &str) -> Result<(), AdapterError> {
    let version = numeric_version(value)?;
    if version.first().copied().unwrap_or_default() < 3
        || (version.first() == Some(&3) && version.get(1).copied().unwrap_or_default() < 3)
    {
        return Err(AdapterError::Unsupported(format!(
            "R {value} is older than the reviewed R 3.3+ CRAN source model"
        )));
    }
    Ok(())
}

fn numeric_version(value: &str) -> Result<Vec<u64>, AdapterError> {
    let parts = value
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterError::Unsupported(format!("R version {value} is unrecognized")))?;
    if parts.len() < 2 {
        return Err(AdapterError::Unsupported(format!(
            "R version {value} is incomplete"
        )));
    }
    Ok(parts)
}

fn effective_cran(snapshot: &Snapshot) -> Result<Option<&str>, AdapterError> {
    let cran = snapshot
        .repositories
        .iter()
        .filter(|repository| repository.name == "CRAN")
        .collect::<Vec<_>>();
    if cran.len() > 1 {
        return Err(AdapterError::Unsupported(
            "R reports more than one repository named CRAN".into(),
        ));
    }
    Ok(cran.first().map(|repository| repository.url.as_str()))
}

fn parse_profile(text: &str, path: &Path) -> Result<ParsedProfile, AdapterError> {
    let range = managed_range(text, path)?;
    let managed = range
        .as_ref()
        .map(|range| managed_value(&text[range.clone()], path))
        .transpose()?;
    Ok(ParsedProfile { managed })
}

fn managed_value(block: &str, path: &Path) -> Result<String, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let value = line
                .strip_prefix("repos[\"CRAN\"] <- ")
                .or_else(|| line.strip_prefix("repos['CRAN'] <- "))?;
            Some(literal_value(value.trim()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed CRAN block in {} must assign repos[CRAN] exactly once",
            path.display()
        )));
    }
    if !is_reviewed(values[0]) {
        return Err(AdapterError::Unsupported(
            "managed CRAN block is bound to an unreviewed endpoint".into(),
        ));
    }
    Ok(values[0].into())
}

fn literal_value(raw: &str) -> Result<&str, AdapterError> {
    let single = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    if !single && !double {
        return Err(AdapterError::InvalidConfiguration(
            "CRAN assignment is not a quoted literal".into(),
        ));
    }
    let value = &raw[1..raw.len() - 1];
    if value.is_empty()
        || value.contains([';', '`', '$', '\n', '\r', ','])
        || (single && value.contains('\''))
        || (double && value.contains('"'))
    {
        return Err(AdapterError::InvalidConfiguration(
            "CRAN assignment is not a safe literal".into(),
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
            "CRAN managed markers in {} are missing, duplicated, or out of order",
            path.display()
        ))),
    }
}

fn rewrite_profile(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    parse_profile(text, path)?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_managed(endpoint, newline);
    if let Some(range) = managed_range(text, path)? {
        return Ok(format!(
            "{}{}{}",
            &text[..range.start],
            block,
            &text[range.end..]
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

fn render_managed(endpoint: &str, newline: &str) -> String {
    [
        MANAGED_BEGIN.to_owned(),
        "local({".into(),
        "    repos <- getOption(\"repos\")".into(),
        format!("    repos[\"CRAN\"] <- \"{endpoint}\""),
        "    options(repos = repos)".into(),
        "})".into(),
        MANAGED_END.into(),
        String::new(),
    ]
    .join(newline)
}

fn render_verification_script() -> String {
    format!(
        r#"{VERIFY_MARKER}
args <- commandArgs(trailingOnly = TRUE)
stopifnot(length(args) == 2L)
endpoint <- sub("/+$", "", args[[1L]])
package_type <- args[[2L]]
stopifnot(package_type %in% c("source", "binary"))
repos <- getOption("repos")
stopifnot(sum(names(repos) == "CRAN") == 1L)
stopifnot(sub("/+$", "", unname(repos[["CRAN"]])) == endpoint)
available <- available.packages(contriburl = contrib.url(endpoint, type = package_type), filters = list())
stopifnot("digest" %in% rownames(available), available["digest", "Version"] == "{DIGEST_VERSION}")
downloads <- file.path(getwd(), "downloads")
unlink(downloads, recursive = TRUE, force = TRUE)
dir.create(downloads, recursive = TRUE, showWarnings = FALSE)
archive <- download.packages("digest", destdir = downloads, repos = endpoint, type = package_type, quiet = TRUE)
stopifnot(nrow(archive) == 1L, file.exists(archive[1L, 2L]))
cat("CRAN\t", endpoint, "\n", sep = "")
cat("PACKAGE\tdigest\t{DIGEST_VERSION}\t", package_type, "\n", sep = "")
"#
    )
}

fn run_verification(
    runtime: &dyn Runtime,
    layout: &Layout,
    endpoint: &str,
    package_type: &str,
) -> Result<String, AdapterError> {
    let profile = path_text(&layout.profile, "R profile")?;
    let library = path_text(&layout.verification_library, "verification library")?;
    let script = path_text(&layout.verification_script, "verification script")?;
    let environment = BTreeMap::from([
        ("R_PROFILE_USER".into(), profile.into()),
        (
            "R_PROFILE".into(),
            path_text(
                &layout.verification_root.join("disabled.Rprofile"),
                "R site profile",
            )?
            .into(),
        ),
        (
            "R_ENVIRON_USER".into(),
            path_text(
                &layout.verification_root.join("disabled.Renviron"),
                "R environ",
            )?
            .into(),
        ),
        ("R_LIBS_USER".into(), library.into()),
        (
            "R_HISTFILE".into(),
            path_text(&layout.verification_root.join("history"), "R history")?.into(),
        ),
    ]);
    let arguments = vec![script.into(), endpoint.into(), package_type.into()];
    let output = runtime.run_in_with_environment(
        &layout.verification_root,
        "Rscript",
        &arguments,
        &environment,
        &["R_REPOSITORIES".into()],
    )?;
    command_output(output, "CRAN source repository verification")
}

fn validate_verification_output(
    context: &SystemContext,
    runtime: &dyn Runtime,
    layout: &Layout,
    output: &str,
    endpoint: &str,
    fixture: &CranFixture,
) -> Result<(), AdapterError> {
    let required = [
        format!("CRAN\t{endpoint}"),
        format!(
            "PACKAGE\tdigest\t{DIGEST_VERSION}\t{}",
            fixture.package_type
        ),
    ];
    for evidence in required {
        if !output.lines().any(|line| line == evidence) {
            return Err(AdapterError::Verification(format!(
                "CRAN verification did not report {evidence}"
            )));
        }
    }
    let archives = runtime.list_files(&layout.verification_downloads)?;
    if archives.len() != 1 {
        return Err(AdapterError::Verification(
            "CRAN verification did not produce exactly one package archive".into(),
        ));
    }
    let archive = path_text(&archives[0], "verification archive")?;
    let (program, arguments) = match context.os {
        OperatingSystem::Linux => ("sha256sum", vec![archive.into()]),
        OperatingSystem::Macos => ("shasum", vec!["-a".into(), "256".into(), archive.into()]),
        OperatingSystem::Windows => (
            "certutil.exe",
            vec!["-hashfile".into(), archive.into(), "SHA256".into()],
        ),
    };
    let output = command_output(
        runtime.run(program, &arguments)?,
        "CRAN package archive digest verification",
    )?;
    let digest = output
        .split_whitespace()
        .find(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            AdapterError::Verification("CRAN digest command returned no SHA-256".into())
        })?;
    if digest != fixture.archive_sha256 {
        return Err(AdapterError::Verification(
            "CRAN verification archive SHA-256 does not match the platform fixture".into(),
        ));
    }
    Ok(())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| selection.tool_id == "cran" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "CRAN requires exactly one registry selection".into(),
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
                "CRAN selection requires one HTTPS {role:?} endpoint"
            )));
        }
        bases.insert(normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("CRAN {role:?} endpoint is unsafe"))
        })?);
    }
    if bases.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "CRAN index, metadata, and artifact endpoints must share one mirror base".into(),
        ));
    }
    let endpoint = bases.into_iter().next().expect("one endpoint");
    let provider = reviewed_provider(&endpoint).ok_or_else(|| {
        AdapterError::InvalidConfiguration("CRAN endpoint is not reviewed".into())
    })?;
    if selection.provider_id != provider {
        return Err(AdapterError::InvalidConfiguration(
            "CRAN provider and endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn reviewed_provider(value: &str) -> Option<&'static str> {
    match normalized_base(value)?.as_str() {
        ALIYUN => Some("aliyun"),
        NJU => Some("nju"),
        TUNA => Some("tuna"),
        USTC => Some("ustc"),
        _ => None,
    }
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

fn is_reviewed(value: &str) -> bool {
    reviewed_provider(value).is_some()
}

fn is_official(value: &str) -> bool {
    value == "@CRAN@"
        || normalized_base(value).is_some_and(|value| OFFICIAL.contains(&value.as_str()))
}

fn is_public(value: &str) -> bool {
    is_reviewed(value) || is_official(value)
}

fn same_base(left: &str, right: &str) -> bool {
    if left == "@CRAN@" || right == "@CRAN@" {
        return left == right;
    }
    normalized_base(left).is_some_and(|left| normalized_base(right).as_deref() == Some(&left))
}

fn public_state(value: &str) -> &'static str {
    if is_public(value) { "public" } else { "custom" }
}

fn profile_sources(parsed: &ParsedProfile, path: &Path) -> Vec<ConfiguredSource> {
    parsed
        .managed
        .as_deref()
        .map(|value| configured_source(value, "managed-rprofile", path))
        .into_iter()
        .collect()
}

fn repository_source(repository: &Repository) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: if is_public(&repository.url) {
            repository.url.clone()
        } else {
            "<preserved>".into()
        },
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["effective-repository-preserved".into()]),
            ("name".into(), vec![repository.name.clone()]),
            ("position".into(), vec![repository.index.to_string()]),
        ]),
    }
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-effective-cran" => {
                return Err(AdapterError::Unsupported(
                    "effective CRAN points to a private, authenticated, or unreviewed repository"
                        .into(),
                ));
            }
            "effective-cran-override" => {
                return Err(AdapterError::Unsupported(
                    "effective CRAN is not represented by the managed user profile".into(),
                ));
            }
            "project-profile-precedence" => {
                return Err(AdapterError::Unsupported(
                    "the current project .Rprofile takes precedence over the user profile".into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "CRAN verification target contains data not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn add_observed_file(
    runtime: &dyn Runtime,
    path: &Path,
    format: &str,
    kind: &str,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let Some(contents) = runtime.read(path)? else {
        return Ok(());
    };
    files.push(path.to_path_buf());
    sources.push(policy_source(kind, path));
    documents.push(ConfigurationDocument {
        path: path.to_path_buf(),
        format: format.into(),
        contents,
    });
    Ok(())
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
            "CRAN current configuration must contain exactly one {format} document"
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

fn configured_source(value: &str, kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(UPSTREAM.into()),
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
        url: "cran-snapshot:<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("CRAN source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "CRAN source has ambiguous {key} metadata"
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

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "CRAN {kind} {} is outside the user home",
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
            "CRAN reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, kind: &str) -> Result<&'a str, AdapterError> {
    path.to_str()
        .ok_or_else(|| AdapterError::Verification(format!("CRAN {kind} path is not UTF-8")))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "CRAN configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn preserve_bom(original: &[u8], mut rendered: Vec<u8>) -> Vec<u8> {
    if original.starts_with(&[0xef, 0xbb, 0xbf]) {
        rendered.splice(..0, [0xef, 0xbb, 0xbf]);
    }
    rendered
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
