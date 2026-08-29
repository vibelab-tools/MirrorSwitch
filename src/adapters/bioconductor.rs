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

const UPSTREAM: &str = "bioconductor--language-registry";
const BIOC_VERSION: &str = "3.23";
const NJU: &str = "https://mirrors.nju.edu.cn/bioconductor";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/bioconductor";
const REVIEWED_MIRRORS: &[&str] = &[NJU, TUNA];
const OFFICIAL_MIRRORS: &[&str] = &["https://bioconductor.org", "https://www.bioconductor.org"];
const MANAGED_BEGIN: &str = "# >>> MirrorSwitch Bioconductor mirror >>>";
const MANAGED_END: &str = "# <<< MirrorSwitch Bioconductor mirror <<<";
const VERIFY_MARKER: &str = "# Managed by MirrorSwitch: Bioconductor verification script v1";
const BIOC_VERSION_SHA: &str = "7a9fdd2f50e69facc752a8d8aede12cdc872d1fb59fea2355f3b499ace6864f4";
const ANNOTATION_SHA: &str = "7bb5a06b5a8c0c2024f317ed0c58b048550ba9ed6cc64266c4afc03a24ec7d6b";
const EXPERIMENT_SHA: &str = "d61d9759ccb6d48798484a178e8bbc3c02c4bcd70e0c9cfb11b0354566aa3654";

const INSPECT_SCRIPT: &str = r#"
if (!requireNamespace("BiocManager", quietly = TRUE)) quit(status = 42L)
cat("R_VERSION\t", as.character(getRversion()), "\n", sep = "")
cat("BIOCMANAGER_VERSION\t", as.character(packageVersion("BiocManager")), "\n", sep = "")
cat("BIOC_VERSION\t", as.character(BiocManager::version()), "\n", sep = "")
mirror <- getOption("BioC_mirror", "https://bioconductor.org")
cat("BIOC_MIRROR\t", as.character(mirror[[1L]]), "\n", sep = "")
repos <- suppressWarnings(BiocManager::repositories())
for (index in seq_along(repos))
    cat("REPOSITORY\t", names(repos)[[index]], "\t", unname(repos[[index]]), "\n", sep = "")
"#;

#[derive(Clone, Copy, Debug, Default)]
pub struct BioconductorAdapter;

impl Adapter for BioconductorAdapter {
    fn key(&self) -> &'static str {
        "bioconductor"
    }

    fn tool_id(&self) -> &'static str {
        "bioconductor"
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
        require_linux(context)?;
        if !runtime.command_exists("Rscript") {
            return Ok(None);
        }
        for command in ["env", "sha256sum"] {
            if !runtime.command_exists(command) {
                return Err(AdapterError::Unsupported(format!(
                    "Bioconductor verification requires {command}"
                )));
            }
        }
        let snapshot = inspect_runtime(runtime)?;
        review_snapshot(&snapshot)?;
        let layout = config_layout(runtime)?;
        Ok(Some(DetectedTool {
            tool_id: "bioconductor".into(),
            executable: Some(PathBuf::from("Rscript")),
            version: Some(snapshot.biocmanager_version.clone()),
            evidence: vec![
                format!("R {}", snapshot.r_version),
                format!("BiocManager {}", snapshot.biocmanager_version),
                format!("Bioconductor {}", snapshot.bioc_version),
                format!(
                    "effective BioC_mirror is {}",
                    public_state(&snapshot.mirror)
                ),
                format!(
                    "BiocManager reports {} repositories",
                    snapshot.repositories.len()
                ),
                format!("selected user profile is {}", layout.profile.display()),
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
        if detected.tool_id != "bioconductor" {
            return Err(AdapterError::InvalidConfiguration(
                "Bioconductor read received another tool's detection result".into(),
            ));
        }
        let snapshot = inspect_runtime(runtime)?;
        review_snapshot(&snapshot)?;
        if detected.version.as_deref() != Some(snapshot.biocmanager_version.as_str()) {
            return Err(AdapterError::Conflict(
                "BiocManager version changed after detection".into(),
            ));
        }
        let layout = config_layout(runtime)?;
        let profile_contents = runtime.read(&layout.profile)?;
        let profile_exists = profile_contents.is_some();
        let profile_contents = profile_contents.unwrap_or_default();
        let profile_text = utf8(&layout.profile, &profile_contents)?;
        let parsed = parse_profile(profile_text, &layout.profile)?;
        let mut sources = profile_sources(&parsed, &layout.profile);
        sources.push(snapshot_source("r-version", &snapshot.r_version));
        sources.push(snapshot_source(
            "biocmanager-version",
            &snapshot.biocmanager_version,
        ));
        sources.push(snapshot_source(
            "bioconductor-version",
            &snapshot.bioc_version,
        ));
        for (name, url) in &snapshot.repositories {
            sources.push(repository_source(name, url));
        }
        let represented = parsed
            .managed
            .as_deref()
            .into_iter()
            .chain(parsed.unmanaged.iter().map(|item| item.value.as_str()))
            .any(|value| same_base(value, &snapshot.mirror));
        if !represented && !is_official(&snapshot.mirror) {
            sources.push(policy_source(
                "effective-mirror-override",
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
            format: "bioconductor-user-rprofile".into(),
            contents: profile_contents,
        }];
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
            format: "bioconductor-verification-script".into(),
            contents: script,
        });
        Ok(CurrentConfiguration {
            tool_id: "bioconductor".into(),
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
        review_biocmanager_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("BiocManager version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "bioconductor".into(),
            adapter_key: "bioconductor".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::from([(UPSTREAM.into(), BIOC_VERSION.into())]),
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let endpoint = selected_endpoint(selections)?;
        let profile = find_document(current, "bioconductor-user-rprofile")?;
        let profile_text = utf8(&profile.path, &profile.contents)?;
        let rendered = rewrite_profile(profile_text, &profile.path, &endpoint)?.into_bytes();
        let script = find_document(current, "bioconductor-verification-script")?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            profile,
            rendered,
            "add or retarget one managed BioC_mirror option while preserving CRAN and private repositories",
            &mut changes,
        );
        add_change(
            context,
            current,
            script,
            render_verification_script().into_bytes(),
            "create an isolated Bioconductor repository verification script",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "bioconductor".into(),
            tool_id: "bioconductor".into(),
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
            let layout = config_layout(runtime)?;
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
                    "Bioconductor transaction receipt contains no known target".into(),
                ));
            }
            let profile = runtime.read(&layout.profile)?.ok_or_else(|| {
                AdapterError::Verification("Bioconductor user profile disappeared".into())
            })?;
            let parsed = parse_profile(utf8(&layout.profile, &profile)?, &layout.profile)?;
            if parsed.dynamic || !parsed.unmanaged.is_empty() {
                return Err(AdapterError::Verification(
                    "R profile gained conflicting BioC_mirror policy".into(),
                ));
            }
            let endpoint = parsed.managed.ok_or_else(|| {
                AdapterError::Verification("managed BioC_mirror is missing".into())
            })?;
            if !is_reviewed(&endpoint) {
                return Err(AdapterError::Verification(
                    "managed BioC_mirror is not reviewed".into(),
                ));
            }
            let script = runtime.read(&layout.verification_script)?.ok_or_else(|| {
                AdapterError::Verification("Bioconductor verification script disappeared".into())
            })?;
            if utf8(&layout.verification_script, &script)? != render_verification_script() {
                return Err(AdapterError::Verification(
                    "Bioconductor verification script is not canonical".into(),
                ));
            }
            let output = run_verification(runtime, &layout, &endpoint)?;
            validate_verification_output(&output, &endpoint)?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "BiocManager resolved release {BIOC_VERSION} indexes and fixed packages through {endpoint}"
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
                "restored {} Bioconductor configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Debug)]
struct Layout {
    profile: PathBuf,
    verification_root: PathBuf,
    verification_script: PathBuf,
    verification_library: PathBuf,
}

#[derive(Debug)]
struct Snapshot {
    r_version: String,
    biocmanager_version: String,
    bioc_version: String,
    mirror: String,
    repositories: Vec<(String, String)>,
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

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Bioconductor v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Bioconductor adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "bioconductor" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Bioconductor operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("Bioconductor requires a user home".into()))?;
    validate_path(&home, "home")?;
    let profile = match runtime
        .environment_variable("R_PROFILE_USER")
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => {
            if value == "/dev/null" {
                return Err(AdapterError::Unsupported(
                    "R_PROFILE_USER=/dev/null disables persistent Bioconductor configuration"
                        .into(),
                ));
            }
            let path = PathBuf::from(value);
            validate_user_path(&path, &home, "R_PROFILE_USER")?;
            path
        }
        None => home.join(".Rprofile"),
    };
    let verification_root = home.join(".mirrorswitch/verification/bioconductor");
    Ok(Layout {
        profile,
        verification_script: verification_root.join("verify.R"),
        verification_library: verification_root.join("library"),
        verification_root,
    })
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

fn inspect_runtime(runtime: &dyn Runtime) -> Result<Snapshot, AdapterError> {
    let arguments = vec!["-e".into(), INSPECT_SCRIPT.into()];
    let output = match runtime.project_dir() {
        Some(directory) => {
            validate_path(&directory, "project")?;
            runtime.run_in(&directory, "Rscript", &arguments)?
        }
        None => runtime.run("Rscript", &arguments)?,
    };
    let output = command_output(output, "BiocManager inspection")?;
    parse_snapshot(&output)
}

fn parse_snapshot(output: &str) -> Result<Snapshot, AdapterError> {
    let mut scalars = BTreeMap::new();
    let mut repositories = Vec::new();
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.as_slice() {
            [key, value] if key != &"REPOSITORY" => match scalars.insert(*key, *value) {
                None => {}
                Some(_) => {
                    return Err(AdapterError::Unsupported(format!(
                        "BiocManager inspection duplicated {key}"
                    )));
                }
            },
            ["REPOSITORY", name, url] if !name.is_empty() && !url.is_empty() => {
                repositories.push(((*name).into(), (*url).into()));
            }
            _ => {}
        }
    }
    let field = |key| {
        scalars
            .get(key)
            .filter(|value| !value.is_empty())
            .map(|value| (*value).to_owned())
            .ok_or_else(|| {
                AdapterError::Unsupported(format!("BiocManager inspection did not report {key}"))
            })
    };
    Ok(Snapshot {
        r_version: field("R_VERSION")?,
        biocmanager_version: field("BIOCMANAGER_VERSION")?,
        bioc_version: field("BIOC_VERSION")?,
        mirror: field("BIOC_MIRROR")?,
        repositories,
    })
}

fn review_snapshot(snapshot: &Snapshot) -> Result<(), AdapterError> {
    let r = numeric_version(&snapshot.r_version)?;
    if r.first() != Some(&4) || r.get(1) != Some(&6) {
        return Err(AdapterError::Unsupported(format!(
            "R {} is outside the reviewed R 4.6.x / Bioconductor {BIOC_VERSION} pairing",
            snapshot.r_version
        )));
    }
    review_biocmanager_version(&snapshot.biocmanager_version)?;
    if snapshot.bioc_version != BIOC_VERSION {
        return Err(AdapterError::Unsupported(format!(
            "Bioconductor {} is not the reviewed release {BIOC_VERSION}",
            snapshot.bioc_version
        )));
    }
    for (name, suffix) in [
        ("BioCsoft", "/packages/3.23/bioc"),
        ("BioCann", "/packages/3.23/data/annotation"),
        ("BioCexp", "/packages/3.23/data/experiment"),
    ] {
        let matching = snapshot
            .repositories
            .iter()
            .filter(|(repository, url)| {
                repository == name && url.trim_end_matches('/').ends_with(suffix)
            })
            .count();
        if matching != 1 {
            return Err(AdapterError::Unsupported(format!(
                "BiocManager repositories do not expose one {name} path for release {BIOC_VERSION}"
            )));
        }
    }
    Ok(())
}

fn review_biocmanager_version(version: &str) -> Result<(), AdapterError> {
    let parts = numeric_version(version)?;
    let supported = parts.first() == Some(&1)
        && match (parts.get(1), parts.get(2)) {
            (Some(minor), _) if *minor > 30 => true,
            (Some(30), Some(patch)) => *patch >= 12,
            _ => false,
        };
    if !supported {
        return Err(AdapterError::Unsupported(format!(
            "BiocManager {version} is outside the reviewed 1.30.12 through 1.x configuration model"
        )));
    }
    Ok(())
}

fn numeric_version(value: &str) -> Result<Vec<u64>, AdapterError> {
    let parts = value
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterError::Unsupported(format!("unrecognized version {value}")))?;
    if parts.len() < 2 {
        return Err(AdapterError::Unsupported(format!(
            "unrecognized version {value}"
        )));
    }
    Ok(parts)
}

fn parse_profile(text: &str, path: &Path) -> Result<ParsedProfile, AdapterError> {
    let managed_range = managed_range(text, path)?;
    let managed = managed_range
        .as_ref()
        .map(|range| managed_value(&text[range.clone()], path))
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
        if active.is_empty() || active.starts_with('#') || !active.contains("BioC_mirror") {
            continue;
        }
        match assignment(active)? {
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

fn managed_value(block: &str, path: &Path) -> Result<String, AdapterError> {
    let values = block
        .lines()
        .filter_map(|line| assignment(line.trim()).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "managed Bioconductor block in {} must assign BioC_mirror exactly once",
            path.display()
        )));
    }
    if !is_reviewed(values[0]) {
        return Err(AdapterError::Unsupported(
            "managed BioC_mirror is bound to an unreviewed endpoint".into(),
        ));
    }
    Ok(values[0].into())
}

fn assignment(line: &str) -> Result<Option<&str>, AdapterError> {
    let Some(inner) = line
        .strip_prefix("options(")
        .and_then(|value| value.strip_suffix(')'))
    else {
        return Ok(None);
    };
    let Some((key, value)) = inner.split_once('=') else {
        return Ok(None);
    };
    let key = key.trim().trim_matches(['\'', '"']);
    if key != "BioC_mirror" {
        return Ok(None);
    }
    literal_value(value.trim()).map(Some)
}

fn literal_value(raw: &str) -> Result<&str, AdapterError> {
    let single = raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'');
    let double = raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"');
    if !single && !double {
        return Err(AdapterError::InvalidConfiguration(
            "BioC_mirror assignment is not a quoted literal".into(),
        ));
    }
    let value = &raw[1..raw.len() - 1];
    if value.is_empty()
        || value.contains([';', '`', '$', '\n', '\r', ','])
        || (single && value.contains('\''))
        || (double && value.contains('"'))
    {
        return Err(AdapterError::InvalidConfiguration(
            "BioC_mirror assignment is not a safe literal".into(),
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
            "Bioconductor managed markers in {} are missing, duplicated, or out of order",
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

fn profile_sources(parsed: &ParsedProfile, path: &Path) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if let Some(value) = &parsed.managed {
        sources.push(configured_source(value, "managed-rprofile", path));
    }
    for assignment in &parsed.unmanaged {
        let kind = if is_public(&assignment.value) {
            "adoptable-rprofile"
        } else {
            "private-rprofile"
        };
        sources.push(if kind == "adoptable-rprofile" {
            configured_source(&assignment.value, kind, path)
        } else {
            policy_source(kind, path)
        });
    }
    if parsed.unmanaged.len() + usize::from(parsed.managed.is_some()) > 1 {
        sources.push(policy_source("duplicate-rprofile", path));
    }
    if parsed.dynamic {
        sources.push(policy_source("dynamic-rprofile", path));
    }
    sources
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-rprofile" => {
                return Err(AdapterError::Unsupported(
                    "existing BioC_mirror points to a private, authenticated, or unreviewed repository"
                        .into(),
                ));
            }
            "duplicate-rprofile" => {
                return Err(AdapterError::InvalidConfiguration(
                    "selected R profile assigns BioC_mirror more than once".into(),
                ));
            }
            "dynamic-rprofile" => {
                return Err(AdapterError::Unsupported(
                    "selected R profile computes BioC_mirror dynamically".into(),
                ));
            }
            "effective-mirror-override" => {
                return Err(AdapterError::Unsupported(
                    "effective BioC_mirror is not represented by the selected user profile".into(),
                ));
            }
            "project-profile-precedence" => {
                return Err(AdapterError::Unsupported(
                    "the current project .Rprofile takes precedence over the user profile".into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Bioconductor verification target contains data not managed by MirrorSwitch"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn rewrite_profile(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    let parsed = parse_profile(text, path)?;
    if parsed.dynamic || parsed.unmanaged.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "R profile cannot be rewritten safely".into(),
        ));
    }
    if parsed
        .unmanaged
        .iter()
        .any(|assignment| !is_public(&assignment.value))
    {
        return Err(AdapterError::Unsupported(
            "private or unreviewed BioC_mirror cannot be replaced".into(),
        ));
    }
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
    if let Some(assignment) = parsed.unmanaged.first() {
        return Ok(format!(
            "{}{}{}",
            &text[..assignment.range.start],
            block,
            &text[assignment.range.end..]
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
    format!(
        "{MANAGED_BEGIN}{newline}options(BioC_mirror = '{endpoint}'){newline}{MANAGED_END}{newline}"
    )
}

fn render_verification_script() -> String {
    format!(
        r#"{VERIFY_MARKER}
args <- commandArgs(trailingOnly = TRUE)
stopifnot(length(args) == 1L, requireNamespace("BiocManager", quietly = TRUE))
base <- sub("/+$", "", args[[1L]])
stopifnot(getRversion() >= "4.6", getRversion() < "4.7", as.character(BiocManager::version()) == "3.23")
repos <- suppressWarnings(BiocManager::repositories())
expected <- c(
    BioCsoft = paste0(base, "/packages/3.23/bioc"),
    BioCann = paste0(base, "/packages/3.23/data/annotation"),
    BioCexp = paste0(base, "/packages/3.23/data/experiment")
)
for (name in names(expected)) {{
    stopifnot(name %in% names(repos))
    stopifnot(sub("/+$", "", unname(repos[[name]])) == expected[[name]])
    cat("REPOSITORY\t", name, "\t", expected[[name]], "\n", sep = "")
}}
checks <- list(
    c("BioCsoft", "BiocVersion", "3.23.1", "{BIOC_VERSION_SHA}"),
    c("BioCann", "AHCytoBands", "0.99.1", "{ANNOTATION_SHA}"),
    c("BioCexp", "adductData", "1.28.0", "{EXPERIMENT_SHA}")
)
downloads <- file.path(getwd(), "downloads")
dir.create(downloads, recursive = TRUE, showWarnings = FALSE)
stopifnot(nzchar(Sys.which("sha256sum")))
options(timeout = 30L)
for (check in checks) {{
    repository <- unname(repos[[check[[1L]]]])
    available <- available.packages(contriburl = contrib.url(repository, type = "source"), filters = list())
    stopifnot(check[[2L]] %in% rownames(available), available[check[[2L]], "Version"] == check[[3L]])
    archive <- download.packages(check[[2L]], destdir = downloads, repos = repository, type = "source", quiet = TRUE)
    stopifnot(nrow(archive) == 1L, file.exists(archive[1L, 2L]))
    digest <- strsplit(system2("sha256sum", shQuote(archive[1L, 2L]), stdout = TRUE), "[[:space:]]+")[[1L]][[1L]]
    stopifnot(digest == check[[4L]])
    cat("PACKAGE\t", check[[2L]], "\t", check[[3L]], "\t", digest, "\n", sep = "")
}}
cat("BIOC_VERSION\t", as.character(BiocManager::version()), "\n", sep = "")
"#
    )
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<String, AdapterError> {
    let matches = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "bioconductor" && selection.upstream_id == UPSTREAM
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Bioconductor requires exactly one registry selection".into(),
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
                "Bioconductor selection requires one HTTPS {role:?} endpoint"
            )));
        }
        bases.insert(normalized_base(&endpoints[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Bioconductor {role:?} endpoint is unsafe"))
        })?);
    }
    if bases.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Bioconductor index, metadata, and artifact endpoints must share one mirror base"
                .into(),
        ));
    }
    let endpoint = bases.into_iter().next().expect("one endpoint");
    let expected_provider = match endpoint.as_str() {
        NJU => "nju",
        TUNA => "tuna",
        _ => {
            return Err(AdapterError::InvalidConfiguration(
                "Bioconductor mirror endpoint is not reviewed".into(),
            ));
        }
    };
    if selection.provider_id != expected_provider {
        return Err(AdapterError::InvalidConfiguration(
            "Bioconductor provider and mirror endpoint do not match".into(),
        ));
    }
    Ok(endpoint)
}

fn run_verification(
    runtime: &dyn Runtime,
    layout: &Layout,
    endpoint: &str,
) -> Result<String, AdapterError> {
    let profile = path_text(&layout.profile, "R profile")?;
    let library = path_text(&layout.verification_library, "verification library")?;
    let script = path_text(&layout.verification_script, "verification script")?;
    let arguments = vec![
        format!("R_PROFILE_USER={profile}"),
        "R_ENVIRON_USER=/dev/null".into(),
        format!("R_LIBS_USER={library}"),
        "R_HISTFILE=/dev/null".into(),
        "Rscript".into(),
        script.into(),
        endpoint.into(),
    ];
    let output = runtime.run_in(&layout.verification_root, "env", &arguments)?;
    command_output(output, "Bioconductor repository verification")
}

fn validate_verification_output(output: &str, endpoint: &str) -> Result<(), AdapterError> {
    let required = [
        format!("BIOC_VERSION\t{BIOC_VERSION}"),
        format!("REPOSITORY\tBioCsoft\t{endpoint}/packages/3.23/bioc"),
        format!("REPOSITORY\tBioCann\t{endpoint}/packages/3.23/data/annotation"),
        format!("REPOSITORY\tBioCexp\t{endpoint}/packages/3.23/data/experiment"),
        format!("PACKAGE\tBiocVersion\t3.23.1\t{BIOC_VERSION_SHA}"),
        format!("PACKAGE\tAHCytoBands\t0.99.1\t{ANNOTATION_SHA}"),
        format!("PACKAGE\tadductData\t1.28.0\t{EXPERIMENT_SHA}"),
    ];
    for evidence in required {
        if !output.lines().any(|line| line == evidence) {
            return Err(AdapterError::Verification(format!(
                "Bioconductor verification did not report {evidence}"
            )));
        }
    }
    Ok(())
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
    let matches = current
        .documents
        .iter()
        .filter(|document| document.format == format)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Bioconductor current configuration must contain exactly one {format} document"
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

fn repository_source(name: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: if is_public_repository(value) {
            value.to_owned()
        } else {
            "<preserved>".into()
        },
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec!["repository-preserved".into()]),
            ("name".into(), vec![name.into()]),
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
        url: format!("bioconductor-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Bioconductor source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Bioconductor source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
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

fn is_public_repository(value: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(value) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.port().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && matches!(
            parsed.host_str(),
            Some(
                "bioconductor.org"
                    | "www.bioconductor.org"
                    | "mirrors.nju.edu.cn"
                    | "mirrors.tuna.tsinghua.edu.cn"
            )
        )
}

fn same_base(left: &str, right: &str) -> bool {
    normalized_base(left).is_some_and(|left| normalized_base(right).as_deref() == Some(&left))
}

fn is_reviewed(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| REVIEWED_MIRRORS.contains(&value.as_str()))
}

fn is_official(value: &str) -> bool {
    normalized_base(value).is_some_and(|value| OFFICIAL_MIRRORS.contains(&value.as_str()))
}

fn is_public(value: &str) -> bool {
    is_reviewed(value) || is_official(value)
}

fn public_state(value: &str) -> &'static str {
    if is_public(value) { "public" } else { "custom" }
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "Bioconductor {kind} {} is outside the user home",
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
            "Bioconductor reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, kind: &str) -> Result<&'a str, AdapterError> {
    path.to_str()
        .ok_or_else(|| AdapterError::Verification(format!("Bioconductor {kind} path is not UTF-8")))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Bioconductor configuration {} is not UTF-8",
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
