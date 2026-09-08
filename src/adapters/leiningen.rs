use std::{
    cmp::Reverse,
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

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const CLOJARS_UPSTREAM: &str = "clojars--language-registry";
const REPOSITORY_VERSION: &str = "leiningen-2.x";
const MAVEN_ENDPOINTS: &[&str] = &[
    "https://maven.aliyun.com/repository/public/",
    "https://repo.huaweicloud.com/repository/maven/",
    "https://repo.nju.edu.cn/maven/",
];
const CLOJARS_ENDPOINTS: &[&str] = &[
    "https://repo.huaweicloud.com/artifactory/maven-clojars-remote/",
    "https://mirrors.nju.edu.cn/clojars/",
    "https://mirrors.tuna.tsinghua.edu.cn/clojars/",
];
const OFFICIAL_MAVEN: &[&str] = &[
    "https://repo1.maven.org/maven2/",
    "https://repo.maven.apache.org/maven2/",
];
const OFFICIAL_CLOJARS: &[&str] = &["https://repo.clojars.org/"];
const VERIFY_PROFILE_MARKER: &str = ";; Managed by MirrorSwitch: Leiningen verification profile v1";
const VERIFY_PROJECT_MARKER: &str = ";; Managed by MirrorSwitch: Leiningen verification project v1";

#[derive(Clone, Copy, Debug, Default)]
pub struct LeiningenAdapter;

impl Adapter for LeiningenAdapter {
    fn key(&self) -> &'static str {
        "leiningen"
    }

    fn tool_id(&self) -> &'static str {
        "leiningen"
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
        if !runtime.command_exists("lein") {
            return Ok(None);
        }
        let environment_command = if context.os == OperatingSystem::Windows {
            "cmd.exe"
        } else {
            "env"
        };
        if !runtime.command_exists(environment_command) {
            return Err(AdapterError::Unsupported(format!(
                "Leiningen verification requires {environment_command}"
            )));
        }
        let output = run_lein(runtime, None, &["version"], "lein version")?;
        let version = lein_version(&output)?;
        reviewed_version(&version)?;
        let layout = config_layout(runtime)?;
        let project = project_observation(runtime, &layout, context.os)?;
        let mut evidence = vec![
            format!("Leiningen {version}"),
            java_evidence(&output),
            format!("user profile is {}", layout.user_profile.display()),
            format!(
                "project repository declaration(s): {}",
                project.repositories
            ),
            format!("project plugin declaration(s): {}", project.plugins),
            format!("credential declaration(s): {}", project.credentials),
        ];
        evidence.push(match project.clojure_version {
            Some(version) => format!("project Clojure {version}"),
            None => {
                "project Clojure version is not a simple literal or no project was found".into()
            }
        });
        Ok(Some(DetectedTool {
            tool_id: "leiningen".into(),
            executable: Some(PathBuf::from("lein")),
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
        require_supported_context(context)?;
        require_scope(scope)?;
        if detected.tool_id != "leiningen" {
            return Err(AdapterError::InvalidConfiguration(
                "Leiningen read received another tool's detection result".into(),
            ));
        }
        let output = run_lein(runtime, None, &["version"], "lein version")?;
        let version = lein_version(&output)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Leiningen version changed after detection".into(),
            ));
        }
        let layout = config_layout(runtime)?;
        let mut sources = environment_sources(runtime);
        sources.push(snapshot_source("leiningen-version", &version));
        if runtime.list_files(&layout.lein_home)?.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| name == "credentials.clj.gpg")
        }) {
            sources.push(policy_source(
                "credentials-detected",
                &layout.lein_home.join("credentials.clj.gpg"),
            ));
        }
        let mut files = Vec::new();
        let mut documents = Vec::new();

        let user = read_document(runtime, &layout.user_profile)?;
        if user.exists {
            files.push(user.path.clone());
            let text = utf8(&user.path, &user.contents)?;
            if text.trim().is_empty() {
                sources.push(policy_source("empty-user-profile", &user.path));
            } else {
                sources.extend(profile_sources(text, &user.path)?);
            }
        }
        documents.push(ConfigurationDocument {
            path: user.path,
            format: "leiningen-user-profile".into(),
            contents: user.contents,
        });

        for (path, kind) in read_only_paths(runtime, &layout, context.os)? {
            let document = read_document(runtime, &path)?;
            if !document.exists {
                continue;
            }
            files.push(path.clone());
            let text = utf8(&path, &document.contents)?;
            sources.extend(read_only_sources(text, &path, kind));
            documents.push(ConfigurationDocument {
                path,
                format: "leiningen-read-only-configuration".into(),
                contents: document.contents,
            });
        }

        for (path, format, marker) in verification_targets(&layout) {
            let document = read_document(runtime, &path)?;
            if document.exists {
                files.push(path.clone());
                let text = utf8(&path, &document.contents)?;
                if !text.starts_with(marker) {
                    sources.push(policy_source("verification-conflict", &path));
                }
            }
            documents.push(ConfigurationDocument {
                path,
                format: format.into(),
                contents: document.contents,
            });
        }

        Ok(CurrentConfiguration {
            tool_id: "leiningen".into(),
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
        reviewed_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Leiningen version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "leiningen".into(),
            adapter_key: "leiningen".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![MAVEN_UPSTREAM.into(), CLOJARS_UPSTREAM.into()],
            repository_versions: BTreeMap::from([
                (MAVEN_UPSTREAM.into(), REPOSITORY_VERSION.into()),
                (CLOJARS_UPSTREAM.into(), REPOSITORY_VERSION.into()),
            ]),
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
        let selected = selected_endpoints(selections)?;
        let user = find_document(current, "leiningen-user-profile")?;
        let user_text = utf8(&user.path, &user.contents)?;
        let mut rendered = rewrite_profile(
            user_text,
            current.files.contains(&user.path),
            &selected.maven,
            &selected.clojars,
        )?
        .into_bytes();
        if user.contents.starts_with(&[0xef, 0xbb, 0xbf]) {
            rendered.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            user,
            rendered,
            "add or retarget exact central and clojars user mirrors while preserving profiles, private repositories, credentials and policies",
            &mut changes,
        );
        let profile = find_document(current, "leiningen-verification-profile")?;
        add_change(
            context,
            current,
            profile,
            render_verification_profile(&selected.maven, &selected.clojars).into_bytes(),
            "create an isolated Leiningen mirror profile",
            &mut changes,
        );
        let project = find_document(current, "leiningen-verification-project")?;
        add_change(
            context,
            current,
            project,
            render_verification_project().into_bytes(),
            "create an isolated Leiningen dependency and plugin project",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "leiningen".into(),
            tool_id: "leiningen".into(),
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
                &layout.user_profile,
                &layout.verification_profile,
                &layout.verification_project,
            ]
            .into_iter()
            .map(|path| rooted(&context.root, path))
            .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Leiningen transaction receipt contains no known target".into(),
                ));
            }
            let user = runtime.read(&layout.user_profile)?.ok_or_else(|| {
                AdapterError::Verification("Leiningen user profile disappeared".into())
            })?;
            let user_pair = effective_pair(utf8(&layout.user_profile, &user)?)?;
            let verification = runtime.read(&layout.verification_profile)?.ok_or_else(|| {
                AdapterError::Verification("Leiningen verification profile disappeared".into())
            })?;
            let verification_text = utf8(&layout.verification_profile, &verification)?;
            if !verification_text.starts_with(VERIFY_PROFILE_MARKER) {
                return Err(AdapterError::Verification(
                    "Leiningen verification profile is not managed".into(),
                ));
            }
            let pair = effective_pair(verification_text)?;
            if pair != user_pair {
                return Err(AdapterError::Verification(
                    "Leiningen user and verification mirror pairs differ".into(),
                ));
            }
            let project = runtime.read(&layout.verification_project)?.ok_or_else(|| {
                AdapterError::Verification("Leiningen verification project disappeared".into())
            })?;
            if utf8(&layout.verification_project, &project)? != render_verification_project() {
                return Err(AdapterError::Verification(
                    "Leiningen verification project is not canonical".into(),
                ));
            }
            let mirrors = run_verification(context, runtime, &layout, &["pprint", ":mirrors"])?;
            let deps = run_verification(context, runtime, &layout, &["deps"])?;
            let name = run_verification(context, runtime, &layout, &["pprint", ":name"])?;
            for endpoint in [&pair.maven, &pair.clojars] {
                if !mirrors.contains(endpoint.trim_end_matches('/')) {
                    return Err(AdapterError::Verification(format!(
                        "Leiningen effective mirrors did not contain {endpoint}"
                    )));
                }
            }
            if !name.contains("mirrorswitch-leiningen-verification") {
                return Err(AdapterError::Verification(
                    "Leiningen plugin query did not return the verification project".into(),
                ));
            }
            if deps.contains("Could not find artifact") {
                return Err(AdapterError::Verification(
                    "Leiningen dependency resolution reported a missing artifact".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Leiningen resolved Maven dependencies and a Clojars plugin through {} and {}",
                    pair.maven, pair.clojars
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
                "restored {} Leiningen configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct Layout {
    user_profile: PathBuf,
    lein_home: PathBuf,
    verification_root: PathBuf,
    verification_profile: PathBuf,
    verification_project: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct ProjectObservation {
    repositories: usize,
    plugins: usize,
    credentials: usize,
    clojure_version: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadOnlyKind {
    System,
    Project,
    ProjectProfiles,
    RepositoryOverrides,
    UserProfileOverride,
}

#[derive(Clone, Debug)]
struct ObservedDocument {
    path: PathBuf,
    exists: bool,
    contents: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MirrorPair {
    maven: String,
    clojars: String,
}

type MapEntry = (Range<usize>, Range<usize>);

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "Leiningen on macOS and Windows requires a native host".into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "Leiningen adapter requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "Leiningen adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "leiningen" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "Leiningen operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn config_layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime.home_dir().ok_or_else(|| {
        AdapterError::Unsupported("Leiningen user configuration requires a home directory".into())
    })?;
    validate_path(&home)?;
    let lein_home = match runtime.environment_variable("LEIN_HOME") {
        Some(value) if !value.trim().is_empty() => {
            let path = PathBuf::from(value);
            validate_path(&path)?;
            path
        }
        _ => home.join(".lein"),
    };
    let verification_root = home.join(".mirrorswitch/verification/leiningen");
    Ok(Layout {
        user_profile: lein_home.join("profiles.clj"),
        lein_home,
        verification_profile: verification_root.join("profiles.clj"),
        verification_project: verification_root.join("project.clj"),
        verification_root,
    })
}

fn read_only_paths(
    runtime: &dyn Runtime,
    layout: &Layout,
    os: OperatingSystem,
) -> Result<Vec<(PathBuf, ReadOnlyKind)>, AdapterError> {
    let mut paths = vec![(
        layout.lein_home.join("profiles.d/user.clj"),
        ReadOnlyKind::UserProfileOverride,
    )];
    if os != OperatingSystem::Windows {
        paths.push((
            PathBuf::from("/etc/leiningen/profiles.clj"),
            ReadOnlyKind::System,
        ));
    }
    if let Some(project) = runtime.project_dir() {
        validate_path(&project)?;
        paths.extend([
            (project.join("project.clj"), ReadOnlyKind::Project),
            (project.join("profiles.clj"), ReadOnlyKind::ProjectProfiles),
            (
                project.join("repository-overrides.clj"),
                ReadOnlyKind::RepositoryOverrides,
            ),
        ]);
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    paths.dedup_by(|left, right| left.0 == right.0);
    Ok(paths)
}

fn project_observation(
    runtime: &dyn Runtime,
    layout: &Layout,
    os: OperatingSystem,
) -> Result<ProjectObservation, AdapterError> {
    let mut observation = ProjectObservation::default();
    for (path, kind) in read_only_paths(runtime, layout, os)? {
        if !matches!(kind, ReadOnlyKind::Project | ReadOnlyKind::ProjectProfiles) {
            continue;
        }
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        let text = utf8(&path, &contents)?;
        observation.repositories += text.matches(":repositories").count();
        observation.plugins +=
            text.matches(":plugin-repositories").count() + text.matches(":plugins").count();
        observation.credentials += text.matches(":username").count()
            + text.matches(":password").count()
            + text.matches(":creds").count();
        if kind == ReadOnlyKind::Project && observation.clojure_version.is_none() {
            observation.clojure_version = dependency_version(text, "org.clojure/clojure");
        }
    }
    if runtime.list_files(&layout.lein_home)?.iter().any(|path| {
        path.file_name()
            .is_some_and(|name| name == "credentials.clj.gpg")
    }) {
        observation.credentials += 1;
    }
    Ok(observation)
}

fn read_document(runtime: &dyn Runtime, path: &Path) -> Result<ObservedDocument, AdapterError> {
    validate_path(path)?;
    let observed = runtime.read(path)?;
    Ok(ObservedDocument {
        path: path.to_path_buf(),
        exists: observed.is_some(),
        contents: observed.unwrap_or_default(),
    })
}

fn verification_targets(layout: &Layout) -> [(PathBuf, &'static str, &'static str); 2] {
    [
        (
            layout.verification_profile.clone(),
            "leiningen-verification-profile",
            VERIFY_PROFILE_MARKER,
        ),
        (
            layout.verification_project.clone(),
            "leiningen-verification-project",
            VERIFY_PROJECT_MARKER,
        ),
    ]
}

fn environment_sources(runtime: &dyn Runtime) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if runtime
        .environment_variable("LEIN_NO_USER_PROFILES")
        .is_some_and(|value| !value.trim().is_empty() && value != "0")
    {
        sources.push(policy_source("precedence-override", Path::new(":env:")));
    }
    if ["LEIN_USERNAME", "LEIN_PASSWORD", "LEIN_GPG"]
        .into_iter()
        .any(|name| {
            runtime
                .environment_variable(name)
                .is_some_and(|value| !value.trim().is_empty())
        })
    {
        sources.push(policy_source("credentials-detected", Path::new(":env:")));
    }
    sources
}

fn profile_sources(text: &str, path: &Path) -> Result<Vec<ConfiguredSource>, AdapterError> {
    let mut sources = Vec::new();
    let root = root_map(text)?;
    let user = unique_entry(text, &root, ":user")?;
    let Some((_, user_value)) = user else {
        sources.push(policy_source("user-profile-absent", path));
        return Ok(sources);
    };
    let user_map = require_map(text, &user_value, ":user")?;
    let mirrors = unique_entry(text, &user_map, ":mirrors")?;
    if let Some((_, mirrors_value)) = mirrors {
        let mirrors_map = require_map(text, &mirrors_value, ":mirrors")?;
        for (name, upstream, allowed) in [
            ("central", MAVEN_UPSTREAM, MAVEN_ENDPOINTS),
            ("clojars", CLOJARS_UPSTREAM, CLOJARS_ENDPOINTS),
        ] {
            if let Some((_, value)) = unique_entry(text, &mirrors_map, &format!("\"{name}\""))? {
                let url = mirror_url(text, &value)?;
                let kind = if allowed.iter().any(|candidate| same_base(&url, candidate)) {
                    "managed-mirror"
                } else if official_urls(name)
                    .iter()
                    .any(|candidate| same_base(&url, candidate))
                {
                    "official-mirror"
                } else {
                    "mirror-name-conflict"
                };
                sources.push(ConfiguredSource {
                    upstream_id: (kind == "managed-mirror").then(|| upstream.into()),
                    url: if kind == "mirror-name-conflict" {
                        "<preserved>".into()
                    } else {
                        url
                    },
                    enabled: true,
                    metadata: BTreeMap::from([
                        ("kind".into(), vec![kind.into()]),
                        ("config_path".into(), vec![path.display().to_string()]),
                    ]),
                });
            }
        }
    }
    if contains_credentials(text) {
        sources.push(policy_source("credentials-detected", path));
    }
    if text.contains(":repositories") || text.contains(":plugin-repositories") {
        sources.push(policy_source("private-repositories-preserved", path));
    }
    Ok(sources)
}

fn read_only_sources(text: &str, path: &Path, kind: ReadOnlyKind) -> Vec<ConfiguredSource> {
    let mut sources = Vec::new();
    if contains_credentials(text) {
        sources.push(policy_source("credentials-detected", path));
    }
    if text.contains(":repositories") || text.contains(":plugin-repositories") {
        sources.push(policy_source("project-repositories-preserved", path));
    }
    let conflict = match kind {
        ReadOnlyKind::Project
            if text.contains(":mirrors")
                && (text.contains("\"central\"") || text.contains("\"clojars\"")) =>
        {
            Some("project-mirror-conflict")
        }
        ReadOnlyKind::ProjectProfiles if text.contains(":user") => Some("user-profile-override"),
        ReadOnlyKind::RepositoryOverrides if text.contains(":mirrors") => {
            Some("repository-override-conflict")
        }
        ReadOnlyKind::UserProfileOverride => Some("user-profile-override"),
        _ => None,
    };
    if let Some(conflict) = conflict {
        sources.push(policy_source(conflict, path));
    }
    sources
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "precedence-override" => {
                return Err(AdapterError::Unsupported(
                    "Leiningen user profiles are disabled by LEIN_NO_USER_PROFILES".into(),
                ));
            }
            "project-mirror-conflict"
            | "user-profile-override"
            | "repository-override-conflict" => {
                return Err(AdapterError::Unsupported(
                    "a higher-precedence Leiningen project profile or repository override controls the target mirrors".into(),
                ));
            }
            "mirror-name-conflict" => {
                return Err(AdapterError::Unsupported(
                    "a Leiningen central or clojars mirror is bound to an unreviewed endpoint"
                        .into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Leiningen verification target contains data not managed by MirrorSwitch"
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
    existed: bool,
    maven: &str,
    clojars: &str,
) -> Result<String, AdapterError> {
    if !existed {
        return Ok(render_profile(maven, clojars));
    }
    if text.trim().is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "existing Leiningen user profile is empty".into(),
        ));
    }
    let root = root_map(text)?;
    let mut edits = Vec::<(Range<usize>, String)>::new();
    let Some((_, user_value)) = unique_entry(text, &root, ":user")? else {
        edits.push((
            root.end - 1..root.end - 1,
            format!(
                "\n :user {{:mirrors {}}}\n",
                render_mirror_map(maven, clojars)
            ),
        ));
        return apply_edits(text, edits).map(|rendered| preserve_newlines(rendered, text));
    };
    let user = require_map(text, &user_value, ":user")?;
    let Some((_, mirrors_value)) = unique_entry(text, &user, ":mirrors")? else {
        edits.push((
            user.end - 1..user.end - 1,
            format!("\n  :mirrors {}\n", render_mirror_map(maven, clojars)),
        ));
        return apply_edits(text, edits).map(|rendered| preserve_newlines(rendered, text));
    };
    let mirrors = require_map(text, &mirrors_value, ":mirrors")?;
    for (name, endpoint, allowed) in [
        ("central", maven, MAVEN_ENDPOINTS),
        ("clojars", clojars, CLOJARS_ENDPOINTS),
    ] {
        let key = format!("\"{name}\"");
        match unique_entry(text, &mirrors, &key)? {
            Some((_, value)) => {
                let map = require_map(text, &value, &key)?;
                reject_credentials(text, &map, name)?;
                let (_, url_value) = unique_entry(text, &map, ":url")?.ok_or_else(|| {
                    AdapterError::InvalidConfiguration(format!(
                        "Leiningen {name} mirror has no literal :url"
                    ))
                })?;
                let old_url = simple_string(text, &url_value).ok_or_else(|| {
                    AdapterError::Unsupported(format!(
                        "Leiningen {name} mirror :url is not a simple string"
                    ))
                })?;
                if !allowed
                    .iter()
                    .any(|candidate| same_base(&old_url, candidate))
                    && !official_urls(name)
                        .iter()
                        .any(|candidate| same_base(&old_url, candidate))
                {
                    return Err(AdapterError::Unsupported(format!(
                        "Leiningen {name} mirror is bound to an unreviewed endpoint"
                    )));
                }
                edits.push((url_value, format!("\"{endpoint}\"")));
            }
            None => edits.push((
                mirrors.end - 1..mirrors.end - 1,
                format!("\n   \"{name}\" {{:name \"{name}\" :url \"{endpoint}\"}}\n"),
            )),
        }
    }
    apply_edits(text, edits).map(|rendered| preserve_newlines(rendered, text))
}

fn preserve_newlines(rendered: String, original: &str) -> String {
    if original.contains("\r\n") {
        rendered.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        rendered
    }
}

fn effective_pair(text: &str) -> Result<MirrorPair, AdapterError> {
    let root = root_map(text)?;
    let (_, user) = unique_entry(text, &root, ":user")?
        .ok_or_else(|| AdapterError::Verification("Leiningen :user profile is missing".into()))?;
    let user = require_map(text, &user, ":user")?;
    let (_, mirrors) = unique_entry(text, &user, ":mirrors")?.ok_or_else(|| {
        AdapterError::Verification("Leiningen :user :mirrors map is missing".into())
    })?;
    let mirrors = require_map(text, &mirrors, ":mirrors")?;
    let value = |name: &str| -> Result<String, AdapterError> {
        let key = format!("\"{name}\"");
        let (_, entry) = unique_entry(text, &mirrors, &key)?.ok_or_else(|| {
            AdapterError::Verification(format!("Leiningen {name} mirror is missing"))
        })?;
        mirror_url(text, &entry)
    };
    let maven = value("central")?;
    let clojars = value("clojars")?;
    if !MAVEN_ENDPOINTS
        .iter()
        .any(|candidate| same_base(&maven, candidate))
        || !CLOJARS_ENDPOINTS
            .iter()
            .any(|candidate| same_base(&clojars, candidate))
    {
        return Err(AdapterError::Verification(
            "Leiningen effective mirrors are outside the reviewed endpoints".into(),
        ));
    }
    Ok(MirrorPair { maven, clojars })
}

fn render_profile(maven: &str, clojars: &str) -> String {
    format!(
        "{{:user {{:mirrors {}}}}}\n",
        render_mirror_map(maven, clojars)
    )
}

fn render_mirror_map(maven: &str, clojars: &str) -> String {
    format!(
        "{{\"central\" {{:name \"central\" :url \"{maven}\"}}\n             \"clojars\" {{:name \"clojars\" :url \"{clojars}\"}}}}"
    )
}

fn render_verification_profile(maven: &str, clojars: &str) -> String {
    format!(
        "{VERIFY_PROFILE_MARKER}\n{{:user {{:mirrors {}}}}}\n",
        render_mirror_map(maven, clojars)
    )
}

fn render_verification_project() -> String {
    format!(
        "{VERIFY_PROJECT_MARKER}\n(defproject mirrorswitch-leiningen-verification \"0.0.0\"\n  :dependencies [[org.apache.commons/commons-lang3 \"3.14.0\"]]\n  :plugins [[lein-pprint \"1.3.2\"]]\n  :local-repo \"repository\"\n  :checksum :fail)\n"
    )
}

fn root_map(text: &str) -> Result<Range<usize>, AdapterError> {
    let start = skip_separators(text, 0, text.len());
    let form = scan_form(text, start, text.len())?;
    if !is_map(text, &form) || skip_separators(text, form.end, text.len()) != text.len() {
        return Err(AdapterError::InvalidConfiguration(
            "Leiningen profiles.clj must contain one top-level literal map".into(),
        ));
    }
    Ok(form)
}

fn require_map(text: &str, form: &Range<usize>, label: &str) -> Result<Range<usize>, AdapterError> {
    if !is_map(text, form) {
        return Err(AdapterError::Unsupported(format!(
            "Leiningen {label} value is not a literal map"
        )));
    }
    Ok(form.clone())
}

fn unique_entry(
    text: &str,
    map: &Range<usize>,
    wanted: &str,
) -> Result<Option<MapEntry>, AdapterError> {
    let entries = map_entries(text, map)?;
    let matches = entries
        .into_iter()
        .filter(|(key, _)| &text[key.clone()] == wanted)
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Leiningen map defines {wanted} more than once"
        )));
    }
    Ok(matches.into_iter().next())
}

fn map_entries(text: &str, map: &Range<usize>) -> Result<Vec<MapEntry>, AdapterError> {
    if !is_map(text, map) {
        return Err(AdapterError::InvalidConfiguration(
            "Leiningen configuration contains a non-map where a map is required".into(),
        ));
    }
    let limit = map.end - 1;
    let mut position = skip_separators(text, map.start + 1, limit);
    let mut entries = Vec::new();
    while position < limit {
        let key = scan_form(text, position, limit)?;
        position = skip_separators(text, key.end, limit);
        if position >= limit {
            return Err(AdapterError::InvalidConfiguration(
                "Leiningen map contains a key without a value".into(),
            ));
        }
        let value = scan_form(text, position, limit)?;
        position = skip_separators(text, value.end, limit);
        entries.push((key, value));
    }
    Ok(entries)
}

fn scan_form(text: &str, start: usize, limit: usize) -> Result<Range<usize>, AdapterError> {
    if start >= limit || !text.is_char_boundary(start) {
        return Err(AdapterError::InvalidConfiguration(
            "Leiningen configuration has an incomplete form".into(),
        ));
    }
    let bytes = text.as_bytes();
    match bytes[start] {
        b'"' => scan_string(text, start, limit),
        b'{' | b'[' | b'(' => scan_collection(text, start, limit),
        b'\'' | b'@' => {
            let next = skip_separators(text, start + 1, limit);
            let form = scan_form(text, next, limit)?;
            Ok(start..form.end)
        }
        b'~' => {
            let prefix = if start + 1 < limit && bytes[start + 1] == b'@' {
                start + 2
            } else {
                start + 1
            };
            let form = scan_form(text, skip_separators(text, prefix, limit), limit)?;
            Ok(start..form.end)
        }
        b'^' => {
            let meta = scan_form(text, skip_separators(text, start + 1, limit), limit)?;
            let target = scan_form(text, skip_separators(text, meta.end, limit), limit)?;
            Ok(start..target.end)
        }
        b'#' if start + 1 < limit && bytes[start + 1] == b'"' => {
            let string = scan_string(text, start + 1, limit)?;
            Ok(start..string.end)
        }
        b'#' if start + 1 < limit && bytes[start + 1] == b'{' => {
            let set = scan_collection(text, start + 1, limit)?;
            Ok(start..set.end)
        }
        b'#' if start + 1 < limit && matches!(bytes[start + 1], b'_' | b'=') => {
            let form = scan_form(text, skip_separators(text, start + 2, limit), limit)?;
            Ok(start..form.end)
        }
        b'\\' => Ok(start..scan_atom_end(text, start + 1, limit)),
        _ => {
            let end = scan_atom_end(text, start, limit);
            if end == start {
                Err(AdapterError::InvalidConfiguration(
                    "Leiningen configuration contains an unexpected delimiter".into(),
                ))
            } else if bytes[start] == b'#' {
                let target = skip_separators(text, end, limit);
                if target == limit {
                    Ok(start..end)
                } else {
                    let form = scan_form(text, target, limit)?;
                    Ok(start..form.end)
                }
            } else {
                Ok(start..end)
            }
        }
    }
}

fn scan_collection(text: &str, start: usize, limit: usize) -> Result<Range<usize>, AdapterError> {
    let bytes = text.as_bytes();
    let close = match bytes[start] {
        b'{' => b'}',
        b'[' => b']',
        b'(' => b')',
        _ => unreachable!(),
    };
    let mut position = skip_separators(text, start + 1, limit);
    while position < limit {
        if bytes[position] == close {
            return Ok(start..position + 1);
        }
        let form = scan_form(text, position, limit)?;
        position = skip_separators(text, form.end, limit);
    }
    Err(AdapterError::InvalidConfiguration(
        "Leiningen configuration contains an unterminated collection".into(),
    ))
}

fn scan_string(text: &str, start: usize, limit: usize) -> Result<Range<usize>, AdapterError> {
    let bytes = text.as_bytes();
    let mut position = start + 1;
    while position < limit {
        match bytes[position] {
            b'\\' => position += 2,
            b'"' => return Ok(start..position + 1),
            _ => position += 1,
        }
    }
    Err(AdapterError::InvalidConfiguration(
        "Leiningen configuration contains an unterminated string".into(),
    ))
}

fn scan_atom_end(text: &str, mut position: usize, limit: usize) -> usize {
    let bytes = text.as_bytes();
    while position < limit
        && !bytes[position].is_ascii_whitespace()
        && !matches!(
            bytes[position],
            b',' | b'{' | b'}' | b'[' | b']' | b'(' | b')' | b'"' | b';'
        )
    {
        position += 1;
    }
    position
}

fn skip_separators(text: &str, mut position: usize, limit: usize) -> usize {
    let bytes = text.as_bytes();
    loop {
        while position < limit && (bytes[position].is_ascii_whitespace() || bytes[position] == b',')
        {
            position += 1;
        }
        if position < limit && bytes[position] == b';' {
            while position < limit && bytes[position] != b'\n' {
                position += 1;
            }
            continue;
        }
        return position;
    }
}

fn is_map(text: &str, form: &Range<usize>) -> bool {
    text.as_bytes().get(form.start) == Some(&b'{')
        && form.end > form.start
        && text.as_bytes().get(form.end - 1) == Some(&b'}')
}

fn mirror_url(text: &str, entry: &Range<usize>) -> Result<String, AdapterError> {
    let map = require_map(text, entry, "mirror")?;
    reject_credentials(text, &map, "mirror")?;
    let (_, url) = unique_entry(text, &map, ":url")?
        .ok_or_else(|| AdapterError::InvalidConfiguration("Leiningen mirror has no :url".into()))?;
    simple_string(text, &url).ok_or_else(|| {
        AdapterError::Unsupported("Leiningen mirror :url is not a simple string".into())
    })
}

fn reject_credentials(text: &str, map: &Range<usize>, name: &str) -> Result<(), AdapterError> {
    for key in [
        ":username",
        ":password",
        ":creds",
        ":passphrase",
        ":private-key-file",
    ] {
        if unique_entry(text, map, key)?.is_some() {
            return Err(AdapterError::Unsupported(format!(
                "Leiningen {name} mirror contains authentication material"
            )));
        }
    }
    Ok(())
}

fn simple_string(text: &str, form: &Range<usize>) -> Option<String> {
    let raw = text.get(form.clone())?;
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains(['\\', '\n', '\r'])).then(|| inner.to_owned())
}

fn apply_edits(text: &str, mut edits: Vec<(Range<usize>, String)>) -> Result<String, AdapterError> {
    edits.sort_by_key(|edit| Reverse(edit.0.start));
    for pair in edits.windows(2) {
        if pair[0].0.start < pair[1].0.end {
            return Err(AdapterError::InvalidConfiguration(
                "Leiningen profile edits overlap".into(),
            ));
        }
    }
    let mut output = text.to_owned();
    for (range, replacement) in edits {
        output.replace_range(range, &replacement);
    }
    Ok(output)
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<MirrorPair, AdapterError> {
    if selections.len() != 2 {
        return Err(AdapterError::InvalidConfiguration(
            "Leiningen plan requires one Maven and one Clojars selection".into(),
        ));
    }
    let maven = selection_base(selections, MAVEN_UPSTREAM, MAVEN_ENDPOINTS)?;
    let clojars = selection_base(selections, CLOJARS_UPSTREAM, CLOJARS_ENDPOINTS)?;
    Ok(MirrorPair { maven, clojars })
}

fn selection_base(
    selections: &[MirrorSelection],
    upstream: &str,
    allowed: &[&str],
) -> Result<String, AdapterError> {
    let selection = selections
        .iter()
        .find(|selection| selection.tool_id == "leiningen" && selection.upstream_id == upstream)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Leiningen selection is missing {upstream}"))
        })?;
    let mut bases = BTreeSet::new();
    for role in [
        EndpointRole::Index,
        EndpointRole::Metadata,
        EndpointRole::Artifacts,
    ] {
        let matches = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Leiningen {upstream} selection must contain exactly one HTTPS {role:?} endpoint"
            )));
        }
        bases.insert(normalized_base(&matches[0].url).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Leiningen {upstream} endpoint is unsafe"))
        })?);
    }
    if bases.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Leiningen {upstream} endpoint roles must use one repository base"
        )));
    }
    let selected = bases.into_iter().next().unwrap();
    let endpoint = allowed
        .iter()
        .find(|candidate| normalized_base(candidate).as_deref() == Some(&selected))
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "Leiningen {upstream} endpoints are not a reviewed repository"
            ))
        })?;
    let expected_provider = provider_for(endpoint).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Leiningen reviewed endpoint has no provider".into())
    })?;
    if selection.provider_id != expected_provider {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Leiningen {upstream} provider does not match its endpoint"
        )));
    }
    Ok((*endpoint).into())
}

fn provider_for(endpoint: &str) -> Option<&'static str> {
    match endpoint {
        "https://maven.aliyun.com/repository/public/" => Some("aliyun"),
        "https://repo.huaweicloud.com/repository/maven/"
        | "https://repo.huaweicloud.com/artifactory/maven-clojars-remote/" => Some("huaweicloud"),
        "https://repo.nju.edu.cn/maven/" | "https://mirrors.nju.edu.cn/clojars/" => Some("nju"),
        "https://mirrors.tuna.tsinghua.edu.cn/clojars/" => Some("tuna"),
        _ => None,
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
    Some(format!(
        "{}/",
        value.trim_end_matches('/').to_ascii_lowercase()
    ))
}

fn same_base(left: &str, right: &str) -> bool {
    normalized_base(left).is_some_and(|value| normalized_base(right).as_deref() == Some(&value))
}

fn official_urls(name: &str) -> &'static [&'static str] {
    match name {
        "central" => OFFICIAL_MAVEN,
        "clojars" => OFFICIAL_CLOJARS,
        _ => &[],
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
            "Leiningen current configuration must contain exactly one {format} document"
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

fn run_verification(
    context: &SystemContext,
    runtime: &dyn Runtime,
    layout: &Layout,
    task: &[&str],
) -> Result<String, AdapterError> {
    if context.os == OperatingSystem::Windows {
        let command = format!(
            "set \"LEIN_NO_USER_PROFILES=1\"&& set \"LEIN_SILENT=true\"&& lein {}",
            task.join(" ")
        );
        let output = runtime.run_in(
            &layout.verification_root,
            "cmd.exe",
            &["/D".into(), "/S".into(), "/C".into(), command],
        )?;
        return command_output(output, "Leiningen dependency/plugin verification");
    }
    let mut arguments = vec![
        "LEIN_NO_USER_PROFILES=1".into(),
        "LEIN_SILENT=true".into(),
        "lein".into(),
    ];
    arguments.extend(task.iter().map(|argument| (*argument).into()));
    let output = runtime.run_in(&layout.verification_root, "env", &arguments)?;
    command_output(output, "Leiningen dependency/plugin verification")
}

fn run_lein(
    runtime: &dyn Runtime,
    directory: Option<&Path>,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let environment = BTreeMap::from([
        ("LEIN_NO_USER_PROFILES".into(), "1".into()),
        ("LEIN_SILENT".into(), "true".into()),
    ]);
    let output = match directory {
        Some(directory) => {
            runtime.run_in_with_environment(directory, "lein", &arguments, &environment, &[])?
        }
        None => runtime.run_with_environment("lein", &arguments, &environment, &[])?,
    };
    command_output(output, label)
}

fn command_output(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    if !output.status.success() {
        let detail = failure_detail(&output)
            .map(|detail| format!("; detail: {detail}"))
            .unwrap_or_default();
        return Err(AdapterError::Runtime(format!(
            "{label} failed with status {}{detail}",
            output.status,
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stdout")))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 stderr")))?;
    Ok(format!("{stdout}\n{stderr}").trim().into())
}

fn failure_detail(output: &std::process::Output) -> Option<String> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            ![
                "http://",
                "https://",
                "password",
                "credential",
                "token",
                "secret",
                "authorization",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
        })
        .collect::<Vec<_>>();
    if let Some(line) = lines.iter().find(|line| {
        let lower = line.to_ascii_lowercase();
        ["error", "exception", "failed", "could not"]
            .iter()
            .any(|marker| lower.contains(marker))
    }) {
        return Some(line.chars().take(240).collect());
    }
    let start = lines.len().saturating_sub(2);
    (!lines.is_empty()).then(|| lines[start..].join(" ").chars().take(240).collect())
}

fn lein_version(output: &str) -> Result<String, AdapterError> {
    let version = output.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("Leiningen"))
            .then(|| words.next())
            .flatten()
            .filter(|value| valid_version(value))
            .map(str::to_owned)
    });
    version
        .ok_or_else(|| AdapterError::Unsupported("Leiningen version output is unrecognized".into()))
}

fn java_evidence(output: &str) -> String {
    output
        .lines()
        .find(|line| line.contains(" on Java "))
        .map(|line| format!("JDK reported by {}", line.trim()))
        .unwrap_or_else(|| "JDK version was not reported by Leiningen".into())
}

fn valid_version(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
        && value.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    if version.split('.').next() != Some("2") {
        return Err(AdapterError::Unsupported(format!(
            "Leiningen {version} is outside the reviewed 2.x repository model"
        )));
    }
    Ok(())
}

fn dependency_version(text: &str, package: &str) -> Option<String> {
    let start = text.find(&format!("[{package}"))?;
    let tail = &text[start + package.len() + 1..];
    let quote = tail.find('"')?;
    let value = &tail[quote + 1..];
    let end = value.find('"')?;
    (!value[..end].is_empty()).then(|| value[..end].into())
}

fn contains_credentials(text: &str) -> bool {
    [
        ":username",
        ":password",
        ":creds",
        ":passphrase",
        ":private-key-file",
    ]
    .into_iter()
    .any(|needle| text.contains(needle))
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("leiningen-snapshot:{value}"),
        enabled: true,
        metadata: BTreeMap::from([("kind".into(), vec![kind.into()])]),
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

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Leiningen source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Leiningen source has ambiguous {key} metadata"
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
            "Leiningen reported unsafe path {}",
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
            "Leiningen configuration {} is not UTF-8",
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
