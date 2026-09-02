use std::{
    collections::BTreeMap,
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

const MANAGED_BEGIN: &str = ";; >>> MirrorSwitch Emacs package archives >>>";
const MANAGED_END: &str = ";; <<< MirrorSwitch Emacs package archives <<<";

#[derive(Clone, Copy)]
struct ArchiveSpec {
    name: &'static str,
    upstream: &'static str,
}

const ARCHIVES: &[ArchiveSpec] = &[
    ArchiveSpec {
        name: "gnu",
        upstream: "gnu-elpa--language-registry",
    },
    ArchiveSpec {
        name: "nongnu",
        upstream: "nongnu-elpa--language-registry",
    },
    ArchiveSpec {
        name: "melpa",
        upstream: "melpa--language-registry",
    },
];

#[derive(Clone, Copy, Debug, Default)]
pub struct ElpaAdapter;

impl Adapter for ElpaAdapter {
    fn key(&self) -> &'static str {
        "elpa"
    }

    fn tool_id(&self) -> &'static str {
        "elpa"
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
        if !runtime.command_exists("emacs") {
            return Ok(None);
        }
        let version = emacs_version(runtime)?;
        review_version(&version)?;
        let layout = layout(runtime)?;
        let contents = runtime.read(&layout.init)?.unwrap_or_default();
        let observation = inspect_init(&layout.init, utf8(&layout.init, &contents)?)?;
        Ok(Some(DetectedTool {
            tool_id: "elpa".into(),
            executable: Some(PathBuf::from("emacs")),
            version: Some(version.clone()),
            evidence: vec![
                format!("GNU Emacs {version}"),
                format!("selected init file is {}", layout.init.display()),
                format!(
                    "literal archive URLs observed: {}",
                    observation.archive_urls
                ),
                format!(
                    "custom-file references observed: {}",
                    observation.custom_files
                ),
                format!(
                    "package-archive-priorities references observed: {}",
                    observation.priority_references
                ),
                format!(
                    "managed package archive block present: {}",
                    observation.managed
                ),
                "GNU/NonGNU signatures are required when published; MELPA is upstream-unsigned"
                    .into(),
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
        if detected.tool_id != "elpa" {
            return Err(AdapterError::InvalidConfiguration(
                "ELPA read received another tool's detection result".into(),
            ));
        }
        let version = emacs_version(runtime)?;
        review_version(&version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Emacs version changed after detection".into(),
            ));
        }
        let layout = layout(runtime)?;
        let contents = runtime.read(&layout.init)?;
        let exists = contents.is_some();
        let contents = contents.unwrap_or_default();
        let text = utf8(&layout.init, &contents)?;
        let observation = inspect_init(&layout.init, text)?;
        let mut sources = vec![snapshot_source("emacs-version", &version)];
        if observation.archive_urls > 0 {
            sources.push(policy_source("user-archives-preserved", &layout.init));
        }
        if observation.custom_files > 0 {
            sources.push(policy_source("custom-file-preserved", &layout.init));
        }
        if observation.priority_references > 0 {
            sources.push(policy_source("archive-priorities-preserved", &layout.init));
        }
        if observation.managed {
            sources.push(policy_source("managed-archive-block", &layout.init));
        }
        Ok(CurrentConfiguration {
            tool_id: "elpa".into(),
            scope,
            files: exists.then_some(layout.init.clone()).into_iter().collect(),
            sources,
            documents: vec![ConfigurationDocument {
                path: layout.init,
                format: "emacs-init".into(),
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
        require_linux(context)?;
        require_current(current)?;
        review_version(detected.version.as_deref().ok_or_else(|| {
            AdapterError::InvalidConfiguration("Emacs version is missing".into())
        })?)?;
        Ok(SelectionRequest {
            tool_id: "elpa".into(),
            adapter_key: "elpa".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: ARCHIVES
                .iter()
                .map(|archive| archive.upstream.into())
                .collect(),
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
                EndpointRole::Packages,
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
        let endpoints = selected_archives(selections)?;
        let init = find_document(current, "emacs-init")?;
        let rendered =
            rewrite_init(utf8(&init.path, &init.contents)?, &init.path, &endpoints)?.into_bytes();
        let changes = if init.contents == rendered {
            Vec::new()
        } else {
            vec![PlannedFileChange {
                target: rooted(&context.root, &init.path),
                old_contents: current
                    .files
                    .contains(&init.path)
                    .then(|| init.contents.clone()),
                old_mode: None,
                new_contents: rendered,
                new_mode: None,
                summary: "insert one managed package.el block that retargets GNU, NonGNU, and MELPA independently while preserving custom archives and priorities".into(),
            }]
        };
        Ok(ChangePlan {
            adapter_key: "elpa".into(),
            tool_id: "elpa".into(),
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
            let layout = layout(runtime)?;
            let target = rooted(&context.root, &layout.init);
            if !receipt.changed_targets.contains(&target) {
                return Err(AdapterError::Verification(
                    "ELPA transaction contains no known target".into(),
                ));
            }
            let contents = runtime
                .read(&layout.init)?
                .ok_or_else(|| AdapterError::Verification("Emacs init file disappeared".into()))?;
            let text = utf8(&layout.init, &contents)?;
            let range = managed_range(text, &layout.init)?.ok_or_else(|| {
                AdapterError::Verification("managed ELPA block is missing".into())
            })?;
            let endpoints = managed_endpoints(&text[range], &layout.init)?;
            let script = verification_script(&layout, &endpoints)?;
            let output = run_emacs(
                runtime,
                &["--batch", "-Q", "--eval", &script],
                "Emacs package refresh",
            )?;
            if !output.contains("MIRRORSWITCH_ELPA_VERIFY=gnu,nongnu,melpa") {
                return Err(AdapterError::Verification(
                    "Emacs did not refresh all three selected archives".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Emacs refreshed GNU, NonGNU, and MELPA independently into {}",
                    layout.verification_dir.display()
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
                "restored {} Emacs init files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

struct Layout {
    init: PathBuf,
    verification_dir: PathBuf,
}

struct InitObservation {
    archive_urls: usize,
    custom_files: usize,
    priority_references: usize,
    managed: bool,
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "ELPA v0.1 supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::User {
        return Err(AdapterError::Unsupported(
            "ELPA adapter supports user scope only".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "elpa" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "ELPA operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("ELPA requires a user home".into()))?;
    validate_path(&home, "home")?;
    let xdg = runtime
        .environment_variable("XDG_CONFIG_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    validate_path(&xdg, "XDG_CONFIG_HOME")?;
    let candidates = [
        home.join(".emacs"),
        home.join(".emacs.el"),
        home.join(".emacs.d/init.el"),
        xdg.join("emacs/init.el"),
    ];
    let mut existing = Vec::new();
    for path in candidates {
        if runtime.read(&path)?.is_some() {
            existing.push(path);
        }
    }
    if existing.len() > 1 {
        return Err(AdapterError::Unsupported(
            "multiple Emacs init candidates exist; select one before configuring ELPA".into(),
        ));
    }
    let init = existing.into_iter().next().unwrap_or_else(|| {
        if runtime.environment_variable("XDG_CONFIG_HOME").is_some() {
            xdg.join("emacs/init.el")
        } else {
            home.join(".emacs.d/init.el")
        }
    });
    validate_user_path(&init, &home, "init file")?;
    Ok(Layout {
        init,
        verification_dir: home.join(".mirrorswitch/verification/emacs/elpa"),
    })
}

fn inspect_init(path: &Path, text: &str) -> Result<InitObservation, AdapterError> {
    let managed = managed_range(text, path)?.is_some();
    Ok(InitObservation {
        archive_urls: text.matches("https://").count(),
        custom_files: text.matches("custom-file").count(),
        priority_references: text.matches("package-archive-priorities").count(),
        managed,
    })
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
            "ELPA managed markers in {} are missing, duplicated, or out of order",
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

fn rewrite_init(
    text: &str,
    path: &Path,
    endpoints: &BTreeMap<String, String>,
) -> Result<String, AdapterError> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let block = render_block(endpoints, newline)?;
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

fn render_block(
    endpoints: &BTreeMap<String, String>,
    newline: &str,
) -> Result<String, AdapterError> {
    let endpoint = |name: &str| {
        endpoints.get(name).ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("ELPA selection lacks {name}"))
        })
    };
    Ok(format!(
        "{MANAGED_BEGIN}{newline}(require 'package){newline}(dolist (archive (reverse '((\"gnu\" . \"{}\"){newline}                                      (\"nongnu\" . \"{}\"){newline}                                      (\"melpa\" . \"{}\")))){newline}  (setf (alist-get (car archive) package-archives nil nil #'string=){newline}        (cdr archive))){newline}{MANAGED_END}{newline}",
        endpoint("gnu")?,
        endpoint("nongnu")?,
        endpoint("melpa")?,
    ))
}

fn managed_endpoints(block: &str, path: &Path) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut endpoints = BTreeMap::new();
    for archive in ARCHIVES {
        let needle = format!("(\"{}\" . \"", archive.name);
        let after = block
            .split_once(&needle)
            .map(|(_, after)| after)
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "managed ELPA block in {} lacks {}",
                    path.display(),
                    archive.name
                ))
            })?;
        let endpoint = after.split('"').next().unwrap_or_default();
        if !valid_endpoint(endpoint, archive.name) {
            return Err(AdapterError::InvalidConfiguration(format!(
                "managed {} endpoint is invalid",
                archive.name
            )));
        }
        endpoints.insert(archive.name.into(), endpoint.into());
    }
    Ok(endpoints)
}

fn selected_archives(
    selections: &[MirrorSelection],
) -> Result<BTreeMap<String, String>, AdapterError> {
    if selections.len() != ARCHIVES.len() {
        return Err(AdapterError::InvalidConfiguration(
            "ELPA requires three independent archive selections".into(),
        ));
    }
    let mut result = BTreeMap::new();
    for archive in ARCHIVES {
        let matches = selections
            .iter()
            .filter(|selection| {
                selection.tool_id == "elpa" && selection.upstream_id == archive.upstream
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "ELPA requires one {} selection",
                archive.name
            )));
        }
        let selection = matches[0];
        let role_url = |role| -> Result<String, AdapterError> {
            let endpoints = selection
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
                .collect::<Vec<_>>();
            if endpoints.len() != 1 {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "{} selection needs one HTTPS {role:?} endpoint",
                    archive.name
                )));
            }
            normalized_endpoint(&endpoints[0].url).ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!("{} endpoint is unsafe", archive.name))
            })
        };
        let index = role_url(EndpointRole::Index)?;
        if role_url(EndpointRole::Metadata)? != index || role_url(EndpointRole::Packages)? != index
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} index, metadata, and package endpoints differ",
                archive.name
            )));
        }
        if !valid_endpoint(&index, archive.name) {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} endpoint is not a reviewed mirror",
                archive.name
            )));
        }
        result.insert(archive.name.into(), index);
    }
    Ok(result)
}

fn valid_endpoint(value: &str, archive: &str) -> bool {
    [
        "https://mirrors.nju.edu.cn/elpa",
        "https://mirrors.tuna.tsinghua.edu.cn/elpa",
        "https://mirrors.ustc.edu.cn/elpa",
    ]
    .iter()
    .any(|root| value == format!("{root}/{archive}/"))
}

fn normalized_endpoint(value: &str) -> Option<String> {
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

fn verification_script(
    layout: &Layout,
    endpoints: &BTreeMap<String, String>,
) -> Result<String, AdapterError> {
    let directory = path_string(&layout.verification_dir)?;
    let endpoint = |name: &str| {
        endpoints
            .get(name)
            .ok_or_else(|| AdapterError::Verification(format!("ELPA verification lacks {name}")))
    };
    Ok(format!(
        "(progn (require 'package) (setq package-user-dir \"{directory}\" package-check-signature 'allow-unsigned package-archives '((\"gnu\" . \"{}\") (\"nongnu\" . \"{}\") (\"melpa\" . \"{}\"))) (package-refresh-contents) (dolist (name '(\"gnu\" \"nongnu\" \"melpa\")) (unless (file-exists-p (expand-file-name (concat \"archives/\" name \"/archive-contents\") package-user-dir)) (error \"archive missing: %s\" name))) (princ \"MIRRORSWITCH_ELPA_VERIFY=gnu,nongnu,melpa\"))",
        endpoint("gnu")?,
        endpoint("nongnu")?,
        endpoint("melpa")?,
    ))
}

fn emacs_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = run_emacs(runtime, &["--version"], "emacs --version")?;
    output
        .split_whitespace()
        .find(|token| {
            token
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
                && token.contains('.')
        })
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("Emacs version output is invalid".into()))
}

fn review_version(version: &str) -> Result<(), AdapterError> {
    let major = version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    if !matches!(major, Some(27..=31)) {
        return Err(AdapterError::Unsupported(format!(
            "Emacs {version} is outside reviewed package.el versions 27 through 31"
        )));
    }
    Ok(())
}

fn run_emacs(
    runtime: &dyn Runtime,
    arguments: &[&str],
    label: &str,
) -> Result<String, AdapterError> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    let output = runtime.run("emacs", &arguments)?;
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
    current
        .documents
        .iter()
        .find(|document| document.format == format)
        .ok_or_else(|| AdapterError::InvalidConfiguration("Emacs init document is missing".into()))
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("elpa-snapshot:{value}"),
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

fn path_string(path: &Path) -> Result<&str, AdapterError> {
    path.to_str().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("path {} is not UTF-8", path.display()))
    })
}

fn validate_user_path(path: &Path, home: &Path, kind: &str) -> Result<(), AdapterError> {
    validate_path(path, kind)?;
    if !path.starts_with(home) || path == home {
        return Err(AdapterError::Unsupported(format!(
            "Emacs {kind} {} is outside the user home",
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
            "Emacs {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!("Emacs init {} is not UTF-8", path.display()))
    })
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id).is_ok();
    Err(AdapterError::Verification(format!(
        "{reason}; Emacs init restored: {restored}"
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
