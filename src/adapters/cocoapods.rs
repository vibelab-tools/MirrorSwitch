use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::{
    Adapter, AdapterError, Runtime,
    catalog::{CompositionPolicy, ConfigurationScope, DeliveryMode, EndpointRole, Protocol},
    context::{ExecutionEnvironment, OperatingSystem, SystemContext},
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration, DetectedTool,
        MirrorSelection, PlannedFileChange, RestoreResult, ServiceImpact, VerificationResult,
    },
    selection::{CompatibilityDimension, SelectionRequest},
    transaction::{ApplyOutcome, TransactionReceipt},
};

const SPECS_UPSTREAM: &str = "cocoapods--git-mirror";
const OFFICIAL_SPECS: &str = "https://github.com/CocoaPods/Specs.git";
const OFFICIAL_CDN: &str = "https://cdn.cocoapods.org";
const TUNA_SPECS: &str = "https://mirrors.tuna.tsinghua.edu.cn/git/CocoaPods/Specs.git";
const NJU_SPECS: &str = "https://mirrors.nju.edu.cn/git/CocoaPods/Specs.git";
const SAMPLE_SPEC: &str = "Specs/a/7/5/AFNetworking/4.0.1/AFNetworking.podspec.json";
const SAMPLE_NAME: &str = "AFNetworking";
const SAMPLE_VERSION: &str = "4.0.1";
const SAMPLE_SOURCE: &str = "https://github.com/AFNetworking/AFNetworking.git";

#[derive(Clone, Copy, Debug, Default)]
pub struct CocoaPodsAdapter;

impl Adapter for CocoaPodsAdapter {
    fn key(&self) -> &'static str {
        "cocoapods"
    }

    fn tool_id(&self) -> &'static str {
        "cocoapods"
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
        require_macos(context)?;
        if !runtime.command_exists("pod") {
            return Ok(None);
        }
        let pod_version =
            command_text(runtime.run("pod", &["--version".into()])?, "pod --version")?;
        reviewed_version(&pod_version)?;
        let ruby_version = if runtime.command_exists("ruby") {
            Some(command_text(
                runtime.run("ruby", &["--version".into()])?,
                "ruby --version",
            )?)
        } else {
            None
        };
        let repositories = repository_list(runtime)?;
        let public_git = repositories
            .iter()
            .filter(|repository| {
                repository.kind == RepositoryKind::Git && is_public_specs(&repository.url)
            })
            .count();
        let cdn = repositories
            .iter()
            .filter(|repository| repository.kind == RepositoryKind::Cdn)
            .count();
        let project = project_podfile(runtime)
            .map(|path| runtime.read(&path))
            .transpose()?
            .flatten()
            .is_some();
        let mut evidence = vec![
            format!("CocoaPods {pod_version}"),
            format!(
                "CocoaPods reports {} repositories: {public_git} public Git Specs, {cdn} CDN, {} other",
                repositories.len(),
                repositories.len().saturating_sub(public_git + cdn)
            ),
            if project {
                "project Podfile detected; project scope remains explicit".into()
            } else {
                "no project Podfile selected".into()
            },
        ];
        if let Some(version) = ruby_version {
            evidence.push(format!("Ruby runtime {version}"));
        }
        Ok(Some(DetectedTool {
            tool_id: "cocoapods".into(),
            executable: Some(PathBuf::from("pod")),
            version: Some(pod_version),
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
        require_macos(context)?;
        require_detected(runtime, detected)?;
        match scope {
            ConfigurationScope::User => read_user_configuration(runtime),
            ConfigurationScope::Project => read_project_configuration(runtime),
            _ => Err(AdapterError::Unsupported(
                "CocoaPods supports only user and explicit project scopes".into(),
            )),
        }
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_macos(context)?;
        if detected.tool_id != "cocoapods" || current.tool_id != "cocoapods" {
            return Err(AdapterError::InvalidConfiguration(
                "CocoaPods selection received another tool".into(),
            ));
        }
        validate_actionable_current(current)?;
        Ok(SelectionRequest {
            tool_id: "cocoapods".into(),
            adapter_key: "cocoapods".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![SPECS_UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::new(),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Git],
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
        require_macos(context)?;
        validate_actionable_current(current)?;
        let endpoint = selected_endpoint(selection)?;
        let document = &current.documents[0];
        let text = utf8(&document.path, &document.contents)?;
        let rendered = match current.scope {
            ConfigurationScope::User => rewrite_git_origin(text, &document.path, endpoint)?,
            ConfigurationScope::Project => rewrite_podfile(text, &document.path, endpoint)?,
            _ => unreachable!("actionable CocoaPods scope was validated"),
        };
        let changes = (rendered.as_bytes() != document.contents)
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &document.path),
                old_contents: Some(document.contents.clone()),
                old_mode: None,
                new_contents: rendered.into_bytes(),
                new_mode: None,
                summary: match current.scope {
                    ConfigurationScope::User => {
                        "change only the existing public CocoaPods Specs Git origin".into()
                    }
                    ConfigurationScope::Project => {
                        "change only the explicit public Specs source in Podfile".into()
                    }
                    _ => unreachable!(),
                },
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "cocoapods".into(),
            tool_id: "cocoapods".into(),
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
        if plan.adapter_key != "cocoapods" || plan.tool_id != "cocoapods" {
            return Err(AdapterError::InvalidConfiguration(
                "CocoaPods apply received another adapter's plan".into(),
            ));
        }
        runtime.apply_plan(plan)
    }

    fn verify(
        &self,
        context: &SystemContext,
        runtime: &mut dyn Runtime,
        receipt: &TransactionReceipt,
    ) -> Result<VerificationResult, AdapterError> {
        let scope = receipt
            .participants
            .iter()
            .find(|participant| participant.adapter_key == "cocoapods")
            .and_then(|_| {
                receipt.changed_targets.first().map(|target| {
                    if target.file_name().is_some_and(|name| name == "Podfile") {
                        ConfigurationScope::Project
                    } else {
                        ConfigurationScope::User
                    }
                })
            })
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("CocoaPods receipt has no adapter target".into())
            })?;
        let result = match scope {
            ConfigurationScope::User => verify_user(runtime),
            ConfigurationScope::Project => verify_project(runtime),
            _ => unreachable!(),
        };
        if let Err(error) = result {
            return verification_failure(runtime, receipt, error.to_string());
        }
        require_macos(context)?;
        Ok(VerificationResult {
            valid: true,
            summary: match scope {
                ConfigurationScope::User => {
                    "CocoaPods and Git read the selected Specs repository and representative podspec"
                        .into()
                }
                ConfigurationScope::Project => {
                    "CocoaPods parsed the Podfile and Git reached its selected Specs source".into()
                }
                _ => unreachable!(),
            },
        })
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
                "restored {} CocoaPods configuration file(s)",
                restored.restored_files
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryKind {
    Git,
    Cdn,
    Other,
}

#[derive(Clone, Debug)]
struct Repository {
    name: String,
    kind: RepositoryKind,
    url: String,
    path: PathBuf,
}

#[derive(Clone, Debug)]
struct PodfileSource {
    value_range: Range<usize>,
    url: String,
    position: usize,
}

fn require_macos(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Macos || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "CocoaPods mirror configuration requires a native macOS host".into(),
        ));
    }
    Ok(())
}

fn reviewed_version(version: &str) -> Result<(), AdapterError> {
    let mut components = version.trim().split('.');
    let major = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AdapterError::Unsupported(format!("unknown CocoaPods version {version}")))?;
    let minor = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AdapterError::Unsupported(format!("unknown CocoaPods version {version}")))?;
    if major == 1 && minor >= 8 {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "CocoaPods {version} is outside the reviewed 1.8+ source model"
        )))
    }
}

fn require_detected(runtime: &dyn Runtime, detected: &DetectedTool) -> Result<(), AdapterError> {
    if detected.tool_id != "cocoapods" {
        return Err(AdapterError::InvalidConfiguration(
            "CocoaPods read received another tool's detection".into(),
        ));
    }
    let version = command_text(runtime.run("pod", &["--version".into()])?, "pod --version")?;
    if detected.version.as_deref() != Some(&version) {
        return Err(AdapterError::Conflict(
            "CocoaPods version changed after detection".into(),
        ));
    }
    Ok(())
}

fn repository_list(runtime: &dyn Runtime) -> Result<Vec<Repository>, AdapterError> {
    let output = runtime.run("pod", &["repo".into(), "list".into(), "--no-ansi".into()])?;
    let text = command_text(output, "pod repo list")?;
    parse_repository_list(&text)
}

fn parse_repository_list(text: &str) -> Result<Vec<Repository>, AdapterError> {
    #[derive(Default)]
    struct Pending {
        name: String,
        kind: Option<RepositoryKind>,
        url: Option<String>,
        path: Option<PathBuf>,
    }

    fn finish(pending: &mut Pending, output: &mut Vec<Repository>) -> Result<(), AdapterError> {
        if pending.name.is_empty() {
            return Ok(());
        }
        let kind = pending.kind.take().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "CocoaPods repository {} has no type",
                pending.name
            ))
        })?;
        let url = pending.url.take().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "CocoaPods repository {} has no URL",
                pending.name
            ))
        })?;
        let path = pending.path.take().ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!(
                "CocoaPods repository {} has no path",
                pending.name
            ))
        })?;
        output.push(Repository {
            name: std::mem::take(&mut pending.name),
            kind,
            url,
            path,
        });
        Ok(())
    }

    let mut repositories = Vec::new();
    let mut pending = Pending::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || repository_count(line) {
            continue;
        }
        if let Some(value) = line.strip_prefix("- Type:") {
            pending.kind = Some(match value.trim().to_ascii_lowercase().as_str() {
                value if value.starts_with("git") => RepositoryKind::Git,
                "cdn" => RepositoryKind::Cdn,
                _ => RepositoryKind::Other,
            });
        } else if let Some(value) = line.strip_prefix("- URL:") {
            pending.url = Some(value.trim().into());
        } else if let Some(value) = line.strip_prefix("- Path:") {
            pending.path = Some(PathBuf::from(value.trim()));
        } else if line.starts_with('-') {
            return Err(AdapterError::InvalidConfiguration(
                "CocoaPods repo list contains an unknown field".into(),
            ));
        } else {
            finish(&mut pending, &mut repositories)?;
            if !safe_repository_name(line) {
                return Err(AdapterError::InvalidConfiguration(
                    "CocoaPods repo list contains an unsafe repository name".into(),
                ));
            }
            pending.name = line.into();
        }
    }
    finish(&mut pending, &mut repositories)?;
    Ok(repositories)
}

fn repository_count(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    fields
        .next()
        .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        && matches!(fields.next(), Some("repo" | "repos"))
        && fields.next().is_none()
}

fn safe_repository_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn read_user_configuration(runtime: &dyn Runtime) -> Result<CurrentConfiguration, AdapterError> {
    let repositories = repository_list(runtime)?;
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("CocoaPods user scope requires a home".into()))?;
    let repos_root = home.join(".cocoapods/repos");
    let mut sources = Vec::new();
    let mut files = Vec::new();
    let mut documents = Vec::new();
    for (position, repository) in repositories.iter().enumerate() {
        let public = is_public_specs(&repository.url);
        sources.push(ConfiguredSource {
            upstream_id: public.then(|| SPECS_UPSTREAM.into()),
            url: if public {
                repository.url.clone()
            } else if repository.kind == RepositoryKind::Cdn
                && normalize_url(&repository.url) == normalize_url(OFFICIAL_CDN)
            {
                format!("{OFFICIAL_CDN}/")
            } else {
                "redacted://private-cocoapods-source".into()
            },
            enabled: true,
            metadata: BTreeMap::from([
                (
                    "kind".into(),
                    vec![
                        match (repository.kind, public) {
                            (RepositoryKind::Git, true) => "public-git-specs",
                            (RepositoryKind::Cdn, _) => "cdn-read-only",
                            _ => "private-or-local-read-only",
                        }
                        .into(),
                    ],
                ),
                ("name".into(), vec![repository.name.clone()]),
                ("position".into(), vec![position.to_string()]),
            ]),
        });
        if repository.kind != RepositoryKind::Git || !public {
            continue;
        }
        let expected = repos_root.join(&repository.name);
        if repository.path != expected {
            return Err(AdapterError::Unsupported(format!(
                "public CocoaPods repository {} is outside the standard user repo directory",
                repository.name
            )));
        }
        let config = repository.path.join(".git/config");
        let contents = runtime.read(&config)?.ok_or_else(|| {
            AdapterError::Unsupported(format!(
                "public CocoaPods repository {} has no Git config",
                repository.name
            ))
        })?;
        let origin = git_origin(utf8(&config, &contents)?, &config)?;
        if normalize_url(&origin) != normalize_url(&repository.url) {
            return Err(AdapterError::Conflict(format!(
                "CocoaPods and Git disagree about repository {} origin",
                repository.name
            )));
        }
        validate_sample_spec(
            runtime
                .read(&repository.path.join(SAMPLE_SPEC))?
                .as_deref()
                .ok_or_else(|| {
                    AdapterError::Unsupported(format!(
                        "public CocoaPods repository {} lacks the representative podspec",
                        repository.name
                    ))
                })?,
        )?;
        files.push(config.clone());
        documents.push(ConfigurationDocument {
            path: config,
            format: "cocoapods-specs-git-config".into(),
            contents,
        });
    }
    Ok(CurrentConfiguration {
        tool_id: "cocoapods".into(),
        scope: ConfigurationScope::User,
        files,
        sources,
        documents,
    })
}

fn read_project_configuration(runtime: &dyn Runtime) -> Result<CurrentConfiguration, AdapterError> {
    let path = project_podfile(runtime).ok_or_else(|| {
        AdapterError::Unsupported("CocoaPods project scope requires a selected project".into())
    })?;
    let contents = runtime.read(&path)?.ok_or_else(|| {
        AdapterError::Unsupported(format!("CocoaPods project has no {}", path.display()))
    })?;
    let parsed = parse_podfile(utf8(&path, &contents)?, &path)?;
    let sources = parsed
        .iter()
        .map(|source| {
            let public = is_public_specs(&source.url);
            ConfiguredSource {
                upstream_id: public.then(|| SPECS_UPSTREAM.into()),
                url: if public {
                    source.url.clone()
                } else if normalize_url(&source.url) == normalize_url(OFFICIAL_CDN) {
                    format!("{OFFICIAL_CDN}/")
                } else {
                    "redacted://private-cocoapods-source".into()
                },
                enabled: true,
                metadata: BTreeMap::from([
                    (
                        "kind".into(),
                        vec![
                            if public {
                                "project-public-git-specs"
                            } else {
                                "project-private-or-cdn-read-only"
                            }
                            .into(),
                        ],
                    ),
                    ("position".into(), vec![source.position.to_string()]),
                ]),
            }
        })
        .collect();
    Ok(CurrentConfiguration {
        tool_id: "cocoapods".into(),
        scope: ConfigurationScope::Project,
        files: vec![path.clone()],
        sources,
        documents: vec![ConfigurationDocument {
            path,
            format: "cocoapods-podfile".into(),
            contents,
        }],
    })
}

fn validate_actionable_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "cocoapods"
        || !matches!(
            current.scope,
            ConfigurationScope::User | ConfigurationScope::Project
        )
        || current.documents.len() != 1
    {
        return Err(AdapterError::Unsupported(
            "CocoaPods needs exactly one existing public Specs Git configuration".into(),
        ));
    }
    let expected_kind = match current.scope {
        ConfigurationScope::User => "public-git-specs",
        ConfigurationScope::Project => "project-public-git-specs",
        _ => unreachable!(),
    };
    let public = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind") == Some(expected_kind))
        .collect::<Vec<_>>();
    if public.len() != 1 || !is_public_specs(&public[0].url) {
        return Err(AdapterError::Unsupported(
            "CocoaPods needs one unambiguous public Specs Git source; CDN-only and duplicate public sources stay unchanged"
                .into(),
        ));
    }
    Ok(())
}

fn parse_podfile(text: &str, path: &Path) -> Result<Vec<PodfileSource>, AdapterError> {
    let mut sources = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let leading = line.len() - line.trim_start().len();
        let active = &line[leading..];
        if active.starts_with('#') || active.is_empty() {
            offset += inclusive.len();
            continue;
        }
        let Some(after_source) = active.strip_prefix("source") else {
            offset += inclusive.len();
            continue;
        };
        if after_source
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            offset += inclusive.len();
            continue;
        }
        let after_source = after_source.trim_start();
        let (after_open, open_paren) = match after_source.strip_prefix('(') {
            Some(value) => (value.trim_start(), true),
            None => (after_source, false),
        };
        let quote = after_open
            .chars()
            .next()
            .filter(|value| matches!(value, '\'' | '"'));
        let Some(quote) = quote else {
            return Err(AdapterError::Unsupported(format!(
                "{} contains a dynamic CocoaPods source declaration",
                path.display()
            )));
        };
        let value_start_in_open = quote.len_utf8();
        let rest = &after_open[value_start_in_open..];
        let Some(value_end) = rest.find(quote) else {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} contains an unterminated CocoaPods source",
                path.display()
            )));
        };
        let url = &rest[..value_end];
        let tail = rest[value_end + quote.len_utf8()..].trim_start();
        let tail = if open_paren {
            tail.strip_prefix(')').ok_or_else(|| {
                AdapterError::InvalidConfiguration(format!(
                    "{} has an unterminated parenthesized CocoaPods source",
                    path.display()
                ))
            })?
        } else {
            tail
        };
        let tail = tail.trim_start();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err(AdapterError::Unsupported(format!(
                "{} contains a compound CocoaPods source declaration",
                path.display()
            )));
        }
        let open_offset = active.len() - after_open.len();
        let value_start = offset + leading + open_offset + value_start_in_open;
        sources.push(PodfileSource {
            value_range: value_start..value_start + url.len(),
            url: url.into(),
            position: sources.len(),
        });
        offset += inclusive.len();
    }
    Ok(sources)
}

fn rewrite_podfile(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    let public = parse_podfile(text, path)?
        .into_iter()
        .filter(|source| is_public_specs(&source.url))
        .collect::<Vec<_>>();
    if public.len() != 1 {
        return Err(AdapterError::Unsupported(
            "Podfile needs exactly one public Specs Git source".into(),
        ));
    }
    let mut output = text.to_owned();
    output.replace_range(public[0].value_range.clone(), endpoint);
    Ok(output)
}

fn git_origin(text: &str, path: &Path) -> Result<String, AdapterError> {
    let mut in_origin = false;
    let mut origin = None;
    for line in text.lines() {
        let active = line.trim();
        if active.starts_with('[') {
            in_origin = active.eq_ignore_ascii_case("[remote \"origin\"]");
            continue;
        }
        if in_origin
            && let Some((key, value)) = active.split_once('=')
            && key.trim().eq_ignore_ascii_case("url")
            && origin.replace(value.trim().to_owned()).is_some()
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "{} contains duplicate CocoaPods origin URLs",
                path.display()
            )));
        }
    }
    origin.ok_or_else(|| {
        AdapterError::Unsupported(format!(
            "{} does not contain an origin remote",
            path.display()
        ))
    })
}

fn rewrite_git_origin(text: &str, path: &Path, endpoint: &str) -> Result<String, AdapterError> {
    git_origin(text, path)?;
    let mut in_origin = false;
    let mut replaced = false;
    let mut output = String::with_capacity(text.len() + endpoint.len());
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        let ending = &line[content.len()..];
        let active = content.trim();
        if active.starts_with('[') {
            in_origin = active.eq_ignore_ascii_case("[remote \"origin\"]");
        }
        if in_origin
            && let Some((key, _)) = active.split_once('=')
            && key.trim().eq_ignore_ascii_case("url")
        {
            let indent = &content[..content.len() - content.trim_start().len()];
            output.push_str(indent);
            output.push_str("url = ");
            output.push_str(endpoint);
            output.push_str(ending);
            replaced = true;
        } else {
            output.push_str(line);
        }
    }
    if replaced {
        Ok(output)
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "{} origin could not be rewritten",
            path.display()
        )))
    }
}

fn verify_user(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let repositories = repository_list(runtime)?;
    let public = repositories
        .iter()
        .filter(|repository| {
            repository.kind == RepositoryKind::Git && is_supported_mirror(&repository.url)
        })
        .collect::<Vec<_>>();
    if public.len() != 1 {
        return Err(AdapterError::Verification(
            "CocoaPods does not report exactly one selected public Specs mirror".into(),
        ));
    }
    let repository = public[0];
    command_success(
        runtime.run(
            "git",
            &[
                "-C".into(),
                repository.path.display().to_string(),
                "ls-remote".into(),
                "--exit-code".into(),
                "origin".into(),
                "HEAD".into(),
            ],
        )?,
        "git ls-remote CocoaPods Specs",
    )?;
    let spec = runtime.run(
        "git",
        &[
            "-C".into(),
            repository.path.display().to_string(),
            "show".into(),
            format!("HEAD:{SAMPLE_SPEC}"),
        ],
    )?;
    command_success(spec.clone(), "git show representative CocoaPods podspec")?;
    validate_sample_spec(&spec.stdout)?;
    command_success(
        runtime.run(
            "pod",
            &[
                "ipc".into(),
                "spec".into(),
                repository.path.join(SAMPLE_SPEC).display().to_string(),
            ],
        )?,
        "pod ipc spec",
    )?;
    verify_sample_source(runtime)
}

fn verify_project(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    let path = project_podfile(runtime).ok_or_else(|| {
        AdapterError::Verification("CocoaPods project disappeared after apply".into())
    })?;
    let contents = runtime
        .read(&path)?
        .ok_or_else(|| AdapterError::Verification("Podfile disappeared after apply".into()))?;
    let public = parse_podfile(utf8(&path, &contents)?, &path)?
        .into_iter()
        .filter(|source| is_supported_mirror(&source.url))
        .collect::<Vec<_>>();
    if public.len() != 1 {
        return Err(AdapterError::Verification(
            "Podfile does not contain exactly one selected Specs mirror".into(),
        ));
    }
    command_success(
        runtime.run(
            "git",
            &[
                "ls-remote".into(),
                "--exit-code".into(),
                public[0].url.clone(),
                "HEAD".into(),
            ],
        )?,
        "git ls-remote Podfile Specs source",
    )?;
    command_success(
        runtime.run(
            "pod",
            &["ipc".into(), "podfile".into(), path.display().to_string()],
        )?,
        "pod ipc podfile",
    )?;
    verify_sample_source(runtime)
}

fn verify_sample_source(runtime: &dyn Runtime) -> Result<(), AdapterError> {
    command_success(
        runtime.run(
            "git",
            &[
                "ls-remote".into(),
                "--exit-code".into(),
                SAMPLE_SOURCE.into(),
                format!("refs/tags/{SAMPLE_VERSION}"),
            ],
        )?,
        "git ls-remote representative pod source",
    )
}

fn validate_sample_spec(contents: &[u8]) -> Result<(), AdapterError> {
    let spec: Value = serde_json::from_slice(contents).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "representative CocoaPods podspec is invalid JSON: {error}"
        ))
    })?;
    let source = spec.get("source").and_then(Value::as_object);
    if spec.get("name").and_then(Value::as_str) != Some(SAMPLE_NAME)
        || spec.get("version").and_then(Value::as_str) != Some(SAMPLE_VERSION)
        || source
            .and_then(|source| source.get("git"))
            .and_then(Value::as_str)
            != Some(SAMPLE_SOURCE)
        || source
            .and_then(|source| source.get("tag"))
            .and_then(Value::as_str)
            != Some(SAMPLE_VERSION)
    {
        return Err(AdapterError::InvalidConfiguration(
            "representative CocoaPods podspec has unexpected identity or source metadata".into(),
        ));
    }
    Ok(())
}

fn selected_endpoint(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| {
            selection.tool_id == "cocoapods" && selection.upstream_id == SPECS_UPSTREAM
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "CocoaPods plan requires exactly one Specs selection".into(),
        ));
    }
    let endpoint = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| endpoint.role == EndpointRole::Git && endpoint.protocol == Protocol::Https)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration(
                "CocoaPods selection has no HTTPS Git endpoint".into(),
            )
        })?;
    if !is_supported_mirror(&endpoint.url) {
        return Err(AdapterError::InvalidConfiguration(
            "CocoaPods selection is not a reviewed Specs Git mirror".into(),
        ));
    }
    Ok(endpoint.url.trim_end_matches('/'))
}

fn project_podfile(runtime: &dyn Runtime) -> Option<PathBuf> {
    runtime.project_dir().map(|project| project.join("Podfile"))
}

fn is_public_specs(url: &str) -> bool {
    normalize_url(url) == normalize_url(OFFICIAL_SPECS) || is_supported_mirror(url)
}

fn is_supported_mirror(url: &str) -> bool {
    [TUNA_SPECS, NJU_SPECS]
        .iter()
        .any(|candidate| normalize_url(url) == normalize_url(candidate))
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Option<&'a str> {
    source
        .metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn command_text(output: std::process::Output, label: &str) -> Result<String, AdapterError> {
    command_success(output.clone(), label)?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| AdapterError::Runtime(format!("{label} returned non-UTF-8 output")))
}

fn command_success(output: std::process::Output, label: &str) -> Result<(), AdapterError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(AdapterError::Runtime(format!(
            "{label} failed with status {}",
            output.status
        )))
    }
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

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "CocoaPods configuration {} is not UTF-8",
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
