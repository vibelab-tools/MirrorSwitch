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

const REPOSITORY_UPSTREAM: &str = "opam-repository--git-mirror";
const CACHE_UPSTREAM: &str = "opam-cache--binary-cache";
const NJU_REPOSITORY: &str = "https://mirrors.nju.edu.cn/git/opam-repository.git";
const NJU_REPOSITORY_CONFIG: &str = "git+https://mirrors.nju.edu.cn/git/opam-repository.git";
const SJTUG_CACHE: &str = "https://mirror.sjtu.edu.cn/opam-cache";
const REPOSITORY_REVISION: &str = "da8b7e6fa7491ffc5dc8eee7f8f60452a1b26ce7";
const CACHE_SHA256: &str = "61f0b75950614ac5378c6ec0d822cce6463402d919d5810b736fc46522b3a73e";
const CACHE_PATH: &str =
    "sha256/61/61f0b75950614ac5378c6ec0d822cce6463402d919d5810b736fc46522b3a73e";

#[derive(Clone, Copy, Debug, Default)]
pub struct OpamAdapter;

impl Adapter for OpamAdapter {
    fn key(&self) -> &'static str {
        "opam"
    }

    fn tool_id(&self) -> &'static str {
        "opam"
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
        if !runtime.command_exists("opam") {
            return Ok(None);
        }
        for command in ["curl", native_digest_command(context), "git"] {
            if !runtime.command_exists(command) {
                return Err(AdapterError::Unsupported(format!(
                    "opam mirror verification requires {command}"
                )));
            }
        }
        let layout = layout(runtime)?;
        require_initialized(runtime, &layout)?;
        let version = opam_version(runtime)?;
        review_version(context, &version)?;
        let repositories = parse_repositories(
            utf8(
                &layout.repos_config,
                &runtime.read(&layout.repos_config)?.unwrap(),
            )?,
            &layout.repos_config,
        )?;
        let switch = optional_opam_query(runtime, &layout.root, &["switch", "show", "--safe"]);
        let ocaml = optional_opam_query(runtime, &layout.root, &["var", "ocaml-version", "--safe"]);
        Ok(Some(DetectedTool {
            tool_id: "opam".into(),
            executable: Some(PathBuf::from("opam")),
            version: Some(version.clone()),
            evidence: vec![
                format!("opam {version}"),
                format!(
                    "native platform is {:?} {:?}",
                    context.os, context.architecture
                ),
                format!("opam root is {}", layout.root.display()),
                format!("configured repositories: {}", repositories.entries),
                format!(
                    "current switch is {}",
                    switch
                        .as_deref()
                        .filter(|value| !value.is_empty())
                        .unwrap_or("unset")
                ),
                format!(
                    "current OCaml version is {}",
                    ocaml
                        .as_deref()
                        .filter(|value| !value.is_empty())
                        .unwrap_or("unset")
                ),
                format!(
                    "download cache is {}",
                    layout.root.join("download-cache").display()
                ),
                format!(
                    "OPAMROOT is {}",
                    if runtime.environment_variable("OPAMROOT").is_some() {
                        "explicit"
                    } else {
                        "default"
                    }
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
        if scope != ConfigurationScope::User {
            return Err(AdapterError::Unsupported(
                "opam adapter supports user scope only".into(),
            ));
        }
        if detected.tool_id != "opam" {
            return Err(AdapterError::InvalidConfiguration(
                "opam read received another tool's detection result".into(),
            ));
        }
        let version = opam_version(runtime)?;
        review_version(context, &version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "opam version changed after detection".into(),
            ));
        }
        let layout = layout(runtime)?;
        require_initialized(runtime, &layout)?;
        let config = runtime.read(&layout.config)?.unwrap();
        let repos = runtime.read(&layout.repos_config)?.unwrap();
        let parsed_repos =
            parse_repositories(utf8(&layout.repos_config, &repos)?, &layout.repos_config)?;
        let parsed_config = parse_config(utf8(&layout.config, &config)?, &layout.config)?;
        let mut files = vec![layout.config.clone(), layout.repos_config.clone()];
        let mut sources = vec![snapshot_source("opam-version", &version)];
        sources.push(if is_public_repository(&parsed_repos.default_url) {
            configured_source(
                &parsed_repos.default_url,
                REPOSITORY_UPSTREAM,
                "default-repository",
                &layout.repos_config,
            )
        } else {
            policy_source("private-default-repository", &layout.repos_config)
        });
        for mirror in &parsed_config.archive_mirrors {
            sources.push(if is_public_cache(mirror) {
                configured_source(mirror, CACHE_UPSTREAM, "archive-mirror", &layout.config)
            } else {
                policy_source("private-archive-mirror-preserved", &layout.config)
            });
        }
        if parsed_config.custom_download_command {
            sources.push(policy_source("custom-download-command", &layout.config));
        }
        if runtime
            .environment_variable("OPAMFETCH")
            .is_some_and(|value| !value.trim().is_empty())
        {
            sources.push(policy_source(
                "custom-fetch-environment",
                Path::new(":env:"),
            ));
        }
        let mut documents = vec![
            ConfigurationDocument {
                path: layout.config.clone(),
                format: "opam-global-config".into(),
                contents: config,
            },
            ConfigurationDocument {
                path: layout.repos_config.clone(),
                format: "opam-repositories-config".into(),
                contents: repos,
            },
        ];
        add_project_documents(runtime, &mut files, &mut sources, &mut documents)?;
        let manifest = runtime.read(&layout.verification_manifest)?;
        let manifest_exists = manifest.is_some();
        let manifest = manifest.unwrap_or_default();
        if manifest_exists {
            files.push(layout.verification_manifest.clone());
            if utf8(&layout.verification_manifest, &manifest)? != render_manifest() {
                sources.push(policy_source(
                    "verification-conflict",
                    &layout.verification_manifest,
                ));
            }
        }
        documents.push(ConfigurationDocument {
            path: layout.verification_manifest,
            format: "opam-verification-manifest".into(),
            contents: manifest,
        });
        Ok(CurrentConfiguration {
            tool_id: "opam".into(),
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
        Ok(SelectionRequest {
            tool_id: "opam".into(),
            adapter_key: "opam".into(),
            context: context.clone(),
            tool_version: None,
            required_upstreams: vec![REPOSITORY_UPSTREAM.into(), CACHE_UPSTREAM.into()],
            repository_versions: BTreeMap::from([(
                REPOSITORY_UPSTREAM.into(),
                REPOSITORY_REVISION.into(),
            )]),
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
        selected_endpoints(selections)?;
        let config = find_document(current, "opam-global-config")?;
        let repos = find_document(current, "opam-repositories-config")?;
        let manifest = find_document(current, "opam-verification-manifest")?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            repos,
            preserve_bom(
                &repos.contents,
                rewrite_repositories(utf8(&repos.path, &repos.contents)?, &repos.path)?
                    .into_bytes(),
            ),
            "retarget only the official default opam repository while preserving anchors and order",
            &mut changes,
        );
        add_change(
            context,
            current,
            config,
            preserve_bom(
                &config.contents,
                rewrite_config(utf8(&config.path, &config.contents)?, &config.path)?.into_bytes(),
            ),
            "append the reviewed checksum-keyed archive mirror while preserving download policy",
            &mut changes,
        );
        add_change(
            context,
            current,
            manifest,
            render_manifest().into_bytes(),
            "create a fixed opam repository and cache verification manifest",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "opam".into(),
            tool_id: "opam".into(),
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
            let known = [
                rooted(&context.root, &layout.config),
                rooted(&context.root, &layout.repos_config),
                rooted(&context.root, &layout.verification_manifest),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if !receipt
                .changed_targets
                .iter()
                .any(|target| known.contains(target))
            {
                return Err(AdapterError::Verification(
                    "opam transaction receipt contains no known target".into(),
                ));
            }
            let repos = runtime.read(&layout.repos_config)?.ok_or_else(|| {
                AdapterError::Verification("opam repositories config disappeared".into())
            })?;
            let parsed_repos =
                parse_repositories(utf8(&layout.repos_config, &repos)?, &layout.repos_config)?;
            if normalized_repository(&parsed_repos.default_url).as_deref()
                != normalized_repository(NJU_REPOSITORY_CONFIG).as_deref()
            {
                return Err(AdapterError::Verification(
                    "opam default repository is not bound to NJU".into(),
                ));
            }
            let config = runtime.read(&layout.config)?.ok_or_else(|| {
                AdapterError::Verification("opam global config disappeared".into())
            })?;
            let parsed_config = parse_config(utf8(&layout.config, &config)?, &layout.config)?;
            if !parsed_config
                .archive_mirrors
                .iter()
                .any(|mirror| same_http_base(mirror, SJTUG_CACHE))
            {
                return Err(AdapterError::Verification(
                    "opam archive mirror is not bound to SJTUG".into(),
                ));
            }
            let manifest = runtime
                .read(&layout.verification_manifest)?
                .ok_or_else(|| {
                    AdapterError::Verification("opam verification manifest disappeared".into())
                })?;
            if utf8(&layout.verification_manifest, &manifest)? != render_manifest() {
                return Err(AdapterError::Verification(
                    "opam verification manifest is not canonical".into(),
                ));
            }
            verify_opam(runtime, &layout, &receipt.transaction_id)?;
            verify_cache(context, runtime, &layout)?;
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "opam updated default at {REPOSITORY_REVISION} and verified cache {CACHE_SHA256}"
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
                "restored {} opam configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

struct Layout {
    root: PathBuf,
    config: PathBuf,
    repos_config: PathBuf,
    verification_root: PathBuf,
    verification_manifest: PathBuf,
    verification_archive: PathBuf,
}

struct ParsedRepositories {
    default_url: String,
    default_url_range: Range<usize>,
    entries: usize,
}

struct ParsedConfig {
    archive_mirrors: Vec<String>,
    archive_range: Option<Range<usize>>,
    insert_at: usize,
    custom_download_command: bool,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux && context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "opam on macOS and Windows requires a native host".into(),
        ));
    }
    if context.os == OperatingSystem::Windows && context.architecture == Architecture::Arm64 {
        return Err(AdapterError::Unsupported(
            "opam on Windows arm64 is unavailable because opam publishes no native Windows arm64 executable"
                .into(),
        ));
    }
    if !matches!(
        context.architecture,
        Architecture::X86_64 | Architecture::Arm64
    ) {
        return Err(AdapterError::Unsupported(
            "opam requires x86_64 or arm64".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "opam" || current.scope != ConfigurationScope::User {
        return Err(AdapterError::InvalidConfiguration(
            "opam operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn layout(runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let home = runtime
        .home_dir()
        .ok_or_else(|| AdapterError::Unsupported("opam requires a user home".into()))?;
    validate_path(&home, "home")?;
    let root = runtime
        .environment_variable("OPAMROOT")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| reported_opam_root(runtime))?;
    validate_path(&root, "root")?;
    let verification_root = home.join(".mirrorswitch/verification/opam");
    Ok(Layout {
        config: root.join("config"),
        repos_config: root.join("repo/repos-config"),
        verification_manifest: verification_root.join("sources.txt"),
        verification_archive: verification_root.join("stdio.v0.16.0.tar.gz"),
        verification_root,
        root,
    })
}

fn reported_opam_root(runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    let output = command_output(
        runtime.run("opam", &["var".into(), "root".into(), "--safe".into()])?,
        "opam var root --safe",
    )?;
    let root = PathBuf::from(output.trim());
    validate_path(&root, "reported root")?;
    Ok(root)
}

fn require_initialized(runtime: &dyn Runtime, layout: &Layout) -> Result<(), AdapterError> {
    if runtime.read(&layout.config)?.is_none() || runtime.read(&layout.repos_config)?.is_none() {
        return Err(AdapterError::Unsupported(
            "opam root is not initialized or lacks repository configuration".into(),
        ));
    }
    Ok(())
}

fn opam_version(runtime: &dyn Runtime) -> Result<String, AdapterError> {
    let output = command_output(
        runtime.run("opam", &["--version".into()])?,
        "opam --version",
    )?;
    let version = output.trim();
    if !valid_version(version) {
        return Err(AdapterError::Unsupported(
            "opam version is unrecognized".into(),
        ));
    }
    Ok(version.into())
}

fn review_version(context: &SystemContext, value: &str) -> Result<(), AdapterError> {
    let major = value
        .split('.')
        .next()
        .and_then(|part| part.parse::<u64>().ok());
    let minor = value
        .split('.')
        .nth(1)
        .and_then(|part| part.parse::<u64>().ok());
    let minimum_minor = if context.os == OperatingSystem::Windows {
        2
    } else {
        1
    };
    if major != Some(2) || minor.is_none_or(|minor| minor < minimum_minor) {
        return Err(AdapterError::Unsupported(format!(
            "opam {value} is outside the reviewed opam 2.{minimum_minor}+ format for {:?}",
            context.os
        )));
    }
    Ok(())
}

fn native_digest_command(context: &SystemContext) -> &'static str {
    match context.os {
        OperatingSystem::Linux => "sha256sum",
        OperatingSystem::Macos => "shasum",
        OperatingSystem::Windows => "certutil.exe",
    }
}

fn valid_version(value: &str) -> bool {
    value.split('.').count() >= 2
        && value.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
}

fn optional_opam_query(runtime: &dyn Runtime, root: &Path, args: &[&str]) -> Option<String> {
    let environment = BTreeMap::from([
        ("OPAMROOT".into(), root.display().to_string()),
        ("OPAMROOTISOK".into(), "1".into()),
    ]);
    let arguments = args.iter().map(|arg| (*arg).into()).collect::<Vec<_>>();
    runtime
        .run_with_environment("opam", &arguments, &environment, &[])
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
}

fn parse_repositories(text: &str, path: &Path) -> Result<ParsedRepositories, AdapterError> {
    if !text.contains("opam-version: \"2.0\"") {
        return Err(AdapterError::Unsupported(
            "opam repositories config is not format 2.0".into(),
        ));
    }
    let marker = "\"default\" {";
    let positions = text
        .match_indices(marker)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opam config {} must contain one default repository",
            path.display()
        )));
    }
    let start = positions[0] + marker.len();
    let remainder = &text[start..];
    let quote = remainder.find('"').ok_or_else(|| {
        AdapterError::InvalidConfiguration("default opam repository URL is missing".into())
    })?;
    let value_start = start + quote + 1;
    let end = text[value_start..].find('"').ok_or_else(|| {
        AdapterError::InvalidConfiguration("default opam repository URL is unterminated".into())
    })? + value_start;
    let value = &text[value_start..end];
    validate_repository_url(value)?;
    let entries = text
        .matches("} ")
        .count()
        .max(text.matches("}\n").count())
        .max(1);
    Ok(ParsedRepositories {
        default_url: value.into(),
        default_url_range: value_start..end,
        entries,
    })
}

fn rewrite_repositories(text: &str, path: &Path) -> Result<String, AdapterError> {
    let parsed = parse_repositories(text, path)?;
    if !is_public_repository(&parsed.default_url) {
        return Err(AdapterError::Unsupported(
            "private default opam repository cannot be replaced".into(),
        ));
    }
    let mut output = text.to_owned();
    output.replace_range(parsed.default_url_range, NJU_REPOSITORY_CONFIG);
    Ok(output)
}

fn parse_config(text: &str, path: &Path) -> Result<ParsedConfig, AdapterError> {
    if !text.contains("opam-version: \"2.0\"") {
        return Err(AdapterError::Unsupported(
            "opam global config is not format 2.0".into(),
        ));
    }
    let custom_download_command = line_spans(text)
        .map(|(_, line)| active_line(line))
        .any(|line| line.starts_with("download-command:"));
    let fields = line_spans(text)
        .filter(|(_, line)| active_line(line).starts_with("archive-mirrors:"))
        .collect::<Vec<_>>();
    if fields.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opam config {} assigns archive-mirrors more than once",
            path.display()
        )));
    }
    let insert_at = line_spans(text)
        .find(|(_, line)| active_line(line).starts_with("opam-root-version:"))
        .map(|(start, line)| start + line.len())
        .unwrap_or_else(|| text.find('\n').map_or(0, |index| index + 1));
    let Some((start, first)) = fields.first().copied() else {
        return Ok(ParsedConfig {
            archive_mirrors: Vec::new(),
            archive_range: None,
            insert_at,
            custom_download_command,
        });
    };
    let mut end = start + first.len();
    if active_line(first).contains('[') && !active_line(first).contains(']') {
        let (relative, line) = line_spans(&text[start..])
            .find(|(_, line)| active_line(line).contains(']'))
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "opam archive-mirrors list is not terminated".into(),
                )
            })?;
        end = start + relative + line.len();
    }
    let block = &text[start..end];
    let values = quoted_values(block)?;
    Ok(ParsedConfig {
        archive_mirrors: values,
        archive_range: Some(start..end),
        insert_at,
        custom_download_command,
    })
}

fn rewrite_config(text: &str, path: &Path) -> Result<String, AdapterError> {
    let parsed = parse_config(text, path)?;
    if parsed.custom_download_command {
        return Err(AdapterError::Unsupported(
            "custom opam download-command bypasses archive mirror policy".into(),
        ));
    }
    let mut mirrors = parsed
        .archive_mirrors
        .into_iter()
        .filter(|mirror| !is_official_cache(mirror) && !same_http_base(mirror, SJTUG_CACHE))
        .collect::<Vec<_>>();
    mirrors.push(SJTUG_CACHE.into());
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let rendered = format!(
        "archive-mirrors: [{}]{newline}",
        mirrors
            .iter()
            .map(|mirror| format!("\"{mirror}\""))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut output = text.to_owned();
    match parsed.archive_range {
        Some(range) => output.replace_range(range, &rendered),
        None => output.insert_str(parsed.insert_at, &rendered),
    }
    Ok(output)
}

fn quoted_values(block: &str) -> Result<Vec<String>, AdapterError> {
    let mut values = Vec::new();
    let mut remainder = block;
    while let Some(start) = remainder.find('"') {
        let value = &remainder[start + 1..];
        let end = value.find('"').ok_or_else(|| {
            AdapterError::InvalidConfiguration("opam string is unterminated".into())
        })?;
        let value = &value[..end];
        if value.contains(['\n', '\r', '\\']) {
            return Err(AdapterError::Unsupported(
                "dynamic or escaped archive mirror is not supported".into(),
            ));
        }
        values.push(value.into());
        remainder = &remainder[start + end + 2..];
    }
    Ok(values)
}

fn selected_endpoints(selections: &[MirrorSelection]) -> Result<(), AdapterError> {
    for (upstream, provider, endpoint) in [
        (REPOSITORY_UPSTREAM, "nju", NJU_REPOSITORY),
        (CACHE_UPSTREAM, "sjtug", SJTUG_CACHE),
    ] {
        let matches = selections
            .iter()
            .filter(|selection| selection.tool_id == "opam" && selection.upstream_id == upstream)
            .collect::<Vec<_>>();
        if matches.len() != 1 || matches[0].provider_id != provider {
            return Err(AdapterError::InvalidConfiguration(format!(
                "opam requires one reviewed {upstream} selection"
            )));
        }
        let mut bases = BTreeSet::new();
        for role in [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ] {
            let endpoints = matches[0]
                .endpoints
                .iter()
                .filter(|item| item.role == role && item.protocol == Protocol::Https)
                .collect::<Vec<_>>();
            if endpoints.len() != 1 {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "opam {upstream} requires one HTTPS {role:?} endpoint"
                )));
            }
            bases.insert(normalized_http(&endpoints[0].url).ok_or_else(|| {
                AdapterError::InvalidConfiguration("opam endpoint is unsafe".into())
            })?);
        }
        if bases.len() != 1 || normalized_http(endpoint).as_ref() != bases.iter().next() {
            return Err(AdapterError::InvalidConfiguration(format!(
                "opam {upstream} roles do not match the reviewed endpoint"
            )));
        }
    }
    Ok(())
}

fn verify_opam(
    runtime: &dyn Runtime,
    layout: &Layout,
    transaction_id: &str,
) -> Result<(), AdapterError> {
    let environment = BTreeMap::from([
        ("OPAMROOT".into(), layout.root.display().to_string()),
        ("OPAMROOTISOK".into(), "1".into()),
        ("OPAMYES".into(), "1".into()),
    ]);
    let list = vec![
        "repository".into(),
        "list".into(),
        "--all".into(),
        "--short".into(),
    ];
    let output = command_output(
        runtime.run_with_environment("opam", &list, &environment, &[])?,
        "opam repository list",
    )?;
    if !output.lines().any(|line| line.trim() == "default") {
        return Err(AdapterError::Verification(
            "opam did not list the default repository".into(),
        ));
    }
    let update = vec!["update".into(), "default".into()];
    command_output(
        runtime.run_with_environment("opam", &update, &environment, &[])?,
        "opam update default",
    )?;
    let source_dir = layout
        .verification_root
        .join(format!("stdio-source-{transaction_id}"));
    let source = vec![
        "source".into(),
        "stdio.v0.16.0".into(),
        format!("--dir={}", source_dir.display()),
    ];
    command_output(
        runtime.run_with_environment("opam", &source, &environment, &[])?,
        "opam source stdio.v0.16.0",
    )?;
    Ok(())
}

fn verify_cache(
    context: &SystemContext,
    runtime: &dyn Runtime,
    layout: &Layout,
) -> Result<(), AdapterError> {
    let archive = path_text(&layout.verification_archive, "archive")?;
    let arguments = vec![
        "--fail".into(),
        "--location".into(),
        "--silent".into(),
        "--show-error".into(),
        "--output".into(),
        archive.into(),
        format!("{SJTUG_CACHE}/{CACHE_PATH}"),
    ];
    command_output(
        runtime.run("curl", &arguments)?,
        "opam archive cache download",
    )?;
    let (program, digest_arguments) = match context.os {
        OperatingSystem::Linux => ("sha256sum", vec![archive.into()]),
        OperatingSystem::Macos => ("shasum", vec!["-a".into(), "256".into(), archive.into()]),
        OperatingSystem::Windows => (
            "certutil.exe",
            vec!["-hashfile".into(), archive.into(), "SHA256".into()],
        ),
    };
    let output = command_output(
        runtime.run(program, &digest_arguments)?,
        "opam archive cache checksum",
    )?;
    if !output
        .split_whitespace()
        .any(|value| value.eq_ignore_ascii_case(CACHE_SHA256))
    {
        return Err(AdapterError::Verification(
            "opam archive cache checksum does not match its path".into(),
        ));
    }
    Ok(())
}

fn add_project_documents(
    runtime: &dyn Runtime,
    files: &mut Vec<PathBuf>,
    sources: &mut Vec<ConfiguredSource>,
    documents: &mut Vec<ConfigurationDocument>,
) -> Result<(), AdapterError> {
    let Some(project) = runtime.project_dir() else {
        return Ok(());
    };
    validate_path(&project, "project")?;
    for name in [".opam-switch/switch-config", "opam.locked"] {
        let path = project.join(name);
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        files.push(path.clone());
        sources.push(policy_source("project-state-preserved", &path));
        documents.push(ConfigurationDocument {
            path,
            format: "opam-project-state-observed".into(),
            contents,
        });
    }
    Ok(())
}

fn render_manifest() -> String {
    format!(
        "repository_revision={REPOSITORY_REVISION}\ncache_sha256={CACHE_SHA256}\npackage=stdio.v0.16.0\n"
    )
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "private-default-repository" => {
                return Err(AdapterError::Unsupported(
                    "private default opam repository cannot be replaced".into(),
                ));
            }
            "custom-download-command" | "custom-fetch-environment" => {
                return Err(AdapterError::Unsupported(
                    "custom opam fetch policy bypasses archive mirrors".into(),
                ));
            }
            "verification-conflict" => {
                return Err(AdapterError::Unsupported(
                    "opam verification target contains data not managed by MirrorSwitch".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_repository_url(value: &str) -> Result<(), AdapterError> {
    normalized_repository(value).ok_or_else(|| {
        AdapterError::InvalidConfiguration("opam repository URL is unsafe".into())
    })?;
    Ok(())
}

fn normalized_repository(value: &str) -> Option<String> {
    let value = value.strip_prefix("git+").unwrap_or(value);
    normalized_http(value)
}

fn normalized_http(value: &str) -> Option<String> {
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

fn is_public_repository(value: &str) -> bool {
    normalized_repository(value).is_some_and(|value| {
        matches!(
            value.as_str(),
            "https://opam.ocaml.org"
                | "https://github.com/ocaml/opam-repository.git"
                | NJU_REPOSITORY
        )
    })
}

fn same_http_base(left: &str, right: &str) -> bool {
    normalized_http(left).is_some_and(|left| normalized_http(right).as_deref() == Some(&left))
}

fn is_official_cache(value: &str) -> bool {
    same_http_base(value, "https://opam.ocaml.org/cache")
}

fn is_public_cache(value: &str) -> bool {
    is_official_cache(value) || same_http_base(value, SJTUG_CACHE)
}

fn active_line(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim()
}

fn line_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, line)
    })
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
            "opam current configuration must contain exactly one {format} document"
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

fn configured_source(value: &str, upstream: &str, kind: &str, path: &Path) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: Some(upstream.into()),
        url: normalized_repository(value)
            .or_else(|| normalized_http(value))
            .unwrap_or_else(|| "<preserved>".into()),
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
        url: "opam-snapshot:<redacted>".into(),
        enabled: true,
        metadata: BTreeMap::from([
            ("kind".into(), vec![kind.into()]),
            ("value".into(), vec![value.into()]),
        ]),
    }
}

fn metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("opam source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opam source has ambiguous {key} metadata"
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

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "opam reported unsafe {kind} path {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, kind: &str) -> Result<&'a str, AdapterError> {
    path.to_str()
        .ok_or_else(|| AdapterError::Verification(format!("opam {kind} path is not UTF-8")))
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    let contents = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents);
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "opam configuration {} is not UTF-8",
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
