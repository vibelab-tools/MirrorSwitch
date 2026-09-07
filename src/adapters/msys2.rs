use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
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

const UPSTREAM: &str = "msys2--static-files";
const MSYS_PACKAGE: &str = "filesystem-2026.03.06-1-x86_64.pkg.tar.zst";
const MSYS_PACKAGE_SHA256: &str =
    "4506b2dbb496281b7645ee2b2d3700f6a2fab3d74a800733f3b3b44eeb8edc5c";
const MSYS_SIGNATURE_SHA256: &str =
    "4f2b4f21dea6b268317998a84ed7ee50c78d4d45a548b1167d9a78e43c3862f2";
const MIRROR_ROOTS: &[&str] = &[
    "https://mirrors.aliyun.com/msys2",
    "https://repo.huaweicloud.com/msys2",
    "https://mirror.nju.edu.cn/msys2",
    "https://mirrors.sjtug.sjtu.edu.cn/msys2",
    "https://mirrors.tuna.tsinghua.edu.cn/msys2",
    "https://mirrors.ustc.edu.cn/msys2",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct Msys2Adapter;

impl Adapter for Msys2Adapter {
    fn key(&self) -> &'static str {
        "msys2"
    }

    fn tool_id(&self) -> &'static str {
        "msys2"
    }

    fn supported_scopes(&self) -> &'static [ConfigurationScope] {
        &[ConfigurationScope::System]
    }

    fn default_scope(&self) -> ConfigurationScope {
        ConfigurationScope::System
    }

    fn composition_policy(&self) -> CompositionPolicy {
        CompositionPolicy::Single
    }

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        require_windows(context)?;
        let layout = layout(context, runtime)?;
        let has_config = runtime.read(&layout.pacman_config)?.is_some();
        let program = layout.pacman.display().to_string();
        let has_pacman = runtime.command_exists(&program);
        if !has_config && !has_pacman {
            return Ok(None);
        }
        if !has_config || !has_pacman {
            return Err(AdapterError::Unsupported(
                "MSYS2 requires both pacman.exe and etc/pacman.conf".into(),
            ));
        }
        let version = pacman_version(runtime, &program)?;
        let config = runtime.read(&layout.pacman_config)?.unwrap();
        let repositories =
            validate_pacman_config(utf8(&layout.pacman_config, &config)?, &layout.repository)?;
        Ok(Some(DetectedTool {
            tool_id: "msys2".into(),
            executable: Some(layout.pacman),
            version: Some(version.clone()),
            evidence: vec![
                format!("MSYS2 Pacman {version}"),
                format!("MSYS2 root is {}", layout.root.display()),
                format!("effective subsystem is {}", layout.subsystem),
                format!(
                    "signed repositories include msys and {} ({} enabled sections)",
                    layout.repository,
                    repositories.len()
                ),
                "MSYS2 mirrorlists are installation-local and independent from Arch Linux".into(),
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
        require_windows(context)?;
        if scope != ConfigurationScope::System {
            return Err(AdapterError::Unsupported(
                "MSYS2 mirrorlists are installation-scoped".into(),
            ));
        }
        let layout = layout(context, runtime)?;
        let program = layout.pacman.display().to_string();
        if detected.tool_id != "msys2"
            || detected.version.as_deref() != Some(&pacman_version(runtime, &program)?)
        {
            return Err(AdapterError::Conflict(
                "MSYS2 Pacman identity or version changed after detection".into(),
            ));
        }
        let config = runtime.read(&layout.pacman_config)?.ok_or_else(|| {
            AdapterError::InvalidConfiguration("MSYS2 pacman.conf disappeared".into())
        })?;
        validate_pacman_config(utf8(&layout.pacman_config, &config)?, &layout.repository)?;
        let msys_contents = runtime.read(&layout.msys_mirrorlist)?.ok_or_else(|| {
            AdapterError::InvalidConfiguration("MSYS2 mirrorlist.msys is missing".into())
        })?;
        let mingw_contents = runtime.read(&layout.mingw_mirrorlist)?.ok_or_else(|| {
            AdapterError::InvalidConfiguration("MSYS2 mirrorlist.mingw is missing".into())
        })?;
        let msys = parse_mirrorlist(
            utf8(&layout.msys_mirrorlist, &msys_contents)?,
            MirrorKind::Msys,
        )?;
        let mingw = parse_mirrorlist(
            utf8(&layout.mingw_mirrorlist, &mingw_contents)?,
            MirrorKind::Mingw,
        )?;
        require_public_anchor(&msys, MirrorKind::Msys)?;
        require_public_anchor(&mingw, MirrorKind::Mingw)?;
        let probe = package_probe(context.architecture, &layout.repository)?;
        let mut sources = mirror_sources(&layout.msys_mirrorlist, &msys, "msys");
        sources.extend(mirror_sources(
            &layout.mingw_mirrorlist,
            &mingw,
            &layout.repository,
        ));
        let probe_metadata = BTreeMap::from([
            ("msys_arch".into(), vec!["x86_64".into()]),
            ("msys_package".into(), vec![MSYS_PACKAGE.into()]),
            (
                "msys_package_digest".into(),
                vec![MSYS_PACKAGE_SHA256.into()],
            ),
            (
                "msys_signature_digest".into(),
                vec![MSYS_SIGNATURE_SHA256.into()],
            ),
            ("mingw_repo".into(), vec![layout.repository.clone()]),
            ("mingw_package".into(), vec![probe.package.into()]),
            (
                "mingw_package_digest".into(),
                vec![probe.package_sha256.into()],
            ),
            (
                "mingw_signature_digest".into(),
                vec![probe.signature_sha256.into()],
            ),
        ]);
        sources.push(ConfiguredSource {
            upstream_id: Some(UPSTREAM.into()),
            url: "msys2://probe-context".into(),
            enabled: false,
            metadata: probe_metadata,
        });
        Ok(CurrentConfiguration {
            tool_id: "msys2".into(),
            scope,
            files: vec![
                layout.msys_mirrorlist.clone(),
                layout.mingw_mirrorlist.clone(),
            ],
            sources,
            documents: vec![
                ConfigurationDocument {
                    path: layout.msys_mirrorlist,
                    format: "msys2-mirrorlist-msys".into(),
                    contents: msys_contents,
                },
                ConfigurationDocument {
                    path: layout.mingw_mirrorlist,
                    format: "msys2-mirrorlist-mingw".into(),
                    contents: mingw_contents,
                },
            ],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_windows(context)?;
        require_current(current)?;
        let probe = current
            .sources
            .iter()
            .find(|source| source.url == "msys2://probe-context")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("MSYS2 probe context is missing".into())
            })?;
        let mut values = BTreeMap::new();
        for key in [
            "msys_arch",
            "msys_package",
            "msys_package_digest",
            "msys_signature_digest",
            "mingw_repo",
            "mingw_package",
            "mingw_package_digest",
            "mingw_signature_digest",
        ] {
            values.insert(key.into(), single_metadata(probe, key)?.into());
        }
        Ok(SelectionRequest {
            tool_id: "msys2".into(),
            adapter_key: "msys2".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams: vec![UPSTREAM.into()],
            repository_versions: BTreeMap::new(),
            probe_contexts: BTreeMap::from([(UPSTREAM.into(), vec![values])]),
            required_compatibility_evidence: vec![
                CompatibilityDimension::OperatingSystem,
                CompatibilityDimension::Architecture,
                CompatibilityDimension::Environment,
            ],
            require_distribution: false,
            allowed_protocols: vec![Protocol::Https],
            required_endpoint_roles: vec![EndpointRole::Metadata, EndpointRole::Artifacts],
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
        require_windows(context)?;
        require_current(current)?;
        let endpoint = selected_root(selection)?;
        let mut changes = Vec::new();
        for document in &current.documents {
            let kind = match document.format.as_str() {
                "msys2-mirrorlist-msys" => MirrorKind::Msys,
                "msys2-mirrorlist-mingw" => MirrorKind::Mingw,
                _ => {
                    return Err(AdapterError::InvalidConfiguration(
                        "MSYS2 plan received an unknown mirrorlist".into(),
                    ));
                }
            };
            let server = match kind {
                MirrorKind::Msys => format!("{endpoint}/msys/$arch/"),
                MirrorKind::Mingw => format!("{endpoint}/mingw/$repo/"),
            };
            let rendered =
                prioritize_server(utf8(&document.path, &document.contents)?, kind, &server)?
                    .into_bytes();
            if rendered != document.contents {
                changes.push(PlannedFileChange {
                    target: rooted(&context.root, &document.path),
                    old_contents: Some(document.contents.clone()),
                    old_mode: None,
                    new_contents: rendered,
                    new_mode: None,
                    summary: format!(
                        "prioritize the selected MSYS2 {} mirror while preserving fallbacks",
                        kind.name()
                    ),
                });
            }
        }
        Ok(ChangePlan {
            adapter_key: "msys2".into(),
            tool_id: "msys2".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
            service_impact: ServiceImpact::None,
        })
    }

    fn apply(
        &self,
        _context: &SystemContext,
        runtime: &mut dyn Runtime,
        plan: &ChangePlan,
    ) -> Result<ApplyOutcome, AdapterError> {
        if plan.adapter_key != "msys2" || plan.tool_id != "msys2" {
            return Err(AdapterError::InvalidConfiguration(
                "MSYS2 apply received another adapter's plan".into(),
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
        let layout = layout(context, runtime)?;
        let result = (|| {
            for (path, kind) in [
                (&layout.msys_mirrorlist, MirrorKind::Msys),
                (&layout.mingw_mirrorlist, MirrorKind::Mingw),
            ] {
                let contents = runtime.read(path)?.ok_or_else(|| {
                    AdapterError::Verification(format!("{} disappeared", path.display()))
                })?;
                let entries = parse_mirrorlist(utf8(path, &contents)?, kind)?;
                let first = entries
                    .iter()
                    .find(|entry| is_public_anchor(&entry.url, kind))
                    .ok_or_else(|| {
                        AdapterError::Verification(format!(
                            "MSYS2 {} mirrorlist has no public server",
                            kind.name()
                        ))
                    })?;
                if !is_reviewed_mirror(&first.url) {
                    return Err(AdapterError::Verification(format!(
                        "MSYS2 {} mirrorlist did not prioritize the selected mirror",
                        kind.name()
                    )));
                }
            }
            let program = layout.pacman.display().to_string();
            let package = package_probe(context.architecture, &layout.repository)?.query_name;
            for (arguments, label) in [
                (
                    vec!["-Syy".into(), "--noconfirm".into()],
                    "MSYS2 pacman refresh",
                ),
                (
                    vec!["-Si".into(), "filesystem".into()],
                    "MSYS2 filesystem query",
                ),
                (
                    vec!["-Si".into(), package.into()],
                    "MSYS2 MinGW package query",
                ),
                (
                    vec!["-Sw".into(), "--noconfirm".into(), package.into()],
                    "MSYS2 signed package download",
                ),
            ] {
                command_success(runtime.run(&program, &arguments)?, label)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            return verification_failure(runtime, receipt, error.to_string());
        }
        Ok(VerificationResult {
            valid: true,
            summary: format!(
                "MSYS2 refreshed signed databases and downloaded a signed {} package",
                layout.repository
            ),
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
                "restored {} MSYS2 mirrorlist file(s)",
                restored.restored_files
            ),
        })
    }
}

struct Layout {
    root: PathBuf,
    pacman: PathBuf,
    pacman_config: PathBuf,
    msys_mirrorlist: PathBuf,
    mingw_mirrorlist: PathBuf,
    subsystem: String,
    repository: String,
}

#[derive(Clone, Copy)]
struct PackageProbe {
    package: &'static str,
    package_sha256: &'static str,
    signature_sha256: &'static str,
    query_name: &'static str,
}

#[derive(Clone, Copy)]
enum MirrorKind {
    Msys,
    Mingw,
}

impl MirrorKind {
    fn name(self) -> &'static str {
        match self {
            Self::Msys => "msys",
            Self::Mingw => "mingw",
        }
    }
}

struct ServerLine {
    range: Range<usize>,
    url: String,
}

fn require_windows(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Windows || context.environment != ExecutionEnvironment::Host {
        return Err(AdapterError::Unsupported(
            "MSYS2 adapter requires a native Windows host".into(),
        ));
    }
    let version = context
        .distribution
        .as_ref()
        .and_then(|distribution| distribution.version_id.as_deref());
    if let Some(version) = version {
        let numbers = version
            .split(|character: char| !character.is_ascii_digit())
            .filter(|value| !value.is_empty())
            .filter_map(|value| value.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if numbers.len() < 3 || numbers[0] != 10 || numbers[1] != 0 || numbers[2] < 17_763 {
            return Err(AdapterError::Unsupported(format!(
                "MSYS2 requires Windows 10 1809 / build 17763 or later, observed {version}"
            )));
        }
        if context.architecture == Architecture::Arm64 && numbers[2] < 22_000 {
            return Err(AdapterError::Unsupported(
                "MSYS2 ARM64 requires Windows 11 x64 emulation".into(),
            ));
        }
    }
    Ok(())
}

fn layout(context: &SystemContext, runtime: &dyn Runtime) -> Result<Layout, AdapterError> {
    let root = runtime
        .environment_variable("MSYS2_ROOT")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_root);
    if !root.is_absolute() {
        return Err(AdapterError::InvalidConfiguration(
            "MSYS2_ROOT must be absolute".into(),
        ));
    }
    let subsystem = runtime
        .environment_variable("MSYSTEM")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match context.architecture {
            Architecture::X86_64 => "UCRT64".into(),
            Architecture::Arm64 => "CLANGARM64".into(),
        })
        .to_ascii_uppercase();
    let repository = match (context.architecture, subsystem.as_str()) {
        (Architecture::Arm64, "CLANGARM64" | "MSYS") => "clangarm64",
        (Architecture::X86_64, "MINGW32") => "mingw32",
        (Architecture::X86_64, "MINGW64") => "mingw64",
        (Architecture::X86_64, "UCRT64" | "MSYS") => "ucrt64",
        (Architecture::X86_64, "CLANG32") => "clang32",
        (Architecture::X86_64, "CLANG64") => "clang64",
        _ => {
            return Err(AdapterError::Unsupported(format!(
                "MSYS2 subsystem {subsystem} does not match the Windows architecture"
            )));
        }
    }
    .to_owned();
    Ok(Layout {
        pacman: root.join("usr").join("bin").join("pacman.exe"),
        pacman_config: root.join("etc").join("pacman.conf"),
        msys_mirrorlist: root.join("etc").join("pacman.d").join("mirrorlist.msys"),
        mingw_mirrorlist: root.join("etc").join("pacman.d").join("mirrorlist.mingw"),
        root,
        subsystem,
        repository,
    })
}

fn default_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\msys64")
    } else {
        PathBuf::from("/msys64")
    }
}

fn pacman_version(runtime: &dyn Runtime, program: &str) -> Result<String, AdapterError> {
    let text = command_text(
        runtime.run(program, &["--version".into()])?,
        "MSYS2 pacman --version",
    )?;
    text.lines()
        .find(|line| line.contains("Pacman"))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Runtime("pacman version output is unknown".into()))
}

fn validate_pacman_config(
    text: &str,
    representative: &str,
) -> Result<BTreeSet<String>, AdapterError> {
    let mut section = String::new();
    let mut sig_level = None;
    let mut repositories = BTreeSet::new();
    for line in text.lines() {
        let active = line.split('#').next().unwrap_or("").trim();
        if active.starts_with('[') && active.ends_with(']') {
            section = active[1..active.len() - 1].to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = active.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if section == "options"
            && key == "siglevel"
            && sig_level.replace(value.to_owned()).is_some()
        {
            return Err(AdapterError::InvalidConfiguration(
                "MSYS2 pacman.conf has multiple global SigLevel settings".into(),
            ));
        }
        if key == "include" && value.ends_with("mirrorlist.msys") && section == "msys" {
            repositories.insert(section.clone());
        }
        if key == "include" && value.ends_with("mirrorlist.mingw") {
            repositories.insert(section.clone());
        }
    }
    let sig_level = sig_level.ok_or_else(|| {
        AdapterError::InvalidConfiguration("MSYS2 pacman.conf has no global SigLevel".into())
    })?;
    let normalized = sig_level.to_ascii_lowercase();
    if !normalized
        .split_whitespace()
        .any(|value| value == "required")
        || normalized
            .split_whitespace()
            .any(|value| matches!(value, "never" | "trustall"))
    {
        return Err(AdapterError::Unsupported(
            "MSYS2 package signature verification is not required".into(),
        ));
    }
    if !repositories.contains("msys") || !repositories.contains(representative) {
        return Err(AdapterError::Unsupported(format!(
            "MSYS2 pacman.conf does not enable msys and {representative}"
        )));
    }
    Ok(repositories)
}

fn parse_mirrorlist(text: &str, kind: MirrorKind) -> Result<Vec<ServerLine>, AdapterError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    for inclusive in text.split_inclusive('\n') {
        let line = inclusive.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if !trimmed.starts_with('#')
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("Server")
        {
            let url = value.trim();
            let placeholder = match kind {
                MirrorKind::Msys => "$arch",
                MirrorKind::Mingw => "$repo",
            };
            let valid = reqwest::Url::parse(url).is_ok_and(|parsed| {
                parsed.scheme() == "https"
                    && parsed.host_str().is_some()
                    && parsed.path_segments().is_some_and(|segments| {
                        segments.into_iter().any(|part| part == placeholder)
                    })
            });
            if !valid {
                return Err(AdapterError::Unsupported(format!(
                    "MSYS2 {} mirrorlist contains an unsupported active server",
                    kind.name()
                )));
            }
            entries.push(ServerLine {
                range: offset..offset + inclusive.len(),
                url: url.into(),
            });
        }
        offset += inclusive.len();
    }
    if entries.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "MSYS2 {} mirrorlist has no active HTTPS servers",
            kind.name()
        )));
    }
    Ok(entries)
}

fn require_public_anchor(entries: &[ServerLine], kind: MirrorKind) -> Result<(), AdapterError> {
    if entries
        .iter()
        .any(|entry| is_public_anchor(&entry.url, kind))
    {
        Ok(())
    } else {
        Err(AdapterError::Unsupported(format!(
            "MSYS2 {} mirrorlist has no recognized official anchor",
            kind.name()
        )))
    }
}

fn prioritize_server(text: &str, kind: MirrorKind, selected: &str) -> Result<String, AdapterError> {
    let entries = parse_mirrorlist(text, kind)?;
    require_public_anchor(&entries, kind)?;
    let anchor = entries
        .iter()
        .find(|entry| is_public_anchor(&entry.url, kind))
        .unwrap();
    if normalize_url(&anchor.url) == normalize_url(selected)
        && entries
            .iter()
            .filter(|entry| normalize_url(&entry.url) == normalize_url(selected))
            .count()
            == 1
    {
        return Ok(text.into());
    }
    let mut output = text.to_owned();
    for entry in entries.iter().rev() {
        if normalize_url(&entry.url) == normalize_url(selected) {
            output.replace_range(entry.range.clone(), "");
        }
    }
    let entries = parse_mirrorlist(&output, kind)?;
    let anchor = entries
        .iter()
        .find(|entry| is_public_anchor(&entry.url, kind))
        .unwrap();
    let line_ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
    output.insert_str(
        anchor.range.start,
        &format!("Server = {selected}{line_ending}"),
    );
    Ok(output)
}

fn mirror_sources(file: &Path, entries: &[ServerLine], repository: &str) -> Vec<ConfiguredSource> {
    entries
        .iter()
        .enumerate()
        .map(|(position, entry)| ConfiguredSource {
            upstream_id: is_public_server(&entry.url).then(|| UPSTREAM.into()),
            url: if is_public_server(&entry.url) {
                entry.url.clone()
            } else {
                "redacted://custom-msys2-mirror".into()
            },
            enabled: true,
            metadata: BTreeMap::from([
                ("kind".into(), vec![format!("{repository}-mirrorlist")]),
                ("file".into(), vec![file.display().to_string()]),
                ("position".into(), vec![position.to_string()]),
            ]),
        })
        .collect()
}

fn selected_root(selections: &[MirrorSelection]) -> Result<&str, AdapterError> {
    let matching = selections
        .iter()
        .filter(|selection| selection.tool_id == "msys2" && selection.upstream_id == UPSTREAM)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(
            "MSYS2 plan requires exactly one mirror selection".into(),
        ));
    }
    let metadata = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Metadata && endpoint.protocol == Protocol::Https
        })
        .map(|endpoint| endpoint.url.trim_end_matches('/'));
    let artifacts = matching[0]
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
        })
        .map(|endpoint| endpoint.url.trim_end_matches('/'));
    let (Some(metadata), Some(artifacts)) = (metadata, artifacts) else {
        return Err(AdapterError::InvalidConfiguration(
            "MSYS2 selection lacks metadata and artifact endpoints".into(),
        ));
    };
    if normalize_url(metadata) != normalize_url(artifacts)
        || !MIRROR_ROOTS
            .iter()
            .any(|root| normalize_url(root) == normalize_url(metadata))
    {
        return Err(AdapterError::InvalidConfiguration(
            "MSYS2 selection is not a reviewed single-provider endpoint".into(),
        ));
    }
    Ok(metadata)
}

fn package_probe(
    architecture: Architecture,
    repository: &str,
) -> Result<PackageProbe, AdapterError> {
    match (architecture, repository) {
        (Architecture::X86_64, "mingw32") => Ok(PackageProbe {
            package: "mingw-w64-i686-jq-1.8.1-1-any.pkg.tar.zst",
            package_sha256: "da80582f25676becfbe72fd1e28396ff9a4b7b409c8ad5c7ffccf6b3a14d8e83",
            signature_sha256: "7ca1d2d280e27eaabe03f9fdab8017529725b7fe8defffef29fe16a0ac3c8b53",
            query_name: "mingw-w64-i686-jq",
        }),
        (Architecture::X86_64, "mingw64") => Ok(PackageProbe {
            package: "mingw-w64-x86_64-jq-1.8.2-1-any.pkg.tar.zst",
            package_sha256: "2bbb90aab5666027d91a180141c7fa21d44de3178fbc4fe8b8d8d21cd672b885",
            signature_sha256: "ebbd67347fe92c66ff795c2c7fe6e93cc751c173507b6ffd77f14ad56c83e652",
            query_name: "mingw-w64-x86_64-jq",
        }),
        (Architecture::X86_64, "ucrt64") => Ok(PackageProbe {
            package: "mingw-w64-ucrt-x86_64-jq-1.8.2-1-any.pkg.tar.zst",
            package_sha256: "ea25467421a30f994502a140eae47617624ccdc2117749baa7f593e7a2da864c",
            signature_sha256: "e523e0f80fecec0d4cecdbe5596f2b621e26c9802e2ca5a3d450db7b9b9509c6",
            query_name: "mingw-w64-ucrt-x86_64-jq",
        }),
        (Architecture::X86_64, "clang32") => Ok(PackageProbe {
            package: "mingw-w64-clang-i686-jq-1.7.1-3-any.pkg.tar.zst",
            package_sha256: "95ec49cdd376bd1c28e0e9402b9e3b022069f720e3f56fc12b7599063ef1bb83",
            signature_sha256: "8d7f1c7f5b8bae9f6ce07a95aab571953f3892e72b926d868882346b51e73373",
            query_name: "mingw-w64-clang-i686-jq",
        }),
        (Architecture::X86_64, "clang64") => Ok(PackageProbe {
            package: "mingw-w64-clang-x86_64-jq-1.8.2-1-any.pkg.tar.zst",
            package_sha256: "50fbc2aeae2e5f97ad82a104e409864366a6e4dacc1186992f0c1e13bfdf4822",
            signature_sha256: "01e6dcea91582816b7f0350074ae5b1bba24e1ce3ed1a426d492b3d83ead55e7",
            query_name: "mingw-w64-clang-x86_64-jq",
        }),
        (Architecture::Arm64, "clangarm64") => Ok(PackageProbe {
            package: "mingw-w64-clang-aarch64-jq-1.8.2-1-any.pkg.tar.zst",
            package_sha256: "d74cc32bcc65252d9f75c581c257ae4a485c61bf290676fbfed90141331ee7de",
            signature_sha256: "d4b3a913693d584fa989b6f3b977b19abc84305899250cc681d4ebdfefe8ebb1",
            query_name: "mingw-w64-clang-aarch64-jq",
        }),
        (Architecture::X86_64, other) => Err(AdapterError::Unsupported(format!(
            "MSYS2 {other} has no reviewed representative package in v0.2"
        ))),
        _ => Err(AdapterError::Unsupported(
            "MSYS2 ARM64 supports only the clangarm64 repository".into(),
        )),
    }
}

fn is_public_anchor(url: &str, kind: MirrorKind) -> bool {
    let expected = match kind {
        MirrorKind::Msys => "/msys/$arch/",
        MirrorKind::Mingw => "/mingw/$repo/",
    };
    ["https://repo.msys2.org", "https://mirror.msys2.org"]
        .iter()
        .any(|root| normalize_url(url) == normalize_url(&format!("{root}{expected}")))
        || is_reviewed_mirror(url)
}

fn is_public_server(url: &str) -> bool {
    is_reviewed_mirror(url)
        || url.starts_with("https://repo.msys2.org/")
        || url.starts_with("https://mirror.msys2.org/")
}

fn is_reviewed_mirror(url: &str) -> bool {
    MIRROR_ROOTS
        .iter()
        .any(|root| normalize_url(url).starts_with(&(normalize_url(root) + "/")))
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id == "msys2"
        && current.scope == ConfigurationScope::System
        && current.documents.len() == 2
    {
        Ok(())
    } else {
        Err(AdapterError::InvalidConfiguration(
            "MSYS2 requires both installation-local mirrorlists".into(),
        ))
    }
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("MSYS2 source is missing {key}"))
    })?;
    if values.len() == 1 {
        Ok(&values[0])
    } else {
        Err(AdapterError::InvalidConfiguration(format!(
            "MSYS2 source has ambiguous {key}"
        )))
    }
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
            "MSYS2 configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.into()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
