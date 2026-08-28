use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
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

const SYSTEM_UNIT: &str = "/etc/systemd/system/guix-daemon.service";
const VENDOR_UNITS: &[&str] = &[
    "/usr/lib/systemd/system/guix-daemon.service",
    "/lib/systemd/system/guix-daemon.service",
];
const DROP_IN_DIRECTORY: &str = "/etc/systemd/system/guix-daemon.service.d";
const DROP_IN: &str = "/etc/systemd/system/guix-daemon.service.d/mirrorswitch.conf";
const ACL: &str = "/etc/guix/acl";
const CI_UPSTREAM: &str = "guix--static-files";
const BORDEAUX_UPSTREAM: &str = "guix-bordeaux--static-files";
const CI_URL: &str = "https://ci.guix.gnu.org";
const BORDEAUX_URL: &str = "https://bordeaux.guix.gnu.org";
const CI_MIRROR: &str = "https://mirror.sjtu.edu.cn/guix";
const BORDEAUX_MIRROR: &str = "https://mirror.sjtu.edu.cn/guix-bordeaux";
const CI_KEY: &str = "8D156F295D24B0D9A86FA5741A840FF2D24F60F7B6C4134814AD55625971B394";
const BORDEAUX_KEY: &str = "7D602902D3A2DBB83F8A0FB98602A754C5493B0B778C8D1DD4E0F41DE14DE34F";

#[derive(Clone, Copy, Debug, Default)]
pub struct GuixAdapter;

impl Adapter for GuixAdapter {
    fn key(&self) -> &'static str {
        "guix"
    }

    fn tool_id(&self) -> &'static str {
        "guix"
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
        require_supported_context(context)?;
        let has_guix = runtime.command_exists("guix");
        let unit = find_base_unit(runtime)?;
        if !has_guix && unit.is_none() {
            return Ok(None);
        }

        let mut evidence = Vec::new();
        let mut version = None;
        if has_guix {
            let output = runtime.run("guix", &["--version".into()])?;
            if !output.status.success() {
                return Err(AdapterError::Runtime(format!(
                    "guix --version failed with status {}",
                    output.status
                )));
            }
            let observed = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            version = (!observed.is_empty()).then_some(observed.clone());
            evidence.push(format!("GNU Guix command {observed}"));
        }
        if let Some((path, _)) = unit {
            evidence.push(format!("Guix daemon systemd unit {}", path.display()));
        }
        if runtime.read(Path::new(ACL))?.is_some() {
            evidence.push(format!("Guix authorized substitute keys {ACL}"));
        }
        if let Some(path) = channel_path(runtime)
            && runtime.read(&path)?.is_some()
        {
            evidence.push(format!("Guix user channels {}", path.display()));
        }
        Ok(Some(DetectedTool {
            tool_id: "guix".into(),
            executable: has_guix.then(|| PathBuf::from("/usr/bin/guix")),
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
        require_supported_context(context)?;
        if scope != ConfigurationScope::System {
            return Err(AdapterError::Unsupported(
                "Guix daemon substitutes support only system scope".into(),
            ));
        }
        if context
            .distribution
            .as_ref()
            .is_some_and(|distribution| matches!(distribution.id.as_str(), "guix" | "guix-system"))
        {
            return Err(AdapterError::Unsupported(
                "Guix System owns daemon substitutes declaratively through guix-service-type"
                    .into(),
            ));
        }

        let configuration = read_daemon_configuration(runtime)?;
        let acl = runtime.read(Path::new(ACL))?.ok_or_else(|| {
            AdapterError::InvalidConfiguration(format!("Guix authorized-key ACL {ACL} is missing"))
        })?;
        let acl_text = utf8(Path::new(ACL), &acl)?;
        let architecture = guix_system(context.architecture);
        let store_hash = probe_store_hash(context.architecture);
        let substitutes = configured_substitutes(&configuration.command)?;
        let recognized = substitutes
            .iter()
            .filter_map(|url| substitute_upstream(url))
            .collect::<BTreeSet<_>>();
        if recognized.is_empty() {
            return Err(AdapterError::Unsupported(
                "Guix daemon has no recognized official or reviewed substitute server".into(),
            ));
        }
        for upstream in &recognized {
            require_authorized_key(acl_text, signing_key(upstream))?;
        }

        let mut sources = substitutes
            .into_iter()
            .map(|url| {
                let upstream = substitute_upstream(&url);
                let mut metadata = BTreeMap::from([
                    (
                        "configuration_surface".into(),
                        vec!["substitute-server".into()],
                    ),
                    ("guix_system".into(), vec![architecture.into()]),
                    ("store_hash".into(), vec![store_hash.into()]),
                ]);
                if let Some(upstream) = upstream {
                    metadata.insert(
                        "authorized_key_q".into(),
                        vec![signing_key(upstream).into()],
                    );
                }
                ConfiguredSource {
                    upstream_id: upstream.map(str::to_owned),
                    url,
                    enabled: true,
                    metadata,
                }
            })
            .collect::<Vec<_>>();

        let mut files = vec![configuration.active_path.clone(), PathBuf::from(ACL)];
        if let Some(path) = channel_path(runtime)
            && let Some(contents) = runtime.read(&path)?
        {
            let text = utf8(&path, &contents)?;
            files.push(path.clone());
            sources.extend(
                extract_channel_urls(text)
                    .into_iter()
                    .map(|url| ConfiguredSource {
                        upstream_id: None,
                        url,
                        enabled: true,
                        metadata: BTreeMap::from([
                            ("configuration_surface".into(), vec!["channel".into()]),
                            (
                                "configuration_file".into(),
                                vec![path.display().to_string()],
                            ),
                        ]),
                    }),
            );
        }

        files.sort();
        files.dedup();
        Ok(CurrentConfiguration {
            tool_id: "guix".into(),
            scope,
            files,
            sources,
            documents: vec![ConfigurationDocument {
                path: configuration.active_path,
                format: "guix-systemd-active-unit".into(),
                contents: configuration.contents,
            }],
        })
    }

    fn selection_request(
        &self,
        context: &SystemContext,
        detected: &DetectedTool,
        current: &CurrentConfiguration,
    ) -> Result<SelectionRequest, AdapterError> {
        require_supported_context(context)?;
        if current.tool_id != "guix" || current.scope != ConfigurationScope::System {
            return Err(AdapterError::InvalidConfiguration(
                "Guix selection requires one system daemon configuration".into(),
            ));
        }
        let mut required_upstreams = Vec::new();
        let mut probe_contexts = BTreeMap::new();
        for source in &current.sources {
            let Some(upstream) = source.upstream_id.as_deref() else {
                continue;
            };
            if !matches!(upstream, CI_UPSTREAM | BORDEAUX_UPSTREAM) {
                continue;
            }
            if !required_upstreams.iter().any(|value| value == upstream) {
                required_upstreams.push(upstream.to_owned());
                probe_contexts.insert(
                    upstream.to_owned(),
                    vec![BTreeMap::from([(
                        "store_hash".into(),
                        single_metadata(source, "store_hash")?.to_owned(),
                    )])],
                );
            }
        }
        if required_upstreams.is_empty() {
            return Err(AdapterError::Unsupported(
                "no signed Guix substitute upstream is configured".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "guix".into(),
            adapter_key: "guix".into(),
            context: context.clone(),
            tool_version: detected.version.clone(),
            required_upstreams,
            repository_versions: BTreeMap::new(),
            probe_contexts,
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
        require_supported_context(context)?;
        if current.tool_id != "guix"
            || current.scope != ConfigurationScope::System
            || current.documents.len() != 1
            || current.documents[0].format != "guix-systemd-active-unit"
        {
            return Err(AdapterError::InvalidConfiguration(
                "Guix plan requires exactly one active daemon unit".into(),
            ));
        }
        let document = &current.documents[0];
        let text = utf8(&document.path, &document.contents)?;
        let command = parse_daemon_command(text)?;
        let existing_urls = configured_substitutes(&command.tokens)?;
        let selected = selected_endpoints(selection)?;
        let new_urls = rewrite_substitutes(&existing_urls, &selected)?;
        let rewritten_command = rewrite_command(&command.tokens, &new_urls)?;
        let target = target_unit_path(&document.path);
        let (old_contents, new_contents) = if target == document.path {
            let mut rewritten = text.to_owned();
            let newline = if text.as_bytes()[command.range.clone()].ends_with(b"\n") {
                "\n"
            } else {
                ""
            };
            rewritten.replace_range(
                command.range,
                &format!("{}{}", render_exec_start(&rewritten_command)?, newline),
            );
            (Some(document.contents.clone()), rewritten.into_bytes())
        } else {
            (
                None,
                format!(
                    "# Managed by MirrorSwitch.\n[Service]\nExecStart=\n{}\n",
                    render_exec_start(&rewritten_command)?
                )
                .into_bytes(),
            )
        };
        let changes = (old_contents.as_deref() != Some(new_contents.as_slice()))
            .then(|| PlannedFileChange {
                target: rooted(&context.root, &target),
                old_contents,
                old_mode: None,
                new_contents,
                new_mode: Some(0o644),
                summary: "replace signed Guix substitute servers without changing channels or authorized keys"
                    .into(),
            })
            .into_iter()
            .collect();
        Ok(ChangePlan {
            adapter_key: "guix".into(),
            tool_id: "guix".into(),
            scope: ConfigurationScope::System,
            changes,
            requires_elevation: true,
            service_impact: ServiceImpact::RestartRequired,
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
            let configuration = read_daemon_configuration(runtime)?;
            let substitutes = configured_substitutes(&configuration.command)?;
            let reviewed = substitutes
                .iter()
                .filter(|url| is_known_mirror(url))
                .cloned()
                .collect::<Vec<_>>();
            if reviewed.is_empty() {
                return Err(AdapterError::Verification(
                    "effective Guix daemon configuration has no reviewed mirror".into(),
                ));
            }
            let acl = runtime.read(Path::new(ACL))?.ok_or_else(|| {
                AdapterError::Verification(format!("Guix authorized-key ACL {ACL} is missing"))
            })?;
            let acl_text = utf8(Path::new(ACL), &acl)?;
            for url in &reviewed {
                require_authorized_key(
                    acl_text,
                    signing_key(substitute_upstream(url).expect("known mirror has upstream")),
                )?;
            }
            let arguments = vec![
                "weather".into(),
                format!("--substitute-urls={}", reviewed.join(" ")),
                format!("--system={}", guix_system(context.architecture)),
                "hello".into(),
            ];
            let output = runtime.run("guix", &arguments)?;
            if !output.status.success() {
                return Err(AdapterError::Verification(format!(
                    "guix weather failed with status {}",
                    output.status
                )));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains("100.0% substitutes available") {
                return Err(AdapterError::Verification(
                    "guix weather did not report complete substitute availability".into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Guix re-read the daemon configuration and found signed substitutes for {}",
                    guix_system(context.architecture)
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
                "restored {} Guix daemon configuration files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

struct DaemonConfiguration {
    active_path: PathBuf,
    contents: Vec<u8>,
    command: Vec<String>,
}

struct ParsedCommand {
    range: Range<usize>,
    tokens: Vec<String>,
}

fn require_supported_context(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux {
        return Err(AdapterError::Unsupported(
            "GNU Guix adapter requires Linux".into(),
        ));
    }
    Ok(())
}

fn find_base_unit(runtime: &dyn Runtime) -> Result<Option<(PathBuf, Vec<u8>)>, AdapterError> {
    for path in std::iter::once(SYSTEM_UNIT).chain(VENDOR_UNITS.iter().copied()) {
        let path = PathBuf::from(path);
        if let Some(contents) = runtime.read(&path)? {
            return Ok(Some((path, contents)));
        }
    }
    Ok(None)
}

fn read_daemon_configuration(runtime: &dyn Runtime) -> Result<DaemonConfiguration, AdapterError> {
    let (base_path, base_contents) = find_base_unit(runtime)?.ok_or_else(|| {
        AdapterError::Unsupported("Guix daemon systemd unit was not found".into())
    })?;
    let drop_ins = runtime.list_files(Path::new(DROP_IN_DIRECTORY))?;
    let unknown = drop_ins
        .iter()
        .filter(|path| path.as_path() != Path::new(DROP_IN))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(AdapterError::Unsupported(format!(
            "Guix daemon has non-MirrorSwitch systemd drop-ins: {}",
            unknown
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let (active_path, contents) = if drop_ins.iter().any(|path| path == Path::new(DROP_IN)) {
        let path = PathBuf::from(DROP_IN);
        let contents = runtime.read(&path)?.ok_or_else(|| {
            AdapterError::Runtime(format!(
                "listed Guix drop-in {} disappeared",
                path.display()
            ))
        })?;
        (path, contents)
    } else {
        (base_path, base_contents)
    };
    let text = utf8(&active_path, &contents)?;
    let command = parse_daemon_command(text)?.tokens;
    Ok(DaemonConfiguration {
        active_path,
        contents,
        command,
    })
}

fn parse_daemon_command(text: &str) -> Result<ParsedCommand, AdapterError> {
    let mut section = String::new();
    let mut commands = Vec::new();
    for (range, logical) in logical_lines(text) {
        let trimmed = logical.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].to_owned();
            continue;
        }
        if section != "Service" || !trimmed.starts_with("ExecStart=") {
            continue;
        }
        let value = trimmed.trim_start_matches("ExecStart=").trim();
        if value.is_empty() {
            continue;
        }
        commands.push(ParsedCommand {
            range,
            tokens: systemd_words(value)?,
        });
    }
    if commands.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Guix daemon unit must have exactly one active ExecStart, found {}",
            commands.len()
        )));
    }
    let command = commands.pop().unwrap();
    if command
        .tokens
        .first()
        .and_then(|path| Path::new(path).file_name())
        .is_none_or(|name| name != "guix-daemon")
    {
        return Err(AdapterError::InvalidConfiguration(
            "Guix daemon ExecStart does not invoke guix-daemon".into(),
        ));
    }
    Ok(command)
}

fn logical_lines(text: &str) -> Vec<(Range<usize>, String)> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut end = 0;
    let mut logical = String::new();
    for line in text.split_inclusive('\n') {
        end += line.len();
        let body = line.trim_end_matches(['\n', '\r']);
        if body.ends_with('\\') {
            logical.push_str(body.trim_end_matches('\\'));
            logical.push(' ');
            continue;
        }
        logical.push_str(body);
        output.push((start..end, std::mem::take(&mut logical)));
        start = end;
    }
    if start < text.len() || !logical.is_empty() {
        output.push((start..text.len(), logical));
    }
    output
}

fn systemd_words(value: &str) -> Result<Vec<String>, AdapterError> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else {
                word.push(character);
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err(AdapterError::InvalidConfiguration(
            "Guix daemon ExecStart has incomplete quoting or escaping".into(),
        ));
    }
    if !word.is_empty() {
        words.push(word);
    }
    Ok(words)
}

fn configured_substitutes(command: &[String]) -> Result<Vec<String>, AdapterError> {
    let mut value = None;
    let mut index = 1;
    while index < command.len() {
        if let Some(found) = command[index].strip_prefix("--substitute-urls=") {
            if value.replace(found.to_owned()).is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "Guix daemon has multiple --substitute-urls options".into(),
                ));
            }
        } else if command[index] == "--substitute-urls" {
            let found = command.get(index + 1).ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Guix daemon --substitute-urls option has no value".into(),
                )
            })?;
            if value.replace(found.clone()).is_some() {
                return Err(AdapterError::InvalidConfiguration(
                    "Guix daemon has multiple --substitute-urls options".into(),
                ));
            }
            index += 1;
        }
        index += 1;
    }
    let urls = value
        .map(|value| value.split_whitespace().map(normalize_url).collect())
        .unwrap_or_else(|| vec![CI_URL.into(), BORDEAUX_URL.into()]);
    if urls.is_empty() {
        return Err(AdapterError::InvalidConfiguration(
            "Guix daemon substitute URL list is empty".into(),
        ));
    }
    Ok(urls)
}

fn rewrite_substitutes(
    current: &[String],
    selected: &BTreeMap<&str, String>,
) -> Result<Vec<String>, AdapterError> {
    let required = current
        .iter()
        .filter_map(|url| substitute_upstream(url))
        .collect::<BTreeSet<_>>();
    if required.len() != selected.len() || required.iter().any(|key| !selected.contains_key(key)) {
        return Err(AdapterError::InvalidConfiguration(
            "Guix selections do not cover exactly the configured signed substitute upstreams"
                .into(),
        ));
    }
    let mut inserted = BTreeSet::new();
    let mut output = Vec::new();
    for url in current {
        if let Some(upstream) = substitute_upstream(url) {
            if inserted.insert(upstream) {
                output.push(selected[upstream].clone());
            }
        } else {
            output.push(url.clone());
        }
    }
    Ok(output)
}

fn rewrite_command(command: &[String], urls: &[String]) -> Result<Vec<String>, AdapterError> {
    let value = urls.join(" ");
    let mut output = Vec::with_capacity(command.len() + 1);
    let mut replaced = false;
    let mut index = 0;
    while index < command.len() {
        if command[index].starts_with("--substitute-urls=") {
            output.push(format!("--substitute-urls={value}"));
            replaced = true;
        } else if command[index] == "--substitute-urls" {
            output.push(format!("--substitute-urls={value}"));
            replaced = true;
            index += 1;
            if index >= command.len() {
                return Err(AdapterError::InvalidConfiguration(
                    "Guix daemon --substitute-urls option has no value".into(),
                ));
            }
        } else {
            output.push(command[index].clone());
        }
        index += 1;
    }
    if !replaced {
        output.push(format!("--substitute-urls={value}"));
    }
    Ok(output)
}

fn selected_endpoints(
    selections: &[MirrorSelection],
) -> Result<BTreeMap<&'static str, String>, AdapterError> {
    let mut output = BTreeMap::new();
    for selection in selections
        .iter()
        .filter(|selection| selection.tool_id == "guix")
    {
        let upstream = match selection.upstream_id.as_str() {
            CI_UPSTREAM => CI_UPSTREAM,
            BORDEAUX_UPSTREAM => BORDEAUX_UPSTREAM,
            _ => {
                return Err(AdapterError::InvalidConfiguration(format!(
                    "Guix selection has unknown upstream {}",
                    selection.upstream_id
                )));
            }
        };
        let endpoint = selection
            .endpoints
            .iter()
            .find(|endpoint| {
                endpoint.role == EndpointRole::Artifacts && endpoint.protocol == Protocol::Https
            })
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration(
                    "Guix selection has no HTTPS artifacts endpoint".into(),
                )
            })?;
        if substitute_upstream(&endpoint.url) != Some(upstream) || !is_known_mirror(&endpoint.url) {
            return Err(AdapterError::InvalidConfiguration(
                "Guix selection is not a reviewed substitute endpoint for its upstream".into(),
            ));
        }
        if output
            .insert(upstream, normalize_url(&endpoint.url))
            .is_some()
        {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Guix plan has multiple selections for {upstream}"
            )));
        }
    }
    Ok(output)
}

fn render_exec_start(command: &[String]) -> Result<String, AdapterError> {
    let mut rendered = Vec::new();
    for word in command {
        if word.contains(['\n', '\r', '\0']) {
            return Err(AdapterError::InvalidConfiguration(
                "Guix daemon argument contains a control character".into(),
            ));
        }
        rendered.push(format!(
            "\"{}\"",
            word.replace('\\', "\\\\").replace('"', "\\\"")
        ));
    }
    Ok(format!("ExecStart={}", rendered.join(" ")))
}

fn target_unit_path(active: &Path) -> PathBuf {
    if active == Path::new(SYSTEM_UNIT) || active == Path::new(DROP_IN) {
        active.to_path_buf()
    } else {
        PathBuf::from(DROP_IN)
    }
}

fn substitute_upstream(url: &str) -> Option<&'static str> {
    match normalize_url(url).as_str() {
        CI_URL | CI_MIRROR => Some(CI_UPSTREAM),
        BORDEAUX_URL | BORDEAUX_MIRROR => Some(BORDEAUX_UPSTREAM),
        _ => None,
    }
}

fn is_known_mirror(url: &str) -> bool {
    matches!(normalize_url(url).as_str(), CI_MIRROR | BORDEAUX_MIRROR)
}

fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_owned()
}

fn signing_key(upstream: &str) -> &'static str {
    match upstream {
        CI_UPSTREAM => CI_KEY,
        BORDEAUX_UPSTREAM => BORDEAUX_KEY,
        _ => unreachable!("only recognized Guix upstreams request signing keys"),
    }
}

fn require_authorized_key(acl: &str, key: &str) -> Result<(), AdapterError> {
    if !acl.contains(&format!("#{key}#")) {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Guix ACL does not authorize the required existing key {key}"
        )));
    }
    Ok(())
}

fn probe_store_hash(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "s5pd3rnzymliafb4la5sca63j86xs0y0",
        Architecture::Arm64 => "s2qnbdlrwlx47h5p6rxlylny1259srmj",
    }
}

fn guix_system(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64-linux",
        Architecture::Arm64 => "aarch64-linux",
    }
}

fn channel_path(runtime: &dyn Runtime) -> Option<PathBuf> {
    runtime
        .home_dir()
        .map(|home| home.join(".config/guix/channels.scm"))
}

fn extract_channel_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut remaining = text;
    while let Some(index) = remaining.find("(url") {
        remaining = &remaining[index + 4..];
        let Some(start) = remaining.find('"') else {
            break;
        };
        remaining = &remaining[start + 1..];
        let Some(end) = remaining.find('"') else {
            break;
        };
        urls.push(remaining[..end].to_owned());
        remaining = &remaining[end + 1..];
    }
    urls
}

fn single_metadata<'a>(source: &'a ConfiguredSource, key: &str) -> Result<&'a str, AdapterError> {
    let values = source.metadata.get(key).ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("Guix source is missing {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Guix source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
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
            "Guix configuration {} is not UTF-8",
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
