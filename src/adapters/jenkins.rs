use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

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

const UPSTREAM: &str = "jenkins-update-center--repository-metadata";
const REVIEWED_VERSION: &str = "2.581";
const UPDATE_CENTER_COMMIT: &str = "3df56b0ada4fc57ca1329946697eb0f896389047";
const EMBEDDED_CERTIFICATE: &[u8] = include_bytes!("assets/lework-update-center.crt");
const CERTIFICATE_SHA256: &str = "c049e4b441fb42675b7bc8c19895f85837c955784299fb2671323b1963da8d18";
const CERTIFICATE_FINGERPRINT: &str =
    "6786622eed42b1b141f79397521438b4e6f1cc314563652d7c28adf6878fc8c4";
const CERTIFICATE_NOT_BEFORE: u64 = 1_583_379_650;
const CERTIFICATE_NOT_AFTER: u64 = 1_898_739_650;
const UPDATE_CONFIG: &str = "hudson.model.UpdateCenter.xml";
const ROOT_CA_DIRECTORY: &str = "update-center-rootCAs";
const ROOT_CA_FILE: &str = "update-center.crt";

const ARTIFACT_MIRRORS: &[(&str, &str)] = &[
    ("tencent", "https://mirrors.cloud.tencent.com/jenkins"),
    ("huawei", "https://mirrors.huaweicloud.com/jenkins"),
    ("tsinghua", "https://mirrors.tuna.tsinghua.edu.cn/jenkins"),
    ("ustc", "https://mirrors.ustc.edu.cn/jenkins"),
    ("aliyun", "https://mirrors.aliyun.com/jenkins"),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct JenkinsAdapter;

impl Adapter for JenkinsAdapter {
    fn key(&self) -> &'static str {
        "jenkins"
    }

    fn tool_id(&self) -> &'static str {
        "jenkins"
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

    fn selected_by_default(&self) -> bool {
        false
    }

    fn detect(
        &self,
        context: &SystemContext,
        runtime: &dyn Runtime,
    ) -> Result<Option<DetectedTool>, AdapterError> {
        require_linux(context)?;
        validate_embedded_certificate()?;
        let home = jenkins_home(runtime)?;
        let update_config = home.join(UPDATE_CONFIG);
        let configuration_exists = runtime.read(&update_config)?.is_some();
        let Some((version, executable)) = jenkins_version(runtime)? else {
            if configuration_exists {
                return Err(AdapterError::Unsupported(
                    "Jenkins Update Center exists but the Jenkins core version cannot be verified"
                        .into(),
                ));
            }
            return Ok(None);
        };
        review_version(&version)?;
        let sites = runtime
            .read(&update_config)?
            .map(|contents| parse_sites(&update_config, &contents))
            .transpose()?
            .unwrap_or_default();
        let default_site = sites.iter().filter(|site| site.id == "default").count();
        if default_site > 1 {
            return Err(AdapterError::InvalidConfiguration(
                "Jenkins has multiple default Update Center sites".into(),
            ));
        }
        Ok(Some(DetectedTool {
            tool_id: "jenkins".into(),
            executable: Some(executable),
            version: Some(version.clone()),
            evidence: vec![
                format!("Jenkins core {version}"),
                format!("JENKINS_HOME is {}", home.display()),
                format!("Update Center configuration is {}", update_config.display()),
                format!("configured Update Center sites: {}", sites.len()),
                format!(
                    "plugin management is {}",
                    if runtime.command_exists("jenkins-plugin-cli") {
                        "jenkins-plugin-cli plus Jenkins UI/API"
                    } else {
                        "Jenkins UI/API"
                    }
                ),
                format!(
                    "service management is {}",
                    if runtime.command_exists("systemctl") {
                        "systemd"
                    } else {
                        "external/manual"
                    }
                ),
                format!("third-party Update Center root fingerprint is {CERTIFICATE_FINGERPRINT}"),
                "Jenkins mirror configuration requires explicit user selection".into(),
                "Jenkins service restart is never automatic".into(),
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
        validate_embedded_certificate()?;
        if detected.tool_id != "jenkins" {
            return Err(AdapterError::InvalidConfiguration(
                "Jenkins read received another tool's detection result".into(),
            ));
        }
        let (version, _) = jenkins_version(runtime)?.ok_or_else(|| {
            AdapterError::Conflict("Jenkins core version disappeared after detection".into())
        })?;
        review_version(&version)?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Jenkins core version changed after detection".into(),
            ));
        }
        let home = jenkins_home(runtime)?;
        let update_path = home.join(UPDATE_CONFIG);
        let certificate_path = home.join(ROOT_CA_DIRECTORY).join(ROOT_CA_FILE);
        let update_contents = runtime.read(&update_path)?;
        let certificate_contents = runtime.read(&certificate_path)?;
        let sites = update_contents
            .as_deref()
            .map(|contents| parse_sites(&update_path, contents))
            .transpose()?
            .unwrap_or_default();
        let defaults = sites
            .iter()
            .filter(|site| site.id == "default")
            .collect::<Vec<_>>();
        let mut sources = vec![snapshot_source("jenkins-version", &version)];
        sources.push(snapshot_source("jenkins-home", path_string(&home)?));
        sources.push(snapshot_source(
            "update-config-path",
            path_string(&update_path)?,
        ));
        sources.push(snapshot_source(
            "certificate-path",
            path_string(&certificate_path)?,
        ));
        sources.push(snapshot_source(
            "service-manager",
            if runtime.command_exists("systemctl") {
                "systemd"
            } else {
                "external/manual"
            },
        ));
        if defaults.len() > 1 {
            sources.push(policy_source("multiple-default-sites", &update_path));
        } else if let Some(site) = defaults.first() {
            if is_official_update_url(&site.url) || managed_update_url(&site.url).is_some() {
                sources.push(ConfiguredSource {
                    upstream_id: Some(UPSTREAM.into()),
                    url: site.url.clone(),
                    enabled: true,
                    metadata: BTreeMap::from([
                        ("kind".into(), vec!["default-update-site".into()]),
                        (
                            "config_path".into(),
                            vec![update_path.display().to_string()],
                        ),
                    ]),
                });
            } else {
                sources.push(policy_source("custom-default-site", &update_path));
            }
        }
        if sites.iter().any(|site| site.id != "default") {
            sources.push(policy_source("private-sites-preserved", &update_path));
        }
        if let Some(contents) = &certificate_contents {
            if contents == EMBEDDED_CERTIFICATE {
                sources.push(policy_source("managed-certificate", &certificate_path));
            } else {
                sources.push(policy_source("certificate-conflict", &certificate_path));
            }
        }
        Ok(CurrentConfiguration {
            tool_id: "jenkins".into(),
            scope,
            files: [
                update_contents.as_ref().map(|_| update_path.clone()),
                certificate_contents
                    .as_ref()
                    .map(|_| certificate_path.clone()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            sources,
            documents: vec![
                ConfigurationDocument {
                    path: update_path,
                    format: "jenkins-update-center-target".into(),
                    contents: update_contents.unwrap_or_default(),
                },
                ConfigurationDocument {
                    path: certificate_path,
                    format: "jenkins-update-center-certificate-target".into(),
                    contents: certificate_contents.unwrap_or_default(),
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
        require_linux(context)?;
        require_current(current)?;
        validate_policy(current)?;
        let version = current_value(current, "jenkins-version")?;
        if detected.version.as_deref() != Some(version.as_str()) {
            return Err(AdapterError::Conflict(
                "Jenkins core version changed before mirror selection".into(),
            ));
        }
        Ok(SelectionRequest {
            tool_id: "jenkins".into(),
            adapter_key: "jenkins".into(),
            context: context.clone(),
            tool_version: Some(version),
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
        validate_policy(current)?;
        validate_embedded_certificate()?;
        let version = current_value(current, "jenkins-version")?;
        if version != REVIEWED_VERSION {
            return Err(AdapterError::Unsupported(format!(
                "signed mirror snapshot targets Jenkins {REVIEWED_VERSION}, not {version}"
            )));
        }
        let selection = selected_configuration(selections)?;
        let update = find_document(current, "jenkins-update-center-target")?;
        let certificate = find_document(current, "jenkins-update-center-certificate-target")?;
        let rendered_update = render_update_center(&update.path, &update.contents, &selection.url)?;
        let mut changes = Vec::new();
        add_change(
            context,
            current,
            update,
            rendered_update.into_bytes(),
            "change only the explicitly selected default Jenkins Update Center while preserving private sites and credentials",
            &mut changes,
        );
        add_change(
            context,
            current,
            certificate,
            EMBEDDED_CERTIFICATE.to_vec(),
            "install the pinned third-party Update Center root certificate without disabling signature verification",
            &mut changes,
        );
        Ok(ChangePlan {
            adapter_key: "jenkins".into(),
            tool_id: "jenkins".into(),
            scope: ConfigurationScope::System,
            requires_elevation: true,
            service_impact: if changes.is_empty() {
                ServiceImpact::None
            } else {
                ServiceImpact::RestartRequired
            },
            changes,
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
            validate_embedded_certificate()?;
            let (version, _) = jenkins_version(runtime)?.ok_or_else(|| {
                AdapterError::Verification("Jenkins core version is unavailable".into())
            })?;
            if version != REVIEWED_VERSION {
                return Err(AdapterError::Verification(format!(
                    "Jenkins core changed to {version} after apply"
                )));
            }
            let home = jenkins_home(runtime)?;
            let update_path = home.join(UPDATE_CONFIG);
            let certificate_path = home.join(ROOT_CA_DIRECTORY).join(ROOT_CA_FILE);
            let expected = [
                rooted(&context.root, &update_path),
                rooted(&context.root, &certificate_path),
            ];
            if receipt.changed_targets.is_empty()
                || receipt
                    .changed_targets
                    .iter()
                    .any(|target| !expected.contains(target))
            {
                return Err(AdapterError::Verification(
                    "Jenkins transaction changed an unexpected target".into(),
                ));
            }
            let update_contents = runtime.read(&update_path)?.ok_or_else(|| {
                AdapterError::Verification("Jenkins Update Center configuration disappeared".into())
            })?;
            let sites = parse_sites(&update_path, &update_contents)?;
            let default = sites
                .iter()
                .find(|site| site.id == "default")
                .and_then(|site| managed_update_url(&site.url))
                .ok_or_else(|| {
                    AdapterError::Verification(
                        "Jenkins default Update Center is not the selected signed snapshot".into(),
                    )
                })?;
            let certificate = runtime.read(&certificate_path)?.ok_or_else(|| {
                AdapterError::Verification("Jenkins Update Center certificate disappeared".into())
            })?;
            if certificate != EMBEDDED_CERTIFICATE {
                return Err(AdapterError::Verification(
                    "Jenkins Update Center certificate no longer matches its pinned fingerprint"
                        .into(),
                ));
            }
            Ok(VerificationResult {
                valid: true,
                summary: format!(
                    "Jenkins {version} default Update Center now uses the immutable {} metadata snapshot with the pinned {CERTIFICATE_FINGERPRINT} root; plugin metadata and git.hpi were digest-checked before planning; service restart was not performed",
                    default.variant
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
                "restored {} Jenkins Update Center files from {}",
                restored.restored_files, restored.transaction_id
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct Site {
    id: String,
    url: String,
    url_range: Range<usize>,
}

struct ManagedUpdateUrl {
    variant: String,
    commit: String,
}

struct SelectedConfiguration {
    url: String,
}

fn validate_embedded_certificate() -> Result<(), AdapterError> {
    let digest = format!("{:x}", Sha256::digest(EMBEDDED_CERTIFICATE));
    if digest != CERTIFICATE_SHA256 {
        return Err(AdapterError::InvalidConfiguration(
            "embedded Jenkins Update Center certificate fingerprint is invalid".into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AdapterError::Runtime(error.to_string()))?
        .as_secs();
    if !(CERTIFICATE_NOT_BEFORE..CERTIFICATE_NOT_AFTER).contains(&now) {
        return Err(AdapterError::Unsupported(
            "pinned Jenkins Update Center certificate is not currently valid".into(),
        ));
    }
    Ok(())
}

fn jenkins_home(runtime: &dyn Runtime) -> Result<PathBuf, AdapterError> {
    if let Some(value) = runtime
        .environment_variable("JENKINS_HOME")
        .filter(|value| !value.trim().is_empty())
    {
        let path = PathBuf::from(value);
        validate_path(&path, "JENKINS_HOME")?;
        return Ok(path);
    }
    for path in ["/etc/default/jenkins", "/etc/sysconfig/jenkins"] {
        let path = PathBuf::from(path);
        let Some(contents) = runtime.read(&path)? else {
            continue;
        };
        let text = utf8(&path, &contents)?;
        for line in text.lines() {
            let active = line.split('#').next().unwrap_or_default().trim();
            if let Some(value) = active.strip_prefix("JENKINS_HOME=") {
                let path = PathBuf::from(value.trim().trim_matches(['\'', '"']));
                validate_path(&path, "JENKINS_HOME")?;
                return Ok(path);
            }
        }
    }
    Ok(PathBuf::from("/var/lib/jenkins"))
}

fn jenkins_version(runtime: &dyn Runtime) -> Result<Option<(String, PathBuf)>, AdapterError> {
    if runtime.command_exists("jenkins") {
        let output = runtime.run("jenkins", &["--version".into()])?;
        if output.status.success() {
            let version = version_from_output(&output.stdout)?;
            return Ok(Some((version, PathBuf::from("jenkins"))));
        }
    }
    let war = PathBuf::from("/usr/share/java/jenkins.war");
    if runtime.read(&war)?.is_some() && runtime.command_exists("java") {
        let output = runtime.run(
            "java",
            &["-jar".into(), path_string(&war)?.into(), "--version".into()],
        )?;
        if output.status.success() {
            let version = version_from_output(&output.stdout)?;
            return Ok(Some((version, PathBuf::from("java"))));
        }
    }
    Ok(None)
}

fn version_from_output(output: &[u8]) -> Result<String, AdapterError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| AdapterError::Runtime("Jenkins version output is not UTF-8".into()))?;
    output
        .split_whitespace()
        .map(|token| token.trim_matches([',', ';', '(', ')']))
        .find(|token| valid_version(token))
        .map(str::to_owned)
        .ok_or_else(|| AdapterError::Unsupported("Jenkins core version is invalid".into()))
}

fn valid_version(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!(parts.next(), Some("2"))
        && parts.next().is_some_and(|part| part.parse::<u64>().is_ok())
        && parts.all(|part| part.parse::<u64>().is_ok())
}

fn review_version(version: &str) -> Result<(), AdapterError> {
    if !valid_version(version) {
        return Err(AdapterError::Unsupported(format!(
            "Jenkins core {version} is outside reviewed 2.x version syntax"
        )));
    }
    Ok(())
}

fn parse_sites(path: &Path, contents: &[u8]) -> Result<Vec<Site>, AdapterError> {
    let text = utf8(path, contents)?;
    let document = roxmltree::Document::parse(text).map_err(|error| {
        AdapterError::InvalidConfiguration(format!(
            "Jenkins Update Center XML {} is invalid: {error}",
            path.display()
        ))
    })?;
    if document.root_element().tag_name().name() != "sites" {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Jenkins Update Center XML {} has an unknown root",
            path.display()
        )));
    }
    let mut sites = Vec::new();
    for site in document
        .root_element()
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "site")
    {
        let id = site
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "id")
            .and_then(|node| node.text())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Jenkins Update Center site has no id".into())
            })?;
        let url_node = site
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "url")
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Jenkins Update Center site has no URL".into())
            })?;
        let url = url_node
            .text()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AdapterError::InvalidConfiguration("Jenkins Update Center site URL is empty".into())
            })?;
        let node_range = url_node.range();
        let fragment = &text[node_range.clone()];
        let start = fragment.find('>').ok_or_else(|| {
            AdapterError::InvalidConfiguration("Jenkins Update Center URL tag is invalid".into())
        })? + 1;
        let end = fragment.rfind("</url>").ok_or_else(|| {
            AdapterError::InvalidConfiguration("Jenkins Update Center URL tag is invalid".into())
        })?;
        sites.push(Site {
            id: id.into(),
            url: url.into(),
            url_range: node_range.start + start..node_range.start + end,
        });
    }
    Ok(sites)
}

fn is_official_update_url(value: &str) -> bool {
    matches!(
        value.trim_end_matches('/'),
        "https://updates.jenkins.io/update-center.json"
            | "http://updates.jenkins.io/update-center.json"
            | "https://updates.jenkins-ci.org/update-center.json"
            | "http://updates.jenkins-ci.org/update-center.json"
    )
}

fn managed_update_url(value: &str) -> Option<ManagedUpdateUrl> {
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("cdn.jsdelivr.net")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.len() != 6
        || segments[0] != "gh"
        || segments[1] != "lework"
        || !segments[2].starts_with("jenkins-update-center@")
        || segments[3] != "updates"
        || segments[5] != "update-center.json"
    {
        return None;
    }
    let commit = segments[2].strip_prefix("jenkins-update-center@")?;
    if commit != UPDATE_CENTER_COMMIT {
        return None;
    }
    let variant = segments[4];
    ARTIFACT_MIRRORS
        .iter()
        .any(|(known, _)| *known == variant)
        .then(|| ManagedUpdateUrl {
            variant: variant.into(),
            commit: commit.into(),
        })
}

fn selected_configuration(
    selections: &[MirrorSelection],
) -> Result<SelectedConfiguration, AdapterError> {
    if selections.len() != 1
        || selections[0].tool_id != "jenkins"
        || selections[0].upstream_id != UPSTREAM
        || selections[0].provider_id != "lework"
    {
        return Err(AdapterError::InvalidConfiguration(
            "Jenkins requires one signed lework Update Center selection".into(),
        ));
    }
    let selection = &selections[0];
    let role_url = |role| -> Result<String, AdapterError> {
        let values = selection
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == role && endpoint.protocol == Protocol::Https)
            .collect::<Vec<_>>();
        if values.len() != 1 {
            return Err(AdapterError::InvalidConfiguration(format!(
                "Jenkins selection needs one HTTPS {role:?} endpoint"
            )));
        }
        normalized_endpoint(&values[0].url)
            .ok_or_else(|| AdapterError::InvalidConfiguration("Jenkins endpoint is unsafe".into()))
    };
    let certificate = role_url(EndpointRole::Index)?;
    let metadata = role_url(EndpointRole::Metadata)?;
    let packages = role_url(EndpointRole::Packages)?;
    let metadata_url = format!("{metadata}/update-center.json");
    let managed = managed_update_url(&metadata_url).ok_or_else(|| {
        AdapterError::InvalidConfiguration("Jenkins metadata endpoint is not immutable".into())
    })?;
    let expected_certificate = format!(
        "https://cdn.jsdelivr.net/gh/lework/jenkins-update-center@{}/rootCA",
        managed.commit
    );
    let expected_packages = ARTIFACT_MIRRORS
        .iter()
        .find(|(variant, _)| *variant == managed.variant)
        .map(|(_, endpoint)| *endpoint)
        .ok_or_else(|| {
            AdapterError::InvalidConfiguration("Jenkins mirror variant is unknown".into())
        })?;
    if certificate != expected_certificate || packages != expected_packages {
        return Err(AdapterError::InvalidConfiguration(
            "Jenkins certificate, metadata, and plugin mirror do not form a reviewed chain".into(),
        ));
    }
    Ok(SelectedConfiguration { url: metadata_url })
}

fn normalized_endpoint(value: &str) -> Option<String> {
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
    Some(value.trim_end_matches('/').to_owned())
}

fn render_update_center(
    path: &Path,
    contents: &[u8],
    selected_url: &str,
) -> Result<String, AdapterError> {
    if contents.is_empty() {
        return Ok(format!(
            "<?xml version='1.1' encoding='UTF-8'?>\n<sites>\n  <site>\n    <id>default</id>\n    <url>{selected_url}</url>\n  </site>\n</sites>\n"
        ));
    }
    let text = utf8(path, contents)?;
    let sites = parse_sites(path, contents)?;
    let defaults = sites
        .iter()
        .filter(|site| site.id == "default")
        .collect::<Vec<_>>();
    if defaults.len() > 1 {
        return Err(AdapterError::InvalidConfiguration(
            "Jenkins has multiple default Update Center sites".into(),
        ));
    }
    if let Some(default) = defaults.first() {
        return Ok(format!(
            "{}{}{}",
            &text[..default.url_range.start],
            selected_url,
            &text[default.url_range.end..]
        ));
    }
    let closing = text.rfind("</sites>").ok_or_else(|| {
        AdapterError::InvalidConfiguration(
            "Jenkins Update Center XML has no closing sites tag".into(),
        )
    })?;
    Ok(format!(
        "{}  <site>\n    <id>default</id>\n    <url>{selected_url}</url>\n  </site>\n{}",
        &text[..closing],
        &text[closing..]
    ))
}

fn validate_policy(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    for source in &current.sources {
        match metadata(source, "kind")? {
            "multiple-default-sites" => {
                return Err(AdapterError::InvalidConfiguration(
                    "Jenkins has multiple default Update Center sites".into(),
                ));
            }
            "custom-default-site" => {
                return Err(AdapterError::Unsupported(
                    "Jenkins default Update Center is custom or private and will not be replaced"
                        .into(),
                ));
            }
            "certificate-conflict" => {
                return Err(AdapterError::Unsupported(
                    "Jenkins Update Center root certificate path contains another certificate"
                        .into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn add_change(
    context: &SystemContext,
    current: &CurrentConfiguration,
    document: &ConfigurationDocument,
    rendered: Vec<u8>,
    summary: &str,
    changes: &mut Vec<PlannedFileChange>,
) {
    if document.contents != rendered {
        changes.push(PlannedFileChange {
            target: rooted(&context.root, &document.path),
            old_contents: current
                .files
                .contains(&document.path)
                .then(|| document.contents.clone()),
            old_mode: None,
            new_contents: rendered,
            new_mode: None,
            summary: summary.into(),
        });
    }
}

fn find_document<'a>(
    current: &'a CurrentConfiguration,
    format: &str,
) -> Result<&'a ConfigurationDocument, AdapterError> {
    current
        .documents
        .iter()
        .find(|document| document.format == format)
        .ok_or_else(|| AdapterError::InvalidConfiguration("Jenkins target is missing".into()))
}

fn current_value(current: &CurrentConfiguration, kind: &str) -> Result<String, AdapterError> {
    let values = current
        .sources
        .iter()
        .filter(|source| metadata(source, "kind").ok() == Some(kind))
        .map(|source| {
            source
                .url
                .split_once(':')
                .map(|(_, value)| value)
                .unwrap_or(&source.url)
                .to_owned()
        })
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Jenkins state has ambiguous {kind}"
        )));
    }
    Ok(values[0].clone())
}

fn snapshot_source(kind: &str, value: &str) -> ConfiguredSource {
    ConfiguredSource {
        upstream_id: None,
        url: format!("jenkins-snapshot:{value}"),
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
        AdapterError::InvalidConfiguration(format!("Jenkins source lacks {key} metadata"))
    })?;
    if values.len() != 1 {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Jenkins source has ambiguous {key} metadata"
        )));
    }
    Ok(&values[0])
}

fn require_linux(context: &SystemContext) -> Result<(), AdapterError> {
    if context.os != OperatingSystem::Linux
        || !matches!(
            context.architecture,
            Architecture::X86_64 | Architecture::Arm64
        )
    {
        return Err(AdapterError::Unsupported(
            "Jenkins Update Center adapter supports Linux x86_64 and arm64 only".into(),
        ));
    }
    Ok(())
}

fn require_scope(scope: ConfigurationScope) -> Result<(), AdapterError> {
    if scope != ConfigurationScope::System {
        return Err(AdapterError::Unsupported(
            "Jenkins Update Center requires system scope".into(),
        ));
    }
    Ok(())
}

fn require_current(current: &CurrentConfiguration) -> Result<(), AdapterError> {
    if current.tool_id != "jenkins" || current.scope != ConfigurationScope::System {
        return Err(AdapterError::InvalidConfiguration(
            "Jenkins operation received another tool or scope".into(),
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<&str, AdapterError> {
    path.to_str().ok_or_else(|| {
        AdapterError::InvalidConfiguration(format!("path {} is not UTF-8", path.display()))
    })
}

fn validate_path(path: &Path, kind: &str) -> Result<(), AdapterError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(AdapterError::InvalidConfiguration(format!(
            "Jenkins {kind} path {} is unsafe",
            path.display()
        )));
    }
    Ok(())
}

fn utf8<'a>(path: &Path, contents: &'a [u8]) -> Result<&'a str, AdapterError> {
    std::str::from_utf8(contents).map_err(|_| {
        AdapterError::InvalidConfiguration(format!(
            "Jenkins configuration {} is not UTF-8",
            path.display()
        ))
    })
}

fn verification_failure<T>(
    runtime: &mut dyn Runtime,
    receipt: &TransactionReceipt,
    reason: String,
) -> Result<T, AdapterError> {
    let restored = runtime.restore_transaction(&receipt.transaction_id)?;
    Err(AdapterError::Verification(format!(
        "{reason}; restored: {}",
        restored.verified
    )))
}

fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        path.to_path_buf()
    } else {
        root.join(path.strip_prefix("/").unwrap_or(path))
    }
}
