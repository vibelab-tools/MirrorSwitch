#![cfg(target_os = "linux")]

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{GhcupAdapter, compiled_adapter_allowlist},
    catalog::{
        CandidateEvaluation, ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod,
        Protocol, ToolCatalogState,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    selection::{CandidateProber, MirrorSelector, ProbeError, ProbeLimits, ProbeObservation},
    transaction::ApplyOutcome,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const GHCUP: &str = "ghcup--release-artifacts";
const METADATA: &str = "https://mirrors.nju.edu.cn/ghcup/yaml_v2/haskell/ghcup-metadata/master/";
const ARTIFACTS: &str = "https://mirror.nju.edu.cn/ghcup/packages/";
const METADATA_URL: &str =
    "https://mirrors.nju.edu.cn/ghcup/yaml_v2/haskell/ghcup-metadata/master/ghcup-0.0.9.yaml";

fn context(
    root: &Path,
    architecture: Architecture,
    environment: ExecutionEnvironment,
) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment,
        distribution: Some(Distribution {
            id: "ubuntu".into(),
            version_id: Some("24.04".into()),
            version_codename: Some("noble".into()),
            id_like: vec!["debian".into()],
        }),
        root: root.to_path_buf(),
    }
}

fn write(root: &Path, path: &str, contents: &[u8]) -> PathBuf {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    path
}

fn executable(root: &Path, path: &str, contents: String) {
    let path = write(root, path, contents.as_bytes());
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn install_ghcup(root: &Path, version: &str, config: &str, failure: &str) {
    executable(
        root,
        "/usr/bin/ghcup",
        format!(
            r#"#!/bin/sh
if [ "$1" = --numeric-version ]; then
  printf '%s\n' '{version}'
  exit 0
fi
case " $* " in
  *" --offline list --raw-format --show-criteria installed "*)
    printf '%s\n' 'GHC 9.6.6 installed' 'Cabal 3.10.2.1 installed'
    exit 0
    ;;
esac
config='{root}{config}'
grep -q '{metadata}' "$config" || exit 70
if grep -q '^gpg-setting:' "$config"; then
  grep -q 'gpg-setting: GPGStrict' "$config" || exit 71
fi
if grep -q '^no-verify:' "$config"; then
  grep -q 'no-verify: false' "$config" || exit 72
fi
grep -q 'host: mirror.nju.edu.cn' "$config" || exit 73
grep -q 'pathPrefix: ghcup/packages' "$config" || exit 74
tool=''
previous=''
for argument in "$@"; do
  if [ "$previous" = --tool ]; then tool="$argument"; fi
  previous="$argument"
done
[ -n "$tool" ] || exit 75
[ '{failure}' != "$tool" ] || exit 76
case "$tool" in
  ghc) printf '%s\n' 'GHC 9.10.3 available' ;;
  cabal) printf '%s\n' 'Cabal 3.14.2.0 available' ;;
  hls) printf '%s\n' 'HLS 2.13.0.0 available' ;;
  stack) printf '%s\n' 'Stack 3.7.1 available' ;;
  *) exit 77 ;;
esac
"#,
            root = root.display(),
            metadata = METADATA_URL,
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn selection() -> Vec<MirrorSelection> {
    vec![MirrorSelection {
        candidate_id: "ghcup-nju-test".into(),
        tool_id: "ghcup".into(),
        upstream_id: GHCUP.into(),
        provider_id: "nju".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: METADATA.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: ARTIFACTS.into(),
            },
        ],
        latency_ms: 2,
        selected_at_unix_ms: 100,
        user_override: false,
    }]
}

#[test]
fn user_config_preserves_channels_security_and_other_mirrors_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_ghcup(
        root,
        "0.2.6.2",
        "/home/developer/.ghcup/config.yaml",
        "none",
    );
    let original = br#"# user policy
url-source:
  - GHCupURL # replace only this default
  - prereleases
  - https://build:credential@example.invalid/private.yaml
gpg-setting: GPGStrict
no-verify: false
mirrors:
  github.com:
    authority:
      host: github-cache.example.invalid
  downloads.haskell.org:
    authority:
      host: old.example.invalid
    pathPrefix: haskell
keep-dirs: Errors
"#;
    let config = write(root, "/home/developer/.ghcup/config.yaml", original);
    let adapter = GhcupAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("0.2.6.2"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("2 record(s)"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(!format!("{current:?}").contains("build:credential@"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [GHCUP]);
    assert_eq!(request.repository_versions[GHCUP], "0.0.9");
    assert_eq!(request.probe_contexts[GHCUP].len(), 2);
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Metadata, EndpointRole::Artifacts]
    );

    let selected = selection();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config_file = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config_file);
    assert_eq!(config_file, tui);
    assert_eq!(cli.changes.len(), 1);
    assert_eq!(cli.changes[0].target, config);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("# replace only this default"));
    assert!(rendered.contains("  - prereleases"));
    assert!(rendered.contains("https://build:credential@example.invalid/private.yaml"));
    assert!(rendered.contains("gpg-setting: GPGStrict"));
    assert!(rendered.contains("no-verify: false"));
    assert!(rendered.contains("host: github-cache.example.invalid"));
    assert!(rendered.contains("keep-dirs: Errors"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("GHCup configuration should change")
    };
    let verified = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(verified.valid, "{}", verified.summary);
    let detected_after = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current_after = adapter
        .read_current(
            &context,
            &runtime,
            &detected_after,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current_after, &selected)
            .unwrap()
            .changes
            .is_empty()
    );

    let restored = adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert!(restored.restored);
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn xdg_scalar_channel_is_preserved_and_verification_failure_restores() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let logical = "/home/developer/.config/ghcup/config.yaml";
    install_ghcup(root, "0.2.6.2", logical, "hls");
    let original = b"url-source: prereleases\ngpg-setting: GPGStrict\nno-verify: false\n";
    let config = write(root, logical, original);
    let environment = BTreeMap::from([("GHCUP_USE_XDG_DIRS".into(), "1".into())]);
    let adapter = GhcupAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = runtime(root, environment);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!("  - {METADATA_URL}")));
    assert!(rendered.contains("  - prereleases"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("XDG GHCup configuration should change")
    };
    let verified = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(!verified.valid);
    assert!(
        verified
            .summary
            .contains("original GHCup configuration restored")
    );
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn install_prefix_creates_and_restores_the_selected_config() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let logical = "/home/developer/sdk/.ghcup/config.yaml";
    install_ghcup(root, "0.1.50.2", logical, "none");
    let environment = BTreeMap::from([(
        "GHCUP_INSTALL_BASE_PREFIX".into(),
        "/home/developer/sdk".into(),
    )]);
    let adapter = GhcupAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, environment);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("GHCup prefix configuration should be created")
    };
    let verified = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(verified.valid);
    adapter.restore(&context, &mut runtime, &receipt).unwrap();
    assert!(!root.join(logical.trim_start_matches('/')).exists());
}

#[test]
fn unsafe_yaml_old_versions_and_mixed_selections_fail_before_apply() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_ghcup(
        root,
        "0.2.6.2",
        "/home/developer/.ghcup/config.yaml",
        "none",
    );
    write(
        root,
        "/home/developer/.ghcup/config.yaml",
        b"url-source:\n  OwnSource:\n    - https://example.invalid/metadata.yaml\n",
    );
    let adapter = GhcupAdapter;
    let system = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let host_runtime = runtime(root, BTreeMap::new());
    let error = adapter.detect(&system, &host_runtime).unwrap_err();
    assert!(error.to_string().contains("non-scalar"));

    let old = tempdir().unwrap();
    install_ghcup(
        old.path(),
        "0.1.49.0",
        "/home/developer/.ghcup/config.yaml",
        "none",
    );
    let old_runtime = runtime(old.path(), BTreeMap::new());
    let error = adapter
        .detect(
            &context(old.path(), Architecture::X86_64, ExecutionEnvironment::Host),
            &old_runtime,
        )
        .unwrap_err();
    assert!(error.to_string().contains("predates"));

    write(
        root,
        "/home/developer/.ghcup/config.yaml",
        b"gpg-setting: GPGStrict\nno-verify: false\n",
    );
    let detected = adapter.detect(&system, &host_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&system, &host_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let mut mixed = selection();
    mixed[0].endpoints[1].url = "https://mirrors.ustc.edu.cn/ghcup/".into();
    let error = adapter.plan(&system, &current, &mixed).unwrap_err();
    assert!(error.to_string().contains("mixes metadata and bindist"));
}

#[derive(Clone)]
struct GhcupProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_metadata: bool,
    metadata: Vec<u8>,
    signature: Vec<u8>,
}

impl CandidateProber for GhcupProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let body = if url.ends_with("ghcup-0.0.9.yaml.sig") {
            self.signature.clone()
        } else if url.ends_with("ghcup-0.0.9.yaml") {
            if self.corrupt_metadata {
                b"ghcupDownloads: corrupt".to_vec()
            } else {
                self.metadata.clone()
            }
        } else {
            Vec::new()
        };
        Ok(ProbeObservation {
            status: 200,
            content_type: Some("application/octet-stream".into()),
            body,
            latency_ms: 1,
        })
    }
}

fn synthetic_catalog() -> (MirrorCatalog, Vec<u8>, Vec<u8>) {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let metadata = format!(
        "ghcupDownloads:\n{}",
        [
            "1ac63f04eac0ad551d45cbde38f27e0e3f43ceefd98833fae1fa3f2dbd042367",
            "052789dfe7f6fba6dc3822de0da272e8a5bd358c37adae17d8e82cff39bc1008",
            "8fbdb305c455585649147f8dcd5c5921cc48afcfa4b09f456e39e11ada122617",
            "cf2e19f664d34ae5edcd2d7ccb7022a7c9691607d42414c26a3de4aa252bed80",
            "3f0613893674783a99ffa8b5be3033d2797af632d6eb45d6f3fb0524d8c9e939",
            "eba07111ce65f082b4eef7382fce73bdb0dce73df2848f6d839ec59cb548f8cf",
            "aae7aadfba87588f85a7b346a224ee88b4b89728251ed4c5df5d912b389c239f",
            "11f97204de91f249487cb74d17c6a58aba11876b0ec431ccb67152991e13404d",
        ]
        .join("\n")
    )
    .into_bytes();
    let signature = b"reviewed detached signature".to_vec();
    let candidate = catalog
        .candidates
        .iter_mut()
        .find(|candidate| candidate.tool_id == "ghcup" && candidate.provider_id == "nju")
        .unwrap();
    for probe in &mut candidate.probes {
        if probe.path.ends_with(".yaml.sig") {
            probe.sha256 = Some(format!("{:x}", Sha256::digest(&signature)));
        } else if probe.path.ends_with(".yaml") && probe.sha256.is_some() {
            probe.sha256 = Some(format!("{:x}", Sha256::digest(&metadata)));
        }
    }
    (catalog, metadata, signature)
}

#[test]
fn catalog_activates_only_the_signed_arch_complete_chain_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    embedded.validate(&compiled_adapter_allowlist()).unwrap();
    assert_eq!(
        embedded
            .tools
            .iter()
            .find(|tool| tool.id == "ghcup")
            .unwrap()
            .state,
        ToolCatalogState::Supported
    );
    let candidates = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "ghcup")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    let actionable = candidates
        .iter()
        .filter(|candidate| candidate.delivery_mode == DeliveryMode::Mirror)
        .collect::<Vec<_>>();
    assert_eq!(actionable.len(), 1);
    let candidate = actionable[0];
    assert_eq!(candidate.provider_id, "nju");
    assert_eq!(candidate.probes.len(), 10);
    assert_eq!(
        candidate
            .endpoints
            .iter()
            .map(|endpoint| endpoint.role)
            .collect::<HashSet<_>>(),
        HashSet::from([EndpointRole::Metadata, EndpointRole::Artifacts])
    );
    assert_eq!(
        candidate.compatibility.architectures,
        [Architecture::X86_64, Architecture::Arm64]
    );

    let (catalog, metadata, signature) = synthetic_catalog();
    let directory = tempdir().unwrap();
    install_ghcup(
        directory.path(),
        "0.2.6.2",
        "/home/developer/.ghcup/config.yaml",
        "none",
    );
    write(
        directory.path(),
        "/home/developer/.ghcup/config.yaml",
        b"gpg-setting: GPGStrict\nno-verify: false\n",
    );
    let adapter = GhcupAdapter;
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let selected = MirrorSelector::with_prober(
        &catalog,
        GhcupProtocolProber {
            calls: calls.clone(),
            corrupt_metadata: false,
            metadata: metadata.clone(),
            signature: signature.clone(),
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable, "{selected:#?}");
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 20);
    let urls = calls
        .borrow()
        .iter()
        .map(|(_, url)| url.clone())
        .collect::<Vec<_>>();
    assert!(urls.iter().any(|url| url.contains("x86_64")));
    assert!(urls.iter().any(|url| url.contains("aarch64")));

    let rejected = MirrorSelector::with_prober(
        &catalog,
        GhcupProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_metadata: true,
            metadata,
            signature,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 101)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.selections.is_empty());
    assert!(matches!(
        rejected.repositories[0].candidates[0].evaluation,
        CandidateEvaluation::ProbeFailed { .. }
    ));
}
