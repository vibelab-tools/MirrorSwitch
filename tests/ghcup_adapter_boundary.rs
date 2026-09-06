#![cfg(unix)]

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

fn native_context(root: &Path, os: OperatingSystem, architecture: Architecture) -> SystemContext {
    SystemContext {
        os,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: match os {
                OperatingSystem::Linux => "linux",
                OperatingSystem::Macos => "macos",
                OperatingSystem::Windows => "windows",
            }
            .into(),
            version_id: None,
            version_codename: None,
            id_like: Vec::new(),
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
        .with_project_dir("/home/developer/project")
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
    assert_eq!(request.probe_contexts[GHCUP].len(), 1);
    assert_eq!(
        request.probe_contexts[GHCUP][0]["ghc_file"],
        "ghc-9.10.3-x86_64-deb12-linux.tar.xz"
    );
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
fn native_platforms_use_real_config_layouts_and_preserve_encoding_and_project_state() {
    let cases = [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "/home/developer/.ghcup/config.yaml",
            None,
            [
                ("ghc_file", "ghc-9.10.3-x86_64-apple-darwin.tar.xz"),
                (
                    "cabal_file",
                    "cabal-install-3.14.2.0-x86_64-apple-darwin.tar.xz",
                ),
                (
                    "hls_file",
                    "haskell-language-server-2.13.0.0-x86_64-apple-darwin.tar.xz",
                ),
                ("stack_file", "stack-3.7.1-osx-x86_64.tar.gz"),
            ],
        ),
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            "/home/developer/.ghcup/config.yaml",
            None,
            [
                ("ghc_file", "ghc-9.10.3-aarch64-apple-darwin.tar.xz"),
                (
                    "cabal_file",
                    "cabal-install-3.14.2.0-aarch64-apple-darwin.tar.xz",
                ),
                (
                    "hls_file",
                    "haskell-language-server-2.13.0.0-aarch64-apple-darwin.tar.xz",
                ),
                ("stack_file", "stack-3.7.1-osx-aarch64.tar.gz"),
            ],
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            "/home/developer/sdk/ghcup/config.yaml",
            Some("/home/developer/sdk"),
            [
                ("ghc_file", "ghc-9.10.3-x86_64-unknown-mingw32.tar.xz"),
                ("cabal_file", "cabal-install-3.14.2.0-x86_64-mingw64.zip"),
                (
                    "hls_file",
                    "haskell-language-server-2.13.0.0-x86_64-mingw64.zip",
                ),
                ("stack_file", "stack-3.7.1-windows-x86_64.tar.gz"),
            ],
        ),
    ];

    for (os, architecture, logical, prefix, files) in cases {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_ghcup(root, "0.2.6.2", logical, "none");
        let original = b"\xef\xbb\xbf# native policy\r\nurl-source:\r\n  - GHCupURL\r\n  - https://build:credential@example.invalid/private.yaml\r\ngpg-setting: GPGStrict\r\nno-verify: false\r\nkeep-dirs: Always\r\n";
        let config = write(root, logical, original);
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let project = write(
            root,
            "/home/developer/project/ghcup.yaml",
            b"url-source: https://project.invalid/metadata.yaml\n",
        );
        fs::set_permissions(&project, fs::Permissions::from_mode(0o400)).unwrap();
        let project_before = fs::read(&project).unwrap();
        let mut environment = BTreeMap::new();
        if let Some(prefix) = prefix {
            environment.insert("GHCUP_INSTALL_BASE_PREFIX".into(), prefix.into());
        }
        let adapter = GhcupAdapter;
        let context = native_context(root, os, architecture);
        let mut runtime = runtime(root, environment);

        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(detected.evidence.iter().any(|line| line.contains(logical)));
        assert!(
            detected
                .evidence
                .iter()
                .any(|line| line.contains(&format!("{os:?} {architecture:?}")))
        );
        assert!(detected.evidence.iter().any(|line| {
            line.contains("project directory /home/developer/project remains read-only")
        }));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(!format!("{current:?}").contains("credential"));
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        assert_eq!(request.probe_contexts[GHCUP].len(), 1);
        for (key, expected) in files {
            assert_eq!(request.probe_contexts[GHCUP][0][key], expected);
        }

        let selected = selection();
        let cli = adapter.plan(&context, &current, &selected).unwrap();
        let config_file = adapter.plan(&context, &current, &selected).unwrap();
        let tui = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(cli, config_file);
        assert_eq!(config_file, tui);
        assert_eq!(cli.changes.len(), 1);
        let rendered = &cli.changes[0].new_contents;
        assert!(rendered.starts_with(&[0xef, 0xbb, 0xbf]));
        assert!(rendered.windows(2).any(|window| window == b"\r\n"));
        assert!(!rendered.windows(2).any(|window| window == b"\n\n"));
        assert!(
            String::from_utf8_lossy(rendered)
                .contains("https://build:credential@example.invalid/private.yaml")
        );

        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("native GHCup configuration should change")
        };
        let verified = adapter.verify(&context, &mut runtime, &receipt).unwrap();
        assert!(verified.valid, "{}", verified.summary);
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&project).unwrap(), project_before);
        assert_eq!(
            fs::metadata(&project).unwrap().permissions().mode() & 0o777,
            0o400
        );

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
        assert!(
            adapter
                .restore(&context, &mut runtime, &receipt)
                .unwrap()
                .restored
        );
        assert_eq!(fs::read(&config).unwrap(), original);
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn unsupported_native_contexts_fail_before_discovery() {
    let directory = tempdir().unwrap();
    let adapter = GhcupAdapter;
    let runtime = runtime(directory.path(), BTreeMap::new());

    let mut mac_container = native_context(
        directory.path(),
        OperatingSystem::Macos,
        Architecture::X86_64,
    );
    mac_container.environment = ExecutionEnvironment::Container;
    assert!(
        adapter
            .detect(&mac_container, &runtime)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );

    let windows_arm = native_context(
        directory.path(),
        OperatingSystem::Windows,
        Architecture::Arm64,
    );
    assert!(
        adapter
            .detect(&windows_arm, &runtime)
            .unwrap_err()
            .to_string()
            .contains("no Windows arm64 GHC toolchain")
    );
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
            "01e4ff9530c124408db0b0f9ec7e4be35b300a6aee939c5758d1acf22d51693f",
            "1a45b672939f72b88187ae1b623e42440ab37c03338484d928f47cdde0f5189f",
            "c4b52ec3eb914643d49d151ef6eeaaf941f1332a485ef9bbdd98ee961deae382",
            "a45175d882373afafc3b0dc8c7cf1aab6d046f6134fe465e03b2e61a7add1098",
            "9f50ddd87be5cb994c719402778d6c7fdd341934fd4fbc0fcc3ecb40d49f860c",
            "a7ce265f063030a2d3648b31419de11ba0d17c67fa5e74a6d285607f6d55d235",
            "919fb3949665a8eccfa4865b5ea3442b8f7438a069501550ef75fdd34834f040",
            "c08d0e3ce2bf1518f3fa654014acd25801f921ef0d4879882ac35c075605feb0",
            "ad17bdbee5f195d50024da1447f458071d9d8a34f90d76907c873abaf95d893f",
            "e45f979e7c24591c6131619666be8f3345345ccf779d8bb7d19cd73ead8b940b",
            "12eec35adab02016fa8bea4bcde0ffc5ccd0f1a149e8024d63e5c211ac305bdc",
            "244b230db60c5f5dee70bd3d4f1f0d7097aee2254429a75369961db7060631af",
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
    assert_eq!(
        candidate.compatibility.operating_systems,
        [
            OperatingSystem::Linux,
            OperatingSystem::Macos,
            OperatingSystem::Windows,
        ]
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
    assert_eq!(calls.borrow().len(), 10);
    let urls = calls
        .borrow()
        .iter()
        .map(|(_, url)| url.clone())
        .collect::<Vec<_>>();
    assert!(urls.iter().any(|url| url.contains("x86_64")));
    assert!(!urls.iter().any(|url| url.contains("aarch64")));

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

#[test]
fn native_candidates_probe_one_exact_complete_platform_chain() {
    let (catalog, metadata, signature) = synthetic_catalog();
    let cases = [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "/home/developer/.ghcup/config.yaml",
            None,
            [
                "ghc-9.10.3-x86_64-apple-darwin.tar.xz",
                "cabal-install-3.14.2.0-x86_64-apple-darwin.tar.xz",
                "haskell-language-server-2.13.0.0-x86_64-apple-darwin.tar.xz",
                "stack-3.7.1-osx-x86_64.tar.gz",
            ],
        ),
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            "/home/developer/.ghcup/config.yaml",
            None,
            [
                "ghc-9.10.3-aarch64-apple-darwin.tar.xz",
                "cabal-install-3.14.2.0-aarch64-apple-darwin.tar.xz",
                "haskell-language-server-2.13.0.0-aarch64-apple-darwin.tar.xz",
                "stack-3.7.1-osx-aarch64.tar.gz",
            ],
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            "/home/developer/sdk/ghcup/config.yaml",
            Some("/home/developer/sdk"),
            [
                "ghc-9.10.3-x86_64-unknown-mingw32.tar.xz",
                "cabal-install-3.14.2.0-x86_64-mingw64.zip",
                "haskell-language-server-2.13.0.0-x86_64-mingw64.zip",
                "stack-3.7.1-windows-x86_64.tar.gz",
            ],
        ),
    ];

    for (os, architecture, logical, prefix, files) in cases {
        let directory = tempdir().unwrap();
        install_ghcup(directory.path(), "0.2.6.2", logical, "none");
        write(
            directory.path(),
            logical,
            b"gpg-setting: GPGStrict\nno-verify: false\n",
        );
        let mut environment = BTreeMap::new();
        if let Some(prefix) = prefix {
            environment.insert("GHCUP_INSTALL_BASE_PREFIX".into(), prefix.into());
        }
        let adapter = GhcupAdapter;
        let context = native_context(directory.path(), os, architecture);
        let runtime = runtime(directory.path(), environment);
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
        assert_eq!(calls.borrow().len(), 10);
        let urls = calls
            .borrow()
            .iter()
            .map(|(_, url)| url.clone())
            .collect::<Vec<_>>();
        for file in files {
            assert!(urls.iter().any(|url| url.ends_with(file)), "{file}");
        }
    }
}
