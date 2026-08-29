#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{DartPubAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "dart-pub--language-registry";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub";
const TUNA_ARTIFACTS: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub/packages";
const SJTUG: &str = "https://mirror.sjtu.edu.cn/dart-pub";
const SJTUG_ARTIFACTS: &str =
    "https://storage.flutter-io.cn/dartlang-pub-exported-api/latest/api/archives";
const RETRY_SHA: &str = "822e118d5b3aafed083109c72d5f484c6dc66707885e07c0fbcb8b986bba7efc";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
        distribution: Some(Distribution {
            id: "debian".into(),
            version_id: Some("12".into()),
            version_codename: Some("bookworm".into()),
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

fn install_dart(root: &Path, version: &str, verification_exit: i32) {
    executable(
        root,
        "/usr/bin/env",
        format!(
            r#"#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    *=*) export "$1"; shift ;;
    *) break ;;
  esac
done
[ "$1" = dart ] || exit 90
shift
exec '{root}/usr/bin/dart' "$@"
"#,
            root = root.display(),
        ),
    );
    executable(
        root,
        "/usr/bin/dart",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then
  printf '%s\n' 'Dart SDK version: {version} (stable) on "linux_x64"' >&2
  exit 0
fi
if [ "$1" = pub ] && [ "$2" = --help ]; then
  printf '%s\n' 'Available subcommands:' '  get' '  deps' '  cache' '  token'
  exit 0
fi
[ -n "${{PUB_HOSTED_URL:-}}" ] || exit 61
[ -n "${{PUB_CACHE:-}}" ] || exit 62
[ "${{DART_SUPPRESS_ANALYTICS:-}}" = 1 ] || exit 63
grep -F 'Managed by MirrorSwitch: Dart Pub verification project' "$PWD/pubspec.yaml" >/dev/null || exit 64
grep -F 'retry: 3.1.2' "$PWD/pubspec.yaml" >/dev/null || exit 65
[ {verification_exit} -eq 0 ] || exit {verification_exit}
if [ "$1" = pub ] && [ "$2" = get ]; then
  mkdir -p '{root}'"${{PUB_CACHE}}"
  printf '%s\n' \
    'packages:' \
    '  retry:' \
    '    dependency: "direct main"' \
    '    description:' \
    '      name: retry' \
    "      url: \"${{PUB_HOSTED_URL}}\"" \
    '    source: hosted' \
    '    version: "3.1.2"' \
    'sdks:' \
    '  dart: ">=2.12.0 <4.0.0"' > "$PWD/pubspec.lock"
  printf '%s\n' 'Got dependencies!'
elif [ "$1" = pub ] && [ "$2" = deps ] && [ "$3" = --style=compact ]; then
  grep -F "url: \"${{PUB_HOSTED_URL}}\"" "$PWD/pubspec.lock" >/dev/null || exit 66
  printf '%s\n' 'mirrorswitch_dart_pub_verification 0.0.0' '- retry 3.1.2'
else
  exit 67
fi
"#,
            root = root.display(),
        ),
    );
}

fn test_runtime(
    root: &Path,
    environment: BTreeMap<String, String>,
    project: Option<&str>,
) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn environment(shell: &str, hosted: Option<&str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
        ("SHELL".into(), shell.into()),
        (
            "PUB_CACHE".into(),
            "/home/developer/custom-pub-cache".into(),
        ),
    ]);
    if let Some(hosted) = hosted {
        values.insert("PUB_HOSTED_URL".into(), hosted.into());
    }
    values
}

fn selection(provider: &str, hosted: &str, artifacts: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("dart-pub-{provider}-test"),
        tool_id: "dart-pub".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: provider.into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: hosted.into(),
            },
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: hosted.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: artifacts.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn tuna_selection() -> [MirrorSelection; 1] {
    [selection("tuna", TUNA, TUNA_ARTIFACTS)]
}

#[test]
fn user_plan_adopts_public_assignment_and_preserves_private_project_and_tokens() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dart(root, "3.9.3", 0);
    let original =
        b"# keep shell policy\nexport EDITOR=vim\nexport PUB_HOSTED_URL=\"https://pub.dev\"\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    write(
        root,
        "/home/developer/.config/dart/pub-tokens.json",
        b"\xff\xfeopaque-token-store",
    );
    let pubspec = br#"name: private_app
publish_to: https://packages.example/publish
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  retry: 3.1.2
  private_package:
    hosted: https://packages.example/dart
    version: 1.0.0
  local_package:
    path: ../local
  source_package:
    git: https://git.example/private.git
"#;
    let pubspec_path = write(root, "/work/project/pubspec.yaml", pubspec);
    let lock = b"packages:\n  private_package:\n    description:\n      url: \"https://packages.example/dart\"\n    source: hosted\n    version: \"1.0.0\"\n";
    let lock_path = write(root, "/work/project/pubspec.lock", lock);
    let adapter = DartPubAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = test_runtime(
        root,
        environment("/bin/bash", Some("https://pub.dev")),
        Some("/work/project"),
    );

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("3.9.3"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "Pub token store file(s): 1 (contents not read)")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let cli = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let config = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let tui = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 2);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("export EDITOR=vim"));
    assert!(changed.contains("MirrorSwitch Dart Pub mirror"));
    assert!(changed.contains(TUNA));
    assert!(!changed.contains("https://pub.dev"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Dart Pub files should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&pubspec_path).unwrap(), pubspec);
    assert_eq!(fs::read(&lock_path).unwrap(), lock);

    let refreshed = test_runtime(
        root,
        environment("/bin/bash", Some(TUNA)),
        Some("/work/project"),
    );
    let current = adapter
        .read_current(&context, &refreshed, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
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
    assert_eq!(fs::read(profile).unwrap(), original);
    assert_eq!(fs::read(pubspec_path).unwrap(), pubspec);
    assert_eq!(fs::read(lock_path).unwrap(), lock);
}

#[test]
fn arm64_fish_missing_profile_produces_stable_sjtug_plan() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dart(root, "2.19.6", 0);
    let adapter = DartPubAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = test_runtime(root, environment("/usr/bin/fish", None), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selected = [selection("sjtug", SJTUG, SJTUG_ARTIFACTS)];
    let first = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(first, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(first.changes.len(), 2);
    let profile = String::from_utf8(first.changes[0].new_contents.clone()).unwrap();
    assert!(profile.contains("set -gx PUB_HOSTED_URL"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &first).unwrap()
    else {
        panic!("Dart Pub files should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn unsupported_versions_precedence_private_dynamic_and_endpoint_mismatch_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = DartPubAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(
                &context,
                &test_runtime(root, environment("/bin/bash", None), None)
            )
            .unwrap()
            .is_none()
    );
    for version in ["2.11.0", "4.0.0"] {
        install_dart(root, version, 0);
        assert!(
            adapter
                .detect(
                    &context,
                    &test_runtime(root, environment("/bin/bash", None), None)
                )
                .unwrap_err()
                .to_string()
                .contains("outside the reviewed")
        );
    }
    install_dart(root, "3.9.3", 0);

    let overridden = test_runtime(
        root,
        environment("/bin/bash", Some("https://pub.dev")),
        None,
    );
    let detected = adapter.detect(&context, &overridden).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &overridden, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
            .unwrap_err()
            .to_string()
            .contains("not represented")
    );

    write(
        root,
        "/home/developer/.bashrc",
        b"export PUB_HOSTED_URL='https://packages.example/dart'\n",
    );
    let base = test_runtime(root, environment("/bin/bash", None), None);
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    write(
        root,
        "/home/developer/.bashrc",
        b"export PUB_HOSTED_URL=\"$DART_MIRROR\"\n",
    );
    assert!(
        adapter
            .read_current(&context, &base, &detected, ConfigurationScope::User)
            .is_err()
    );
    write(root, "/home/developer/.bashrc", b"# clean\n");
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    let mut mismatched = tuna_selection();
    mismatched[0].endpoints[2].url = SJTUG_ARTIFACTS.into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
}

#[test]
fn failed_real_get_restores_profile_and_managed_fixture() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dart(root, "3.9.3", 9);
    let original = b"export EDITOR=nano\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = DartPubAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = test_runtime(root, environment("/bin/bash", None), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Dart Pub files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/dart-pub/pubspec.yaml")
            .exists()
    );
}

#[test]
fn embedded_catalog_has_two_content_complete_and_two_inert_inventory_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "dart-pub")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 4);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 2);
    assert_eq!(
        complete
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["sjtug", "tuna"])
    );
    for candidate in complete {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Proxy);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [OperatingSystem::Linux]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(candidate.probes.len(), 4);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert_eq!(candidate.probes[2].method, HttpMethod::Head);
        assert_eq!(candidate.probes[3].sha256.as_deref(), Some(RETRY_SHA));
        assert!(
            candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Index)
        );
        assert!(
            candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Metadata)
        );
        assert!(
            candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
        );
    }
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .count(),
        2
    );
}
