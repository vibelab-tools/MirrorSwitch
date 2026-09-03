#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{FlutterAdapter, compiled_adapter_allowlist},
    catalog::{
        CompositionPolicy, ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod,
        Protocol,
    },
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const STORAGE_UPSTREAM: &str = "flutter--release-artifacts";
const PUB_UPSTREAM: &str = "dart-pub--language-registry";
const NJU_STORAGE: &str = "https://mirrors.nju.edu.cn/flutter";
const SJTUG_STORAGE: &str = "https://mirror.sjtu.edu.cn";
const TUNA_PUB: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub";
const TUNA_ARTIFACTS: &str = "https://mirrors.tuna.tsinghua.edu.cn/dart-pub/packages";
const SJTUG_PUB: &str = "https://mirror.sjtu.edu.cn/dart-pub";
const SJTUG_ARTIFACTS: &str =
    "https://storage.flutter-io.cn/dartlang-pub-exported-api/latest/api/archives";
const FRAMEWORK_REVISION: &str = "d3b14c876900e553bc736ca19295fc09e3853e8e";
const ENGINE_REVISION: &str = "a804b261645ef8c13eb3d5c44a5c2fb0340c5539";
const ENGINE_CONTENT_HASH: &str = "1cf1c4773fb941c4c74a7f8bb144a8837596c0f4";
const RELEASE_IDENTITY: &str = "stable/3.47.2/d3b14c876900e553bc736ca19295fc09e3853e8e/a804b261645ef8c13eb3d5c44a5c2fb0340c5539";
const VERIFY_PUBSPEC: &str = "# Managed by MirrorSwitch: Flutter verification project v1\nname: mirrorswitch_flutter_verification\npublish_to: none\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  retry: 3.1.2\n";

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
            id: "debian".into(),
            version_id: Some("13".into()),
            version_codename: Some("trixie".into()),
            id_like: Vec::new(),
        }),
        root: root.to_path_buf(),
    }
}

fn native_context(root: &Path, os: OperatingSystem, architecture: Architecture) -> SystemContext {
    SystemContext {
        os,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: None,
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

fn install_flutter(
    root: &Path,
    version: &str,
    channel: &str,
    repository: &str,
    verification_failure: &str,
) {
    executable(
        root,
        "/usr/bin/flutter",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ] && [ "$2" = --machine ]; then
  printf '%s\n' '{{"frameworkVersion":"{version}","channel":"{channel}","repositoryUrl":"{repository}","frameworkRevision":"{framework}","engineRevision":"{engine}","engineContentHash":"{content_hash}","dartSdkVersion":"3.13.2","devToolsVersion":"2.51.1"}}'
  exit 0
fi
if [ "$1" = precache ] && [ "$2" = --help ]; then
  printf '%s\n' 'Populate the Flutter tool cache.' '    --linux' '    --macos' '    --windows'
  exit 0
fi
if [ "$1" = --suppress-analytics ]; then
  shift
fi
printf '%s\n' "$*" >> '{root}/flutter-commands.log'
[ -n "${{FLUTTER_STORAGE_BASE_URL:-}}" ] || exit 61
[ -n "${{PUB_HOSTED_URL:-}}" ] || exit 62
[ "${{DART_SUPPRESS_ANALYTICS:-}}" = 1 ] || exit 63
[ "${{FLUTTER_SUPPRESS_ANALYTICS:-}}" = true ] || exit 64
if [ "$1" = precache ] && {{ [ "$2" = --linux ] || [ "$2" = --macos ] || [ "$2" = --windows ]; }}; then
  [ '{verification_failure}' = precache ] && exit 9
  printf '%s\n' 'Already up-to-date.'
  exit 0
fi
if [ "$1" = doctor ] && [ "$2" = --verbose ]; then
  [ '{verification_failure}' = doctor ] && exit 9
  printf '%s\n' '[✓] Flutter (Channel {channel}, {version}, on Linux)'
  exit 0
fi
[ "$1" = pub ] || exit 65
[ -n "${{PUB_CACHE:-}}" ] || exit 66
grep -F 'Managed by MirrorSwitch: Flutter verification project v1' "$PWD/pubspec.yaml" >/dev/null || exit 67
grep -F 'retry: 3.1.2' "$PWD/pubspec.yaml" >/dev/null || exit 68
if [ "$2" = get ]; then
  [ '{verification_failure}' = get ] && exit 9
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
    '  dart: ">=3.0.0 <4.0.0"' > "$PWD/pubspec.lock"
  printf '%s\n' 'Got dependencies!'
  exit 0
fi
if [ "$2" = deps ] && [ "$3" = --style=compact ]; then
  [ '{verification_failure}' = deps ] && exit 9
  grep -F "url: \"${{PUB_HOSTED_URL}}\"" "$PWD/pubspec.lock" >/dev/null || exit 69
  printf '%s\n' 'mirrorswitch_flutter_verification 0.0.0' '- retry 3.1.2'
  exit 0
fi
exit 70
"#,
            root = root.display(),
            framework = FRAMEWORK_REVISION,
            engine = ENGINE_REVISION,
            content_hash = ENGINE_CONTENT_HASH,
        ),
    );
}

fn install_windows_registry(
    root: &Path,
    storage: Option<&str>,
    hosted: Option<&str>,
    mutation_exit: i32,
) -> (PathBuf, PathBuf) {
    let storage_state = root.join("windows-registry/flutter-storage");
    let pub_state = root.join("windows-registry/pub-hosted");
    fs::create_dir_all(storage_state.parent().unwrap()).unwrap();
    if let Some(value) = storage {
        fs::write(&storage_state, value).unwrap();
    }
    if let Some(value) = hosted {
        fs::write(&pub_state, value).unwrap();
    }
    executable(
        root,
        "/usr/bin/reg.exe",
        format!(
            r#"#!/bin/sh
storage='{storage_state}'
hosted='{pub_state}'
variable="$4"
case "$variable" in FLUTTER_STORAGE_BASE_URL) state="$storage" ;; PUB_HOSTED_URL) state="$hosted" ;; *) exit 90 ;; esac
case "$1" in
  query)
    [ -f "$state" ] || exit 1
    printf '%s\n' 'HKEY_CURRENT_USER\Environment' "    $variable    REG_SZ    $(cat "$state")"
    ;;
  add)
    [ {mutation_exit} -eq 0 ] || exit {mutation_exit}
    printf '%s' "$8" > "$state"
    ;;
  delete)
    [ {mutation_exit} -eq 0 ] || exit {mutation_exit}
    rm -f "$state"
    ;;
  *) exit 91 ;;
esac
"#,
            storage_state = storage_state.display(),
            pub_state = pub_state.display(),
        ),
    );
    (storage_state, pub_state)
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

fn environment(
    shell: &str,
    storage: Option<&str>,
    hosted: Option<&str>,
) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([("SHELL".into(), shell.into())]);
    if let Some(storage) = storage {
        values.insert("FLUTTER_STORAGE_BASE_URL".into(), storage.into());
    }
    if let Some(hosted) = hosted {
        values.insert("PUB_HOSTED_URL".into(), hosted.into());
    }
    values
}

fn windows_environment(storage: Option<&str>, hosted: Option<&str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
        ("APPDATA".into(), "/home/developer/AppData/Roaming".into()),
        (
            "LOCALAPPDATA".into(),
            "/home/developer/AppData/Local".into(),
        ),
    ]);
    if let Some(storage) = storage {
        values.insert("FLUTTER_STORAGE_BASE_URL".into(), storage.into());
    }
    if let Some(hosted) = hosted {
        values.insert("PUB_HOSTED_URL".into(), hosted.into());
    }
    values
}

fn storage_selection(provider: &str, base: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("flutter-storage-{provider}-test"),
        tool_id: "flutter".into(),
        upstream_id: STORAGE_UPSTREAM.into(),
        provider_id: provider.into(),
        endpoints: [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ]
        .into_iter()
        .map(|role| Endpoint {
            role,
            protocol: Protocol::Https,
            url: base.into(),
        })
        .collect(),
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn pub_selection(provider: &str, hosted: &str, artifacts: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("flutter-pub-{provider}-test"),
        tool_id: "flutter".into(),
        upstream_id: PUB_UPSTREAM.into(),
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

fn tuna_selections() -> Vec<MirrorSelection> {
    vec![
        storage_selection("nju", NJU_STORAGE),
        pub_selection("tuna", TUNA_PUB, TUNA_ARTIFACTS),
    ]
}

fn sjtug_selections() -> Vec<MirrorSelection> {
    vec![
        storage_selection("sjtug", SJTUG_STORAGE),
        pub_selection("sjtug", SJTUG_PUB, SJTUG_ARTIFACTS),
    ]
}

#[test]
fn user_plan_verifies_both_repositories_and_preserves_project_and_tokens() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "",
    );
    let original = b"# keep shell policy\nexport FLUTTER_STORAGE_BASE_URL='https://storage.googleapis.com'\nexport EDITOR=vim\nexport PUB_HOSTED_URL=https://pub.dev\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let token = write(
        root,
        "/home/developer/.config/dart/pub-tokens.json",
        b"\xff\xfeopaque-token-store",
    );
    let pubspec = br#"name: private_app
publish_to: https://packages.example/publish
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  private_package:
    hosted: https://packages.example/dart
    version: 1.0.0
  local_package:
    path: ../local
  source_package:
    git: https://git.example/private.git
  flutter:
    sdk: flutter
"#;
    let project_pubspec = write(root, "/work/project/pubspec.yaml", pubspec);
    let project_lock = b"packages:\n  private_package:\n    description:\n      url: \"https://packages.example/dart\"\n    source: hosted\n    version: \"1.0.0\"\n";
    let project_lock_path = write(root, "/work/project/pubspec.lock", project_lock);
    let adapter = FlutterAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(
        root,
        environment(
            "/bin/bash",
            Some("https://storage.googleapis.com"),
            Some("https://pub.dev"),
        ),
        Some("/work/project"),
    );

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("3.47.2"));
    assert!(detected.evidence.iter().any(|line| line
        == "Flutter engine artifact revision is a804b261645ef8c13eb3d5c44a5c2fb0340c5539"));
    assert!(
        detected.evidence.iter().any(|line| line
            == "Flutter engine content hash is 1cf1c4773fb941c4c74a7f8bb144a8837596c0f4")
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "Pub token store file(s): 1 (contents not read)")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [STORAGE_UPSTREAM, PUB_UPSTREAM]);
    assert_eq!(
        request.repository_versions[STORAGE_UPSTREAM],
        RELEASE_IDENTITY
    );

    let selections = tuna_selections();
    let cli = adapter.plan(&context, &current, &selections).unwrap();
    let config = adapter.plan(&context, &current, &selections).unwrap();
    let tui = adapter.plan(&context, &current, &selections).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 3);
    assert!(!cli.requires_elevation);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("export EDITOR=vim"));
    assert!(changed.contains("MirrorSwitch Flutter mirrors"));
    assert!(changed.contains(NJU_STORAGE));
    assert!(changed.contains(TUNA_PUB));
    assert!(!changed.contains("storage.googleapis.com"));
    assert!(!changed.contains("https://pub.dev"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Flutter profile and verification files should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&project_pubspec).unwrap(), pubspec);
    assert_eq!(fs::read(&project_lock_path).unwrap(), project_lock);
    assert_eq!(fs::read(&token).unwrap(), b"\xff\xfeopaque-token-store");
    let commands = fs::read_to_string(root.join("flutter-commands.log")).unwrap();
    assert!(commands.lines().any(|line| line == "precache --linux"));
    assert!(commands.lines().any(|line| line == "doctor --verbose"));
    assert!(commands.lines().any(|line| line == "pub get"));
    assert!(
        commands
            .lines()
            .any(|line| line == "pub deps --style=compact")
    );

    let refreshed = test_runtime(
        root,
        environment("/bin/bash", Some(NJU_STORAGE), Some(TUNA_PUB)),
        Some("/work/project"),
    );
    let current = adapter
        .read_current(&context, &refreshed, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections)
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
    assert_eq!(fs::read(project_pubspec).unwrap(), pubspec);
    assert_eq!(fs::read(project_lock_path).unwrap(), project_lock);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/flutter/pubspec.yaml")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/flutter/pubspec.lock")
            .exists()
    );
}

#[test]
fn macos_profile_preserves_bom_native_tokens_and_project_state() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "",
    );
    let original = b"\xef\xbb\xbf# macOS shell policy\nexport FLUTTER_STORAGE_BASE_URL='https://storage.googleapis.com'\nexport PUB_HOSTED_URL='https://pub.dev'\n";
    let profile = write(root, "/home/developer/.zshrc", original);
    let token = write(
        root,
        "/home/developer/Library/Application Support/dart/pub-tokens.json",
        b"\xffnative-token-store",
    );
    let project_contents = b"name: native_flutter\npublish_to: none\n";
    let project = write(root, "/work/project/pubspec.yaml", project_contents);
    let adapter = FlutterAdapter;
    let context = native_context(root, OperatingSystem::Macos, Architecture::Arm64);
    let mut runtime = test_runtime(
        root,
        environment("/bin/zsh", None, None),
        Some("/work/project"),
    );

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Macos Arm64"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("--macos precache"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "Pub token store file(s): 1 (contents not read)")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts[STORAGE_UPSTREAM][0];
    assert_eq!(probe["flutter_release_manifest"], "releases_macos.json");
    assert_eq!(probe["flutter_engine_platform"], "darwin-arm64");
    let selected = tuna_selections();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert!(cli.changes[0].new_contents.starts_with(&[0xef, 0xbb, 0xbf]));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("macOS Flutter files should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &selected)
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
    assert_eq!(fs::read(token).unwrap(), b"\xffnative-token-store");
    assert_eq!(fs::read(project).unwrap(), project_contents);
}

#[test]
fn windows_registry_pair_is_private_idempotent_and_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "",
    );
    let (storage_state, pub_state) = install_windows_registry(
        root,
        Some("https://storage.googleapis.com"),
        Some("https://pub.dev"),
        0,
    );
    let token = write(
        root,
        "/home/developer/AppData/Roaming/dart/pub-tokens.json",
        b"\xffwindows-token-store",
    );
    let project_contents = b"name: windows_flutter\npublish_to: none\n";
    let project = write(root, "/work/project/pubspec.yaml", project_contents);
    let adapter = FlutterAdapter;
    let context = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    let mut runtime = test_runtime(root, windows_environment(None, None), Some("/work/project"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Windows X86_64"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("--windows precache"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("Windows user environment"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    let probe = &request.probe_contexts[STORAGE_UPSTREAM][0];
    assert_eq!(probe["flutter_release_manifest"], "releases_windows.json");
    assert_eq!(probe["flutter_engine_platform"], "windows-x64");
    let selected = sjtug_selections();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 3);
    assert!(!format!("{cli:?}").contains("storage.googleapis.com"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Windows Flutter state should change")
    };
    assert_eq!(fs::read_to_string(&storage_state).unwrap(), SJTUG_STORAGE);
    assert_eq!(fs::read_to_string(&pub_state).unwrap(), SJTUG_PUB);
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &selected)
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
    assert_eq!(
        fs::read_to_string(storage_state).unwrap(),
        "https://storage.googleapis.com"
    );
    assert_eq!(fs::read_to_string(pub_state).unwrap(), "https://pub.dev");
    assert!(
        !root
            .join("home/developer/AppData/Local/MirrorSwitch/flutter/environment-recovery.json")
            .exists()
    );
    assert_eq!(fs::read(token).unwrap(), b"\xffwindows-token-store");
    assert_eq!(fs::read(project).unwrap(), project_contents);
}

#[test]
fn arm64_and_shell_specific_profiles_produce_stable_unprivileged_plans() {
    let cases = [
        (
            Architecture::Arm64,
            "/usr/bin/fish",
            "https://mirrors.nju.edu.cn/git/flutter-sdk.git",
            BTreeMap::new(),
            "/home/developer/.config/fish/conf.d/mirrorswitch-flutter.fish",
            "set -gx FLUTTER_STORAGE_BASE_URL",
        ),
        (
            Architecture::X86_64,
            "/bin/zsh",
            "git@github.com:flutter/flutter.git",
            BTreeMap::from([("ZDOTDIR".into(), "/home/developer/zsh".into())]),
            "/home/developer/zsh/.zshrc",
            "export FLUTTER_STORAGE_BASE_URL",
        ),
        (
            Architecture::X86_64,
            "/bin/bash",
            "https://github.com/flutter/flutter.git",
            BTreeMap::from([("BASH_ENV".into(), "/home/developer/container.env".into())]),
            "/home/developer/container.env",
            "export FLUTTER_STORAGE_BASE_URL",
        ),
    ];
    for (architecture, shell, repository, extra, expected_profile, assignment) in cases {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_flutter(root, "3.47.2", "beta", repository, "");
        let mut values = environment(shell, None, None);
        values.extend(extra);
        let adapter = FlutterAdapter;
        let context = context(root, architecture, ExecutionEnvironment::Container);
        let runtime = test_runtime(root, values, None);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let selections = sjtug_selections();
        let plan = adapter.plan(&context, &current, &selections).unwrap();
        assert_eq!(plan, adapter.plan(&context, &current, &selections).unwrap());
        assert!(!plan.requires_elevation);
        let profile = plan
            .changes
            .iter()
            .find(|change| {
                change
                    .target
                    .ends_with(expected_profile.trim_start_matches('/'))
            })
            .unwrap();
        assert!(
            String::from_utf8(profile.new_contents.clone())
                .unwrap()
                .contains(assignment)
        );
    }
}

#[test]
fn unsupported_versions_policy_conflicts_and_mismatched_selections_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = FlutterAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    assert!(
        adapter
            .detect(
                &context,
                &test_runtime(root, environment("/bin/bash", None, None), None)
            )
            .unwrap()
            .is_none()
    );
    for (version, channel, repository) in [
        ("3.21.9", "stable", "https://github.com/flutter/flutter.git"),
        ("3.47.2", "main", "https://github.com/flutter/flutter.git"),
        ("3.47.2", "stable", "https://git.example/flutter.git"),
    ] {
        install_flutter(root, version, channel, repository, "");
        assert!(
            adapter
                .detect(
                    &context,
                    &test_runtime(root, environment("/bin/bash", None, None), None)
                )
                .is_err()
        );
    }
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "",
    );

    let overridden = test_runtime(
        root,
        environment(
            "/bin/bash",
            Some("https://storage.googleapis.com"),
            Some("https://pub.dev"),
        ),
        None,
    );
    let detected = adapter.detect(&context, &overridden).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &overridden, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selections())
            .unwrap_err()
            .to_string()
            .contains("not represented")
    );

    write(
        root,
        "/home/developer/.bashrc",
        b"export FLUTTER_STORAGE_BASE_URL='https://packages.example/flutter'\nexport PUB_HOSTED_URL='https://pub.dev'\n",
    );
    let base = test_runtime(root, environment("/bin/bash", None, None), None);
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selections())
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    write(
        root,
        "/home/developer/.bashrc",
        b"export FLUTTER_STORAGE_BASE_URL=\"$FLUTTER_MIRROR\"\n",
    );
    assert!(
        adapter
            .read_current(&context, &base, &detected, ConfigurationScope::User)
            .is_err()
    );
    write(
        root,
        "/home/developer/.bashrc",
        b"# >>> MirrorSwitch Dart Pub mirror >>>\n# <<< MirrorSwitch Dart Pub mirror <<<\n",
    );
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selections())
            .unwrap_err()
            .to_string()
            .contains("Dart Pub adapter")
    );

    write(root, "/home/developer/.bashrc", b"# clean\n");
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selections()[..1])
            .is_err()
    );
    let mut mismatched = tuna_selections();
    mismatched[0].endpoints[2].url = SJTUG_STORAGE.into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
}

#[test]
fn failed_pub_query_restores_the_previous_profile_and_lockfile() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "deps",
    );
    let original_profile = format!(
        "# keep\n# >>> MirrorSwitch Flutter mirrors >>>\nexport FLUTTER_STORAGE_BASE_URL='{NJU_STORAGE}'\nexport PUB_HOSTED_URL='{TUNA_PUB}'\n# <<< MirrorSwitch Flutter mirrors <<<\n"
    );
    let profile = write(root, "/home/developer/.bashrc", original_profile.as_bytes());
    write(
        root,
        "/home/developer/.mirrorswitch/verification/flutter/pubspec.yaml",
        VERIFY_PUBSPEC.as_bytes(),
    );
    let original_lock = format!(
        "packages:\n  retry:\n    description:\n      url: \"{TUNA_PUB}\"\n    source: hosted\n    version: \"3.1.2\"\n"
    );
    let lock = write(
        root,
        "/home/developer/.mirrorswitch/verification/flutter/pubspec.lock",
        original_lock.as_bytes(),
    );
    let adapter = FlutterAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(root, environment("/bin/bash", None, None), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &sjtug_selections())
        .unwrap();
    assert_eq!(plan.changes.len(), 2);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Flutter profile and verification lock should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read_to_string(profile).unwrap(), original_profile);
    assert_eq!(fs::read_to_string(lock).unwrap(), original_lock);
}

#[test]
fn failed_windows_pub_query_restores_registry_pair_and_recovery_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "get",
    );
    let (storage_state, pub_state) = install_windows_registry(
        root,
        Some("https://storage.googleapis.com"),
        Some("https://pub.dev"),
        0,
    );
    let adapter = FlutterAdapter;
    let context = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    let mut runtime = test_runtime(root, windows_environment(None, None), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &tuna_selections())
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Windows Flutter state should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("registry restored: true"));
    assert_eq!(
        fs::read_to_string(storage_state).unwrap(),
        "https://storage.googleapis.com"
    );
    assert_eq!(fs::read_to_string(pub_state).unwrap(), "https://pub.dev");
    assert!(
        !root
            .join("home/developer/AppData/Local/MirrorSwitch/flutter/environment-recovery.json")
            .exists()
    );
}

#[test]
fn non_native_platform_windows_arm_and_missing_registry_client_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_flutter(
        root,
        "3.47.2",
        "stable",
        "https://github.com/flutter/flutter.git",
        "",
    );
    let adapter = FlutterAdapter;
    let macos_container = SystemContext {
        environment: ExecutionEnvironment::Container,
        ..native_context(root, OperatingSystem::Macos, Architecture::Arm64)
    };
    assert!(
        adapter
            .detect(&macos_container, &test_runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
    let windows_arm = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    assert!(
        adapter
            .detect(
                &windows_arm,
                &test_runtime(root, windows_environment(None, None), None)
            )
            .unwrap_err()
            .to_string()
            .contains("no native Windows arm64 archive")
    );
    let windows = native_context(root, OperatingSystem::Windows, Architecture::X86_64);
    assert!(
        adapter
            .detect(
                &windows,
                &test_runtime(root, windows_environment(None, None), None)
            )
            .unwrap_err()
            .to_string()
            .contains("reg.exe")
    );
}

#[test]
fn embedded_catalog_keeps_storage_and_pub_independent_and_content_complete() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "flutter")
        .unwrap();
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    assert_eq!(tool.composition, CompositionPolicy::Single);

    let storage = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "flutter" && candidate.upstream_id == STORAGE_UPSTREAM
        })
        .collect::<Vec<_>>();
    assert_eq!(storage.len(), 4);
    let complete_storage = storage
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        complete_storage
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "sjtug"])
    );
    for candidate in complete_storage {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [
                OperatingSystem::Linux,
                OperatingSystem::Macos,
                OperatingSystem::Windows,
            ]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(
            candidate.compatibility.repository_versions,
            [RELEASE_IDENTITY]
        );
        assert_eq!(candidate.probes.len(), 3);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        let release_marker = candidate.probes[0].contains.as_deref().unwrap();
        assert!(release_marker.contains(FRAMEWORK_REVISION));
        assert!(release_marker.contains("\"channel\": \"stable\""));
        assert!(release_marker.contains("\"version\": \"3.47.2\""));
        assert_eq!(
            candidate.probes[1].sha256.as_deref(),
            Some("{flutter_engine_provenance_sha}")
        );
        assert_eq!(candidate.probes[2].method, HttpMethod::Head);
        assert!(
            candidate.probes[0]
                .path
                .contains("{flutter_release_manifest}")
        );
        assert!(
            candidate.probes[1]
                .path
                .contains("{flutter_engine_platform}")
        );
    }
    assert_eq!(
        storage
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .count(),
        2
    );

    let pub_candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "flutter" && candidate.upstream_id == PUB_UPSTREAM)
        .collect::<Vec<_>>();
    assert_eq!(pub_candidates.len(), 4);
    let complete_pub = pub_candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        complete_pub
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["sjtug", "tuna"])
    );
    assert!(complete_pub.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Proxy
            && candidate.compatibility.operating_systems
                == [
                    OperatingSystem::Linux,
                    OperatingSystem::Macos,
                    OperatingSystem::Windows,
                ]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.probes.len() == 4
            && candidate.probes[3].sha256.as_deref()
                == Some("822e118d5b3aafed083109c72d5f484c6dc66707885e07c0fbcb8b986bba7efc")
    }));
    assert_eq!(
        pub_candidates
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .count(),
        2
    );
}
