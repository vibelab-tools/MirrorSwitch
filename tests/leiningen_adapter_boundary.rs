#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{LeiningenAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const CLOJARS_UPSTREAM: &str = "clojars--language-registry";
const MAVEN: &str = "https://maven.aliyun.com/repository/public/";
const CLOJARS: &str = "https://mirrors.tuna.tsinghua.edu.cn/clojars/";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
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

fn install_lein(root: &Path, version: &str, verification_exit: i32) {
    executable(
        root,
        "/usr/bin/lein",
        format!(
            r#"#!/bin/sh
if [ "$1" = version ]; then
  [ "${{LEIN_NO_USER_PROFILES:-}}" = 1 ] || exit 58
  [ "${{LEIN_SILENT:-}}" = true ] || exit 59
  printf '%s\n' 'Leiningen {version} on Java 17.0.13 OpenJDK 64-Bit Server VM'
  exit 0
fi
[ "${{LEIN_NO_USER_PROFILES:-}}" = 1 ] || exit 61
[ "${{LEIN_SILENT:-}}" = true ] || exit 62
grep -F 'Managed by MirrorSwitch: Leiningen verification profile' "$PWD/profiles.clj" >/dev/null || exit 63
grep -F 'mirrorswitch-leiningen-verification' "$PWD/project.clj" >/dev/null || exit 64
grep -F 'commons-lang3 "3.14.0"' "$PWD/project.clj" >/dev/null || exit 65
grep -F 'lein-pprint "1.3.2"' "$PWD/project.clj" >/dev/null || exit 66
if [ {verification_exit} -ne 0 ]; then
  printf '%s\n' 'controlled Leiningen verification failure' >&2
  exit {verification_exit}
fi
if [ "$1" = pprint ] && [ "$2" = :mirrors ]; then
  printf '%s\n' '{{central https://maven.aliyun.com/repository/public/, clojars https://mirrors.tuna.tsinghua.edu.cn/clojars/}}'
elif [ "$1" = deps ]; then
  printf '%s\n' 'dependency resolution complete'
elif [ "$1" = pprint ] && [ "$2" = :name ]; then
  printf '%s\n' 'mirrorswitch-leiningen-verification'
else
  exit 67
fi
"#,
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selection(upstream: &str, provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("leiningen-{provider}-{upstream}-test"),
        tool_id: "leiningen".into(),
        upstream_id: upstream.into(),
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
            url: endpoint.into(),
        })
        .collect(),
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn selections() -> [MirrorSelection; 2] {
    [
        selection(MAVEN_UPSTREAM, "aliyun", MAVEN),
        selection(CLOJARS_UPSTREAM, "tuna", CLOJARS),
    ]
}

#[test]
fn user_plan_preserves_profiles_private_repositories_credentials_and_project_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_lein(root, "2.12.0", 0);
    let original = br#";; keep user policy
{:user {:repositories [["private" {:url "https://packages.example/maven"
                                    :username :env/private-user
                                    :password :env/private-password}]]
        :plugins [[lein-ancient "0.7.0"]]
        :mirrors {"central" {:name "central" :url "https://repo1.maven.org/maven2/"
                              :snapshots false}}}
 :dev {:jvm-opts ["-Dfeature=true"]}}
"#;
    let profile = write(root, "/home/developer/.lein/profiles.clj", original);
    write(
        root,
        "/home/developer/.lein/credentials.clj.gpg",
        b"opaque-secret",
    );
    let project = br#"(defproject private/app "1.0.0"
  :dependencies [[org.clojure/clojure "1.11.1"]]
  :repositories [["private" {:url "https://packages.example/maven"
                              :username :env/private-user}]])
"#;
    let project_path = write(root, "/work/project/project.clj", project);
    let adapter = LeiningenAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, BTreeMap::new(), Some("/work/project"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.12.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "project Clojure 1.11.1")
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "credential declaration(s): 2")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[MAVEN_UPSTREAM], "leiningen-2.x");
    assert_eq!(
        request.repository_versions[CLOJARS_UPSTREAM],
        "leiningen-2.x"
    );
    assert!(current.sources.iter().any(|source| {
        source
            .metadata
            .get("kind")
            .is_some_and(|values| values == &["credentials-detected"])
    }));
    let cli = adapter.plan(&context, &current, &selections()).unwrap();
    let config = adapter.plan(&context, &current, &selections()).unwrap();
    let tui = adapter.plan(&context, &current, &selections()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 3);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains(":username :env/private-user"));
    assert!(changed.contains(":password :env/private-password"));
    assert!(changed.contains(MAVEN));
    assert!(changed.contains(CLOJARS));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Leiningen files should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&project_path).unwrap(), project);
    let after = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &after, &selections())
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
    assert_eq!(fs::read(project_path).unwrap(), project);
}

#[test]
fn missing_profile_arm64_and_custom_lein_home_produce_stable_create_plan() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_lein(root, "2.11.2", 0);
    let adapter = LeiningenAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(
        root,
        BTreeMap::from([("LEIN_HOME".into(), "/data/lein-home".into())]),
        None,
    );
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let first = adapter.plan(&context, &current, &selections()).unwrap();
    assert_eq!(
        first,
        adapter.plan(&context, &current, &selections()).unwrap()
    );
    assert_eq!(first.changes.len(), 3);
    assert!(
        first
            .changes
            .iter()
            .any(|change| change.target.ends_with("data/lein-home/profiles.clj"))
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &first).unwrap()
    else {
        panic!("Leiningen files should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn versions_precedence_dynamic_profiles_and_unsafe_selections_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = LeiningenAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new(), None))
            .unwrap()
            .is_none()
    );
    install_lein(root, "1.7.1", 0);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("outside the reviewed")
    );
    install_lein(root, "2.12.0", 0);

    let disabled = runtime(
        root,
        BTreeMap::from([("LEIN_NO_USER_PROFILES".into(), "1".into())]),
        None,
    );
    let detected = adapter.detect(&context, &disabled).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &disabled, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections())
            .unwrap_err()
            .to_string()
            .contains("disabled")
    );

    let base = runtime(root, BTreeMap::new(), Some("/work/project"));
    write(
        root,
        "/work/project/profiles.clj",
        b"{:user {:mirrors {}}}\n",
    );
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections())
            .unwrap_err()
            .to_string()
            .contains("higher-precedence")
    );
    fs::remove_file(root.join("work/project/profiles.clj")).unwrap();

    write(
        root,
        "/home/developer/.lein/profiles.clj",
        b"{:user (load-file \"dynamic.clj\")}\n",
    );
    let error = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap_err();
    assert!(error.to_string().contains("literal map"));

    fs::remove_file(root.join("home/developer/.lein/profiles.clj")).unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    let mut unsafe_selection = selections();
    unsafe_selection[0].endpoints[1].url = "https://packages.example/maven/".into();
    assert!(adapter.plan(&context, &current, &unsafe_selection).is_err());
}

#[test]
fn failed_resolution_restores_user_profile_and_verification_fixture() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_lein(root, "2.12.0", 9);
    let original = b"{:user {:plugins [[lein-ancient \"0.7.0\"]]}}\n";
    let profile = write(root, "/home/developer/.lein/profiles.clj", original);
    let adapter = LeiningenAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Leiningen files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("detail: controlled Leiningen verification failure")
    );
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/leiningen/project.clj")
            .exists()
    );
}

#[test]
fn macos_and_windows_preserve_native_profiles_and_verification_commands() {
    for (os, architecture, bom, newline) in [
        (OperatingSystem::Macos, Architecture::X86_64, false, "\n"),
        (OperatingSystem::Windows, Architecture::Arm64, true, "\r\n"),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_lein(root, "2.12.0", 0);
        let text = format!(
            ";; native Leiningen profile{newline}{{:user {{:repositories [[\"central\" {{:url \"https://repo1.maven.org/maven2/\"}}] [\"clojars\" {{:url \"https://repo.clojars.org/\"}}] [\"private\" {{:url \"https://reader:secret@packages.invalid.example/\"}}]] :plugins [[lein-ancient \"0.7.0\"]]}}}}{newline}"
        );
        let mut original = text.into_bytes();
        if bom {
            original.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let profile = write(root, "/home/developer/.lein/profiles.clj", &original);
        write(root, "/etc/leiningen/profiles.clj", b"{:user {}}\n");
        let project_contents = b"(defproject native \"0.1.0\" :dependencies [[org.clojure/clojure \"1.12.0\"]] :repositories [[\"private\" \"https://packages.invalid.example/\"]])\n";
        let project = write(root, "/work/project/project.clj", project_contents);
        let context = native_context(root, os, architecture);
        let adapter = LeiningenAdapter;
        let mut runtime = runtime(root, BTreeMap::new(), Some("/work/project"));
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert_eq!(
            current
                .documents
                .iter()
                .any(|document| { document.path == Path::new("/etc/leiningen/profiles.clj") }),
            os != OperatingSystem::Windows
        );
        assert!(!serde_json::to_string(&current).unwrap().contains("secret"));
        let selected = selections();
        let plan = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
        let change = plan
            .changes
            .iter()
            .find(|change| change.target == profile)
            .unwrap();
        assert_eq!(change.new_contents.starts_with(&[0xef, 0xbb, 0xbf]), bom);
        let rendered = std::str::from_utf8(
            change
                .new_contents
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&change.new_contents),
        )
        .unwrap();
        assert!(rendered.contains("lein-ancient"));
        assert!(rendered.contains("reader:secret@"));
        assert!(!rendered.replace(newline, "").contains('\n'));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
        else {
            panic!("native Leiningen profile should change")
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
        assert_eq!(fs::read(project).unwrap(), project_contents);
    }
}

#[test]
fn embedded_catalog_has_six_complete_maven_and_clojars_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "leiningen" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 6);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.upstream_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([MAVEN_UPSTREAM, CLOJARS_UPSTREAM])
    );
    for candidate in candidates {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Proxy);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [
                OperatingSystem::Linux,
                OperatingSystem::Macos,
                OperatingSystem::Windows
            ]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(candidate.probes.len(), 4);
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
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert_eq!(candidate.probes[2].method, HttpMethod::Head);
        if candidate.upstream_id == CLOJARS_UPSTREAM {
            assert!(candidate.probes[1].path.ends_with("lein-pprint-1.3.2.pom"));
            assert!(candidate.probes[2].path.ends_with("lein-pprint-1.3.2.jar"));
        } else {
            assert!(
                candidate.probes[0]
                    .path
                    .ends_with("commons-lang3-3.14.0.pom")
            );
            assert!(
                candidate.probes[2]
                    .path
                    .ends_with("commons-lang3-3.14.0.jar")
            );
        }
    }
}
