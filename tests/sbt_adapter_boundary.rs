#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{SbtAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const IVY_UPSTREAM: &str = "sbt-plugins--language-registry";
const MAVEN: &str = "https://repo.huaweicloud.com/repository/maven/";
const IVY: &str = "https://repo.huaweicloud.com/repository/ivy/";

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

fn install_sbt(root: &Path, version: &str, verification_exit: i32, numeric_version: bool) {
    executable(
        root,
        "/usr/bin/java",
        "#!/bin/sh\nprintf '%s\\n' 'openjdk version \"21.0.9\" 2025-10-21 LTS' >&2\n".into(),
    );
    executable(
        root,
        "/usr/bin/sbt",
        format!(
            r#"#!/bin/sh
if [ "$1" = --numeric-version ]; then
  [ {numeric_version} = true ] || exit 2
  printf '\033[32m%s\033[0m\n' '{version}'
  exit 0
fi
if [ "$1" = --version ]; then
  [ {numeric_version} = true ] || exit 2
  printf '\033[32m%s\033[0m\n' 'sbt version in this project: {version}'
  exit 0
fi
if [ "$1" = --script-version ]; then
  printf '%s\n' '1.12.11'
  exit 0
fi
repositories=
for argument in "$@"; do
  case "$argument" in
    -Dsbt.repository.config=*) repositories=${{argument#-Dsbt.repository.config=}} ;;
  esac
done
[ -n "$repositories" ] || exit 61
physical='{root}'"$repositories"
grep -F 'mirrorswitch-maven: https://repo.huaweicloud.com/repository/maven' "$physical" >/dev/null || exit 62
grep -F 'mirrorswitch-ivy: https://repo.huaweicloud.com/repository/ivy/' "$physical" >/dev/null || exit 63
grep -F 'sbt-native-packager' "$PWD"/project/plugins.sbt >/dev/null || exit 64
grep -F 'commons-lang3' "$PWD"/build.sbt >/dev/null || exit 65
if [ {verification_exit} -ne 0 ]; then
  printf '%s\n' '[error] controlled sbt verification failure' >&2
  exit {verification_exit}
fi
printf '%s\n' \
  '[info] ArrayBuffer(https://repo.huaweicloud.com/repository/ivy/, https://repo.huaweicloud.com/repository/maven/)' \
  '[success] dependency update completed' \
  '[info] 2.13.16' \
  '[info] mirrorswitch-sbt-verification'
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    fs::create_dir_all(root.join("work/project/project")).unwrap();
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection(upstream: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("sbt-{upstream}-test"),
        tool_id: "sbt".into(),
        upstream_id: upstream.into(),
        provider_id: "huaweicloud".into(),
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
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn selections() -> [MirrorSelection; 2] {
    [
        selection(MAVEN_UPSTREAM, MAVEN),
        selection(IVY_UPSTREAM, IVY),
    ]
}

#[test]
fn user_plan_preserves_private_resolvers_credentials_and_project_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_sbt(root, "1.13.0", 0, true);
    let original = br#"# keep launcher policy
[repositories]
  local
  corporate: https://reader:private-secret@packages.example/repository
  maven-central
  public-central: https://repo1.maven.org/maven2/
"#;
    let repositories = write(root, "/home/developer/.sbt/repositories", original);
    let build = br#"ThisBuild / scalaVersion := "2.13.16"
resolvers += "private" at "https://packages.example/maven"
credentials += Credentials(Path.userHome / ".sbt" / ".credentials")
"#;
    let build_path = write(root, "/work/project/build.sbt", build);
    let plugins = br#"addSbtPlugin("com.example" % "private-plugin" % "1.0.0")
resolvers += "private-plugins" at "https://packages.example/plugins"
"#;
    let plugins_path = write(root, "/work/project/project/plugins.sbt", plugins);
    write(
        root,
        "/work/project/project/build.properties",
        b"sbt.version=1.13.0\n",
    );
    let adapter = SbtAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(
        root,
        BTreeMap::from([(
            "SBT_CREDENTIALS".into(),
            "/home/developer/.sbt/.credentials".into(),
        )]),
    );

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.13.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("JDK openjdk"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("project Scala 2.13.16"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("private-secret"));
    assert!(!serialized.contains("packages.example"));
    assert!(
        current
            .sources
            .iter()
            .any(|source| source.metadata["kind"] == ["credentials-detected"])
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [MAVEN_UPSTREAM, IVY_UPSTREAM]);
    assert_eq!(request.repository_versions[MAVEN_UPSTREAM], "sbt-1.x");
    assert_eq!(request.repository_versions[IVY_UPSTREAM], "sbt-1.x");
    assert_eq!(
        request.required_endpoint_roles,
        [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts
        ]
    );
    let selected = selections();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 5);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("mirrorswitch-maven"));
    assert!(rendered.contains("mirrorswitch-ivy"));
    assert!(rendered.contains("scala_[scalaVersion]"));
    assert!(rendered.contains("private-secret"));
    assert!(rendered.contains("  maven-central\n"));
    assert!(rendered.find("local").unwrap() < rendered.find("mirrorswitch-maven").unwrap());
    assert!(rendered.find("mirrorswitch-ivy").unwrap() < rendered.find("corporate:").unwrap());

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("sbt user repositories should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&build_path).unwrap(), build);
    assert_eq!(fs::read(&plugins_path).unwrap(), plugins);
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
    assert_eq!(fs::read(repositories).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/sbt/build.sbt")
            .exists()
    );
}

#[test]
fn sbt_two_arm64_and_missing_repository_file_produce_the_same_plan_for_all_entries() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_sbt(root, "2.0.8", 0, false);
    write(
        root,
        "/work/project/project/build.properties",
        b"sbt.version=2.0.8\n",
    );
    let adapter = SbtAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[MAVEN_UPSTREAM], "sbt-2.x");
    assert_eq!(request.repository_versions[IVY_UPSTREAM], "sbt-2.x");
    let selected = selections();
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 5);
    let repositories = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(repositories.starts_with("# Managed by MirrorSwitch"));
    assert!(repositories.contains("\n  local\n"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("sbt files should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn versions_precedence_layout_and_managed_identity_conflicts_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = SbtAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new()))
            .unwrap()
            .is_none()
    );
    for version in ["0.13.18", "3.0.0"] {
        install_sbt(root, version, 0, true);
        assert!(
            adapter
                .detect(&context, &runtime(root, BTreeMap::new()))
                .unwrap_err()
                .to_string()
                .contains("outside the reviewed")
        );
    }

    install_sbt(root, "1.13.0", 0, true);
    let base = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    write(
        root,
        "/home/developer/.sbt/repositories",
        b"[repositories]\n  private: https://packages.example/maven\n  local\n",
    );
    assert!(
        adapter
            .read_current(&context, &base, &detected, ConfigurationScope::User)
            .unwrap_err()
            .to_string()
            .contains("not the first resolver")
    );

    write(
        root,
        "/home/developer/.sbt/repositories",
        b"[repositories]\n  local\n  mirrorswitch-ivy: https://private.example/ivy, [organization]/[module]/[revision]/[artifact].[ext]\n",
    );
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections())
            .unwrap_err()
            .to_string()
            .contains("resolver id")
    );

    let overridden = runtime(
        root,
        BTreeMap::from([(
            "SBT_OPTS".into(),
            "-Dsbt.repository.config=/tmp/repositories".into(),
        )]),
    );
    write(
        root,
        "/home/developer/.sbt/repositories",
        b"[repositories]\n  local\n",
    );
    let detected = adapter.detect(&context, &overridden).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &overridden, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections())
            .unwrap_err()
            .to_string()
            .contains("precedence")
    );

    write(
        root,
        "/home/developer/.mirrorswitch/verification/sbt/build.sbt",
        b"user-owned\n",
    );
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selections())
            .unwrap_err()
            .to_string()
            .contains("verification target")
    );

    let mut mixed = selections();
    mixed[0].endpoints[2].url = "https://repo.nju.edu.cn/maven/".into();
    let current = {
        fs::remove_file(root.join("home/developer/.mirrorswitch/verification/sbt/build.sbt"))
            .unwrap();
        adapter
            .read_current(&context, &base, &detected, ConfigurationScope::User)
            .unwrap()
    };
    assert!(adapter.plan(&context, &current, &mixed).is_err());
}

#[test]
fn failed_real_resolution_restores_repository_and_all_verification_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_sbt(root, "1.13.0", 9, true);
    let original = b"[repositories]\n  local\n  private: https://packages.example/maven\n";
    let repositories = write(root, "/home/developer/.sbt/repositories", original);
    let adapter = SbtAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &selections()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("sbt files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("detail: [error] controlled sbt verification failure")
    );
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(repositories).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/sbt/build.sbt")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/sbt/project/plugins.sbt")
            .exists()
    );
}

#[test]
fn macos_and_windows_preserve_native_repository_file_layout() {
    for (os, architecture, bom, newline) in [
        (OperatingSystem::Macos, Architecture::X86_64, false, "\n"),
        (OperatingSystem::Windows, Architecture::Arm64, true, "\r\n"),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_sbt(root, "1.13.0", 0, true);
        let text = format!(
            "# native sbt repositories{newline}[repositories]{newline}  local{newline}  corporate: https://reader:secret@packages.invalid.example/repository{newline}  maven-central{newline}"
        );
        let mut original = text.into_bytes();
        if bom {
            original.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let repositories = write(root, "/home/developer/.sbt/repositories", &original);
        let project_contents = b"ThisBuild / scalaVersion := \"2.13.16\"\n";
        let project = write(root, "/work/project/build.sbt", project_contents);
        write(
            root,
            "/work/project/project/build.properties",
            b"sbt.version=1.13.0\n",
        );
        let context = native_context(root, os, architecture);
        let adapter = SbtAdapter;
        let mut runtime = runtime(root, BTreeMap::new());
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(!serde_json::to_string(&current).unwrap().contains("secret"));
        let plan = adapter.plan(&context, &current, &selections()).unwrap();
        assert_eq!(
            plan,
            adapter.plan(&context, &current, &selections()).unwrap()
        );
        let change = plan
            .changes
            .iter()
            .find(|change| change.target == repositories)
            .unwrap();
        assert_eq!(change.new_contents.starts_with(&[0xef, 0xbb, 0xbf]), bom);
        let rendered = std::str::from_utf8(
            change
                .new_contents
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&change.new_contents),
        )
        .unwrap();
        assert!(rendered.contains("corporate: https://reader:secret@"));
        assert!(!rendered.replace(newline, "").contains('\n'));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
        else {
            panic!("native sbt repositories should change")
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
                .plan(&context, &updated, &selections())
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
        assert_eq!(fs::read(repositories).unwrap(), original);
        assert_eq!(fs::read(project).unwrap(), project_contents);
    }
}

#[test]
fn embedded_catalog_has_one_complete_maven_and_one_complete_ivy_candidate() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "sbt" && !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.upstream_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    for candidate in candidates {
        assert_eq!(candidate.provider_id, "huaweicloud");
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
        if candidate.upstream_id == IVY_UPSTREAM {
            assert!(candidate.probes[0].path.ends_with("ivys/ivy.xml"));
            assert!(
                candidate.probes[2]
                    .path
                    .ends_with("jars/sbt-native-packager.jar")
            );
        } else {
            assert_eq!(candidate.upstream_id, MAVEN_UPSTREAM);
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
