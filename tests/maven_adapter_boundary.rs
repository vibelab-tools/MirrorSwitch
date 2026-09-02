#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{MavenAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const ALIYUN: &str = "https://maven.aliyun.com/repository/public/";
const HUAWEI: &str = "https://repo.huaweicloud.com/repository/maven/";
const NJU: &str = "https://repo.nju.edu.cn/maven/";

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

fn install_maven(
    root: &Path,
    version: &str,
    endpoint: &str,
    mirror_id: &str,
    dependency_exit: i32,
) {
    write(
        root,
        "/usr/share/maven/conf/settings.xml",
        b"<?xml version=\"1.0\"?><settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\"/>\n",
    );
    executable(
        root,
        "/usr/bin/mvn",
        format!(
            r#"#!/bin/sh
if [ "$1" = --version ]; then
  printf '\033[1mApache Maven {version}\033[m\nMaven home: /usr/share/maven\nJava version: 21.0.9, vendor: Test JDK\nOS name: linux, arch: amd64\n'
  exit 0
fi
settings=
repository=
for argument in "$@"; do
  case "$argument" in
    -Dmaven.repo.local=*) repository=${{argument#-Dmaven.repo.local=}} ;;
  esac
  if [ "$previous" = --settings ]; then settings=$argument; fi
  previous=$argument
done
[ -n "$settings" ] || exit 61
grep -F '{endpoint}' '{root}'"$settings" >/dev/null || exit 62
case "$*" in
  *effective-settings*)
    printf '<settings><mirrors><mirror><id>{mirror_id}</id><url>{endpoint}</url><mirrorOf>central</mirrorOf></mirror></mirrors></settings>\n'
    exit 0
    ;;
  *maven-dependency-plugin*)
    [ {dependency_exit} -eq 0 ] || exit {dependency_exit}
    artifact='{root}'"$repository"/org/apache/commons/commons-lang3/3.14.0
    mkdir -p "$artifact"
    printf 'test-jar' > "$artifact/commons-lang3-3.14.0.jar"
    printf 'commons-lang3-3.14.0.jar>{mirror_id}=\n' > "$artifact/_remote.repositories"
    exit 0
    ;;
esac
exit 63
"#,
            root = root.display(),
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    fs::create_dir_all(root.join("work/project")).unwrap();
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_project_dir("/work/project")
        .with_environment(environment)
}

fn selection(index: &str, artifact: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "maven-test".into(),
        tool_id: "maven".into(),
        upstream_id: MAVEN_UPSTREAM.into(),
        provider_id: "test-provider".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: index.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: artifact.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_plan_preserves_private_policy_servers_proxies_plugins_and_project_pom() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_maven(root, "3.9.11", HUAWEI, "mirrorswitch-central", 0);
    let settings_contents = br#"<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <!-- keep user policy -->
  <servers>
    <server><id>private-releases</id><username>reader</username><password>secret-value</password></server>
  </servers>
  <mirrors>
    <mirror>
      <id>corporate-external</id>
      <url>https://private.example/repository</url>
      <mirrorOf>external:*,!central</mirrorOf>
    </mirror>
  </mirrors>
  <proxies>
    <proxy><id>office</id><username>proxy-user</username><password>proxy-secret</password><host>proxy.example</host></proxy>
  </proxies>
  <profiles>
    <profile>
      <id>private-policy</id>
      <repositories><repository><id>private-releases</id><url>https://private.example/releases</url></repository></repositories>
      <pluginRepositories><pluginRepository><id>private-plugins</id><url>https://private.example/plugins</url></pluginRepository></pluginRepositories>
    </profile>
  </profiles>
</settings>
"#;
    let settings = write(root, "/home/developer/.m2/settings.xml", settings_contents);
    let pom_contents = br#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>app</artifactId><version>1</version>
  <repositories><repository><id>private-project</id><url>https://private.example/project</url></repository></repositories>
  <pluginRepositories><pluginRepository><id>private-plugin</id><url>https://private.example/plugin</url></pluginRepository></pluginRepositories>
</project>
"#;
    let pom = write(root, "/work/project/pom.xml", pom_contents);
    let adapter = MavenAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("Apache Maven 3.9.11"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("Java version: 21.0.9"))
    );
    assert_eq!(adapter.default_scope(), ConfigurationScope::User);
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("secret-value"));
    assert!(!serialized.contains("proxy-secret"));
    for kind in [
        "preserved-mirror",
        "project-repositories",
        "project-plugin-repositories",
    ] {
        assert!(
            current
                .sources
                .iter()
                .any(|source| source.metadata["kind"] == [kind])
        );
    }
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [MAVEN_UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [EndpointRole::Index, EndpointRole::Artifacts]
    );
    let chosen = [selection(HUAWEI, HUAWEI)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 2);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("<id>mirrorswitch-central</id>"));
    assert!(rendered.contains("<mirrorOf>central</mirrorOf>"));
    assert!(rendered.contains("<mirrorOf>external:*,!central</mirrorOf>"));
    assert!(rendered.contains("secret-value"));
    assert!(rendered.contains("proxy-secret"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Maven user settings should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&pom).unwrap(), pom_contents);
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &updated, &chosen)
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
    assert_eq!(fs::read(settings).unwrap(), settings_contents);
    assert!(
        !root
            .join("home/developer/.m2/mirrorswitch/verification/pom.xml")
            .exists()
    );
}

#[test]
fn arm64_adopts_a_public_exact_central_mirror_without_changing_its_identity() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_maven(root, "3.6.3", NJU, "public-central", 0);
    let original = br#"<?xml version="1.0"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <mirrors>
    <!-- preserve this identity and order -->
    <mirror><id>public-central</id><name>Existing public mirror</name><url>https://repo.maven.apache.org/maven2/</url><mirrorOf>central</mirrorOf></mirror>
  </mirrors>
  <servers><server><id>private</id><password>keep-me</password></server></servers>
</settings>
"#;
    let settings = write(root, "/home/developer/.m2/settings.xml", original);
    write(
        root,
        "/work/project/pom.xml",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>t</artifactId><version>1</version></project>\n",
    );
    let adapter = MavenAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.context.architecture, Architecture::Arm64);
    let chosen = [selection(NJU, NJU)];
    let cli = adapter.plan(&context, &current, &chosen).unwrap();
    let config = adapter.plan(&context, &current, &chosen).unwrap();
    let tui = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains("<id>public-central</id>"));
    assert!(!rendered.contains("mirrorswitch-central"));
    assert!(rendered.contains("<url>https://repo.nju.edu.cn/maven/</url>"));
    assert!(rendered.contains("keep-me"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Maven public Central mirror should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(settings).unwrap(), original);
}

#[test]
fn failed_dependency_resolution_restores_settings_and_verification_project() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_maven(root, "3.9.11", ALIYUN, "mirrorswitch-central", 9);
    write(
        root,
        "/work/project/pom.xml",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>t</artifactId><version>1</version></project>\n",
    );
    let adapter = MavenAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &[selection(ALIYUN, ALIYUN)])
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Maven settings should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert!(!root.join("home/developer/.m2/settings.xml").exists());
    assert!(
        !root
            .join("home/developer/.m2/mirrorswitch/verification/pom.xml")
            .exists()
    );
}

#[test]
fn versions_private_central_credentials_precedence_and_conflicts_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = MavenAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new()))
            .unwrap()
            .is_none()
    );
    for version in ["3.6.2", "4.0.0-rc-6"] {
        install_maven(root, version, HUAWEI, "mirrorswitch-central", 0);
        assert!(
            adapter
                .detect(&context, &runtime(root, BTreeMap::new()))
                .unwrap_err()
                .to_string()
                .contains("outside the reviewed")
        );
    }
    install_maven(root, "3.9.11", HUAWEI, "mirrorswitch-central", 0);
    write(
        root,
        "/work/project/pom.xml",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId><artifactId>t</artifactId><version>1</version></project>\n",
    );
    let base_runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &base_runtime).unwrap().unwrap();
    let cases = [
        (
            "<settings><mirrors><mirror><id>private</id><url>https://private.example/maven</url><mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            "private or unreviewed",
        ),
        (
            "<settings><mirrors><mirror><id>secured</id><url>https://repo.nju.edu.cn/maven/</url><mirrorOf>central</mirrorOf></mirror></mirrors><servers><server><id>secured</id><password>secret</password></server></servers></settings>",
            "matching server entry",
        ),
        (
            "<settings><mirrors><mirror><id>a</id><url>https://repo.nju.edu.cn/maven/</url><mirrorOf>central</mirrorOf></mirror><mirror><id>b</id><url>https://repo.huaweicloud.com/repository/maven/</url><mirrorOf>central</mirrorOf></mirror></mirrors></settings>",
            "more than one exact",
        ),
        (
            "<settings><mirrors><mirror><id>blocked</id><url>https://repo.nju.edu.cn/maven/</url><mirrorOf>central</mirrorOf><mirrorOfLayouts>legacy</mirrorOfLayouts></mirror></mirrors></settings>",
            "excludes Maven's default layout",
        ),
        ("<settings>", "invalid XML"),
    ];
    for (contents, expected) in cases {
        write(
            root,
            "/home/developer/.m2/settings.xml",
            contents.as_bytes(),
        );
        let result =
            adapter.read_current(&context, &base_runtime, &detected, ConfigurationScope::User);
        let message = match result {
            Ok(current) => adapter
                .plan(&context, &current, &[selection(HUAWEI, HUAWEI)])
                .unwrap_err()
                .to_string(),
            Err(error) => error.to_string(),
        };
        assert!(message.contains(expected), "{message}");
    }

    fs::remove_file(root.join("home/developer/.m2/settings.xml")).unwrap();
    let overridden = runtime(
        root,
        BTreeMap::from([("MAVEN_ARGS".into(), "--settings /tmp/custom.xml".into())]),
    );
    let detected = adapter.detect(&context, &overridden).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &overridden, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI, HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("MAVEN_ARGS")
    );

    write(
        root,
        "/home/developer/.m2/mirrorswitch/verification/pom.xml",
        b"<project>user-owned</project>\n",
    );
    let current = adapter
        .read_current(&context, &base_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI, HUAWEI)])
            .unwrap_err()
            .to_string()
            .contains("verification project")
    );

    let current = {
        fs::remove_file(root.join("home/developer/.m2/mirrorswitch/verification/pom.xml")).unwrap();
        adapter
            .read_current(&context, &base_runtime, &detected, ConfigurationScope::User)
            .unwrap()
    };
    assert!(
        adapter
            .plan(&context, &current, &[selection(HUAWEI, NJU)])
            .is_err()
    );
}

#[test]
fn macos_and_windows_preserve_native_user_settings_layout() {
    for (os, architecture, bom, newline) in [
        (OperatingSystem::Macos, Architecture::X86_64, false, "\n"),
        (OperatingSystem::Windows, Architecture::Arm64, true, "\r\n"),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_maven(root, "3.9.11", HUAWEI, "mirrorswitch-central", 0);
        let text = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{newline}<settings>{newline}  <!-- native settings -->{newline}  <servers><server><id>private</id><username>reader</username><password>secret</password></server></servers>{newline}  <proxies><proxy><id>office</id><host>proxy.invalid.example</host></proxy></proxies>{newline}</settings>{newline}"
        );
        let mut original = text.into_bytes();
        if bom {
            original.splice(..0, [0xef, 0xbb, 0xbf]);
        }
        let settings = write(root, "/home/developer/.m2/settings.xml", &original);
        let project_contents = b"<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>native</artifactId><version>1</version></project>\n";
        let project = write(root, "/work/project/pom.xml", project_contents);
        let context = native_context(root, os, architecture);
        let adapter = MavenAdapter;
        let mut runtime = runtime(root, BTreeMap::new());
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(!serde_json::to_string(&current).unwrap().contains("secret"));
        let chosen = [selection(HUAWEI, HUAWEI)];
        let plan = adapter.plan(&context, &current, &chosen).unwrap();
        assert_eq!(plan, adapter.plan(&context, &current, &chosen).unwrap());
        let change = plan
            .changes
            .iter()
            .find(|change| change.target == settings)
            .unwrap();
        assert_eq!(change.new_contents.starts_with(&[0xef, 0xbb, 0xbf]), bom);
        let rendered = std::str::from_utf8(
            change
                .new_contents
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&change.new_contents),
        )
        .unwrap();
        assert!(rendered.contains("<id>private</id>"));
        assert!(!rendered.replace(newline, "").contains('\n'));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
        else {
            panic!("native Maven settings should change")
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
                .plan(&context, &updated, &chosen)
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
        assert_eq!(fs::read(settings).unwrap(), original);
        assert_eq!(fs::read(project).unwrap(), project_contents);
    }
}

#[test]
fn embedded_catalog_has_three_complete_maven_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "maven"
                && candidate.upstream_id == MAVEN_UPSTREAM
                && !candidate.probes.is_empty()
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    assert!(candidates.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Proxy
            && candidate.compatibility.operating_systems
                == [
                    OperatingSystem::Linux,
                    OperatingSystem::Macos,
                    OperatingSystem::Windows,
                ]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Index)
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
            && candidate.probes.len() == 4
            && candidate.probes[0].method == HttpMethod::Get
            && candidate.probes[0]
                .path
                .ends_with("commons-lang3-3.14.0.pom")
            && candidate.probes[1].method == HttpMethod::Get
            && candidate.probes[1].path.ends_with("maven-metadata.xml")
            && candidate.probes[2].method == HttpMethod::Head
            && candidate.probes[2]
                .path
                .ends_with("commons-lang3-3.14.0.jar")
            && candidate.probes[3].method == HttpMethod::Get
            && candidate.probes[3]
                .path
                .ends_with("commons-lang3-3.14.0.jar.sha1")
            && candidate.probes[3].contains.as_deref()
                == Some("1ed471194b02f2c6cb734a0cd6f6f107c673afae")
    }));
}
