#![cfg(unix)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{ComposerAdapter, compiled_adapter_allowlist},
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
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const UPSTREAM: &str = "packagist--language-registry";
const MIRROR: &str = "https://repo.huaweicloud.com/repository/php/";
const SOURCE: &str = "https://github.com/php-fig/log/";
const DIST_BODY: &[u8] = b"reviewed synthetic composer dist";
const SOURCE_BODY: &[u8] = b"reviewed synthetic composer source";

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

fn install_composer(
    root: &Path,
    version: &str,
    global_config: Option<&[u8]>,
    query_exit: i32,
) -> PathBuf {
    let physical_home = root.join("home/developer/.composer");
    let verification_home = root.join("home/developer/.mirrorswitch/verification/composer");
    fs::create_dir_all(&physical_home).unwrap();
    let physical_config = physical_home.join("config.json");
    if let Some(contents) = global_config {
        fs::write(&physical_config, contents).unwrap();
    }
    executable(
        root,
        "/usr/bin/php",
        "#!/bin/sh\n[ \"$1\" = --version ] || exit 70\nprintf '%s\\n' 'PHP 8.4.13 (cli) (built: test)'\n".into(),
    );
    executable(
        root,
        "/usr/bin/composer",
        format!(
            r#"#!/bin/sh
global_config='{config}'
verification_config='{verification_config}'
verification_home='{verification_home}'
case "$*" in
  "--version --no-ansi") printf '%s\n' 'Composer version {version} 2026-08-01 00:00:00' ;;
  "config --global home") printf '%s\n' '/home/developer/.composer' ;;
  "config --global --list --source")
    [ "$COMPOSER_HOME" = '/home/developer/.composer' ] || exit 71
    [ -z "${{COMPOSER+x}}" ] || exit 72
    grep -q 'repo.huaweicloud.com/repository/php' "$global_config" || exit 73
    printf '%s\n' '[repositories.packagist.url] https://repo.huaweicloud.com/repository/php/ (/home/developer/.composer/config.json)'
    ;;
  "diagnose --no-interaction --no-plugins")
    [ "$(pwd -P)" = "$(cd "$verification_home" && pwd -P)" ] || exit 74
    [ "$COMPOSER_HOME" = '/home/developer/.mirrorswitch/verification/composer' ] || exit 75
    [ -z "${{COMPOSER+x}}" ] || exit 76
    [ -z "${{COMPOSER_AUTH+x}}" ] || exit 77
    grep -q 'repo.huaweicloud.com/repository/php' "$verification_config" || exit 78
    printf '%s\n' 'Checking connectivity to https://repo.huaweicloud.com/repository/php/: OK'
    ;;
  "show psr/log 3.0.2 --all --no-interaction --no-plugins")
    [ "$(pwd -P)" = "$(cd "$verification_home" && pwd -P)" ] || exit 79
    [ "$COMPOSER_HOME" = '/home/developer/.mirrorswitch/verification/composer' ] || exit 80
    [ -z "${{COMPOSER+x}}" ] || exit 81
    [ -z "${{COMPOSER_AUTH+x}}" ] || exit 82
    grep -q 'repo.huaweicloud.com/repository/php' "$verification_config" || exit 83
    [ {query_exit} -eq 0 ] || exit {query_exit}
    printf '%s\n' \
      'name     : psr/log' \
      'versions : 3.0.2' \
      'source   : [git] https://github.com/php-fig/log.git f16e1d5863e37f8d8c2a01719f5b34baa2b714d3' \
      'dist     : [zip] https://repo.huaweicloud.com/repository/php/psr/log/3.0.2/psr-log-3.0.2.zip f16e1d5863e37f8d8c2a01719f5b34baa2b714d3'
    ;;
  *) exit 84 ;;
esac
"#,
            config = physical_config.display(),
            verification_config = verification_home.join("config.json").display(),
            verification_home = verification_home.display(),
        ),
    );
    physical_config
}

fn runtime(root: &Path, environment: BTreeMap<String, String>, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selection() -> MirrorSelection {
    MirrorSelection {
        candidate_id: "composer-test".into(),
        tool_id: "composer".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "huaweicloud".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: MIRROR.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: MIRROR.into(),
            },
            Endpoint {
                role: EndpointRole::Git,
                protocol: Protocol::Https,
                url: SOURCE.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn composer_two_preserves_private_project_and_auth_state_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let original = br#"{
  "config": {"secure-http": true},
  "repositories": [
    {"name":"private","type":"composer","url":"https://build:credential@packages.corp.example/api","canonical":false},
    {"name":"source","type":"vcs","url":"https://git.corp.example/team/library.git"},
    {"name":"packagist","type":"composer","url":"https://repo.packagist.org"}
  ],
  "extra": {"preserve": true}
}
"#;
    let config = install_composer(root, "2.10.2", Some(original), 0);
    let project = br#"{"repositories":[{"type":"vcs","url":"ssh://git@corp.example/project.git"}],"require":{"psr/log":"3.0.2"}}
"#;
    let project_path = write(root, "/work/project/composer.json", project);
    let lock_path = write(root, "/work/project/composer.lock", b"project-lock\n");
    let global_auth = write(
        root,
        "/home/developer/.composer/auth.json",
        b"global-secret\n",
    );
    let project_auth = write(root, "/work/project/auth.json", b"project-secret\n");
    let adapter = ComposerAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(
        root,
        BTreeMap::from([("COMPOSER_AUTH".into(), "environment-secret".into())]),
        Some("/work/project"),
    );

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.10.2"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("PHP 8.4.13"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("v2 repository protocol"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("3 global and 1 project"))
    );
    assert!(!format!("{detected:?}").contains("environment-secret"));

    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(current.documents.len(), 3);
    assert!(!format!("{current:?}").contains("build:credential@"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(request.repository_versions[UPSTREAM], "v2");
    assert_eq!(
        request.required_endpoint_roles,
        [
            EndpointRole::Index,
            EndpointRole::Artifacts,
            EndpointRole::Git
        ]
    );

    let selected = [selection()];
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(cli, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(cli.changes.len(), 2);
    assert_eq!(cli.changes[0].target, config);
    let before: Value = serde_json::from_slice(original).unwrap();
    let after: Value = serde_json::from_slice(&cli.changes[0].new_contents).unwrap();
    assert_eq!(after["config"], before["config"]);
    assert_eq!(after["extra"], before["extra"]);
    assert_eq!(after["repositories"][0], before["repositories"][0]);
    assert_eq!(after["repositories"][1], before["repositories"][1]);
    assert_eq!(
        after["repositories"][2]["url"],
        "https://repo.huaweicloud.com/repository/php"
    );
    assert_eq!(after["repositories"][2]["name"], "mirrorswitch-packagist");
    assert_eq!(after["repositories"][3]["packagist.org"], false);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("global config should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&project_path).unwrap(), project);
    assert_eq!(fs::read(&lock_path).unwrap(), b"project-lock\n");
    assert_eq!(fs::read(&global_auth).unwrap(), b"global-secret\n");
    assert_eq!(fs::read(&project_auth).unwrap(), b"project-secret\n");
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
    assert_eq!(fs::read(config).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/composer/config.json")
            .exists()
    );
}

#[test]
fn synthetic_native_contexts_preserve_bom_newlines_auth_security_and_project_state() {
    for (os, architecture, original) in [
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            br#"{
  "config": {"secure-http": true, "cafile": "/private/fixture/ca.pem"},
  "repositories": [{"name":"private","type":"composer","url":"https://fixture:credential@packages.corp.example/api","canonical":false}],
  "extra": {"preserve": true}
}
"#
            .as_slice(),
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            b"\xef\xbb\xbf{\r\n  \"config\": {\"secure-http\": true, \"cafile\": \"C:/fixture/ca.pem\"},\r\n  \"repositories\": [{\"name\":\"private\",\"type\":\"composer\",\"url\":\"https://fixture:credential@packages.corp.example/api\",\"canonical\":false}],\r\n  \"extra\": {\"preserve\": true}\r\n}\r\n".as_slice(),
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        let config = install_composer(root, "2.10.3", Some(original), 0);
        let project_contents = br#"{"repositories":[{"type":"vcs","url":"ssh://git@corp.example/project.git"}],"config":{"secure-http":true},"require":{"psr/log":"3.0.2"}}
"#;
        let project = write(root, "/work/project/composer.json", project_contents);
        let lock = write(root, "/work/project/composer.lock", b"native-lock\n");
        let global_auth = write(
            root,
            "/home/developer/.composer/auth.json",
            b"global-fixture-credential\n",
        );
        let project_auth = write(
            root,
            "/work/project/auth.json",
            b"project-fixture-credential\n",
        );
        let adapter = ComposerAdapter;
        let context = native_context(root, os, architecture);
        let mut runtime = runtime(
            root,
            BTreeMap::from([("COMPOSER_AUTH".into(), "environment-fixture".into())]),
            Some("/work/project"),
        );

        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(detected.evidence.iter().any(|line| line.contains(&format!("{os:?}"))));
        assert!(!format!("{detected:?}").contains("environment-fixture"));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let selected = [selection()];
        let cli = adapter.plan(&context, &current, &selected).unwrap();
        let config_plan = adapter.plan(&context, &current, &selected).unwrap();
        let tui = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(cli, config_plan);
        assert_eq!(config_plan, tui);
        assert!(!format!("{cli:?}").contains("fixture:credential"));
        let rendered = &cli.changes[0].new_contents;
        assert_eq!(
            rendered.starts_with(&[0xef, 0xbb, 0xbf]),
            os == OperatingSystem::Windows
        );
        if os == OperatingSystem::Windows {
            assert!(rendered.iter().enumerate().all(|(index, byte)| {
                *byte != b'\n' || index > 0 && rendered[index - 1] == b'\r'
            }));
        }

        let ApplyOutcome::Applied(receipt) =
            adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("Composer global config should change")
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
        assert_eq!(fs::read(config).unwrap(), original);
        assert_eq!(fs::read(project).unwrap(), project_contents);
        assert_eq!(fs::read(lock).unwrap(), b"native-lock\n");
        assert_eq!(fs::read(global_auth).unwrap(), b"global-fixture-credential\n");
        assert_eq!(fs::read(project_auth).unwrap(), b"project-fixture-credential\n");
    }
}

#[test]
fn composer_one_uses_object_config_and_arm64_container_protocol() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let config = install_composer(
        root,
        "1.10.28",
        Some(
            br#"{"config":{"preferred-install":"dist"},"repositories":{"z-private":{"type":"composer","url":"https://z.corp.example/api"},"a-private":{"type":"vcs","url":"https://a.corp.example/repo.git"}}}
"#,
        ),
        0,
    );
    let adapter = ComposerAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let runtime = runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "v1");
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    let rendered: Value = serde_json::from_slice(&plan.changes[0].new_contents).unwrap();
    assert_eq!(
        rendered["repositories"]["packagist.org"]["url"],
        "https://repo.huaweicloud.com/repository/php"
    );
    assert_eq!(rendered["config"]["preferred-install"], "dist");
    assert_eq!(
        rendered["repositories"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["z-private", "a-private", "packagist.org"]
    );
    assert_eq!(plan.changes[0].target, config);
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
            .unwrap_err()
            .to_string()
            .contains("project composer.json")
    );
}

#[test]
fn disabled_ambiguous_private_packagist_and_escaping_override_are_blocked() {
    let adapter = ComposerAdapter;
    let cases: [(&[u8], &str); 5] = [
        (br#"{"repositories":{"packagist.org":false}}
"#, "explicitly disables"),
        (br#"{"repositories":{"packagist":{"type":"composer","url":"https://private.example/api"}}}
"#, "private or unreviewed"),
        (br#"{"repositories":[{"name":"packagist","type":"composer","url":"https://repo.packagist.org"},{"type":"composer","url":"https://mirrors.aliyun.com/composer"}]}
"#, "multiple public"),
        (
            br#"{"config":{"disable-tls":true}}
"#,
            "disables Composer HTTPS",
        ),
        (
            br#"{"config":{"secure-http":false}}
"#,
            "disables Composer HTTPS",
        ),
    ];
    for (contents, expected) in cases {
        let directory = tempdir().unwrap();
        install_composer(directory.path(), "2.10.2", Some(contents), 0);
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let runtime = runtime(directory.path(), BTreeMap::new(), None);
        let error = adapter.detect(&context, &runtime).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }

    let directory = tempdir().unwrap();
    install_composer(directory.path(), "2.10.2", Some(b"{}\n"), 0);
    write(directory.path(), "/outside/composer.json", b"{}\n");
    let outside_context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let outside_runtime = runtime(
        directory.path(),
        BTreeMap::from([("COMPOSER".into(), "/outside/composer.json".into())]),
        Some("/work/project"),
    );
    assert!(
        adapter
            .detect(&outside_context, &outside_runtime)
            .unwrap_err()
            .to_string()
            .contains("outside the detected project")
    );

    for project in [
        br#"{"repositories":{"packagist.org":{"type":"composer","url":"https://repo.packagist.org"}}}
"#
            .as_slice(),
        br#"{"config":{"secure-http":false}}
"#.as_slice(),
    ] {
        let directory = tempdir().unwrap();
        install_composer(directory.path(), "2.10.3", Some(b"{}\n"), 0);
        write(directory.path(), "/work/project/composer.json", project);
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let runtime = runtime(directory.path(), BTreeMap::new(), Some("/work/project"));
        assert!(adapter.detect(&context, &runtime).unwrap_err().to_string().contains("project"));
    }
}

#[test]
fn failed_real_composer_query_restores_the_original_global_config() {
    let directory = tempdir().unwrap();
    let original =
        br#"{"repositories":{"packagist":{"type":"composer","url":"https://repo.packagist.org"}}}
"#;
    let config = install_composer(directory.path(), "2.10.2", Some(original), 77);
    let adapter = ComposerAdapter;
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let mut runtime = runtime(directory.path(), BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("global config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(config).unwrap(), original);
    assert!(
        !directory
            .path()
            .join("home/developer/.mirrorswitch/verification/composer/config.json")
            .exists()
    );
}

#[derive(Clone)]
struct ComposerProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_dist: bool,
    corrupt_source: bool,
}

impl CandidateProber for ComposerProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let (content_type, body) = if url.ends_with("psr-log-3.0.2.zip") {
            (
                Some("application/zip".into()),
                if self.corrupt_dist {
                    b"corrupt".to_vec()
                } else {
                    DIST_BODY.to_vec()
                },
            )
        } else if url.ends_with("archive/refs/tags/3.0.2.zip") {
            (
                Some("application/zip".into()),
                if self.corrupt_source {
                    b"corrupt".to_vec()
                } else {
                    SOURCE_BODY.to_vec()
                },
            )
        } else if url.ends_with("packages.json") {
            (
                Some("application/json".into()),
                br#"{"providers-lazy-url":"/p/%package%.json"}"#.to_vec(),
            )
        } else if url.contains("/p2/psr/log.json") {
            (Some("application/json".into()), br#"{"packages":{"psr/log":[{"dist":{"url":"https://repo.huaweicloud.com/repository/php/psr/log/3.0.2/psr-log-3.0.2.zip"},"source":{"url":"https://github.com/php-fig/log.git"}}]}}"#.to_vec())
        } else {
            (
                Some("application/json".into()),
                br#"{"packages":{"psr/log":{}}}"#.to_vec(),
            )
        };
        Ok(ProbeObservation {
            status: 200,
            content_type,
            body,
            latency_ms: 1,
        })
    }
}

fn catalog_for_synthetic_artifacts() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "composer")
    {
        for probe in &mut candidate.probes {
            if probe.path.ends_with("psr-log-3.0.2.zip") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(DIST_BODY)));
            } else if probe.path.ends_with("archive/refs/tags/3.0.2.zip") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(SOURCE_BODY)));
            }
        }
    }
    catalog
}

#[test]
fn catalog_requires_v1_v2_metadata_dist_and_source_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let candidate = embedded
        .candidates
        .iter()
        .find(|candidate| candidate.tool_id == "composer")
        .unwrap();
    assert_eq!(candidate.provider_id, "huaweicloud");
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
    assert_eq!(candidate.compatibility.repository_versions, ["v1", "v2"]);
    assert_eq!(candidate.probes.len(), 6);
    assert!(
        candidate
            .probes
            .iter()
            .any(|probe| probe.path == "/p/psr/log.json")
    );
    assert!(
        candidate
            .probes
            .iter()
            .any(|probe| probe.path == "/p2/psr/log.json")
    );
    assert!(candidate.probes.iter().any(|probe| {
        probe.path.ends_with("psr-log-3.0.2.zip")
            && probe.sha256.as_deref()
                == Some("1e8dcf2df933fc3440b29146c5ca4e93ece51c5c7a9ac9653d926ec971c90892")
    }));
    assert!(candidate.probes.iter().any(|probe| {
        probe.path.ends_with("archive/refs/tags/3.0.2.zip")
            && probe.sha256.as_deref()
                == Some("c365225b9567800008110f8f7b2873bed86c5a0c40ce3ae399059ff3c22b778e")
    }));

    let catalog = catalog_for_synthetic_artifacts();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == "composer")
        .unwrap();
    assert_eq!(tool.state, ToolCatalogState::Supported);
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);

    let directory = tempdir().unwrap();
    install_composer(directory.path(), "2.10.2", Some(b"{}\n"), 0);
    let adapter = ComposerAdapter;
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), BTreeMap::new(), None);
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
        ComposerProtocolProber {
            calls: calls.clone(),
            corrupt_dist: false,
            corrupt_source: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable);
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 6);

    for prober in [
        ComposerProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_dist: true,
            corrupt_source: false,
        },
        ComposerProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_dist: false,
            corrupt_source: true,
        },
    ] {
        let rejected = MirrorSelector::with_prober(&catalog, prober, ProbeLimits::default())
            .select_at(&request, 100)
            .unwrap();
        assert!(!rejected.actionable);
        assert!(rejected.repositories[0].candidates.iter().any(|candidate| {
            matches!(
                &candidate.evaluation,
                CandidateEvaluation::ProbeFailed { reason } if reason.contains("SHA-256")
            )
        }));
    }
}

#[test]
fn unsupported_version_non_native_or_windows_arm_context_and_missing_commands_are_inert() {
    let adapter = ComposerAdapter;
    let directory = tempdir().unwrap();
    install_composer(directory.path(), "3.0.0", Some(b"{}\n"), 0);
    let linux = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    assert!(
        adapter
            .detect(&linux, &installed)
            .unwrap_err()
            .to_string()
            .contains("reviewed 1.10+/2.x")
    );

    let directory = tempdir().unwrap();
    install_composer(directory.path(), "2.10.2", Some(b"{}\n"), 0);
    let windows = native_context(
        directory.path(),
        OperatingSystem::Windows,
        Architecture::X86_64,
    );
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    assert!(adapter.detect(&windows, &installed).unwrap().is_some());
    let windows_arm = SystemContext {
        architecture: Architecture::Arm64,
        ..windows.clone()
    };
    assert!(
        adapter
            .detect(&windows_arm, &installed)
            .unwrap_err()
            .to_string()
            .contains("native Windows arm64 runtime")
    );
    let macos_container = SystemContext {
        environment: ExecutionEnvironment::Container,
        ..native_context(
            directory.path(),
            OperatingSystem::Macos,
            Architecture::Arm64,
        )
    };
    assert!(
        adapter
            .detect(&macos_container, &installed)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );

    let empty = tempdir().unwrap();
    let runtime = runtime(empty.path(), BTreeMap::new(), None);
    let context = context(
        empty.path(),
        Architecture::Arm64,
        ExecutionEnvironment::Container,
    );
    assert!(adapter.detect(&context, &runtime).unwrap().is_none());
}
