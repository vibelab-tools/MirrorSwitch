#![cfg(unix)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{BundlerAdapter, compiled_adapter_allowlist},
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

const UPSTREAM: &str = "rubygems--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/rubygems/";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/rubygems/";
const GEM_BODY: &[u8] = b"synthetic net-protocol-0.3.0 gem";

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

fn install_bundler(root: &Path, bundler: &str, ruby: &str, failure: &str) {
    let verification = root.join("home/developer/.mirrorswitch/verification/bundler");
    executable(
        root,
        "/usr/bin/bundle",
        format!(
            r#"#!/bin/sh
config='{config}'
gemfile='{gemfile}'
case "$*" in
  "--version") printf '%s\n' 'Bundler version {bundler}' ;;
  "config get mirror."*)
    [ "$BUNDLE_USER_CONFIG" = '/home/developer/.mirrorswitch/verification/bundler/home/.bundle/config' ] || exit 70
    [ "$BUNDLE_APP_CONFIG" = '/home/developer/.mirrorswitch/verification/bundler/.bundle' ] || exit 71
    [ "$BUNDLE_GEMFILE" = '/home/developer/.mirrorswitch/verification/bundler/Gemfile' ] || exit 72
    [ '{failure}' != config ] || exit 73
    endpoint=$(sed -n 's/^.*: "\([^"]*\)"$/\1/p' "$config")
    key=$(sed -n 's/^BUNDLE_MIRROR__\([^:]*\):.*$/mirror.\1/p' "$config")
    [ -n "$endpoint" ] || exit 74
    printf '%s\n' "$key" "Set for your local app (/home/developer/.mirrorswitch/verification/bundler/.bundle/config): \"$endpoint\""
    ;;
  "lock --print")
    [ '{failure}' != lock ] || exit 75
    source=$(sed -n 's/^source "\([^"]*\)"$/\1/p' "$gemfile")
    [ -n "$source" ] || exit 76
    printf '%s\n' \
      'GEM' \
      "  remote: $source" \
      '  specs:' \
      '    net-protocol (0.3.0)' \
      '      timeout' \
      '    timeout (0.6.1)' \
      '' \
      'PLATFORMS' \
      '  x86_64-linux' \
      '' \
      'DEPENDENCIES' \
      '  net-protocol (= 0.3.0)'
    ;;
  *) exit 77 ;;
esac
"#,
            config = verification.join(".bundle/config").display(),
            gemfile = verification.join("Gemfile").display(),
        ),
    );
    executable(
        root,
        "/usr/bin/ruby",
        format!(
            "#!/bin/sh\n[ \"$1\" = --version ] || exit 71\nprintf '%s\\n' 'ruby {ruby} (test revision) [x86_64-linux]'\n"
        ),
    );
}

fn runtime(root: &Path, environment: BTreeMap<String, String>, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment);
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selection(provider: &str, endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: format!("bundler-{provider}-test"),
        tool_id: "bundler".into(),
        upstream_id: UPSTREAM.into(),
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
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn user_plan_preserves_private_credentials_project_and_fallback_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_bundler(root, "4.0.19", "3.4.10", "none");
    let original = br#"---
# global policy
BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "https://mirrors.ustc.edu.cn/rubygems/"
BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/__FALLBACK_TIMEOUT: "3"
BUNDLE_MIRROR__HTTPS://GEMS__CORP__EXAMPLE/: "https://build:credential@gems.corp.example/cache"
BUNDLE_GEMS__CORP__EXAMPLE: "user:secret"
BUNDLE_BUILD__NATIVE: "--with-cflags=\"-O2\""
BUNDLE_WITHOUT: "development"
"#;
    let global = write(root, "/home/developer/.bundle/config", original);
    let gemfile = br#"source "https://rubygems.org"

source "https://build:credential@gems.corp.example/api/source:cache" do
  gem "private-package"
end

gem "source:fixture"
gem "net-protocol", "= 0.3.0"
"#;
    let project_gemfile = write(root, "/work/app/Gemfile", gemfile);
    let lockfile = br#"GEM
  remote: https://rubygems.org/
  specs:
    net-protocol (0.3.0)

GEM
  remote: https://gems.corp.example/api/
  specs:
    private-package (1.0.0)
"#;
    let project_lock = write(root, "/work/app/Gemfile.lock", lockfile);
    let local = write(
        root,
        "/work/app/.bundle/config",
        b"---\nBUNDLE_PATH: \"vendor/bundle\"\n",
    );
    let adapter = BundlerAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, BTreeMap::new(), Some("/work/app/subdirectory"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("4.0.19"));
    assert!(detected.evidence.iter().any(|line| line == "Ruby 3.4.10"));
    assert!(detected.evidence.iter().any(|line| {
        line.contains("credential")
            && line.contains("opaque")
            && line.contains("Gemfile")
            && line.contains("global config")
    }));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(
        current
            .sources
            .iter()
            .find(|source| source.upstream_id.as_deref() == Some(UPSTREAM))
            .unwrap()
            .url,
        "https://rubygems.org/"
    );
    let serialized = serde_json::to_string(&current).unwrap();
    assert!(!serialized.contains("build:credential"));
    assert!(!serialized.contains("user:secret"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(
        request.required_endpoint_roles,
        [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts
        ]
    );

    let selected = [selection("aliyun", ALIYUN)];
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 3);
    assert!(!cli.requires_elevation);
    let rendered = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(&format!(
        "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"{ALIYUN}\""
    )));
    assert!(rendered.contains("__FALLBACK_TIMEOUT: \"3\""));
    assert!(rendered.contains("https://build:credential@gems.corp.example/cache"));
    assert!(rendered.contains("BUNDLE_GEMS__CORP__EXAMPLE: \"user:secret\""));
    assert!(rendered.contains("BUNDLE_BUILD__NATIVE: \"--with-cflags=\\\"-O2\\\"\""));
    assert!(!format!("{cli:?}").contains("build:credential"));
    assert!(!format!("{cli:?}").contains("user:secret"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Bundler configs should change")
    };
    let verification = adapter.verify(&context, &mut runtime, &receipt).unwrap();
    assert!(verification.valid);
    assert!(verification.summary.contains("net-protocol-0.3.0"));
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
    assert_eq!(fs::read(global).unwrap(), original);
    assert_eq!(fs::read(project_gemfile).unwrap(), gemfile);
    assert_eq!(fs::read(project_lock).unwrap(), lockfile);
    assert_eq!(
        fs::read(local).unwrap(),
        b"---\nBUNDLE_PATH: \"vendor/bundle\"\n"
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/bundler/.bundle/config")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/bundler/Gemfile")
            .exists()
    );
}

#[test]
fn synthetic_native_contexts_preserve_bom_newlines_security_and_project_files() {
    for (os, architecture, original) in [
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            b"---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://mirrors.ustc.edu.cn/rubygems/\"\nBUNDLE_GEMS__CORP__EXAMPLE: \"fixture:credential\"\nBUNDLE_SSL_CA_CERT: \"/private/fixture/ca.pem\"\nBUNDLE_HTTPS_PROXY: \"https://proxy.corp.example/\"\n".as_slice(),
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            b"\xef\xbb\xbf---\r\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://mirrors.ustc.edu.cn/rubygems/\"\r\nBUNDLE_GEMS__CORP__EXAMPLE: \"fixture:credential\"\r\nBUNDLE_SSL_CA_CERT: 'C:/fixture/ca.pem'\r\nBUNDLE_HTTPS_PROXY: \"https://proxy.corp.example/\"\r\n".as_slice(),
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_bundler(root, "4.0.19", "3.4.10", "none");
        let global = write(root, "/home/developer/.bundle/config", original);
        let gemfile_contents = b"source 'https://rubygems.org'\ngem 'net-protocol', '= 0.3.0'\n";
        let lockfile_contents = b"GEM\n  remote: https://rubygems.org/\n";
        let local_contents = if os == OperatingSystem::Windows {
            b"\xef\xbb\xbf---\r\nBUNDLE_PATH: \"vendor/bundle\"\r\n".as_slice()
        } else {
            b"---\nBUNDLE_PATH: \"vendor/bundle\"\n".as_slice()
        };
        let gemfile = write(root, "/work/app/Gemfile", gemfile_contents);
        let lockfile = write(root, "/work/app/Gemfile.lock", lockfile_contents);
        let local = write(root, "/work/app/.bundle/config", local_contents);
        let adapter = BundlerAdapter;
        let context = native_context(root, os, architecture);
        let mut runtime = runtime(root, BTreeMap::new(), Some("/work/app"));

        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(detected.evidence.iter().any(|line| line.contains(&format!("{os:?}"))));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let chosen = [selection("aliyun", ALIYUN)];
        let cli = adapter.plan(&context, &current, &chosen).unwrap();
        let config = adapter.plan(&context, &current, &chosen).unwrap();
        let tui = adapter.plan(&context, &current, &chosen).unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
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
        let project_current = adapter
            .read_current(
                &context,
                &runtime,
                &detected,
                ConfigurationScope::Project,
            )
            .unwrap();
        let project_plan = adapter.plan(&context, &project_current, &chosen).unwrap();
        let project_target = project_plan
            .changes
            .iter()
            .find(|change| change.target.ends_with("work/app/.bundle/config"))
            .unwrap();
        assert_eq!(
            project_target
                .new_contents
                .starts_with(&[0xef, 0xbb, 0xbf]),
            os == OperatingSystem::Windows
        );
        if os == OperatingSystem::Windows {
            assert!(
                project_target
                    .new_contents
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| {
                        *byte != b'\n'
                            || index > 0 && project_target.new_contents[index - 1] == b'\r'
                    })
            );
        }

        let ApplyOutcome::Applied(receipt) =
            adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("Bundler configuration should change")
        };
        assert!(
            adapter
                .verify(&context, &mut runtime, &receipt)
                .unwrap()
                .valid
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
                .plan(&context, &current_after, &chosen)
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
        assert_eq!(fs::read(global).unwrap(), original);
        assert_eq!(fs::read(gemfile).unwrap(), gemfile_contents);
        assert_eq!(fs::read(lockfile).unwrap(), lockfile_contents);
        assert_eq!(fs::read(local).unwrap(), local_contents);
    }
}

#[test]
fn explicit_arm64_project_scope_and_failed_lock_restore_every_managed_target() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_bundler(root, "2.4.20", "3.2.3", "lock");
    let global = write(
        root,
        "/home/developer/.bundle/config",
        format!("---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"{ALIYUN}\"\n").as_bytes(),
    );
    let gemfile = write(
        root,
        "/work/app/Gemfile",
        b"source 'https://rubygems.org'\ngem 'net-protocol', '= 0.3.0'\n",
    );
    let lockfile = write(
        root,
        "/work/app/Gemfile.lock",
        b"GEM\n  remote: https://rubygems.org/\n",
    );
    let original_local = b"---\nBUNDLE_WITHOUT: \"test\"\n";
    let local = write(root, "/work/app/.bundle/config", original_local);
    let adapter = BundlerAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = runtime(root, BTreeMap::new(), Some("/work/app"));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let cli = adapter
        .plan(&context, &current, &[selection("tuna", TUNA)])
        .unwrap();
    let config = adapter
        .plan(&context, &current, &[selection("tuna", TUNA)])
        .unwrap();
    let tui = adapter
        .plan(&context, &current, &[selection("tuna", TUNA)])
        .unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    let plan = cli;
    assert_eq!(plan.scope, ConfigurationScope::Project);
    assert_eq!(plan.changes[0].target, local);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("project config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(local).unwrap(), original_local);
    assert!(fs::read_to_string(global).unwrap().contains(ALIYUN));
    assert!(
        fs::read_to_string(gemfile)
            .unwrap()
            .contains("net-protocol")
    );
    assert!(
        fs::read_to_string(lockfile)
            .unwrap()
            .contains("rubygems.org")
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/bundler/.bundle/config")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/bundler/Gemfile")
            .exists()
    );
}

#[test]
fn user_config_environment_paths_and_implicit_project_free_default_are_supported() {
    let adapter = BundlerAdapter;
    for (environment, expected) in [
        (
            BTreeMap::from([(
                "BUNDLE_USER_CONFIG".into(),
                "/home/developer/configs/bundle.yml".into(),
            )]),
            "/home/developer/configs/bundle.yml",
        ),
        (
            BTreeMap::from([(
                "BUNDLE_USER_HOME".into(),
                "/home/developer/bundler-home".into(),
            )]),
            "/home/developer/bundler-home/config",
        ),
    ] {
        let directory = tempdir().unwrap();
        install_bundler(directory.path(), "2.5.23", "3.3.8", "none");
        let runtime = runtime(directory.path(), environment, None);
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(detected.evidence.iter().any(|line| line.contains(expected)));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let plan = adapter
            .plan(&context, &current, &[selection("tuna", TUNA)])
            .unwrap();
        assert_eq!(
            plan.changes[0].target,
            directory.path().join(expected.trim_start_matches('/'))
        );
        let rendered = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
        assert!(rendered.starts_with("---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"));
    }
}

#[test]
fn dynamic_conflicting_override_transport_and_path_policies_are_blocked() {
    let adapter = BundlerAdapter;
    type UnsafeCase<'a> = (
        &'a [u8],
        Option<&'a [u8]>,
        BTreeMap<String, String>,
        &'a str,
    );
    let cases: &[UnsafeCase<'_>] = &[
        (
            b"source ENV.fetch('GEM_SOURCE')\n",
            None,
            BTreeMap::new(),
            "dynamic Bundler source",
        ),
        (
            b"source 'https://rubygems.org'\nsource 'https://mirrors.tuna.tsinghua.edu.cn/rubygems'\n",
            None,
            BTreeMap::new(),
            "exactly one",
        ),
        (
            b"eval_gemfile 'dependencies.rb'\nsource 'https://rubygems.org'\n",
            None,
            BTreeMap::new(),
            "eval_gemfile",
        ),
        (
            b"source 'https://rubygems.org'\n",
            Some(b"---\nBUNDLE_MIRROR__ALL: \"https://cache.example\"\n"),
            BTreeMap::new(),
            "catch-all",
        ),
        (
            b"source 'https://rubygems.org'\n",
            Some(b"---\nBUNDLE_DISABLE_CHECKSUM_VALIDATION: \"true\"\n"),
            BTreeMap::new(),
            "checksum validation",
        ),
        (
            b"source 'https://user:secret@rubygems.org'\n",
            None,
            BTreeMap::new(),
            "credential-bearing public",
        ),
        (
            b"source 'https://rubygems.org'\n",
            None,
            BTreeMap::from([("BUNDLE_IGNORE_CONFIG".into(), "1".into())]),
            "prevents persisted",
        ),
        (
            b"source 'https://rubygems.org'\n",
            None,
            BTreeMap::from([(
                "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/".into(),
                TUNA.into(),
            )]),
            "overrides Bundler configuration",
        ),
    ];
    for (gemfile, config, environment, expected) in cases {
        let directory = tempdir().unwrap();
        install_bundler(directory.path(), "2.4.20", "3.2.3", "none");
        write(directory.path(), "/work/app/Gemfile", gemfile);
        if let Some(config) = config {
            write(directory.path(), "/home/developer/.bundle/config", config);
        }
        let runtime = runtime(directory.path(), environment.clone(), Some("/work/app"));
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let error = adapter.detect(&context, &runtime).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }

    let directory = tempdir().unwrap();
    install_bundler(directory.path(), "2.4.20", "3.2.3", "none");
    let outside_runtime = runtime(
        directory.path(),
        BTreeMap::from([("BUNDLE_USER_CONFIG".into(), "/etc/bundler/config".into())]),
        None,
    );
    let outside_context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(
        adapter
            .detect(&outside_context, &outside_runtime)
            .unwrap_err()
            .to_string()
            .contains("inside /home/developer")
    );

    let directory = tempdir().unwrap();
    install_bundler(directory.path(), "2.4.20", "3.2.3", "none");
    write(
        directory.path(),
        "/work/app/Gemfile",
        b"source 'https://rubygems.org'\n",
    );
    write(
        directory.path(),
        "/work/app/.bundle/config",
        format!("---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"{TUNA}\"\n").as_bytes(),
    );
    let runtime = runtime(directory.path(), BTreeMap::new(), Some("/work/app"));
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap_err()
            .to_string()
            .contains("select project scope explicitly")
    );
}

#[derive(Clone)]
struct BundlerProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_gem: bool,
}

impl CandidateProber for BundlerProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let (content_type, body) = if url.ends_with("net-protocol-0.3.0.gem") {
            (
                Some("application/octet-stream".into()),
                if self.corrupt_gem {
                    b"corrupt".to_vec()
                } else {
                    GEM_BODY.to_vec()
                },
            )
        } else if url.ends_with("info/net-protocol") {
            (
                Some("text/plain".into()),
                b"---\n0.3.0 timeout:>= 0|checksum:test\n".to_vec(),
            )
        } else if url.ends_with("net-protocol-0.3.0.gemspec.rz") {
            (Some("application/octet-stream".into()), b"gemspec".to_vec())
        } else {
            (Some("application/octet-stream".into()), Vec::new())
        };
        Ok(ProbeObservation {
            status: 200,
            content_type,
            body,
            latency_ms: 1,
        })
    }
}

fn catalog_for_synthetic_gem() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "bundler")
    {
        for probe in &mut candidate.probes {
            if probe.path.ends_with("net-protocol-0.3.0.gem") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(GEM_BODY)));
            } else if probe.path.ends_with("net-protocol-0.3.0.gemspec.rz") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(b"gemspec")));
            }
        }
    }
    catalog
}

#[test]
fn catalog_uses_case_specific_index_dependency_and_gem_sha_gates_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let candidates = embedded
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "bundler")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 5);
    assert_eq!(
        embedded
            .tools
            .iter()
            .find(|tool| tool.id == "bundler")
            .unwrap()
            .state,
        ToolCatalogState::Supported
    );
    let actionable = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(actionable.len(), 4);
    assert_eq!(
        actionable
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "nju", "tuna", "ustc"])
    );
    for candidate in actionable {
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
        assert_eq!(candidate.endpoints.len(), 3);
        let paths = candidate
            .probes
            .iter()
            .map(|probe| probe.path.as_str())
            .collect::<Vec<_>>();
        if matches!(candidate.provider_id.as_str(), "tuna" | "ustc") {
            assert!(paths.contains(&"/versions"));
            assert_eq!(
                paths
                    .iter()
                    .filter(|path| **path == "/info/net-protocol")
                    .count(),
                2
            );
        } else {
            assert!(paths.contains(&"/specs.4.8.gz"));
            let gemspec = candidate
                .probes
                .iter()
                .find(|probe| probe.path.ends_with("net-protocol-0.3.0.gemspec.rz"))
                .unwrap();
            assert_eq!(
                gemspec.sha256.as_deref(),
                Some("19ecdd263f82ef67af89a112014f1905b4074d831b7ecfa67d64eb3fc6359229")
            );
        }
        assert_eq!(
            candidate
                .probes
                .iter()
                .find(|probe| probe.path.ends_with("net-protocol-0.3.0.gem"))
                .unwrap()
                .sha256
                .as_deref(),
            Some("ba310c3d4f1cad46bb1ab20336b06669b1ff8f7c568d9cb9342b32a718547472")
        );
    }

    let catalog = catalog_for_synthetic_gem();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let directory = tempdir().unwrap();
    install_bundler(directory.path(), "2.4.20", "3.2.3", "none");
    let adapter = BundlerAdapter;
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
        BundlerProtocolProber {
            calls: calls.clone(),
            corrupt_gem: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable, "{selected:#?}");
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 14);

    let rejected = MirrorSelector::with_prober(
        &catalog,
        BundlerProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_gem: true,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(!rejected.actionable);
    assert!(
        rejected.repositories[0]
            .candidates
            .iter()
            .filter(|candidate| candidate.provider_id != "huaweicloud")
            .all(|candidate| {
                matches!(
                    &candidate.evaluation,
                    CandidateEvaluation::ProbeFailed { reason } if reason.contains("SHA-256")
                )
            })
    );
}

#[test]
fn unsupported_versions_non_native_context_scope_and_missing_clients_are_inert() {
    let adapter = BundlerAdapter;
    let directory = tempdir().unwrap();
    install_bundler(directory.path(), "1.17.3", "2.6.10", "none");
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
            .contains("2.x through 4.x")
    );

    let directory = tempdir().unwrap();
    install_bundler(directory.path(), "2.4.20", "2.5.9", "none");
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    assert!(
        adapter
            .detect(&linux, &installed)
            .unwrap_err()
            .to_string()
            .contains("2.6 through 4.x")
    );

    let directory = tempdir().unwrap();
    install_bundler(directory.path(), "2.4.20", "3.2.3", "none");
    let installed = runtime(directory.path(), BTreeMap::new(), None);
    let windows = native_context(
        directory.path(),
        OperatingSystem::Windows,
        Architecture::X86_64,
    );
    assert!(adapter.detect(&windows, &installed).unwrap().is_some());
    let windows_container = SystemContext {
        environment: ExecutionEnvironment::Container,
        ..windows.clone()
    };
    assert!(
        adapter
            .detect(&windows_container, &installed)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );

    let detected = adapter.detect(&linux, &installed).unwrap().unwrap();
    assert!(
        adapter
            .read_current(&linux, &installed, &detected, ConfigurationScope::System,)
            .unwrap_err()
            .to_string()
            .contains("user and explicit project")
    );

    let empty = tempdir().unwrap();
    let empty_runtime = runtime(empty.path(), BTreeMap::new(), None);
    let empty_context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(
        adapter
            .detect(&empty_context, &empty_runtime)
            .unwrap()
            .is_none()
    );
}
