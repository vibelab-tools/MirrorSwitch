#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{PyenvAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "python-releases--release-artifacts";
const HUAWEI: &str = "https://repo.huaweicloud.com/python";
const NJU: &str = "https://mirrors.nju.edu.cn/python";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/python";
const RELEASE_IDENTITY: &str =
    "3.14.7/3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81";
const ARCHIVE_SHA: &str = "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81";
const SIGNATURE_SHA: &str = "ae37dfde764ccb50a8ad649940bdeba47c93ef99be2501db9759894b7c2b5b9d";

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

fn definition(checksum: &str) -> String {
    format!(
        "if has_tar_xz_support; then\n    install_package \"Python-3.14.7\" \"https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tar.xz#{checksum}\" standard verify_py314 copy_python_gdb ensurepip\nelse\n    install_package \"Python-3.14.7\" \"https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tgz#62859805f6fdf25e2bcbf3fa3217801e1996887ca33e6a2af80674bdfa2dbe07\" standard verify_py314 copy_python_gdb ensurepip\nfi\n"
    )
}

fn install_pyenv(root: &Path, version: &str, checksum: &str, download_exit: i32) {
    install_pyenv_at(root, "/home/developer", version, checksum, download_exit);
}

fn install_pyenv_at(root: &Path, home: &str, version: &str, checksum: &str, download_exit: i32) {
    executable(
        root,
        "/usr/bin/env",
        format!(
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    *=*) export \"$1\"; shift ;;\n    *) break ;;\n  esac\ndone\nprogram=$1\nshift\nexec '{root}/usr/bin/'\"$program\" \"$@\"\n",
            root = root.display()
        ),
    );
    executable(
        root,
        "/usr/bin/pyenv",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'pyenv {version}'; exit 0; fi\nif [ \"$1\" = root ]; then echo '{home}/.pyenv'; exit 0; fi\nif [ \"$1 $2\" = 'install --version' ]; then echo 'python-build 2.6.18'; exit 0; fi\nif [ \"$1 $2\" = 'install --list' ]; then printf '%s\\n' 'Available versions:' '  3.13.15' '  3.14.7'; exit 0; fi\nexit 70\n"
        ),
    );
    executable(
        root,
        "/usr/bin/curl",
        format!(
            "#!/bin/sh\n[ {download_exit} -eq 0 ] || exit {download_exit}\noutput=\nurl=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --output) output=$2; shift 2 ;;\n    http*) url=$1; shift ;;\n    *) shift ;;\n  esac\ndone\n[ -n \"$output\" ] && [ -n \"$url\" ] || exit 71\ncase \"$url\" in\n  https://repo.huaweicloud.com/python/3.14.7/Python-3.14.7.tar.xz|https://mirrors.nju.edu.cn/python/3.14.7/Python-3.14.7.tar.xz|https://mirrors.tuna.tsinghua.edu.cn/python/3.14.7/Python-3.14.7.tar.xz) ;;\n  *) exit 72 ;;\nesac\nmkdir -p '{root}'\"$(dirname \"$output\")\"\nprintf '%s\\n' archive > '{root}'\"$output\"\n",
            root = root.display()
        ),
    );
    executable(
        root,
        "/usr/bin/sha256sum",
        format!("#!/bin/sh\nprintf '%s  %s\\n' '{ARCHIVE_SHA}' \"$1\"\n"),
    );
    executable(
        root,
        "/usr/bin/shasum",
        format!(
            "#!/bin/sh\nfor argument in \"$@\"; do archive=$argument; done\nprintf '%s  %s\\n' '{ARCHIVE_SHA}' \"$archive\"\n"
        ),
    );
    executable(
        root,
        "/usr/bin/rm",
        format!(
            "#!/bin/sh\npath=$2\n/bin/rm -f '{root}'\"$path\"\n",
            root = root.display()
        ),
    );
    write(
        root,
        &format!("{home}/.pyenv/plugins/python-build/share/python-build/3.14.7"),
        definition(checksum).as_bytes(),
    );
}

fn test_runtime(root: &Path, environment: BTreeMap<String, String>) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(environment)
}

fn native_runtime(
    root: &Path,
    home: &str,
    project: &str,
    environment: BTreeMap<String, String>,
) -> OsRuntime {
    OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home(home)
        .with_project_dir(project)
        .with_environment(environment)
}

fn environment(shell: &str, mirror: Option<&str>, skip: Option<&str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([("SHELL".into(), shell.into())]);
    if let Some(mirror) = mirror {
        values.insert("PYTHON_BUILD_MIRROR_URL".into(), mirror.into());
    }
    if let Some(skip) = skip {
        values.insert("PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM".into(), skip.into());
    }
    values
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("pyenv-{provider}-test"),
        tool_id: "pyenv".into(),
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
        latency_ms: 3,
        selected_at_unix_ms: 123,
        user_override: false,
    }]
}

#[test]
fn user_plan_preserves_pyenv_initialization_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pyenv(root, "2.8.4", ARCHIVE_SHA, 0);
    let original = format!(
        "export PYENV_ROOT=\"$HOME/.pyenv\"\nexport PATH=\"$PYENV_ROOT/bin:$PATH\"\neval \"$(pyenv init -)\"\nexport EDITOR=vim\nexport PYTHON_BUILD_MIRROR_URL='{NJU}'\nexport PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM=1\n"
    );
    let profile = write(root, "/home/developer/.bashrc", original.as_bytes());
    let adapter = PyenvAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(root, environment("/bin/bash", Some(NJU), Some("1")));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("2.8.4"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "existing active pyenv init line(s): 1 (preserved)")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], RELEASE_IDENTITY);
    let selected = selection("tuna", TUNA);
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 2);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert_eq!(changed.matches("pyenv init").count(), 1);
    assert!(changed.contains("export EDITOR=vim"));
    assert!(changed.contains(TUNA));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("pyenv profile and manifest should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let refreshed = test_runtime(root, environment("/bin/bash", Some(TUNA), Some("1")));
    let current = adapter
        .read_current(&context, &refreshed, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selected)
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
    assert_eq!(fs::read_to_string(profile).unwrap(), original);
}

#[test]
fn arm64_fish_and_container_bash_use_the_same_url_mode() {
    let cases = [
        (
            Architecture::Arm64,
            "/usr/bin/fish",
            BTreeMap::new(),
            "/home/developer/.config/fish/conf.d/mirrorswitch-python-build.fish",
        ),
        (
            Architecture::X86_64,
            "/bin/bash",
            BTreeMap::from([("BASH_ENV".into(), "/home/developer/container.env".into())]),
            "/home/developer/container.env",
        ),
    ];
    for (architecture, shell, extra, expected) in cases {
        let directory = tempdir().unwrap();
        install_pyenv(directory.path(), "2.8.4", ARCHIVE_SHA, 0);
        let mut values = environment(shell, None, None);
        values.extend(extra);
        let adapter = PyenvAdapter;
        let context = context(
            directory.path(),
            architecture,
            ExecutionEnvironment::Container,
        );
        let runtime = test_runtime(directory.path(), values);
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let plan = adapter
            .plan(&context, &current, &selection("huaweicloud", HUAWEI))
            .unwrap();
        let profile = plan
            .changes
            .iter()
            .find(|change| change.target.ends_with(expected.trim_start_matches('/')))
            .unwrap();
        let text = String::from_utf8(profile.new_contents.clone()).unwrap();
        assert!(text.contains(HUAWEI));
        assert!(text.contains("PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM"));
    }
}

#[test]
fn macos_profiles_use_native_shasum_and_preserve_project_and_text_layout() {
    for architecture in [Architecture::X86_64, Architecture::Arm64] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        let home = "/Users/developer";
        install_pyenv_at(root, home, "2.8.4", ARCHIVE_SHA, 0);
        fs::remove_file(root.join("usr/bin/sha256sum")).unwrap();
        let original = b"\xef\xbb\xbf# native zsh policy\nexport PYENV_ROOT=\"$HOME/.pyenv\"\nexport PRIVATE_PYTHON_TOKEN='fixture-only'\neval \"$(pyenv init -)\"\n";
        let profile = write(root, "/Users/developer/.zshrc", original);
        let mut permissions = fs::metadata(&profile).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&profile, permissions).unwrap();
        let project = "/Users/developer/project";
        let project_file = write(
            root,
            "/Users/developer/project/.python-version",
            b"private-project-fixture\n",
        );
        let context = native_context(root, OperatingSystem::Macos, architecture);
        let mut runtime = native_runtime(root, home, project, environment("/bin/zsh", None, None));
        let adapter = PyenvAdapter;
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        let evidence = detected.evidence.join("\n");
        assert!(evidence.contains("Macos"));
        assert!(evidence.contains(&format!("{architecture:?}")));
        assert!(evidence.contains(home));
        assert!(evidence.contains("/Users/developer/.pyenv"));
        assert!(evidence.contains(project));
        assert!(!evidence.contains("fixture-only"));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        assert_eq!(request.context.os, OperatingSystem::Macos);
        assert_eq!(request.context.architecture, architecture);
        let selected = selection("tuna", TUNA);
        let cli = adapter.plan(&context, &current, &selected).unwrap();
        let config = adapter.plan(&context, &current, &selected).unwrap();
        let tui = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
        assert_eq!(cli.changes.len(), 2);
        let profile_change = cli
            .changes
            .iter()
            .find(|change| change.target == profile)
            .unwrap();
        assert!(profile_change.new_contents.starts_with(&[0xef, 0xbb, 0xbf]));
        let rendered = String::from_utf8_lossy(&profile_change.new_contents);
        assert!(rendered.contains("fixture-only"));
        assert!(rendered.contains(TUNA));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("native pyenv profile and manifest should change")
        };
        assert!(
            adapter
                .verify(&context, &mut runtime, &receipt)
                .unwrap()
                .valid
        );
        assert_eq!(
            fs::read(&project_file).unwrap(),
            b"private-project-fixture\n"
        );
        assert_eq!(
            fs::metadata(&profile).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !root
                .join("Users/developer/.mirrorswitch/verification/pyenv/Python-3.14.7.tar.xz")
                .exists()
        );
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(
            adapter
                .plan(&context, &current, &selected)
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
        assert_eq!(fs::read(&profile).unwrap(), original);
        assert!(
            !root
                .join("Users/developer/.mirrorswitch/verification/pyenv/release.txt")
                .exists()
        );
    }
}

#[test]
fn windows_and_non_native_macos_contexts_are_inert() {
    let directory = tempdir().unwrap();
    let adapter = PyenvAdapter;
    let runtime = native_runtime(
        directory.path(),
        "/Users/developer",
        "/Users/developer/project",
        BTreeMap::new(),
    );
    let windows = native_context(
        directory.path(),
        OperatingSystem::Windows,
        Architecture::X86_64,
    );
    assert!(
        adapter
            .detect(&windows, &runtime)
            .unwrap_err()
            .to_string()
            .contains("pyenv-win")
    );
    let mut mac_container = native_context(
        directory.path(),
        OperatingSystem::Macos,
        Architecture::Arm64,
    );
    mac_container.environment = ExecutionEnvironment::Container;
    assert!(
        adapter
            .detect(&mac_container, &runtime)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
}

#[test]
fn custom_definition_private_skip_version_and_selection_conflicts_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = PyenvAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    assert!(
        adapter
            .detect(
                &context,
                &test_runtime(root, environment("/bin/bash", None, None))
            )
            .unwrap()
            .is_none()
    );
    install_pyenv(root, "1.2.0", ARCHIVE_SHA, 0);
    assert!(
        adapter
            .detect(
                &context,
                &test_runtime(root, environment("/bin/bash", None, None))
            )
            .is_err()
    );
    install_pyenv(root, "2.8.4", "bad-checksum", 0);
    assert!(
        adapter
            .detect(
                &context,
                &test_runtime(root, environment("/bin/bash", None, None))
            )
            .is_err()
    );
    install_pyenv(root, "2.8.4", ARCHIVE_SHA, 0);
    let mut custom = environment("/bin/bash", None, None);
    custom.insert("PYTHON_BUILD_DEFINITIONS".into(), "/opt/private".into());
    assert!(
        adapter
            .detect(&context, &test_runtime(root, custom))
            .is_err()
    );

    write(root, "/home/developer/.bashrc", b"export PYTHON_BUILD_MIRROR_URL='https://packages.example/python'\nexport PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM=1\n");
    let base = test_runtime(root, environment("/bin/bash", None, None));
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection("nju", NJU))
            .is_err()
    );
    write(
        root,
        "/home/developer/.bashrc",
        b"export PYTHON_BUILD_SKIP_MIRROR=1\n",
    );
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection("nju", NJU))
            .is_err()
    );
    write(root, "/home/developer/.bashrc", b"# clean\n");
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    let mut mismatched = selection("nju", NJU);
    mismatched[0].endpoints[2].url = TUNA.into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
}

#[test]
fn failed_archive_download_restores_profile_and_manifest() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_pyenv(root, "2.8.4", ARCHIVE_SHA, 9);
    let original = b"export EDITOR=nano\n";
    let profile = write(root, "/home/developer/.bashrc", original);
    let adapter = PyenvAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(root, environment("/bin/bash", None, None));
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("nju", NJU))
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("pyenv files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/pyenv/release.txt")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/pyenv/Python-3.14.7.tar.xz")
            .exists()
    );
}

#[test]
fn embedded_catalog_has_three_compatible_and_one_inert_candidate() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "pyenv")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 4);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        complete
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["huaweicloud", "nju", "tuna"])
    );
    for candidate in complete {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [OperatingSystem::Linux, OperatingSystem::Macos]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(
            candidate.compatibility.repository_versions,
            [RELEASE_IDENTITY]
        );
        assert_eq!(candidate.probes.len(), 4);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert_eq!(candidate.probes[1].sha256.as_deref(), Some(SIGNATURE_SHA));
        assert_eq!(candidate.probes[2].method, HttpMethod::Head);
        assert_eq!(candidate.probes[3].sha256.as_deref(), Some(ARCHIVE_SHA));
    }
    let aliyun = candidates
        .iter()
        .find(|candidate| candidate.provider_id == "aliyun")
        .unwrap();
    assert!(aliyun.probes.is_empty());
    assert_ne!(aliyun.delivery_mode, DeliveryMode::Mirror);
}
