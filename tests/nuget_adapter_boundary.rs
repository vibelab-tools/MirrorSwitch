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
    adapters::{NugetAdapter, compiled_adapter_allowlist},
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

const UPSTREAM: &str = "nuget--language-registry";
const INDEX: &str = "https://repo.huaweicloud.com/repository/nuget/v3/";
const REGISTRATION: &str =
    "https://repo.huaweicloud.com/artifactory/api/nuget/v3/nuget-remote/registration-semver2/";
const FLAT: &str = "https://repo.huaweicloud.com/artifactory/api/nuget/v3/nuget-remote/";
const SERVICE_INDEX: &str = "https://repo.huaweicloud.com/repository/nuget/v3/index.json";
const PACKAGE_BODY: &[u8] = b"PKreviewed synthetic NuGet package";
type UnsafeCase<'a> = (&'a [u8], Option<&'a [u8]>, &'a str);

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

fn windows_context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Windows,
        architecture,
        environment: ExecutionEnvironment::Host,
        distribution: Some(Distribution {
            id: "windows".into(),
            version_id: Some("Microsoft Windows [Version 10.0.26100.1]".into()),
            version_codename: None,
            id_like: Vec::new(),
        }),
        root: root.to_path_buf(),
    }
}

fn macos_context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Macos,
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

fn utf16le(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn decode_utf16le(bytes: &[u8]) -> String {
    assert_eq!(&bytes[..2], &[0xff, 0xfe]);
    String::from_utf16(
        &bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn executable(root: &Path, path: &str, contents: String) {
    let path = write(root, path, contents.as_bytes());
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn install_dotnet(root: &Path, version: &str, restore_exit: i32) {
    let physical_root = root.display();
    executable(
        root,
        "/usr/bin/dotnet",
        format!(
            r#"#!/bin/sh
root='{physical_root}'
case "$*" in
  "--version") printf '%s\n' '{version}' ;;
  "nuget list source --format Detailed --configfile "*)
    config=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = config ]; then config=$argument; fi
      if [ "$argument" = --configfile ]; then previous=config; else previous=''; fi
    done
    LC_ALL=C tr -d '\000' < "$root$config" | LC_ALL=C grep -q 'repo.huaweicloud.com/repository/nuget/v3/index.json' || exit 71
    printf '%s\n' 'E  mirrorswitch [https://repo.huaweicloud.com/repository/nuget/v3/index.json]'
    ;;
  "restore "*)
    [ {restore_exit} -eq 0 ] || exit {restore_exit}
    packages=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = packages ]; then packages=$argument; fi
      if [ "$argument" = --packages ]; then previous=packages; else previous=''; fi
    done
    [ -n "$packages" ] || exit 72
    target="$root$packages/nuget.versioning/6.12.1"
    mkdir -p "$target"
    printf '%s' 'PKreviewed synthetic NuGet package' > "$target/nuget.versioning.6.12.1.nupkg"
    printf '%s\n' '{{"source":"https://repo.huaweicloud.com/repository/nuget/v3/index.json","contentHash":"synthetic"}}' > "$target/.nupkg.metadata"
    printf '%s\n' 'Restored NuGet.Versioning 6.12.1 from Huawei.'
    ;;
  *) exit 73 ;;
esac
"#,
        ),
    );
}

fn install_nuget(root: &Path, version: &str, install_exit: i32) {
    let physical_root = root.display();
    executable(
        root,
        "/usr/bin/nuget",
        format!(
            r#"#!/bin/sh
root='{physical_root}'
case "$*" in
  "help") printf '%s\n' 'NuGet Version: {version}' 'usage: NuGet <command>' ;;
  "sources List "*)
    config=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = config ]; then config=$argument; fi
      if [ "$argument" = -ConfigFile ]; then previous=config; else previous=''; fi
    done
    LC_ALL=C tr -d '\000' < "$root$config" | LC_ALL=C grep -q 'repo.huaweicloud.com/repository/nuget/v3/index.json' || exit 81
    printf '%s\n' '1. mirrorswitch [Enabled]' '   https://repo.huaweicloud.com/repository/nuget/v3/index.json'
    ;;
  "install NuGet.Versioning "*)
    [ {install_exit} -eq 0 ] || exit {install_exit}
    output=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = output ]; then output=$argument; fi
      if [ "$argument" = -OutputDirectory ]; then previous=output; else previous=''; fi
    done
    [ -n "$output" ] || exit 82
    target="$root$output/NuGet.Versioning.6.12.1"
    mkdir -p "$target"
    printf '%s' 'PKreviewed synthetic NuGet package' > "$target/NuGet.Versioning.6.12.1.nupkg"
    printf '%s\n' 'Successfully installed NuGet.Versioning 6.12.1 from Huawei.'
    ;;
  *) exit 83 ;;
esac
"#,
        ),
    );
}

fn install_mono(root: &Path, version: &str) {
    executable(
        root,
        "/usr/bin/mono",
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then printf '%s\\n' 'Mono JIT compiler version {version} (native test)'; exit 0; fi\nexit 91\n"
        ),
    );
}

fn runtime(root: &Path, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
        .with_environment(BTreeMap::new());
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn windows_runtime(root: &Path, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/Users/test")
        .with_environment(BTreeMap::from([
            ("APPDATA".into(), "/Users/test/AppData/Roaming".into()),
            ("LOCALAPPDATA".into(), "/Users/test/AppData/Local".into()),
            ("ProgramFiles(x86)".into(), "/ProgramFilesX86".into()),
            ("ProgramData".into(), "/ProgramData".into()),
        ]));
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn macos_runtime(root: &Path, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/Users/developer")
        .with_environment(BTreeMap::new());
    project.map_or(runtime.clone(), |path| runtime.with_project_dir(path))
}

fn selection() -> MirrorSelection {
    MirrorSelection {
        candidate_id: "nuget-test".into(),
        tool_id: "nuget".into(),
        upstream_id: UPSTREAM.into(),
        provider_id: "huaweicloud".into(),
        endpoints: vec![
            Endpoint {
                role: EndpointRole::Index,
                protocol: Protocol::Https,
                url: INDEX.into(),
            },
            Endpoint {
                role: EndpointRole::Metadata,
                protocol: Protocol::Https,
                url: REGISTRATION.into(),
            },
            Endpoint {
                role: EndpointRole::Artifacts,
                protocol: Protocol::Https,
                url: FLAT.into(),
            },
        ],
        latency_ms: 4,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

#[test]
fn dotnet_preserves_hierarchy_private_auth_mapping_disabled_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dotnet(root, "8.0.419", 0);
    write(
        root,
        "/etc/opt/NuGet/Config/10-machine.config",
        br#"<?xml version="1.0"?><configuration><packageSources><add key="machine-private" value="https://machine.corp.example/v3/index.json" /></packageSources></configuration>
"#,
    );
    write(
        root,
        "/home/developer/.nuget/config/20-extra.config",
        br#"<configuration><packageSources><add key="extra-private" value="https://extra.corp.example/v3/index.json" /></packageSources></configuration>
"#,
    );
    let original = br#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <!-- preserve comment and ordering -->
  <packageSources>
    <add key="private" value="https://build:credential@packages.corp.example/v3/index.json" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <disabledPackageSources>
    <add key="private" value="true" />
  </disabledPackageSources>
  <packageSourceCredentials>
    <private><add key="Username" value="build" /><add key="ClearTextPassword" value="secret" /></private>
  </packageSourceCredentials>
  <packageSourceMapping>
    <packageSource key="private"><package pattern="Corp.*" /></packageSource>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
  </packageSourceMapping>
</configuration>
"#;
    let user = write(root, "/home/developer/.nuget/NuGet/NuGet.Config", original);
    let project = write(
        root,
        "/work/NuGet.Config",
        br#"<configuration><packageSources><add key="project-private" value="https://project.corp.example/v3/index.json" /></packageSources></configuration>
"#,
    );
    let lock = write(root, "/work/app/packages.lock.json", b"project-lock\n");
    let adapter = NugetAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, Some("/work/app"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("dotnet=8.0.419"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("1 machine"))
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("1 project"))
    );
    assert!(!format!("{detected:?}").contains("secret"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(!format!("{current:?}").contains("build:credential@"));
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    assert_eq!(request.repository_versions[UPSTREAM], "v3");
    assert_eq!(
        request.required_endpoint_roles,
        [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts
        ]
    );

    let selected = [selection()];
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(cli, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(cli.changes.len(), 3);
    let user_change = cli
        .changes
        .iter()
        .find(|change| change.target == user)
        .unwrap();
    let rendered = String::from_utf8(user_change.new_contents.clone()).unwrap();
    assert!(rendered.contains(SERVICE_INDEX));
    assert!(rendered.contains("https://build:credential@packages.corp.example"));
    assert!(rendered.contains("ClearTextPassword\" value=\"secret"));
    assert!(rendered.contains("packageSource key=\"nuget.org\""));
    assert!(rendered.contains("add key=\"private\" value=\"true\""));
    assert!(rendered.contains("preserve comment and ordering"));
    assert!(!format!("{cli:?}").contains("secret"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("NuGet config should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&project).unwrap(), br#"<configuration><packageSources><add key="project-private" value="https://project.corp.example/v3/index.json" /></packageSources></configuration>
"#);
    assert_eq!(fs::read(&lock).unwrap(), b"project-lock\n");
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
    assert_eq!(fs::read(user).unwrap(), original);
}

#[test]
fn nuget_cli_arm64_container_overrides_inherited_public_source_in_its_own_user_path() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nuget(root, "6.14.0.2", 0);
    write(
        root,
        "/etc/opt/NuGet/Config/official.config",
        br#"<configuration><packageSources><add key="NuGet official package source" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>
"#,
    );
    let adapter = NugetAdapter;
    let context = context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = runtime(root, None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("nuget-cli=6.14.0.2"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    let user = root.join("home/developer/.config/NuGet/NuGet.Config");
    let rendered = plan
        .changes
        .iter()
        .find(|change| change.target == user)
        .unwrap();
    let rendered = String::from_utf8(rendered.new_contents.clone()).unwrap();
    assert!(rendered.contains("key=\"NuGet official package source\""));
    assert!(rendered.contains(SERVICE_INDEX));
    assert!(!plan.requires_elevation);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("NuGet CLI config should change")
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
    assert!(!user.exists());
}

#[test]
fn unsafe_v2_disabled_credentials_mapping_multiple_and_read_only_overrides_are_blocked() {
    let adapter = NugetAdapter;
    let cases: [UnsafeCase<'_>; 8] = [
        (
            br#"<configuration><packageSources><add key="nuget.org" value="https://www.nuget.org/api/v2/" /></packageSources></configuration>"#,
            None,
            "v2",
        ),
        (
            br#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources><disabledPackageSources><add key="nuget.org" value="true" /></disabledPackageSources></configuration>"#,
            None,
            "disabled",
        ),
        (
            br#"<configuration><packageSources><add key="NuGet official package source" value="https://api.nuget.org/v3/index.json" /></packageSources><packageSourceCredentials><NuGet_x0020_official_x0020_package_x0020_source><add key="ClearTextPassword" value="secret" /></NuGet_x0020_official_x0020_package_x0020_source></packageSourceCredentials></configuration>"#,
            None,
            "credentials",
        ),
        (
            br#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources><packageSourceMapping><packageSource key="private"><package pattern="*" /></packageSource></packageSourceMapping></configuration>"#,
            None,
            "packageSourceMapping",
        ),
        (
            br#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /><add key="public-two" value="https://repo.huaweicloud.com/repository/nuget/v3/index.json" /></packageSources></configuration>"#,
            None,
            "multiple public",
        ),
        (
            br#"<configuration><packageSources><add key="private" value="https://packages.corp.example/v3/index.json" /></packageSources></configuration>"#,
            None,
            "only custom",
        ),
        (
            br#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>"#,
            Some(br#"<configuration><packageSources><clear /><add key="private" value="https://project.example/v3/index.json" /></packageSources></configuration>"#),
            "read-only",
        ),
        (
            br#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources><packageSourceMapping><packageSource key="nuget.org"><package pattern="*" /></packageSource></packageSourceMapping></configuration>"#,
            Some(br#"<configuration><packageSourceMapping><clear /><packageSource key="private"><package pattern="*" /></packageSource></packageSourceMapping></configuration>"#),
            "packageSourceMapping",
        ),
    ];
    for (user, project, expected) in cases {
        let directory = tempdir().unwrap();
        install_dotnet(directory.path(), "8.0.419", 0);
        write(
            directory.path(),
            "/home/developer/.nuget/NuGet/NuGet.Config",
            user,
        );
        if let Some(project) = project {
            write(directory.path(), "/work/app/NuGet.Config", project);
        }
        let context = context(
            directory.path(),
            Architecture::X86_64,
            ExecutionEnvironment::Host,
        );
        let runtime = runtime(directory.path(), Some("/work/app"));
        let error = adapter.detect(&context, &runtime).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn failed_real_restore_rolls_back_user_and_managed_verification_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dotnet(root, "8.0.419", 77);
    let original = br#"<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>
"#;
    let user = write(root, "/home/developer/.nuget/NuGet/NuGet.Config", original);
    let adapter = NugetAdapter;
    let context = context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = runtime(root, None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("NuGet config should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(user).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.nuget/mirrorswitch/verification/NuGet.Config")
            .exists()
    );
    assert!(!root.join("home/developer/.nuget/mirrorswitch/verification/MirrorSwitch.NuGet.Verification.csproj").exists());
}

#[derive(Clone)]
struct NugetProtocolProber {
    calls: Rc<RefCell<Vec<(HttpMethod, String)>>>,
    corrupt_package: bool,
}

impl CandidateProber for NugetProtocolProber {
    fn probe(
        &self,
        method: HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push((method, url.into()));
        let (content_type, body) = if url.ends_with(".nupkg") {
            (
                Some("application/octet-stream".into()),
                if self.corrupt_package {
                    b"corrupt".to_vec()
                } else {
                    PACKAGE_BODY.to_vec()
                },
            )
        } else if url.ends_with("/index.json") && url.contains("repository/nuget/v3") {
            (Some("application/json".into()), format!(r#"{{"version":"3.0.0","resources":[{{"@type":"PackageBaseAddress/3.0.0"}},{{"@id":"{REGISTRATION}"}}]}}"#).into_bytes())
        } else if url.contains("registration-semver2") && url.contains("/page/") {
            (
                Some("application/json".into()),
                br#"{"items":[{"catalogEntry":{"id":"NuGet.Versioning","version":"6.12.1"}}]}"#
                    .to_vec(),
            )
        } else if url.contains("registration-semver2") {
            (Some("application/json".into()), br#"{"items":[{"@id":"registration-semver2/nuget.versioning/page/6.0.5/7.9.0.json"}]}"#.to_vec())
        } else {
            (
                Some("application/json".into()),
                br#"{"versions":["6.12.1"]}"#.to_vec(),
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

fn catalog_for_synthetic_package() -> MirrorCatalog {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    for candidate in catalog
        .candidates
        .iter_mut()
        .filter(|candidate| candidate.tool_id == "nuget")
    {
        for probe in &mut candidate.probes {
            if probe.path.ends_with(".nupkg") {
                probe.sha256 = Some(format!("{:x}", Sha256::digest(PACKAGE_BODY)));
            }
        }
    }
    catalog
}

#[test]
fn catalog_requires_service_index_registration_flat_container_and_sha_before_latency() {
    let embedded: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let candidate = embedded
        .candidates
        .iter()
        .find(|candidate| candidate.tool_id == "nuget")
        .unwrap();
    assert_eq!(candidate.provider_id, "huaweicloud");
    assert_eq!(candidate.delivery_mode, DeliveryMode::Proxy);
    assert_eq!(
        candidate.compatibility.operating_systems,
        [
            OperatingSystem::Linux,
            OperatingSystem::Macos,
            OperatingSystem::Windows,
        ]
    );
    assert_eq!(candidate.compatibility.repository_versions, ["v3"]);
    assert_eq!(candidate.probes.len(), 6);
    assert_eq!(
        candidate
            .probes
            .iter()
            .find(|probe| probe.path.ends_with(".nupkg"))
            .unwrap()
            .sha256
            .as_deref(),
        Some("7ff7a30aecc20302ace0de0473ac9fd91a2fae1053d278f48510cffb4dff232e")
    );
    assert!(candidate.probes.iter().any(|probe| {
        probe.endpoint_role == EndpointRole::Metadata && probe.path.contains("nuget.versioning")
    }));

    let catalog = catalog_for_synthetic_package();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    assert_eq!(
        catalog
            .tools
            .iter()
            .find(|tool| tool.id == "nuget")
            .unwrap()
            .state,
        ToolCatalogState::Supported
    );
    let directory = tempdir().unwrap();
    install_dotnet(directory.path(), "8.0.419", 0);
    let adapter = NugetAdapter;
    let context = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let runtime = runtime(directory.path(), None);
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
        NugetProtocolProber {
            calls: calls.clone(),
            corrupt_package: false,
        },
        ProbeLimits::default(),
    )
    .select_at(&request, 100)
    .unwrap();
    assert!(selected.actionable);
    assert_eq!(selected.selections.len(), 1);
    assert_eq!(calls.borrow().len(), 6);
    let rejected = MirrorSelector::with_prober(
        &catalog,
        NugetProtocolProber {
            calls: Rc::new(RefCell::new(Vec::new())),
            corrupt_package: true,
        },
        ProbeLimits::default(),
    )
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

#[test]
fn macos_clients_preserve_distinct_user_machine_project_and_mono_boundaries() {
    for architecture in [Architecture::X86_64, Architecture::Arm64] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_dotnet(root, "8.0.419", 0);
        install_nuget(root, "6.14.0.2", 0);
        install_mono(root, "6.12.0.206");
        let machine = write(
            root,
            "/Library/Application Support/NuGet/Config/enterprise.Config",
            b"<configuration><packageSources><add key=\"enterprise\" value=\"https://packages.corp.example/v3/index.json\" /></packageSources></configuration>\n",
        );
        let additional_dotnet = write(
            root,
            "/Users/developer/.nuget/config/20-extra.Config",
            b"<configuration><packageSources><add key=\"dotnet-extra\" value=\"https://extra.corp.example/v3/index.json\" /></packageSources></configuration>\n",
        );
        let additional_cli = write(
            root,
            "/Users/developer/.config/NuGet/config/20-extra.Config",
            b"<configuration><packageSources><add key=\"mono-extra\" value=\"https://mono.corp.example/v3/index.json\" /></packageSources></configuration>\n",
        );
        let mut dotnet_original = vec![0xef, 0xbb, 0xbf];
        dotnet_original.extend_from_slice(br#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="private" value="https://build:fixture-only@private.example/v3/index.json" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <packageSourceCredentials><private><add key="ClearTextPassword" value="fixture-only" /></private></packageSourceCredentials>
  <packageSourceMapping><packageSource key="private"><package pattern="Corp.*" /></packageSource><packageSource key="nuget.org"><package pattern="*" /></packageSource></packageSourceMapping>
</configuration>
"#);
        let dotnet_user = write(
            root,
            "/Users/developer/.nuget/NuGet/NuGet.Config",
            &dotnet_original,
        );
        let cli_original = br#"<configuration>
  <packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" /></packageSources>
</configuration>
"#;
        let cli_user = write(
            root,
            "/Users/developer/.config/NuGet/NuGet.Config",
            cli_original,
        );
        let project = write(
            root,
            "/Users/developer/project/NuGet.Config",
            b"<configuration><packageSources><add key=\"project-private\" value=\"https://project.corp.example/v3/index.json\" /></packageSources></configuration>\n",
        );
        let lock = write(
            root,
            "/Users/developer/project/packages.lock.json",
            b"project-lock\n",
        );
        let mut permissions = fs::metadata(&dotnet_user).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&dotnet_user, permissions).unwrap();
        let immutable = [
            (machine.clone(), fs::read(&machine).unwrap()),
            (
                additional_dotnet.clone(),
                fs::read(&additional_dotnet).unwrap(),
            ),
            (additional_cli.clone(), fs::read(&additional_cli).unwrap()),
            (project.clone(), fs::read(&project).unwrap()),
            (lock.clone(), fs::read(&lock).unwrap()),
        ];
        let context = macos_context(root, architecture);
        let adapter = NugetAdapter;
        let mut runtime = macos_runtime(root, Some("/Users/developer/project"));
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert_eq!(
            detected.version.as_deref(),
            Some("dotnet=8.0.419;nuget-cli=6.14.0.2;mono=6.12.0.206")
        );
        let evidence = detected.evidence.join("\n");
        assert!(evidence.contains("Macos"));
        assert!(evidence.contains(&format!("{architecture:?}")));
        assert!(evidence.contains("/Users/developer"));
        assert!(evidence.contains("/Users/developer/project"));
        assert!(evidence.contains("native Mono 6.12.0.206"));
        assert!(evidence.contains("1 machine"));
        assert!(!evidence.contains("fixture-only"));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(!format!("{current:?}").contains("fixture-only"));
        let request = adapter
            .selection_request(&context, &detected, &current)
            .unwrap();
        assert_eq!(request.context.os, OperatingSystem::Macos);
        assert_eq!(request.context.architecture, architecture);
        let selected = [selection()];
        let cli = adapter.plan(&context, &current, &selected).unwrap();
        let config = adapter.plan(&context, &current, &selected).unwrap();
        let tui = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
        assert_eq!(cli.changes.len(), 4);
        assert!(
            cli.changes
                .iter()
                .any(|change| change.target == dotnet_user)
        );
        assert!(cli.changes.iter().any(|change| change.target == cli_user));
        let dotnet_rendered = &cli
            .changes
            .iter()
            .find(|change| change.target == dotnet_user)
            .unwrap()
            .new_contents;
        assert!(dotnet_rendered.starts_with(&[0xef, 0xbb, 0xbf]));
        assert!(String::from_utf8_lossy(dotnet_rendered).contains("fixture-only"));
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("macOS NuGet configurations should change")
        };
        assert!(
            adapter
                .verify(&context, &mut runtime, &receipt)
                .unwrap()
                .valid
        );
        for (path, contents) in &immutable {
            assert_eq!(&fs::read(path).unwrap(), contents);
        }
        assert_eq!(
            fs::metadata(&dotnet_user).unwrap().permissions().mode() & 0o777,
            0o600
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
        assert_eq!(fs::read(&dotnet_user).unwrap(), dotnet_original);
        assert_eq!(fs::read(&cli_user).unwrap(), cli_original);
        for (path, contents) in &immutable {
            assert_eq!(&fs::read(path).unwrap(), contents);
        }
        assert!(
            !root
                .join("Users/developer/.nuget/mirrorswitch/verification/NuGet.Config")
                .exists()
        );
    }
}

#[test]
fn macos_requires_native_host_and_mono_for_nuget_cli() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_nuget(root, "6.14.0.2", 0);
    let adapter = NugetAdapter;
    let runtime = macos_runtime(root, None);
    let context = macos_context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime)
            .unwrap_err()
            .to_string()
            .contains("Mono")
    );
    install_mono(root, "4.2.0");
    assert!(
        adapter
            .detect(&context, &runtime)
            .unwrap_err()
            .to_string()
            .contains("4.4.2")
    );
    let mut container = context;
    container.environment = ExecutionEnvironment::Container;
    assert!(
        adapter
            .detect(&container, &runtime)
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
}

#[test]
fn windows_clients_share_one_user_config_and_preserve_machine_and_project_policy() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_dotnet(root, "10.0.100", 0);
    install_nuget(root, "7.0.0", 0);
    let machine = write(
        root,
        "/ProgramFilesX86/NuGet/Config/VisualStudio.Offline.config",
        b"<configuration><packageSources><add key=\"vs-offline\" value=\"C:\\Program Files (x86)\\Microsoft SDKs\\NuGetPackages\\\" /></packageSources></configuration>\r\n",
    );
    let program_data = write(
        root,
        "/ProgramData/NuGet/Config/enterprise.config",
        b"<configuration><packageSources><add key=\"enterprise\" value=\"https://packages.corp.example/v3/index.json\" /></packageSources></configuration>\r\n",
    );
    let additional = write(
        root,
        "/Users/test/AppData/Roaming/NuGet/config/20-extra.Config",
        b"<configuration><packageSources><add key=\"additional\" value=\"https://additional.corp.example/v3/index.json\" /></packageSources></configuration>\r\n",
    );
    let original = utf16le(concat!(
        "<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n",
        "<configuration>\r\n",
        "  <!-- preserve Windows CRLF and source order -->\r\n",
        "  <packageSources>\r\n",
        "    <add key=\"private\" value=\"https://build:credential@private.example/v3/index.json\" />\r\n",
        "    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" protocolVersion=\"3\" />\r\n",
        "  </packageSources>\r\n",
        "  <disabledPackageSources><add key=\"private\" value=\"true\" /></disabledPackageSources>\r\n",
        "  <packageSourceCredentials><private><add key=\"Username\" value=\"build\" /><add key=\"ClearTextPassword\" value=\"secret\" /></private></packageSourceCredentials>\r\n",
        "  <packageSourceMapping>\r\n",
        "    <packageSource key=\"private\"><package pattern=\"Corp.*\" /></packageSource>\r\n",
        "    <packageSource key=\"nuget.org\"><package pattern=\"*\" /></packageSource>\r\n",
        "  </packageSourceMapping>\r\n",
        "</configuration>\r\n",
    ));
    let user = write(
        root,
        "/Users/test/AppData/Roaming/NuGet/NuGet.Config",
        &original,
    );
    let project = write(
        root,
        "/work/NuGet.Config",
        b"<configuration><packageSources><add key=\"project-private\" value=\"https://project.corp.example/v3/index.json\" /></packageSources></configuration>\r\n",
    );
    let immutable = [
        (machine.clone(), fs::read(&machine).unwrap()),
        (program_data.clone(), fs::read(&program_data).unwrap()),
        (additional.clone(), fs::read(&additional).unwrap()),
        (project.clone(), fs::read(&project).unwrap()),
    ];
    let context = windows_context(root, Architecture::Arm64);
    let adapter = NugetAdapter;
    let mut runtime = windows_runtime(root, Some("/work/app"));

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(
        detected.version.as_deref(),
        Some("dotnet=10.0.100;nuget-cli=7.0.0")
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line.contains("2 machine"))
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert_eq!(
        current
            .documents
            .iter()
            .filter(|document| document.format.starts_with("nuget-user-"))
            .count(),
        1
    );
    assert_eq!(
        current
            .sources
            .iter()
            .filter(|source| {
                source
                    .metadata
                    .get("kind")
                    .is_some_and(|values| values == &["nuget-client"])
            })
            .count(),
        2
    );
    assert!(!format!("{current:?}").contains("build:credential@"));
    let plan = adapter.plan(&context, &current, &[selection()]).unwrap();
    assert_eq!(
        plan.changes
            .iter()
            .filter(|change| change.target == user)
            .count(),
        1
    );
    assert_eq!(plan.changes.len(), 3);
    let rendered = decode_utf16le(
        &plan
            .changes
            .iter()
            .find(|change| change.target == user)
            .unwrap()
            .new_contents,
    );
    assert!(rendered.contains(SERVICE_INDEX));
    assert!(!rendered.replace("\r\n", "").contains('\n'));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Windows NuGet plan should apply once per shared config")
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
            .plan(&context, &updated, &[selection()])
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
    assert_eq!(fs::read(&user).unwrap(), original);
    for (path, contents) in immutable {
        assert_eq!(fs::read(path).unwrap(), contents);
    }
}

#[test]
fn unsupported_platform_versions_and_missing_clients_are_inert() {
    let adapter = NugetAdapter;
    let directory = tempdir().unwrap();
    install_dotnet(directory.path(), "11.0.100", 0);
    let linux = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    let installed = runtime(directory.path(), None);
    assert!(
        adapter
            .detect(&linux, &installed)
            .unwrap_err()
            .to_string()
            .contains("6.x through 10.x")
    );

    let directory = tempdir().unwrap();
    install_nuget(directory.path(), "5.11.6", 0);
    let installed = runtime(directory.path(), None);
    let linux = context(
        directory.path(),
        Architecture::Arm64,
        ExecutionEnvironment::Container,
    );
    let error = adapter.detect(&linux, &installed).unwrap_err();
    assert!(error.to_string().contains("6.x/7.x"), "{error}");

    let empty = tempdir().unwrap();
    let runtime = runtime(empty.path(), None);
    let context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(adapter.detect(&context, &runtime).unwrap().is_none());
}
