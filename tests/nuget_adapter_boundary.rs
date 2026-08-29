#![cfg(target_os = "linux")]

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
    grep -q 'repo.huaweicloud.com/repository/nuget/v3/index.json' "$root$config" || exit 71
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
    grep -q 'repo.huaweicloud.com/repository/nuget/v3/index.json' "$root$config" || exit 81
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

fn runtime(root: &Path, project: Option<&str>) -> OsRuntime {
    let runtime = OsRuntime::new(root, vec![PathBuf::from("/usr/bin")])
        .with_home("/home/developer")
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

    let directory = tempdir().unwrap();
    install_dotnet(directory.path(), "8.0.419", 0);
    let installed = runtime(directory.path(), None);
    let mut windows = context(
        directory.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    windows.os = OperatingSystem::Windows;
    assert!(
        adapter
            .detect(&windows, &installed)
            .unwrap_err()
            .to_string()
            .contains("Linux")
    );

    let empty = tempdir().unwrap();
    let runtime = runtime(empty.path(), None);
    let context = context(
        empty.path(),
        Architecture::X86_64,
        ExecutionEnvironment::Host,
    );
    assert!(adapter.detect(&context, &runtime).unwrap().is_none());
}
