#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{CpanAdapter, compiled_adapter_allowlist},
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

const UPSTREAM: &str = "cpan--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/CPAN";
const NJU: &str = "https://mirrors.nju.edu.cn/CPAN";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/CPAN";
const USTC: &str = "https://mirrors.ustc.edu.cn/CPAN";
const TRY_TINY_PATH: &str = "E/ET/ETHER/Try-Tiny-0.32.tar.gz";
const TRY_TINY_SHA: &str = "ef2d6cab0bad18e3ab1c4e6125cc5f695c7e459899f512451c8fa3ef83fa7fc0";

fn test_context(
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

fn install_clients(
    root: &Path,
    cpan_pm: bool,
    cpanm: bool,
    system_config: Option<&str>,
    query_failure: &str,
) {
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
program=$1
shift
exec '{root}/usr/bin/'"$program" "$@"
"#,
            root = root.display(),
        ),
    );
    let cpan_fields = if cpan_pm {
        format!(
            ",\"cpanVersion\":\"2.38\",\"cpanHome\":\"/home/developer/.local/share/.cpan\",\"myConfig\":\"/home/developer/.local/share/.cpan/CPAN/MyConfig.pm\"{}",
            system_config.map_or_else(String::new, |path| {
                format!(",\"systemConfig\":\"{path}\"")
            })
        )
    } else {
        String::new()
    };
    executable(
        root,
        "/usr/bin/perl",
        format!(
            r#"#!/bin/sh
case "$*" in
  *MIRRORSWITCH_CPAN_DISCOVERY_V1*)
    printf '%s\n' '{{"perlVersion":"5.40.2","archname":"x86_64-linux-thread-multi"{cpan_fields}}}'
    exit 0
    ;;
  *MIRRORSWITCH_CPAN_QUERY_V1*)
    printf '%s\n' 'cpan-pm' >> '{root}/client-queries.log'
    [ '{query_failure}' = cpan-pm ] && exit 9
    grep -F 'Try::Tiny' /dev/null >/dev/null 2>&1 || true
    printf '%s\n' 'MIRRORSWITCH_CPAN_FILE={try_tiny}'
    exit 0
    ;;
esac
exit 70
"#,
            root = root.display(),
            try_tiny = TRY_TINY_PATH,
        ),
    );
    if cpanm {
        executable(
            root,
            "/usr/bin/cpanm",
            format!(
                r#"#!/bin/sh
if [ "$1" = --version ]; then
  printf '%s\n' 'cpanm (App::cpanminus) version 1.7049 (/usr/bin/cpanm)'
  exit 0
fi
printf '%s\n' 'cpanm' >> '{root}/client-queries.log'
[ '{query_failure}' = cpanm ] && exit 9
[ "$1" = --info ] && [ "$2" = Try::Tiny ] || exit 71
[ -n "${{PERL_CPANM_HOME:-}}" ] || exit 72
[ -n "${{PERL_CPANM_OPT:-}}" ] || exit 73
case "${{PERL_CPANM_OPT}}" in
  *mirrors.aliyun.com/CPAN*|*mirrors.nju.edu.cn/CPAN*|*mirrors.tuna.tsinghua.edu.cn/CPAN*|*mirrors.ustc.edu.cn/CPAN*) ;;
  *) exit 74 ;;
esac
printf '%s\n' '{try_tiny}'
"#,
                root = root.display(),
                try_tiny = TRY_TINY_PATH,
            ),
        );
    }
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

fn user_config(urls: &[&str], pushy: &str, randomize: &str) -> String {
    format!(
        "\n$CPAN::Config = {{\n  'auto_commit' => q[0],\n  'http_proxy' => q[http://proxy.example:8080],\n  'pushy_https' => q[{pushy}],\n  'randomize_urllist' => q[{randomize}],\n  'urllist' => [{}],\n  'yaml_module' => q[YAML],\n}};\n1;\n__END__\n",
        urls.iter()
            .map(|url| format!("q[{url}]"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn environment(shell: &str, cpanm_options: Option<&str>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([("SHELL".into(), shell.into())]);
    if let Some(options) = cpanm_options {
        values.insert("PERL_CPANM_OPT".into(), options.into());
    }
    values
}

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("cpan-{provider}-test"),
        tool_id: "cpan".into(),
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
fn both_clients_preserve_private_order_project_policy_and_are_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, true, true, None, "");
    let original_config = user_config(
        &[
            "https://darkpan.example/CPAN/",
            "https://www.cpan.org/",
            "file:///srv/minicpan/",
        ],
        "1",
        "1",
    );
    let config = write(
        root,
        "/home/developer/.local/share/.cpan/CPAN/MyConfig.pm",
        original_config.as_bytes(),
    );
    let original_options = "--quiet --mirror https://darkpan.example/CPAN/ --mirror https://www.cpan.org/ --cascade-search";
    let original_profile = format!(
        "# keep shell policy\nexport EDITOR=vim\nexport PERL_CPANM_OPT='{original_options}'\n"
    );
    let profile = write(root, "/home/developer/.bashrc", original_profile.as_bytes());
    let cpanfile = b"requires 'Private::Module', url => 'https://darkpan.example/dist.tar.gz', dist => 'PRIVATE/Private-1.0.tar.gz';\nmirror 'https://darkpan.example/CPAN/';\n";
    let project = write(root, "/work/project/cpanfile", cpanfile);
    let adapter = CpanAdapter;
    let context = test_context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(
        root,
        environment("/bin/bash", Some(original_options)),
        Some("/work/project"),
    );

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("5.40.2"));
    assert!(detected.evidence.iter().any(|line| line == "CPAN.pm 2.38"));
    assert!(detected.evidence.iter().any(|line| line == "cpanm 1.7049"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    let selected = selection("tuna", TUNA);
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config_plan = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config_plan);
    assert_eq!(config_plan, tui);
    assert_eq!(cli.changes.len(), 2);
    assert!(!cli.requires_elevation);

    let cpan_change = cli
        .changes
        .iter()
        .find(|change| change.target.ends_with("CPAN/MyConfig.pm"))
        .unwrap();
    let cpan_text = String::from_utf8(cpan_change.new_contents.clone()).unwrap();
    assert!(cpan_text.contains("'pushy_https' => q[0]"));
    assert!(cpan_text.contains("'randomize_urllist' => q[0]"));
    assert!(cpan_text.contains("http://proxy.example:8080"));
    let private = cpan_text.find("https://darkpan.example/CPAN/").unwrap();
    let selected_position = cpan_text.find(TUNA).unwrap();
    let local = cpan_text.find("file:///srv/minicpan/").unwrap();
    assert!(private < selected_position && selected_position < local);
    assert!(!cpan_text.contains("https://www.cpan.org/"));

    let profile_change = cli
        .changes
        .iter()
        .find(|change| change.target.ends_with(".bashrc"))
        .unwrap();
    let profile_text = String::from_utf8(profile_change.new_contents.clone()).unwrap();
    let expected_options = format!(
        "--quiet --mirror https://darkpan.example/CPAN/ --mirror {TUNA} --cascade-search --mirror-only"
    );
    assert!(profile_text.contains(&expected_options));
    assert!(profile_text.contains("export EDITOR=vim"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("both CPAN client configurations should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&project).unwrap(), cpanfile);
    assert_eq!(
        fs::read_to_string(root.join("client-queries.log")).unwrap(),
        "cpan-pm\ncpanm\n"
    );

    let refreshed = test_runtime(
        root,
        environment("/bin/bash", Some(&expected_options)),
        Some("/work/project"),
    );
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
    assert_eq!(fs::read_to_string(config).unwrap(), original_config);
    assert_eq!(fs::read_to_string(profile).unwrap(), original_profile);
    assert_eq!(fs::read(project).unwrap(), cpanfile);
}

#[test]
fn arm64_copies_initialized_system_config_to_an_unprivileged_user_override() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let system_path = "/usr/share/perl5/CPAN/Config.pm";
    install_clients(root, true, false, Some(system_path), "");
    let system = user_config(&["https://www.cpan.org/"], "1", "1")
        .replace("  'pushy_https' => q[1],\n", "")
        .replace("  'randomize_urllist' => q[1],\n", "");
    let system_file = write(root, system_path, system.as_bytes());
    let adapter = CpanAdapter;
    let context = test_context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("nju", NJU))
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(!plan.requires_elevation);
    assert!(
        plan.changes[0]
            .target
            .ends_with("home/developer/.local/share/.cpan/CPAN/MyConfig.pm")
    );
    assert!(plan.changes[0].old_contents.is_none());
    let user_override = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(user_override.contains("'pushy_https' => q[0]"));
    assert!(user_override.contains("'randomize_urllist' => q[0]"));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("CPAN user override should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read_to_string(&system_file).unwrap(), system);
    assert!(
        adapter
            .restore(&context, &mut runtime, &receipt)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read_to_string(system_file).unwrap(), system);
    assert!(
        !root
            .join("home/developer/.local/share/.cpan/CPAN/MyConfig.pm")
            .exists()
    );
}

#[test]
fn cpanm_only_fish_client_is_configured_without_assuming_cpan_pm() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, true, true, None, "");
    let adapter = CpanAdapter;
    let context = test_context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = test_runtime(root, environment("/usr/bin/fish", None), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "CPAN.pm configuration is uninitialized")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("ustc", USTC))
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    let profile = String::from_utf8(plan.changes[0].new_contents.clone()).unwrap();
    assert!(profile.contains(&format!("set -gx PERL_CPANM_OPT '--from {USTC}'")));
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("cpanm fish profile should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn unsafe_client_policy_is_isolated_and_endpoint_mismatches_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, true, true, None, "");
    let dynamic = b"\n$CPAN::Config = {\n  'urllist' => $ENV{CPAN_URLS},\n};\n1;\n";
    write(
        root,
        "/home/developer/.local/share/.cpan/CPAN/MyConfig.pm",
        dynamic,
    );
    let exclusive = "--from https://darkpan.example/CPAN/";
    write(
        root,
        "/home/developer/.bashrc",
        format!("export PERL_CPANM_OPT='{exclusive}'\n").as_bytes(),
    );
    let adapter = CpanAdapter;
    let context = test_context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let base = test_runtime(root, environment("/bin/bash", Some(exclusive)), None);
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .selection_request(&context, &detected, &current)
            .is_err()
    );

    let safe = user_config(&["https://www.cpan.org/"], "1", "1");
    write(
        root,
        "/home/developer/.local/share/.cpan/CPAN/MyConfig.pm",
        safe.as_bytes(),
    );
    let overridden = test_runtime(
        root,
        environment("/bin/bash", Some("--from https://www.cpan.org/")),
        None,
    );
    let current = adapter
        .read_current(&context, &overridden, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("aliyun", ALIYUN))
        .unwrap();
    assert_eq!(plan.changes.len(), 1);
    assert!(plan.changes[0].target.ends_with("CPAN/MyConfig.pm"));

    let no_shell = test_runtime(root, BTreeMap::new(), None);
    let detected_without_shell = adapter.detect(&context, &no_shell).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &no_shell,
            &detected_without_shell,
            ConfigurationScope::User,
        )
        .unwrap();
    assert_eq!(
        adapter
            .plan(&context, &current, &selection("aliyun", ALIYUN))
            .unwrap()
            .changes
            .len(),
        1
    );

    let mut mismatched = selection("aliyun", ALIYUN);
    mismatched[0].endpoints[2].url = NJU.into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());

    let empty = tempdir().unwrap();
    install_clients(empty.path(), false, false, None, "");
    assert!(
        adapter
            .detect(
                &test_context(
                    empty.path(),
                    Architecture::X86_64,
                    ExecutionEnvironment::Host,
                ),
                &test_runtime(empty.path(), BTreeMap::new(), None),
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn failed_second_client_query_restores_both_original_configurations() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_clients(root, true, true, None, "cpanm");
    let original_config = user_config(&["https://www.cpan.org/"], "1", "1");
    let config = write(
        root,
        "/home/developer/.local/share/.cpan/CPAN/MyConfig.pm",
        original_config.as_bytes(),
    );
    let original_options = "--quiet";
    let original_profile = format!("export PERL_CPANM_OPT='{original_options}'\n");
    let profile = write(root, "/home/developer/.bashrc", original_profile.as_bytes());
    let adapter = CpanAdapter;
    let context = test_context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(root, environment("/bin/bash", Some(original_options)), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("aliyun", ALIYUN))
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("both CPAN configurations should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read_to_string(config).unwrap(), original_config);
    assert_eq!(fs::read_to_string(profile).unwrap(), original_profile);
}

#[test]
fn embedded_catalog_has_four_content_complete_cpan_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog.tools.iter().find(|tool| tool.id == "cpan").unwrap();
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    assert_eq!(tool.composition, CompositionPolicy::Single);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "cpan")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 4);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["aliyun", "nju", "tuna", "ustc"])
    );
    for candidate in candidates {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [OperatingSystem::Linux]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(candidate.probes.len(), 5);
        assert_eq!(candidate.probes[0].method, HttpMethod::Head);
        assert!(
            candidate.probes[1]
                .contains
                .as_deref()
                .is_some_and(|value| value.contains("Try-Tiny"))
        );
        assert_eq!(candidate.probes[2].contains.as_deref(), Some(TRY_TINY_SHA));
        assert_eq!(candidate.probes[3].method, HttpMethod::Head);
        assert_eq!(candidate.probes[4].sha256.as_deref(), Some(TRY_TINY_SHA));
        for role in [
            EndpointRole::Index,
            EndpointRole::Metadata,
            EndpointRole::Artifacts,
        ] {
            assert!(
                candidate
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.role == role)
            );
        }
    }
}
