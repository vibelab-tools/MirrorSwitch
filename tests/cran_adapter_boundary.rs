#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{CranAdapter, compiled_adapter_allowlist},
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

const UPSTREAM: &str = "cran--language-registry";
const ALIYUN: &str = "https://mirrors.aliyun.com/CRAN";
const NJU: &str = "https://mirrors.nju.edu.cn/CRAN";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/CRAN";
const USTC: &str = "https://mirrors.ustc.edu.cn/CRAN";
const DESCRIPTION_SHA: &str = "07dcde79e44828236433e7de97be2e49b8f4e689b262160fff1a76b300a71043";
const ARCHIVE_SHA: &str = "8bf048b49b2d17077138fae758bda56bbd53278d9437f2fdeaedf979c90a13c9";

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
            id: "ubuntu".into(),
            version_id: Some("24.04".into()),
            version_codename: Some("noble".into()),
            id_like: vec!["debian".into()],
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

fn install_r(
    root: &Path,
    version: &str,
    platform: &str,
    repositories: &[(&str, &str)],
    query_exit: i32,
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
[ "$1" = Rscript ] || exit 90
shift
exec '{root}/usr/bin/Rscript' "$@"
"#,
            root = root.display(),
        ),
    );
    let repository_lines = repositories
        .iter()
        .enumerate()
        .map(|(index, (name, url))| {
            if *name == "CRAN" {
                format!(
                    "printf 'REPOSITORY\\t{}\\tCRAN\\t%s\\n' \"${{selected:-{url}}}\"",
                    index + 1
                )
            } else {
                format!("printf 'REPOSITORY\\t{}\\t{name}\\t{url}\\n'", index + 1)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    executable(
        root,
        "/usr/bin/Rscript",
        format!(
            r#"#!/bin/sh
if [ "$1" = -e ]; then
  selected=$(sed -n 's/^[[:space:]]*repos\["CRAN"\] <- "\(.*\)"/\1/p' '{root}/home/developer/.Rprofile' 2>/dev/null | tail -n 1)
  printf 'R_VERSION\t{version}\n'
  printf 'R_PLATFORM\t{platform}\n'
  printf 'SITE_PROFILE\t/etc/R/Rprofile.site\tpresent\n'
  printf 'R_PROFILE_USER\t\n'
  printf 'R_REPOSITORIES\tset\n'
  {repository_lines}
  exit 0
fi
[ -n "${{R_PROFILE_USER:-}}" ] || exit 61
[ -n "${{R_LIBS_USER:-}}" ] || exit 62
[ "$2" != "" ] || exit 63
grep -F 'MirrorSwitch CRAN mirror' '{root}'"${{R_PROFILE_USER}}" >/dev/null || exit 64
[ {query_exit} -eq 0 ] || exit {query_exit}
printf 'CRAN\t%s\n' "$2"
printf 'PACKAGE\tdigest\t0.6.39\t{archive_sha}\n'
"#,
            root = root.display(),
            archive_sha = ARCHIVE_SHA,
        ),
    );
    executable(root, "/usr/bin/sha256sum", "#!/bin/sh\nexit 0\n".into());
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

fn selection(provider: &str, endpoint: &str) -> [MirrorSelection; 1] {
    [MirrorSelection {
        candidate_id: format!("cran-{provider}-test"),
        tool_id: "cran".into(),
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
fn user_plan_preserves_named_repositories_bioconductor_ide_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.6.0",
        "x86_64-pc-linux-gnu",
        &[
            ("CRAN", "https://cloud.r-project.org"),
            ("Private", "https://packages.example/r"),
            ("BioCsoft", "https://bioconductor.org/packages/3.23/bioc"),
        ],
        0,
    );
    let original = b"# keep R policy\noptions(repos = c(CRAN = 'https://cloud.r-project.org', Private = 'https://packages.example/r'))\n# >>> MirrorSwitch Bioconductor mirror >>>\noptions(BioC_mirror = 'https://mirrors.nju.edu.cn/bioconductor')\n# <<< MirrorSwitch Bioconductor mirror <<<\n";
    let profile = write(root, "/home/developer/.Rprofile", original);
    let preferences = br#"{
  "cran_mirror": {
    "name": "Global (CDN)",
    "host": "RStudio",
    "url": "https://cran.rstudio.com/",
    "country": "us"
  },
  "save_workspace": "never"
}
"#;
    let preferences_path = write(
        root,
        "/home/developer/.config/rstudio/rstudio-prefs.json",
        preferences,
    );
    let adapter = CranAdapter;
    let context = test_context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(root, BTreeMap::new(), None);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("4.6.0"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "R reports 3 effective repositories")
    );
    assert!(
        detected
            .evidence
            .iter()
            .any(|line| line == "RStudio CRAN mirror preference is present and preserved")
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.required_upstreams, [UPSTREAM]);
    let selected = selection("tuna", TUNA);
    let cli = adapter.plan(&context, &current, &selected).unwrap();
    let config = adapter.plan(&context, &current, &selected).unwrap();
    let tui = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 2);
    assert!(!cli.requires_elevation);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("Private = 'https://packages.example/r'"));
    assert!(changed.contains("MirrorSwitch Bioconductor mirror"));
    assert!(changed.contains("repos[\"CRAN\"]"));
    assert!(changed.contains(TUNA));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("CRAN profile and verification script should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&preferences_path).unwrap(), preferences);
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
    assert_eq!(fs::read(profile).unwrap(), original);
    assert_eq!(fs::read(preferences_path).unwrap(), preferences);
}

#[test]
fn arm64_missing_profile_appends_cran_without_replacing_other_repositories() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.5.2",
        "aarch64-unknown-linux-gnu",
        &[("Private", "file:///srv/r-packages")],
        0,
    );
    let adapter = CranAdapter;
    let context = test_context(root, Architecture::Arm64, ExecutionEnvironment::Container);
    let mut runtime = test_runtime(
        root,
        BTreeMap::from([("R_PROFILE_USER".into(), "~/config/Rprofile".into())]),
        None,
    );
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selected = selection("ustc", USTC);
    let plan = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(plan, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(plan.changes.len(), 2);
    assert!(
        plan.changes
            .iter()
            .any(|change| change.target.ends_with("home/developer/config/Rprofile"))
    );
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("explicit R profile should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn private_duplicate_old_and_project_precedence_policies_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = CranAdapter;
    let context = test_context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    assert!(
        adapter
            .detect(&context, &test_runtime(root, BTreeMap::new(), None))
            .unwrap()
            .is_none()
    );

    install_r(
        root,
        "3.2.5",
        "x86_64-pc-linux-gnu",
        &[("CRAN", "https://cloud.r-project.org")],
        0,
    );
    assert!(
        adapter
            .detect(&context, &test_runtime(root, BTreeMap::new(), None))
            .is_err()
    );

    install_r(
        root,
        "4.6.0",
        "x86_64-pc-linux-gnu",
        &[("CRAN", "https://packages.example/r")],
        0,
    );
    let base = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection("aliyun", ALIYUN))
            .is_err()
    );

    install_r(
        root,
        "4.6.0",
        "x86_64-pc-linux-gnu",
        &[
            ("CRAN", "https://cloud.r-project.org"),
            ("CRAN", "https://cran.rstudio.com"),
        ],
        0,
    );
    assert!(
        adapter
            .detect(&context, &test_runtime(root, BTreeMap::new(), None))
            .is_err()
    );

    install_r(
        root,
        "4.6.0",
        "x86_64-pc-linux-gnu",
        &[("CRAN", "https://cloud.r-project.org")],
        0,
    );
    write(
        root,
        "/work/project/.Rprofile",
        b"source('renv/activate.R')\n",
    );
    let lock = b"{\"R\": {\"Version\": \"4.6.0\"}, \"Repositories\": [{\"Name\": \"CRAN\", \"URL\": \"https://snapshot.example\"}]}\n";
    let lock_path = write(root, "/work/project/renv.lock", lock);
    let project_runtime = test_runtime(root, BTreeMap::new(), Some("/work/project"));
    let detected = adapter.detect(&context, &project_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &project_runtime,
            &detected,
            ConfigurationScope::User,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &selection("nju", NJU))
            .unwrap_err()
            .to_string()
            .contains("project .Rprofile")
    );
    assert_eq!(fs::read(lock_path).unwrap(), lock);
}

#[test]
fn explicit_user_profile_preserves_project_and_renv_files() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.6.0",
        "aarch64-unknown-linux-gnu",
        &[("CRAN", "https://cloud.r-project.org")],
        0,
    );
    let project_profile = b"source('renv/activate.R')\n";
    let project_profile_path = write(root, "/work/project/.Rprofile", project_profile);
    let lock = b"{\"Repositories\": []}\n";
    let lock_path = write(root, "/work/project/renv.lock", lock);
    let adapter = CranAdapter;
    let context = test_context(root, Architecture::Arm64, ExecutionEnvironment::Host);
    let runtime = test_runtime(
        root,
        BTreeMap::from([(
            "R_PROFILE_USER".into(),
            "/home/developer/explicit.Rprofile".into(),
        )]),
        Some("/work/project"),
    );
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("nju", NJU))
        .unwrap();
    assert!(
        plan.changes
            .iter()
            .all(|change| !change.target.starts_with(root.join("work/project")))
    );
    assert_eq!(fs::read(project_profile_path).unwrap(), project_profile);
    assert_eq!(fs::read(lock_path).unwrap(), lock);
}

#[test]
fn failed_real_package_query_restores_profile_and_verification_script() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.6.0",
        "x86_64-pc-linux-gnu",
        &[("CRAN", "https://cloud.r-project.org")],
        9,
    );
    let original = b"options(width = 120)\n";
    let profile = write(root, "/home/developer/.Rprofile", original);
    let adapter = CranAdapter;
    let context = test_context(root, Architecture::X86_64, ExecutionEnvironment::Host);
    let mut runtime = test_runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(&context, &current, &selection("aliyun", ALIYUN))
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("CRAN files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/cran/verify.R")
            .exists()
    );
}

#[test]
fn embedded_catalog_has_four_source_complete_cran_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let tool = catalog.tools.iter().find(|tool| tool.id == "cran").unwrap();
    assert_eq!(tool.supported_scopes, [ConfigurationScope::User]);
    assert_eq!(tool.composition, CompositionPolicy::Single);
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "cran")
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
        assert_eq!(candidate.probes.len(), 4);
        assert_eq!(candidate.probes[0].method, HttpMethod::Head);
        assert_eq!(candidate.probes[1].sha256.as_deref(), Some(DESCRIPTION_SHA));
        assert_eq!(candidate.probes[2].method, HttpMethod::Head);
        assert_eq!(candidate.probes[3].sha256.as_deref(), Some(ARCHIVE_SHA));
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
