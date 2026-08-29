#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{BioconductorAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const UPSTREAM: &str = "bioconductor--language-registry";
const NJU: &str = "https://mirrors.nju.edu.cn/bioconductor";
const TUNA: &str = "https://mirrors.tuna.tsinghua.edu.cn/bioconductor";
const BIOC_VERSION_SHA: &str = "7a9fdd2f50e69facc752a8d8aede12cdc872d1fb59fea2355f3b499ace6864f4";
const ANNOTATION_SHA: &str = "7bb5a06b5a8c0c2024f317ed0c58b048550ba9ed6cc64266c4afc03a24ec7d6b";
const EXPERIMENT_SHA: &str = "d61d9759ccb6d48798484a178e8bbc3c02c4bcd70e0c9cfb11b0354566aa3654";

fn context(root: &Path, architecture: Architecture) -> SystemContext {
    SystemContext {
        os: OperatingSystem::Linux,
        architecture,
        environment: ExecutionEnvironment::Container,
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

fn install_r(
    root: &Path,
    r_version: &str,
    biocmanager_version: &str,
    bioc_version: &str,
    mirror: &str,
    verification_exit: i32,
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
    executable(
        root,
        "/usr/bin/sha256sum",
        "#!/bin/sh\nprintf '%064d  %s\\n' 0 \"$1\"\n".into(),
    );
    executable(
        root,
        "/usr/bin/Rscript",
        format!(
            r#"#!/bin/sh
if [ "$1" = -e ]; then
  printf '%s\n' \
    'R_VERSION	{r_version}' \
    'BIOCMANAGER_VERSION	{biocmanager_version}' \
    'BIOC_VERSION	{bioc_version}' \
    'BIOC_MIRROR	{mirror}' \
    'REPOSITORY	BioCsoft	{mirror}/packages/{bioc_version}/bioc' \
    'REPOSITORY	BioCann	{mirror}/packages/{bioc_version}/data/annotation' \
    'REPOSITORY	BioCexp	{mirror}/packages/{bioc_version}/data/experiment' \
    'REPOSITORY	CRAN	https://cran.example/public'
  exit 0
fi
[ -n "${{R_PROFILE_USER:-}}" ] || exit 61
[ "${{R_ENVIRON_USER:-}}" = /dev/null ] || exit 62
[ -n "${{R_LIBS_USER:-}}" ] || exit 63
grep -F 'MirrorSwitch Bioconductor mirror' '{root}'"${{R_PROFILE_USER}}" >/dev/null || exit 64
grep -F 'Managed by MirrorSwitch: Bioconductor verification script' '{root}'"$1" >/dev/null || exit 65
[ {verification_exit} -eq 0 ] || exit {verification_exit}
endpoint=$2
printf '%s\n' \
  "REPOSITORY	BioCsoft	${{endpoint}}/packages/3.23/bioc" \
  "REPOSITORY	BioCann	${{endpoint}}/packages/3.23/data/annotation" \
  "REPOSITORY	BioCexp	${{endpoint}}/packages/3.23/data/experiment" \
  'PACKAGE	BiocVersion	3.23.1	{BIOC_VERSION_SHA}' \
  'PACKAGE	AHCytoBands	0.99.1	{ANNOTATION_SHA}' \
  'PACKAGE	adductData	1.28.0	{EXPERIMENT_SHA}' \
  'BIOC_VERSION	3.23'
"#,
            root = root.display(),
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
        candidate_id: format!("bioconductor-{provider}-test"),
        tool_id: "bioconductor".into(),
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
        latency_ms: 6,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn tuna_selection() -> [MirrorSelection; 1] {
    [selection("tuna", TUNA)]
}

#[test]
fn user_plan_preserves_cran_and_private_repositories_and_is_reversible() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.6.1",
        "1.30.27",
        "3.23",
        "https://bioconductor.org",
        0,
    );
    let original = br#"# keep R policy
options(repos = c(CRAN = "https://cran.example/public", Private = "https://packages.example/r"))
options(BioC_mirror = "https://bioconductor.org")
"#;
    let profile = write(root, "/home/developer/.Rprofile", original);
    let adapter = BioconductorAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, BTreeMap::new(), None);

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("1.30.27"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        current
            .sources
            .iter()
            .all(|source| !source.url.contains("packages.example"))
    );
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.repository_versions[UPSTREAM], "3.23");
    let cli = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let config = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let tui = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    assert_eq!(cli, config);
    assert_eq!(config, tui);
    assert_eq!(cli.changes.len(), 2);
    let changed = String::from_utf8(cli.changes[0].new_contents.clone()).unwrap();
    assert!(changed.contains("CRAN = \"https://cran.example/public\""));
    assert!(changed.contains("Private = \"https://packages.example/r\""));
    assert!(changed.contains(TUNA));
    assert!(!changed.contains("options(BioC_mirror = \"https://bioconductor.org\")"));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
    else {
        panic!("Bioconductor files should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
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
}

#[test]
fn arm64_explicit_user_profile_produces_stable_nju_plan() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.6.0",
        "1.30.12",
        "3.23",
        "https://bioconductor.org",
        0,
    );
    let adapter = BioconductorAdapter;
    let context = context(root, Architecture::Arm64);
    let environment = BTreeMap::from([(
        "R_PROFILE_USER".into(),
        "/home/developer/.config/R/profile".into(),
    )]);
    let mut runtime = runtime(root, environment, None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let selected = [selection("nju", NJU)];
    let first = adapter.plan(&context, &current, &selected).unwrap();
    assert_eq!(first, adapter.plan(&context, &current, &selected).unwrap());
    assert_eq!(first.changes.len(), 2);
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &first).unwrap()
    else {
        panic!("Bioconductor files should be created")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
}

#[test]
fn incompatible_versions_private_dynamic_project_precedence_and_mismatch_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    let adapter = BioconductorAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new(), None))
            .unwrap()
            .is_none()
    );
    for (r, manager, bioc) in [
        ("4.5.2", "1.30.27", "3.22"),
        ("4.6.1", "1.30.11", "3.23"),
        ("4.6.1", "1.30.27", "3.24"),
    ] {
        install_r(root, r, manager, bioc, "https://bioconductor.org", 0);
        assert!(
            adapter
                .detect(&context, &runtime(root, BTreeMap::new(), None))
                .is_err()
        );
    }
    install_r(
        root,
        "4.6.1",
        "1.30.27",
        "3.23",
        "https://packages.example/bioc",
        0,
    );
    write(
        root,
        "/home/developer/.Rprofile",
        b"options(BioC_mirror = 'https://packages.example/bioc')\n",
    );
    let base = runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &base).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    install_r(
        root,
        "4.6.1",
        "1.30.27",
        "3.23",
        "https://bioconductor.org",
        0,
    );
    write(
        root,
        "/home/developer/.Rprofile",
        b"options(BioC_mirror = Sys.getenv('BIOC_MIRROR'))\n",
    );
    assert!(
        adapter
            .read_current(&context, &base, &detected, ConfigurationScope::User)
            .is_err()
    );
    write(root, "/home/developer/.Rprofile", b"# clean\n");
    write(
        root,
        "/work/project/.Rprofile",
        b"options(repos = c(CRAN='private'))\n",
    );
    let project = runtime(root, BTreeMap::new(), Some("/work/project"));
    let detected = adapter.detect(&context, &project).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &project, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &tuna_selection())
            .unwrap_err()
            .to_string()
            .contains("takes precedence")
    );

    let current = adapter
        .read_current(&context, &base, &detected, ConfigurationScope::User)
        .unwrap();
    let mut mismatched = tuna_selection();
    mismatched[0].endpoints[2].url = NJU.into();
    assert!(adapter.plan(&context, &current, &mismatched).is_err());
}

#[test]
fn failed_real_repository_query_restores_profile_and_script() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r(
        root,
        "4.6.1",
        "1.30.27",
        "3.23",
        "https://bioconductor.org",
        9,
    );
    let original = b"options(warn = 1)\n";
    let profile = write(root, "/home/developer/.Rprofile", original);
    let adapter = BioconductorAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new(), None);
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter.plan(&context, &current, &tuna_selection()).unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Bioconductor files should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert_eq!(fs::read(profile).unwrap(), original);
    assert!(
        !root
            .join("home/developer/.mirrorswitch/verification/bioconductor/verify.R")
            .exists()
    );
}

#[test]
fn embedded_catalog_has_two_complete_and_one_inert_inventory_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let candidates = catalog
        .candidates
        .iter()
        .filter(|candidate| candidate.tool_id == "bioconductor")
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 3);
    let complete = candidates
        .iter()
        .filter(|candidate| !candidate.probes.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(complete.len(), 2);
    assert_eq!(
        complete
            .iter()
            .map(|candidate| candidate.provider_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nju", "tuna"])
    );
    for candidate in complete {
        assert_eq!(candidate.delivery_mode, DeliveryMode::Mirror);
        assert_eq!(
            candidate.compatibility.operating_systems,
            [OperatingSystem::Linux]
        );
        assert_eq!(
            candidate.compatibility.architectures,
            [Architecture::X86_64, Architecture::Arm64]
        );
        assert_eq!(candidate.compatibility.repository_versions, ["3.23"]);
        assert_eq!(candidate.probes.len(), 6);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert_eq!(
            candidate.probes[1].sha256.as_deref(),
            Some(BIOC_VERSION_SHA)
        );
        assert_eq!(candidate.probes[3].sha256.as_deref(), Some(ANNOTATION_SHA));
        assert_eq!(candidate.probes[5].sha256.as_deref(), Some(EXPERIMENT_SHA));
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
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.probes.is_empty())
            .count(),
        1
    );
}
