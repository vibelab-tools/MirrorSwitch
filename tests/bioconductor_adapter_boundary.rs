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
const WORKFLOW_SHA: &str = "5080e8a12ebe6870f1ca610078c71b8be548d8119f0aff07eb69a91bb7c0a515";
const BOOK_SHA: &str = "b828a9c927a5c4df6cff572f1159322e36e891ac4db932f78453354407b023dc";

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

fn install_r(
    root: &Path,
    r_version: &str,
    biocmanager_version: &str,
    bioc_version: &str,
    mirror: &str,
    verification_exit: i32,
) {
    install_r_for_platform(
        root,
        r_version,
        biocmanager_version,
        bioc_version,
        mirror,
        verification_exit,
        "x86_64-pc-linux-gnu",
        "",
        BIOC_VERSION_SHA,
    );
}

#[allow(clippy::too_many_arguments)]
fn install_r_for_platform(
    root: &Path,
    r_version: &str,
    biocmanager_version: &str,
    bioc_version: &str,
    mirror: &str,
    verification_exit: i32,
    platform: &str,
    r_arch: &str,
    soft_digest: &str,
) {
    for command in ["sha256sum", "shasum", "certutil.exe"] {
        executable(
            root,
            &format!("/usr/bin/{command}"),
            format!(
                r#"#!/bin/sh
case "$*" in
  *BiocVersion*) digest='{soft_digest}' ;;
  *AHCytoBands*) digest='{ANNOTATION_SHA}' ;;
  *adductData*) digest='{EXPERIMENT_SHA}' ;;
  *annotation_1.36.0*) digest='{WORKFLOW_SHA}' ;;
  *BiocBookDemo*) digest='{BOOK_SHA}' ;;
  *) exit 80 ;;
esac
printf '%s  fixture\n' "$digest"
"#,
            ),
        );
    }
    executable(
        root,
        "/usr/bin/Rscript",
        format!(
            r#"#!/bin/sh
if [ "$1" = -e ]; then
	printf '%s\n' \
	    'R_VERSION	{r_version}' \
	    'R_PLATFORM	{platform}' \
	    'R_ARCH	{r_arch}' \
	    'BIOCMANAGER_LIBRARY	/home/developer/R/library' \
    'BIOCMANAGER_VERSION	{biocmanager_version}' \
    'BIOC_VERSION	{bioc_version}' \
    'BIOC_MIRROR	{mirror}' \
    'REPOSITORY	BioCsoft	{mirror}/packages/{bioc_version}/bioc' \
    'REPOSITORY	BioCann	{mirror}/packages/{bioc_version}/data/annotation' \
	    'REPOSITORY	BioCexp	{mirror}/packages/{bioc_version}/data/experiment' \
	    'REPOSITORY	BioCworkflows	{mirror}/packages/{bioc_version}/workflows' \
	    'REPOSITORY	BioCbooks	{mirror}/packages/{bioc_version}/books' \
    'REPOSITORY	CRAN	https://cran.example/public'
  exit 0
fi
[ -n "${{R_PROFILE_USER:-}}" ] || exit 61
	[ -n "${{R_ENVIRON_USER:-}}" ] || exit 62
[ -n "${{R_LIBS_USER:-}}" ] || exit 63
grep -F 'MirrorSwitch Bioconductor mirror' '{root}'"${{R_PROFILE_USER}}" >/dev/null || exit 64
grep -F 'Managed by MirrorSwitch: Bioconductor verification script' '{root}'"$1" >/dev/null || exit 65
[ {verification_exit} -eq 0 ] || exit {verification_exit}
	endpoint=$2
	software_type=$3
	rm -rf "$PWD/downloads"
	mkdir -p "$PWD/downloads"
	if [ "$software_type" = binary ]; then
	  case '{platform}' in *mingw*) soft='BiocVersion_3.23.1.zip' ;; *) soft='BiocVersion_3.23.1.tgz' ;; esac
	else
	  soft='BiocVersion_3.23.1.tar.gz'
	fi
	printf x > "$PWD/downloads/$soft"
	printf x > "$PWD/downloads/AHCytoBands_0.99.1.tar.gz"
	printf x > "$PWD/downloads/adductData_1.28.0.tar.gz"
	printf x > "$PWD/downloads/annotation_1.36.0.tar.gz"
	printf x > "$PWD/downloads/BiocBookDemo_1.10.0.tar.gz"
	printf '%s\n' \
  "REPOSITORY	BioCsoft	${{endpoint}}/packages/3.23/bioc" \
  "REPOSITORY	BioCann	${{endpoint}}/packages/3.23/data/annotation" \
	  "REPOSITORY	BioCexp	${{endpoint}}/packages/3.23/data/experiment" \
	  "REPOSITORY	BioCworkflows	${{endpoint}}/packages/3.23/workflows" \
	  "REPOSITORY	BioCbooks	${{endpoint}}/packages/3.23/books" \
	  "PACKAGE	BiocVersion	3.23.1	${{software_type}}" \
	  'PACKAGE	AHCytoBands	0.99.1	source' \
	  'PACKAGE	adductData	1.28.0	source' \
	  'PACKAGE	annotation	1.36.0	source' \
	  'PACKAGE	BiocBookDemo	1.10.0	source' \
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
fn macos_and_windows_use_native_software_binary_and_data_source_fixtures() {
    for (os, architecture, platform, r_arch, soft_digest, index, original) in [
        (
            OperatingSystem::Macos,
            Architecture::X86_64,
            "x86_64-apple-darwin20",
            "",
            "be92ad13d620fb7e0671c552f3fe5b481b92a0cd08ff3a0b7994c29c35056b7e",
            "packages/3.23/bioc/bin/macosx/big-sur-x86_64/contrib/4.6/PACKAGES",
            b"# macOS policy\noptions(BioC_mirror = 'https://bioconductor.org')\n".as_slice(),
        ),
        (
            OperatingSystem::Macos,
            Architecture::Arm64,
            "aarch64-apple-darwin20",
            "/aarch64",
            "cea69c8e00240f6f6c0aeb8f7123c39f21132df8487d96d98018b6e0ef5f9805",
            "packages/3.23/bioc/bin/macosx/sonoma-arm64/contrib/4.6/PACKAGES",
            b"\xef\xbb\xbf# macOS arm policy\noptions(BioC_mirror = 'https://bioconductor.org')\n".as_slice(),
        ),
        (
            OperatingSystem::Windows,
            Architecture::X86_64,
            "x86_64-w64-mingw32",
            "/x64",
            "e5e5fc60309103fc40dfebf08842c357860ad09139ffcb58b54e3d0ff1e58e0f",
            "packages/3.23/bioc/bin/windows/contrib/4.6/PACKAGES",
            b"\xef\xbb\xbf# Windows policy\r\noptions(BioC_mirror = 'https://bioconductor.org')\r\n".as_slice(),
        ),
    ] {
        let directory = tempdir().unwrap();
        let root = directory.path();
        install_r_for_platform(
            root,
            "4.6.1",
            "1.30.27",
            "3.23",
            "https://bioconductor.org",
            0,
            platform,
            r_arch,
            soft_digest,
        );
        let profile = write(root, "/home/developer/.Rprofile", original);
        let project_contents = b"{\"Bioconductor\": {\"Version\": \"3.23\"}}\n";
        let project = write(root, "/work/project/renv.lock", project_contents);
        let adapter = BioconductorAdapter;
        let context = native_context(root, os, architecture);
        let mut runtime = runtime(root, BTreeMap::new(), Some("/work/project"));
        let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
        assert!(detected.evidence.iter().any(|line| line.contains(&format!("{os:?}"))));
        let current = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        let request = adapter.selection_request(&context, &detected, &current).unwrap();
        assert_eq!(request.probe_contexts[UPSTREAM][0]["bioc_soft_index_path"], index);
        let selected = [selection("nju", NJU)];
        let cli = adapter.plan(&context, &current, &selected).unwrap();
        let config = adapter.plan(&context, &current, &selected).unwrap();
        let tui = adapter.plan(&context, &current, &selected).unwrap();
        assert_eq!(cli, config);
        assert_eq!(config, tui);
        assert_eq!(
            cli.changes[0].new_contents.starts_with(&[0xef, 0xbb, 0xbf]),
            original.starts_with(&[0xef, 0xbb, 0xbf])
        );
        let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli).unwrap()
        else {
            panic!("Bioconductor profile should change")
        };
        assert!(adapter.verify(&context, &mut runtime, &receipt).unwrap().valid);
        let updated = adapter
            .read_current(&context, &runtime, &detected, ConfigurationScope::User)
            .unwrap();
        assert!(adapter.plan(&context, &updated, &selected).unwrap().changes.is_empty());
        assert!(adapter.restore(&context, &mut runtime, &receipt).unwrap().restored);
        assert_eq!(fs::read(profile).unwrap(), original);
        assert_eq!(fs::read(project).unwrap(), project_contents);
    }
}

#[test]
fn arm64_explicit_user_profile_produces_stable_nju_plan() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r_for_platform(
        root,
        "4.6.0",
        "1.30.12",
        "3.23",
        "https://bioconductor.org",
        0,
        "aarch64-unknown-linux-gnu",
        "",
        BIOC_VERSION_SHA,
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
    install_r_for_platform(
        root,
        "4.6.1",
        "1.30.27",
        "3.23",
        "https://bioconductor.org",
        9,
        "aarch64-unknown-linux-gnu",
        "",
        BIOC_VERSION_SHA,
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
fn non_native_platform_and_windows_arm_are_inert() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_r_for_platform(
        root,
        "4.6.1",
        "1.30.27",
        "3.23",
        "https://bioconductor.org",
        0,
        "x86_64-w64-mingw32",
        "/x64",
        "e5e5fc60309103fc40dfebf08842c357860ad09139ffcb58b54e3d0ff1e58e0f",
    );
    let adapter = BioconductorAdapter;
    let macos_container = SystemContext {
        environment: ExecutionEnvironment::Container,
        ..native_context(root, OperatingSystem::Macos, Architecture::Arm64)
    };
    assert!(
        adapter
            .detect(&macos_container, &runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("native host")
    );
    let windows_arm = native_context(root, OperatingSystem::Windows, Architecture::Arm64);
    assert!(
        adapter
            .detect(&windows_arm, &runtime(root, BTreeMap::new(), None))
            .unwrap_err()
            .to_string()
            .contains("no reviewed native Windows arm64 runtime")
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
        assert_eq!(candidate.compatibility.repository_versions, ["3.23"]);
        assert_eq!(candidate.probes.len(), 10);
        assert_eq!(candidate.probes[0].method, HttpMethod::Get);
        assert_eq!(
            candidate.probes[1].sha256.as_deref(),
            Some("{bioc_soft_archive_sha}")
        );
        assert_eq!(candidate.probes[0].path, "/{bioc_soft_index_path}");
        assert_eq!(candidate.probes[1].path, "/{bioc_soft_archive_path}");
        assert_eq!(candidate.probes[1].expected_content_type, None);
        assert_eq!(candidate.probes[3].sha256.as_deref(), Some(ANNOTATION_SHA));
        assert_eq!(candidate.probes[5].sha256.as_deref(), Some(EXPERIMENT_SHA));
        assert_eq!(candidate.probes[7].sha256.as_deref(), Some(WORKFLOW_SHA));
        assert_eq!(candidate.probes[9].sha256.as_deref(), Some(BOOK_SHA));
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
