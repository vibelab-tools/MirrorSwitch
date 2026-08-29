#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mirrorswitch::{
    Adapter, MirrorCatalog,
    adapters::{GradleAdapter, compiled_adapter_allowlist},
    catalog::{ConfigurationScope, DeliveryMode, Endpoint, EndpointRole, HttpMethod, Protocol},
    catalog_update::EMBEDDED_CATALOG,
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    detection::OsRuntime,
    plan::MirrorSelection,
    transaction::ApplyOutcome,
};
use tempfile::tempdir;

const MAVEN_UPSTREAM: &str = "maven--language-registry";
const DISTRIBUTION_UPSTREAM: &str = "gradle-distributions--release-artifacts";
const HUAWEI_MAVEN: &str = "https://repo.huaweicloud.com/repository/maven/";
const NJU_GRADLE: &str = "https://mirrors.nju.edu.cn/gradle/";
const CHECKSUM: &str = "8d97a97984f6cbd2b85fe4c60a743440a347544bf18818048e611f5288d46c94";

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

fn install_gradle(
    root: &Path,
    command: &str,
    version: &str,
    selected_file: &str,
    selected_endpoint: &str,
    query_exit: i32,
) {
    let selected_file = root.join(selected_file.trim_start_matches('/'));
    executable(
        root,
        command,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  printf '\\nGradle {version}\\n\\nLauncher JVM: 21.0.9 (Test JDK)\\n'\n  exit 0\nfi\ncase \"$*\" in\n  *mirrorSwitchVerify*)\n    grep -F '{selected_endpoint}' '{selected_file}' >/dev/null || exit 65\n    [ {query_exit} -eq 0 ] || exit {query_exit}\n    printf 'MIRRORSWITCH_GRADLE_OK commons-lang3-3.14.0.jar {selected_endpoint}\\n'\n    exit 0\n    ;;\nesac\nexit 64\n",
            selected_file = selected_file.display(),
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

fn maven_selection(index: &str, artifact: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "gradle-maven-test".into(),
        tool_id: "gradle".into(),
        upstream_id: MAVEN_UPSTREAM.into(),
        provider_id: "huaweicloud".into(),
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
        latency_ms: 5,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn distribution_selection(endpoint: &str) -> MirrorSelection {
    MirrorSelection {
        candidate_id: "gradle-distribution-test".into(),
        tool_id: "gradle".into(),
        upstream_id: DISTRIBUTION_UPSTREAM.into(),
        provider_id: "nju".into(),
        endpoints: vec![Endpoint {
            role: EndpointRole::Releases,
            protocol: Protocol::Https,
            url: endpoint.into(),
        }],
        latency_ms: 7,
        selected_at_unix_ms: 123,
        user_override: false,
    }
}

fn wrapper_properties(url: &str, checksum: Option<&str>) -> Vec<u8> {
    format!(
        "# wrapper policy\ndistributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\ndistributionUrl={}\nnetworkTimeout=10000\nvalidateDistributionUrl=true\n{}zipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n",
        url.replace(':', "\\:"),
        checksum
            .map(|value| format!("distributionSha256Sum={value}\n"))
            .unwrap_or_default(),
    )
    .into_bytes()
}

#[test]
fn user_init_plan_preserves_project_repositories_filters_and_other_init_scripts() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_gradle(
        root,
        "/usr/bin/gradle",
        "9.7.1",
        "/home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle",
        HUAWEI_MAVEN,
        0,
    );
    let root_init = write(
        root,
        "/home/developer/.gradle/init.gradle",
        b"// keep root init\n",
    );
    let corporate_init = write(
        root,
        "/home/developer/.gradle/init.d/20-corporate.init.gradle",
        b"allprojects { repositories { maven { url = 'https://corp.example/maven' } } }\n",
    );
    let settings_contents = b"pluginManagement { repositories { gradlePluginPortal() } }\n\ndependencyResolutionManagement {\n  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n  repositories {\n    exclusiveContent {\n      forRepository { maven { url = uri(\"https://private.example/maven\") } }\n      filter { includeGroup(\"internal\") }\n    }\n    mavenCentral { content { excludeGroup(\"internal\") } }\n  }\n}\n";
    let settings = write(root, "/work/project/settings.gradle.kts", settings_contents);
    let build_contents = b"plugins { java }\nrepositories { mavenCentral() }\ndependencies { implementation(\"org.apache.commons:commons-lang3:3.14.0\") }\n";
    let build = write(root, "/work/project/build.gradle.kts", build_contents);
    write(
        root,
        "/work/project/gradle/wrapper/gradle-wrapper.properties",
        &wrapper_properties(
            "https://services.gradle.org/distributions/gradle-9.7.1-bin.zip",
            Some(CHECKSUM),
        ),
    );
    let adapter = GradleAdapter;
    let context = context(root, Architecture::X86_64);
    let mut runtime = runtime(root, BTreeMap::new());

    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("Gradle 9.7.1"));
    assert!(
        detected
            .evidence
            .iter()
            .any(|value| value.contains("Launcher JVM"))
    );
    assert_eq!(adapter.default_scope(), ConfigurationScope::User);
    assert_eq!(
        adapter.supported_scopes(),
        [ConfigurationScope::User, ConfigurationScope::Project]
    );
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    for kind in [
        "project-repositories",
        "content-filter",
        "exclusive-content",
        "plugin-management",
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

    let chosen = [maven_selection(HUAWEI_MAVEN, HUAWEI_MAVEN)];
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert_eq!(cli_plan.scope, ConfigurationScope::User);
    assert_eq!(cli_plan.changes.len(), 2);
    assert!(!cli_plan.requires_elevation);
    assert!(
        cli_plan.changes[0]
            .target
            .ends_with("home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle")
    );
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(rendered.contains(HUAWEI_MAVEN));
    assert!(rendered.contains("repository.setUrl(mirrorSwitchEndpoint)"));
    assert!(!rendered.contains("private.example"));
    assert!(cli_plan.changes.iter().any(|change| {
        change
            .target
            .ends_with("home/developer/.gradle/mirrorswitch/verification/settings.gradle")
    }));

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("Gradle user init should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    assert_eq!(fs::read(&root_init).unwrap(), b"// keep root init\n");
    assert_eq!(
        fs::read(&corporate_init).unwrap(),
        b"allprojects { repositories { maven { url = 'https://corp.example/maven' } } }\n"
    );
    assert_eq!(fs::read(&settings).unwrap(), settings_contents);
    assert_eq!(fs::read(&build).unwrap(), build_contents);
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
    assert!(
        !root
            .join("home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle")
            .exists()
    );
    assert!(
        !root
            .join("home/developer/.gradle/mirrorswitch/verification/settings.gradle")
            .exists()
    );
}

#[test]
fn arm64_project_wrapper_plan_preserves_version_checksum_and_properties() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_gradle(
        root,
        "/work/project/gradlew",
        "8.12.1",
        "/work/project/gradle/wrapper/gradle-wrapper.properties",
        NJU_GRADLE,
        0,
    );
    let original = wrapper_properties(
        "https://services.gradle.org/distributions/gradle-8.12.1-bin.zip",
        Some(CHECKSUM),
    );
    let wrapper = write(
        root,
        "/work/project/gradle/wrapper/gradle-wrapper.properties",
        &original,
    );
    let build_contents =
        b"repositories { mavenCentral(); maven { url = uri('https://private.example/maven') } }\n";
    let build = write(root, "/work/project/build.gradle", build_contents);
    let adapter = GradleAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    assert_eq!(detected.version.as_deref(), Some("Gradle 8.12.1"));
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
        .unwrap();
    let request = adapter
        .selection_request(&context, &detected, &current)
        .unwrap();
    assert_eq!(request.context.architecture, Architecture::Arm64);
    assert_eq!(request.required_upstreams, [DISTRIBUTION_UPSTREAM]);
    assert_eq!(request.required_endpoint_roles, [EndpointRole::Releases]);
    assert_eq!(
        request.probe_contexts[DISTRIBUTION_UPSTREAM][0]["distribution_file"],
        "gradle-8.12.1-bin.zip"
    );
    assert_eq!(
        request.probe_contexts[DISTRIBUTION_UPSTREAM][0]["distribution_checksum"],
        CHECKSUM
    );
    let chosen = [distribution_selection(NJU_GRADLE)];
    let cli_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let config_plan = adapter.plan(&context, &current, &chosen).unwrap();
    let tui_plan = adapter.plan(&context, &current, &chosen).unwrap();
    assert_eq!(cli_plan, config_plan);
    assert_eq!(config_plan, tui_plan);
    assert_eq!(cli_plan.scope, ConfigurationScope::Project);
    assert!(
        cli_plan.changes[0]
            .target
            .ends_with("work/project/gradle/wrapper/gradle-wrapper.properties")
    );
    let rendered = String::from_utf8(cli_plan.changes[0].new_contents.clone()).unwrap();
    assert!(
        rendered
            .contains("distributionUrl=https\\://mirrors.nju.edu.cn/gradle/gradle-8.12.1-bin.zip")
    );
    assert!(rendered.contains(&format!("distributionSha256Sum={CHECKSUM}")));
    assert!(rendered.contains("networkTimeout=10000"));
    assert_eq!(fs::read(&build).unwrap(), build_contents);

    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &cli_plan).unwrap()
    else {
        panic!("Gradle wrapper should change")
    };
    assert!(
        adapter
            .verify(&context, &mut runtime, &receipt)
            .unwrap()
            .valid
    );
    let updated = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::Project)
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
    assert_eq!(fs::read(wrapper).unwrap(), original);
}

#[test]
fn failed_dependency_resolution_restores_the_user_init_script() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    install_gradle(
        root,
        "/usr/bin/gradle",
        "8.12.1",
        "/home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle",
        HUAWEI_MAVEN,
        9,
    );
    write(
        root,
        "/work/project/settings.gradle",
        b"rootProject.name='probe'\n",
    );
    let adapter = GradleAdapter;
    let context = context(root, Architecture::Arm64);
    let mut runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &runtime).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &runtime, &detected, ConfigurationScope::User)
        .unwrap();
    let plan = adapter
        .plan(
            &context,
            &current,
            &[maven_selection(HUAWEI_MAVEN, HUAWEI_MAVEN)],
        )
        .unwrap();
    let ApplyOutcome::Applied(receipt) = adapter.apply(&context, &mut runtime, &plan).unwrap()
    else {
        panic!("Gradle user init should change")
    };
    let error = adapter
        .verify(&context, &mut runtime, &receipt)
        .unwrap_err();
    assert!(error.to_string().contains("configuration restored: true"));
    assert!(
        !root
            .join("home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle")
            .exists()
    );
}

#[test]
fn unsupported_versions_conflicts_credentials_and_endpoint_mismatches_are_rejected() {
    let directory = tempdir().unwrap();
    let root = directory.path();
    executable(root, "/usr/bin/java", "#!/bin/sh\nexit 0\n".into());
    let adapter = GradleAdapter;
    let context = context(root, Architecture::X86_64);
    assert!(
        adapter
            .detect(&context, &runtime(root, BTreeMap::new()))
            .unwrap()
            .is_none()
    );
    for version in ["7.5.1", "10.0.0"] {
        install_gradle(
            root,
            "/usr/bin/gradle",
            version,
            "/home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle",
            HUAWEI_MAVEN,
            0,
        );
        let error = adapter
            .detect(&context, &runtime(root, BTreeMap::new()))
            .unwrap_err();
        assert!(
            error.to_string().contains("outside the reviewed"),
            "{error}"
        );
    }
    install_gradle(
        root,
        "/usr/bin/gradle",
        "9.7.1",
        "/home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle",
        HUAWEI_MAVEN,
        0,
    );
    write(
        root,
        "/work/project/settings.gradle",
        b"rootProject.name='probe'\n",
    );
    let base_runtime = runtime(root, BTreeMap::new());
    let detected = adapter.detect(&context, &base_runtime).unwrap().unwrap();
    write(
        root,
        "/home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle",
        b"// user-owned file\n",
    );
    let current = adapter
        .read_current(&context, &base_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &[maven_selection(HUAWEI_MAVEN, HUAWEI_MAVEN)]
            )
            .unwrap_err()
            .to_string()
            .contains("without the MirrorSwitch marker")
    );

    fs::remove_file(root.join("home/developer/.gradle/init.d/zz-mirrorswitch.init.gradle"))
        .unwrap();
    write(
        root,
        "/home/developer/.gradle/mirrorswitch/verification/settings.gradle",
        b"rootProject.name = 'user-owned'\n",
    );
    let current = adapter
        .read_current(&context, &base_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &[maven_selection(HUAWEI_MAVEN, HUAWEI_MAVEN)]
            )
            .unwrap_err()
            .to_string()
            .contains("verification project target")
    );

    fs::remove_file(root.join("home/developer/.gradle/mirrorswitch/verification/settings.gradle"))
        .unwrap();
    let overridden = runtime(
        root,
        BTreeMap::from([(
            "GRADLE_OPTS".into(),
            "-Dgradle.user.home=/custom/home".into(),
        )]),
    );
    let detected = adapter.detect(&context, &overridden).unwrap().unwrap();
    let current = adapter
        .read_current(&context, &overridden, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(
        adapter
            .plan(
                &context,
                &current,
                &[maven_selection(HUAWEI_MAVEN, HUAWEI_MAVEN)]
            )
            .is_err()
    );

    let mut mismatched = maven_selection(HUAWEI_MAVEN, "https://repo.nju.edu.cn/maven/");
    mismatched.provider_id = "mixed".into();
    let current = adapter
        .read_current(&context, &base_runtime, &detected, ConfigurationScope::User)
        .unwrap();
    assert!(adapter.plan(&context, &current, &[mismatched]).is_err());

    let wrapper_path = "/work/project/gradle/wrapper/gradle-wrapper.properties";
    write(
        root,
        wrapper_path,
        &wrapper_properties(
            "https://services.gradle.org/distributions/gradle-9.7.1-bin.zip",
            None,
        ),
    );
    assert!(
        adapter
            .read_current(
                &context,
                &base_runtime,
                &detected,
                ConfigurationScope::Project,
            )
            .unwrap_err()
            .to_string()
            .contains("executable gradlew")
    );
    install_gradle(
        root,
        "/work/project/gradlew",
        "9.7.1",
        wrapper_path,
        NJU_GRADLE,
        0,
    );
    let detected = adapter.detect(&context, &base_runtime).unwrap().unwrap();
    let current = adapter
        .read_current(
            &context,
            &base_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(
        adapter
            .selection_request(&context, &detected, &current)
            .unwrap_err()
            .to_string()
            .contains("distributionSha256Sum")
    );

    write(
        root,
        wrapper_path,
        &wrapper_properties(
            "https://private.example/gradle-9.7.1-bin.zip",
            Some(CHECKSUM),
        ),
    );
    let current = adapter
        .read_current(
            &context,
            &base_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(
        adapter
            .plan(&context, &current, &[distribution_selection(NJU_GRADLE)])
            .unwrap_err()
            .to_string()
            .contains("private or unmapped")
    );

    write(
        root,
        wrapper_path,
        &wrapper_properties(
            "https://services.gradle.org/distributions/gradle-9.7.1-bin.zip",
            Some(CHECKSUM),
        ),
    );
    write(
        root,
        "/home/developer/.gradle/gradle.properties",
        b"systemProp.gradle.wrapperUser=reader\nsystemProp.gradle.wrapperPassword=secret\n",
    );
    let current = adapter
        .read_current(
            &context,
            &base_runtime,
            &detected,
            ConfigurationScope::Project,
        )
        .unwrap();
    assert!(!serde_json::to_string(&current).unwrap().contains("secret"));
    assert!(
        adapter
            .plan(&context, &current, &[distribution_selection(NJU_GRADLE)])
            .unwrap_err()
            .to_string()
            .contains("credentials")
    );

    write(
        root,
        "/home/developer/.gradle/gradle.properties",
        b"systemProp.gradle.wrapperUser=reader\nsystemProp.gradle.wrapperUser=duplicate\n",
    );
    assert!(
        adapter
            .read_current(
                &context,
                &base_runtime,
                &detected,
                ConfigurationScope::Project,
            )
            .unwrap_err()
            .to_string()
            .contains("more than once")
    );
}

#[test]
fn embedded_catalog_separates_maven_and_distribution_candidates() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    let maven = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "gradle"
                && candidate.upstream_id == MAVEN_UPSTREAM
                && !candidate.probes.is_empty()
        })
        .collect::<Vec<_>>();
    assert_eq!(maven.len(), 3);
    assert!(maven.iter().all(|candidate| {
        candidate.compatibility.operating_systems == [OperatingSystem::Linux]
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.delivery_mode == DeliveryMode::Proxy
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Index)
            && candidate
                .endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Artifacts)
            && candidate.probes.len() == 2
            && candidate.probes[0].method == HttpMethod::Get
            && candidate.probes[0]
                .path
                .ends_with("commons-lang3-3.14.0.pom")
            && candidate.probes[1].method == HttpMethod::Head
            && candidate.probes[1]
                .path
                .ends_with("commons-lang3-3.14.0.jar")
    }));

    let distributions = catalog
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.tool_id == "gradle"
                && candidate.upstream_id == DISTRIBUTION_UPSTREAM
                && !candidate.probes.is_empty()
        })
        .collect::<Vec<_>>();
    assert_eq!(distributions.len(), 2);
    assert!(distributions.iter().all(|candidate| {
        candidate.provider_id == "huaweicloud" || candidate.provider_id == "nju"
    }));
    assert!(distributions.iter().all(|candidate| {
        candidate.delivery_mode == DeliveryMode::Mirror
            && candidate.compatibility.architectures == [Architecture::X86_64, Architecture::Arm64]
            && candidate.endpoints.len() == 1
            && candidate.endpoints[0].role == EndpointRole::Releases
            && candidate.probes.len() == 2
            && candidate.probes[0].path == "/{distribution_file}.sha256"
            && candidate.probes[0].contains.as_deref() == Some("{distribution_checksum}")
            && candidate.probes[1].method == HttpMethod::Head
            && candidate.probes[1].path == "/{distribution_file}"
    }));
    assert!(catalog.candidates.iter().any(|candidate| {
        candidate.tool_id == "gradle"
            && candidate.provider_id == "aliyun"
            && candidate.upstream_id == DISTRIBUTION_UPSTREAM
            && candidate.probes.is_empty()
    }));
    assert!(catalog.candidates.iter().any(|candidate| {
        candidate.tool_id == "gradle"
            && candidate.provider_id == "sjtug"
            && candidate.upstream_id == DISTRIBUTION_UPSTREAM
            && candidate.probes.is_empty()
    }));
}
