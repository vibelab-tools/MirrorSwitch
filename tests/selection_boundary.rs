use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    rc::Rc,
    thread,
    time::Duration,
};

use mirrorswitch::{
    MirrorCatalog,
    catalog::{CandidateEvaluation, CompositionPolicy, DeliveryMode, EndpointRole, Protocol},
    context::{Architecture, Distribution, ExecutionEnvironment, OperatingSystem, SystemContext},
    selection::{
        CandidateProber, CompatibilityDimension, HttpCandidateProber, MirrorSelector, ProbeError,
        ProbeLimits, ProbeObservation, SelectionError, SelectionRequest,
    },
};
use serde_json::{Value, json};

fn candidate(
    id: &str,
    provider_id: &str,
    tool_id: &str,
    upstream_id: &str,
    endpoint: &str,
) -> Value {
    json!({
        "id": id,
        "provider_id": provider_id,
        "upstream_id": upstream_id,
        "tool_id": tool_id,
        "catalog_state": "cataloged",
        "delivery_mode": "mirror",
        "raw_names": [upstream_id],
        "endpoints": [{
            "role": "index",
            "protocol": "https",
            "url": endpoint
        }],
        "compatibility": {
            "operating_systems": ["linux"],
            "architectures": ["x86_64"],
            "environments": ["host"],
            "distributions": [{
                "id": "ubuntu",
                "versions": ["24.04"],
                "codenames": ["noble"]
            }],
            "tool_version": "24.0",
            "repository_versions": ["1"]
        },
        "probes": [{
            "endpoint_role": "index",
            "method": "get",
            "path": "/simple/{package}/",
            "expected_status": [200],
            "expected_content_type": "text/html",
            "contains": "pip-release"
        }],
        "source_urls": ["https://source.invalid"],
        "observed_at": "2026-08-28T00:00:00Z"
    })
}

fn catalog() -> MirrorCatalog {
    let mut arm = candidate(
        "arm",
        "arm-provider",
        "pip",
        "pypi--language-registry",
        "https://arm.invalid/pypi/",
    );
    arm["compatibility"]["architectures"] = json!(["arm64"]);
    let mut partial = candidate(
        "partial",
        "partial-provider",
        "pip",
        "pypi--language-registry",
        "https://partial.invalid/pypi/",
    );
    partial["catalog_state"] = json!("partial");
    let candidates = vec![
        candidate(
            "tie",
            "a-provider",
            "pip",
            "pypi--language-registry",
            "https://tie.invalid/pypi/",
        ),
        candidate(
            "fast",
            "b-provider",
            "pip",
            "pypi--language-registry",
            "https://fast.invalid/pypi/",
        ),
        candidate(
            "slow",
            "slow-provider",
            "pip",
            "pypi--language-registry",
            "https://slow.invalid/pypi/",
        ),
        candidate(
            "bad-content",
            "bad-provider",
            "pip",
            "pypi--language-registry",
            "https://bad.invalid/pypi/",
        ),
        candidate(
            "timeout",
            "timeout-provider",
            "pip",
            "pypi--language-registry",
            "https://timeout.invalid/pypi/",
        ),
        arm,
        partial,
        candidate(
            "npm",
            "npm-provider",
            "npm",
            "npm--language-registry",
            "https://npm.invalid/registry/",
        ),
    ];
    serde_json::from_value(json!({
        "schema_version": 2,
        "content_version": "selection-tests",
        "content_revision": 1,
        "generated_at": "2026-08-28T00:00:00Z",
        "providers": [
            {"id": "a-provider", "display_name": "A", "catalog_source": "https://a.invalid"},
            {"id": "b-provider", "display_name": "B", "catalog_source": "https://b.invalid"},
            {"id": "slow-provider", "display_name": "Slow", "catalog_source": "https://slow.invalid"},
            {"id": "bad-provider", "display_name": "Bad", "catalog_source": "https://bad.invalid"},
            {"id": "timeout-provider", "display_name": "Timeout", "catalog_source": "https://timeout.invalid"},
            {"id": "arm-provider", "display_name": "Arm", "catalog_source": "https://arm.invalid"},
            {"id": "partial-provider", "display_name": "Partial", "catalog_source": "https://partial.invalid"},
            {"id": "npm-provider", "display_name": "npm", "catalog_source": "https://npm.invalid"}
        ],
        "upstreams": [
            {
                "id": "pypi--language-registry",
                "family": "pypi",
                "display_name": "PyPI",
                "content_kind": "language-registry",
                "aliases": []
            },
            {
                "id": "npm--language-registry",
                "family": "npm",
                "display_name": "npm",
                "content_kind": "language-registry",
                "aliases": []
            }
        ],
        "tools": [
            {
                "id": "pip",
                "adapter_key": "pip",
                "display_name": "pip",
                "state": "supported",
                "implementation_issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/39",
                "supported_scopes": ["user"],
                "composition": "single"
            },
            {
                "id": "npm",
                "adapter_key": "npm",
                "display_name": "npm",
                "state": "supported",
                "implementation_issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/35",
                "supported_scopes": ["user"],
                "composition": "single"
            }
        ],
        "candidates": candidates
    }))
    .unwrap()
}

fn request() -> SelectionRequest {
    SelectionRequest {
        tool_id: "pip".into(),
        adapter_key: "pip".into(),
        context: SystemContext {
            os: OperatingSystem::Linux,
            architecture: Architecture::X86_64,
            environment: ExecutionEnvironment::Host,
            distribution: Some(Distribution {
                id: "ubuntu".into(),
                version_id: Some("24.04".into()),
                version_codename: Some("noble".into()),
                id_like: vec!["debian".into()],
            }),
            root: PathBuf::from("/"),
        },
        tool_version: Some("24.0".into()),
        required_upstreams: vec!["pypi--language-registry".into()],
        repository_versions: BTreeMap::from([("pypi--language-registry".into(), "1".into())]),
        probe_contexts: BTreeMap::from([(
            "pypi--language-registry".into(),
            vec![BTreeMap::from([("package".into(), "pip".into())])],
        )]),
        required_compatibility_evidence: vec![
            CompatibilityDimension::OperatingSystem,
            CompatibilityDimension::Architecture,
            CompatibilityDimension::Environment,
        ],
        require_distribution: true,
        allowed_protocols: vec![Protocol::Https],
        required_endpoint_roles: vec![EndpointRole::Index],
        allowed_delivery_modes: vec![DeliveryMode::Mirror],
        composition_policy: CompositionPolicy::Single,
        overrides: BTreeMap::new(),
    }
}

fn success(latency_ms: u64) -> Result<ProbeObservation, ProbeError> {
    Ok(ProbeObservation {
        status: 200,
        content_type: Some("text/html; charset=utf-8".into()),
        body: b"repository metadata: pip-release".to_vec(),
        latency_ms,
    })
}

struct DeterministicProber {
    responses: HashMap<String, Result<ProbeObservation, ProbeError>>,
    calls: Rc<RefCell<Vec<String>>>,
}

impl DeterministicProber {
    fn standard() -> Self {
        Self {
            responses: HashMap::from([
                ("https://tie.invalid/pypi/simple/pip/".into(), success(20)),
                ("https://fast.invalid/pypi/simple/pip/".into(), success(20)),
                ("https://slow.invalid/pypi/simple/pip/".into(), success(50)),
                (
                    "https://bad.invalid/pypi/simple/pip/".into(),
                    Ok(ProbeObservation {
                        status: 200,
                        content_type: Some("text/html".into()),
                        body: b"unrelated page".to_vec(),
                        latency_ms: 1,
                    }),
                ),
                (
                    "https://timeout.invalid/pypi/simple/pip/".into(),
                    Err(ProbeError::Timeout),
                ),
            ]),
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn tracked() -> (Self, Rc<RefCell<Vec<String>>>) {
        let prober = Self::standard();
        let calls = Rc::clone(&prober.calls);
        (prober, calls)
    }
}

impl CandidateProber for DeterministicProber {
    fn probe(
        &self,
        _method: mirrorswitch::catalog::HttpMethod,
        url: &str,
        _limits: ProbeLimits,
    ) -> Result<ProbeObservation, ProbeError> {
        self.calls.borrow_mut().push(url.into());
        self.responses
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(ProbeError::Http(format!("unexpected probe {url}"))))
    }
}

#[test]
fn filters_before_probing_and_selects_each_tool_deterministically() {
    let catalog = catalog();
    let (prober, calls) = DeterministicProber::tracked();
    let selector = MirrorSelector::with_prober(&catalog, prober, ProbeLimits::default());
    let outcome = selector.select_at(&request(), 123_456).unwrap();

    assert!(outcome.actionable);
    assert_eq!(outcome.measured_at_unix_ms, 123_456);
    assert_eq!(outcome.selections.len(), 1);
    assert_eq!(outcome.selections[0].candidate_id, "tie");
    assert_eq!(outcome.selections[0].provider_id, "a-provider");
    assert_eq!(outcome.selections[0].latency_ms, 20);
    assert!(!outcome.selections[0].user_override);

    let calls = calls.borrow();
    assert_eq!(calls.len(), 5);
    assert!(calls.iter().all(|url| !url.contains("arm.invalid")));
    assert!(calls.iter().all(|url| !url.contains("partial.invalid")));
    assert!(calls.iter().all(|url| !url.contains("npm.invalid")));

    let reports = &outcome.repositories[0].candidates;
    assert!(reports.iter().any(|report| {
        report.candidate_id == "arm"
            && matches!(report.evaluation, CandidateEvaluation::Incompatible { .. })
    }));
    assert!(reports.iter().any(|report| {
        report.candidate_id == "bad-content"
            && matches!(report.evaluation, CandidateEvaluation::ProbeFailed { .. })
    }));
    assert!(reports.iter().any(|report| {
        report.candidate_id == "timeout"
            && matches!(report.evaluation, CandidateEvaluation::ProbeFailed { .. })
    }));

    let machine_output = serde_json::to_value(&outcome).unwrap();
    assert_eq!(machine_output["measured_at_unix_ms"], 123_456);
    assert_eq!(machine_output["selections"][0]["candidate_id"], "tie");
}

#[test]
fn user_override_is_still_probed_and_cannot_force_a_failed_candidate() {
    let catalog = catalog();
    let selector = MirrorSelector::with_prober(
        &catalog,
        DeterministicProber::standard(),
        ProbeLimits::default(),
    );
    let mut overridden = request();
    overridden
        .overrides
        .insert("pypi--language-registry".into(), "slow".into());
    let selected = selector.select_at(&overridden, 7).unwrap();
    assert_eq!(selected.selections[0].candidate_id, "slow");
    assert!(selected.selections[0].user_override);

    overridden
        .overrides
        .insert("pypi--language-registry".into(), "timeout".into());
    let rejected = selector.select_at(&overridden, 8).unwrap();
    assert!(!rejected.actionable);
    assert!(rejected.selections.is_empty());
    assert!(
        rejected.repositories[0]
            .failure_reason
            .as_deref()
            .unwrap()
            .contains("user override timeout")
    );
}

#[test]
fn one_missing_required_repository_prevents_partial_tool_changes() {
    let catalog = catalog();
    let selector = MirrorSelector::with_prober(
        &catalog,
        DeterministicProber::standard(),
        ProbeLimits::default(),
    );
    let mut request = request();
    request.required_upstreams.push("missing-repository".into());

    let outcome = selector.select_at(&request, 9).unwrap();
    assert!(!outcome.actionable);
    assert!(outcome.selections.is_empty());
    assert_eq!(outcome.repositories[0].selected_candidate_ids, ["tie"]);
    assert_eq!(
        outcome.repositories[1].failure_reason.as_deref(),
        Some("no compatible candidate passed every content probe")
    );
}

#[test]
fn protocol_and_version_mismatches_are_rejected_before_network_access() {
    let catalog = catalog();
    let (prober, calls) = DeterministicProber::tracked();
    let selector = MirrorSelector::with_prober(&catalog, prober, ProbeLimits::default());
    let mut incompatible = request();
    incompatible.allowed_protocols = vec![Protocol::Http];
    incompatible
        .repository_versions
        .insert("pypi--language-registry".into(), "2".into());

    let outcome = selector.select_at(&incompatible, 10).unwrap();
    assert!(!outcome.actionable);
    assert!(calls.borrow().is_empty());
    assert!(
        outcome.repositories[0].candidates.iter().all(|report| {
            matches!(report.evaluation, CandidateEvaluation::Incompatible { .. })
        })
    );
}

#[test]
fn unspecified_required_compatibility_is_not_treated_as_all_platforms() {
    let mut catalog = catalog();
    catalog.candidates.retain(|candidate| candidate.id == "tie");
    catalog.candidates[0].compatibility.architectures.clear();
    let (prober, calls) = DeterministicProber::tracked();
    let selector = MirrorSelector::with_prober(&catalog, prober, ProbeLimits::default());

    let outcome = selector.select_at(&request(), 10).unwrap();
    assert!(!outcome.actionable);
    assert!(calls.borrow().is_empty());
    let CandidateEvaluation::Incompatible { reasons } =
        &outcome.repositories[0].candidates[0].evaluation
    else {
        panic!("candidate should be incompatible")
    };
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("no architecture compatibility evidence"))
    );
}

#[test]
fn multiple_sources_require_matching_compiled_composition_policy() {
    let mut catalog = catalog();
    catalog.tools[0].composition = CompositionPolicy::Priority;
    let selector = MirrorSelector::with_prober(
        &catalog,
        DeterministicProber::standard(),
        ProbeLimits::default(),
    );
    let conflict = selector.select_at(&request(), 11).unwrap_err();
    assert!(matches!(
        conflict,
        SelectionError::CompositionConflict { .. }
    ));

    let mut allowed = request();
    allowed.composition_policy = CompositionPolicy::Priority;
    let outcome = selector.select_at(&allowed, 12).unwrap();
    assert_eq!(
        outcome
            .selections
            .iter()
            .map(|selection| selection.candidate_id.as_str())
            .collect::<Vec<_>>(),
        ["tie", "fast", "slow"]
    );
}

#[test]
fn probe_content_marker_expands_safe_runtime_context() {
    let mut catalog = catalog();
    catalog.candidates.retain(|candidate| candidate.id == "tie");
    catalog.candidates[0].probes[0].contains = Some("{package}-release".into());
    let selector = MirrorSelector::with_prober(
        &catalog,
        DeterministicProber::standard(),
        ProbeLimits::default(),
    );

    let outcome = selector.select_at(&request(), 13).unwrap();

    assert!(outcome.actionable);
    assert_eq!(outcome.selections[0].candidate_id, "tie");
}

#[test]
fn adapter_identity_is_a_configuration_format_boundary() {
    let catalog = catalog();
    let selector = MirrorSelector::with_prober(
        &catalog,
        DeterministicProber::standard(),
        ProbeLimits::default(),
    );
    let mut wrong_adapter = request();
    wrong_adapter.adapter_key = "poetry".into();

    let error = selector.select_at(&wrong_adapter, 13).unwrap_err();
    assert!(matches!(error, SelectionError::AdapterMismatch { .. }));
}

#[test]
fn real_http_probe_uses_repository_metadata_path_and_validates_content() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let length = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..length]);
        assert!(request.starts_with("GET /mirror/simple/pip/ HTTP/1.1"));
        let body = b"signed repository metadata: pip-release";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });

    let mut catalog = catalog();
    catalog.candidates.retain(|candidate| candidate.id == "tie");
    let candidate = &mut catalog.candidates[0];
    candidate.endpoints[0].protocol = Protocol::Http;
    candidate.endpoints[0].url = format!("http://{address}/mirror/");
    let mut request = request();
    request.allowed_protocols = vec![Protocol::Http];
    let selector = MirrorSelector::with_prober(
        &catalog,
        HttpCandidateProber,
        ProbeLimits {
            timeout: Duration::from_secs(1),
            max_bytes: 1024,
        },
    );

    let outcome = selector.select_at(&request, 14).unwrap();
    server.join().unwrap();
    assert!(outcome.actionable);
    assert_eq!(outcome.selections[0].candidate_id, "tie");
}

#[test]
fn repository_path_probe_context_cannot_escape_the_mirror_endpoint() {
    let mut catalog = catalog();
    catalog.candidates.retain(|candidate| candidate.id == "tie");
    catalog.candidates[0].probes[0].path = "/{repository_path}repodata/repomd.xml".into();
    let (prober, calls) = DeterministicProber::tracked();
    let selector = MirrorSelector::with_prober(&catalog, prober, ProbeLimits::default());
    let mut request = request();
    request.probe_contexts.insert(
        "pypi--language-registry".into(),
        vec![BTreeMap::from([(
            "repository_path".into(),
            "safe/../escape/".into(),
        )])],
    );

    let outcome = selector.select_at(&request, 15).unwrap();

    assert!(!outcome.actionable);
    assert!(calls.borrow().is_empty());
    let CandidateEvaluation::ProbeFailed { reason } =
        &outcome.repositories[0].candidates[0].evaluation
    else {
        panic!("unsafe repository path should fail before network access")
    };
    assert!(reason.contains("not a safe path segment"));
}

#[test]
fn real_http_probe_rejects_an_oversized_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            .unwrap();
    });

    let error = HttpCandidateProber
        .probe(
            mirrorswitch::catalog::HttpMethod::Get,
            &format!("http://{address}/metadata"),
            ProbeLimits {
                timeout: Duration::from_secs(1),
                max_bytes: 10,
            },
        )
        .unwrap_err();
    server.join().unwrap();
    assert_eq!(error, ProbeError::TooLarge { limit_bytes: 10 });
}
