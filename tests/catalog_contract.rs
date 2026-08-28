use mirrorswitch::{
    MirrorCatalog,
    catalog::{CandidateEvaluation, CatalogEntryState, CompositionPolicy, ConfigurationScope},
};

const MINIMAL_CATALOG: &str = r#"
{
  "schema_version": 2,
  "content_version": "2026.08.28.1",
  "content_revision": 202608280001,
  "generated_at": "2026-08-28T00:00:00Z",
  "providers": [
    {
      "id": "example",
      "display_name": "Example Mirror",
      "catalog_source": "https://example.invalid/mirrors"
    }
  ],
  "upstreams": [
    {
      "id": "pypi",
      "family": "pypi",
      "display_name": "Python Package Index",
      "content_kind": "language-registry",
      "aliases": ["PyPI"]
    }
  ],
  "tools": [
    {
      "id": "pip",
      "adapter_key": "pip",
      "display_name": "pip",
      "state": "planned",
      "implementation_issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/39",
      "supported_scopes": ["user", "project", "environment"],
      "composition": "single"
    }
  ],
  "candidates": [
    {
      "id": "example-pypi-pip",
      "provider_id": "example",
      "upstream_id": "pypi",
      "tool_id": "pip",
      "catalog_state": "cataloged",
      "delivery_mode": "mirror",
      "raw_names": ["pypi"],
      "endpoints": [
        {
          "role": "index",
          "protocol": "https",
          "url": "https://example.invalid/pypi/simple"
        }
      ],
      "compatibility": {
        "operating_systems": ["linux"],
        "architectures": ["x86-64", "arm64"],
        "environments": ["host", "container"],
        "distributions": [],
        "repository_versions": []
      },
      "probes": [
        {
          "endpoint_role": "index",
          "method": "get",
          "path": "/pip/",
          "expected_status": [200],
          "expected_content_type": "text/html"
        }
      ],
      "source_urls": ["https://example.invalid/help/pypi"],
      "observed_at": "2026-08-28T00:00:00Z"
    }
  ]
}
"#;

#[test]
fn catalog_keeps_inventory_separate_from_runtime_evaluation() {
    let catalog: MirrorCatalog = serde_json::from_str(MINIMAL_CATALOG).unwrap();
    let candidate = &catalog.candidates[0];

    assert_eq!(candidate.catalog_state, CatalogEntryState::Cataloged);
    assert_eq!(catalog.tools[0].composition, CompositionPolicy::Single);
    assert_eq!(
        catalog.tools[0].supported_scopes,
        [
            ConfigurationScope::User,
            ConfigurationScope::Project,
            ConfigurationScope::Environment,
        ]
    );

    let runtime_state = CandidateEvaluation::AdapterUnavailable;
    assert_ne!(
        format!("{:?}", candidate.catalog_state),
        format!("{runtime_state:?}")
    );
}

#[test]
fn catalog_rejects_executable_remote_fields() {
    let untrusted =
        MINIMAL_CATALOG.replace("\"probes\": [", "\"command\": \"curl | sh\", \"probes\": [");

    let error = serde_json::from_str::<MirrorCatalog>(&untrusted).unwrap_err();
    assert!(error.to_string().contains("unknown field `command`"));
}
