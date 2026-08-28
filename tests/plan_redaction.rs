use std::path::PathBuf;

use mirrorswitch::{
    catalog::ConfigurationScope,
    plan::{
        ChangePlan, ConfigurationDocument, ConfiguredSource, CurrentConfiguration,
        PlannedFileChange, ServiceImpact,
    },
};

#[test]
fn debug_plan_redacts_rendered_configuration() {
    let plan = ChangePlan {
        adapter_key: "pip".into(),
        tool_id: "pip".into(),
        scope: ConfigurationScope::User,
        changes: vec![PlannedFileChange {
            target: PathBuf::from("/tmp/pip.conf"),
            old_contents: Some(b"index-url=https://old:secret@example.invalid/simple".to_vec()),
            old_mode: Some(0o600),
            new_contents: b"index-url=https://user:secret@example.invalid/simple".to_vec(),
            new_mode: Some(0o600),
            summary: "replace the public PyPI source".into(),
        }],
        requires_elevation: false,
        service_impact: ServiceImpact::None,
    };

    let output = format!("{plan:?}");
    assert!(output.contains("<redacted:"));
    assert!(!output.contains("secret"));
    assert!(!output.contains("user:"));
    assert!(!output.contains("old:"));
}

#[test]
fn current_configuration_documents_expose_only_digest_metadata() {
    let current = CurrentConfiguration {
        tool_id: "apt".into(),
        scope: ConfigurationScope::System,
        sources: Vec::new(),
        files: vec![PathBuf::from("/etc/apt/sources.list")],
        documents: vec![ConfigurationDocument {
            path: PathBuf::from("/etc/apt/sources.list"),
            format: "apt-list".into(),
            contents: b"deb https://user:secret@example.invalid stable main".to_vec(),
        }],
    };

    let output = format!("{current:?} {}", serde_json::to_string(&current).unwrap());
    assert!(output.contains("sha256"));
    assert!(output.contains("<redacted:"));
    assert!(!output.contains("user:"));
    assert!(!output.contains("secret"));
}

#[test]
fn current_source_debug_and_json_redact_credentials_and_query_values() {
    let source = ConfiguredSource {
        upstream_id: Some("private".into()),
        url: "https://user:secret@example.invalid/index?token=secret#secret".into(),
        enabled: true,
        metadata: Default::default(),
    };

    let output = format!("{source:?} {}", serde_json::to_string(&source).unwrap());

    assert!(output.contains("<redacted>@example.invalid/index?<redacted>#<redacted>"));
    assert!(!output.contains("user:"));
    assert!(!output.contains("secret"));
}
