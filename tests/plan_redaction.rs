use std::path::PathBuf;

use mirrorswitch::{
    catalog::ConfigurationScope,
    plan::{ChangePlan, PlannedFileChange, ServiceImpact},
};

#[test]
fn debug_plan_redacts_rendered_configuration() {
    let plan = ChangePlan {
        adapter_key: "pip".into(),
        tool_id: "pip".into(),
        scope: ConfigurationScope::User,
        changes: vec![PlannedFileChange {
            target: PathBuf::from("/tmp/pip.conf"),
            expected_digest: None,
            new_contents: b"index-url=https://user:secret@example.invalid/simple".to_vec(),
            summary: "replace the public PyPI source".into(),
        }],
        requires_elevation: false,
        service_impact: ServiceImpact::None,
    };

    let output = format!("{plan:?}");
    assert!(output.contains("<redacted:"));
    assert!(!output.contains("secret"));
    assert!(!output.contains("user:"));
}
