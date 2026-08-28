use std::collections::HashSet;

use mirrorswitch::{MirrorCatalog, catalog::ToolCatalogState, catalog_update::EMBEDDED_CATALOG};

#[test]
fn embedded_runtime_catalog_is_valid_and_keeps_planned_tools_inert() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();

    catalog.validate(&HashSet::new()).unwrap();
    assert_eq!(catalog.providers.len(), 6);
    assert_eq!(catalog.tools.len(), 75);
    assert_eq!(catalog.candidates.len(), 498);
    assert!(
        catalog
            .tools
            .iter()
            .all(|tool| tool.state == ToolCatalogState::Planned)
    );
}

#[test]
fn supported_tool_must_match_a_compiled_adapter_identity() {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let tool = &mut catalog.tools[0];
    tool.state = ToolCatalogState::Supported;
    tool.adapter_key = "another-adapter".into();
    let allowlist = HashSet::from(["another-adapter".to_owned()]);

    let error = catalog.validate(&allowlist).unwrap_err();
    assert!(error.to_string().contains("cannot activate adapter"));
}
