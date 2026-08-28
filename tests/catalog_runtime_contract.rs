use std::collections::HashSet;

use mirrorswitch::{
    MirrorCatalog, adapters::compiled_adapter_allowlist, catalog::ToolCatalogState,
    catalog_update::EMBEDDED_CATALOG,
};

#[test]
fn embedded_runtime_catalog_is_valid_and_keeps_planned_tools_inert() {
    let catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();

    catalog.validate(&compiled_adapter_allowlist()).unwrap();
    assert_eq!(catalog.providers.len(), 6);
    assert_eq!(catalog.tools.len(), 75);
    assert_eq!(catalog.candidates.len(), 507);
    assert_eq!(
        catalog
            .tools
            .iter()
            .filter(|tool| tool.state == ToolCatalogState::Supported)
            .map(|tool| tool.id.as_str())
            .collect::<Vec<_>>(),
        [
            "apk", "apt", "conda", "dnf", "flatpak", "guix", "nix", "npm", "opkg", "pacman", "pdm",
            "pip", "pnpm", "poetry", "portage", "xbps", "yarn", "yum", "zypper"
        ]
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

#[test]
fn repository_probe_cannot_target_a_root_or_escape_its_endpoint() {
    let mut catalog: MirrorCatalog = serde_json::from_slice(EMBEDDED_CATALOG).unwrap();
    let candidate = catalog
        .candidates
        .iter_mut()
        .find(|candidate| !candidate.probes.is_empty())
        .unwrap();
    candidate.probes[0].path = "/../".into();

    let error = catalog.validate(&compiled_adapter_allowlist()).unwrap_err();
    assert!(error.to_string().contains("invalid declarative probe path"));
}
