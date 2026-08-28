mod apt;

use std::collections::HashSet;

use crate::Adapter;

pub use apt::AptAdapter;

static APT: AptAdapter = AptAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![&APT]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
