mod apt;
mod dnf;

use std::collections::HashSet;

use crate::Adapter;

pub use apt::AptAdapter;
pub use dnf::DnfAdapter;

static APT: AptAdapter = AptAdapter;
static DNF: DnfAdapter = DnfAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![&APT, &DNF]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
