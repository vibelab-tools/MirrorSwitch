mod apt;
mod dnf;
mod yum;

use std::collections::HashSet;

use crate::Adapter;

pub use apt::AptAdapter;
pub use dnf::DnfAdapter;
pub use yum::YumAdapter;

static APT: AptAdapter = AptAdapter;
static DNF: DnfAdapter = DnfAdapter;
static YUM: YumAdapter = YumAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![&APT, &DNF, &YUM]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
