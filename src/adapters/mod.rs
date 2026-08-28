mod apt;
mod dnf;
mod pacman;
mod yum;

use std::collections::HashSet;

use crate::Adapter;

pub use apt::AptAdapter;
pub use dnf::DnfAdapter;
pub use pacman::PacmanAdapter;
pub use yum::YumAdapter;

static APT: AptAdapter = AptAdapter;
static DNF: DnfAdapter = DnfAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static YUM: YumAdapter = YumAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![&APT, &DNF, &YUM, &PACMAN]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
