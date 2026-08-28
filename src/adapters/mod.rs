mod apt;
mod dnf;
mod pacman;
mod yum;
mod zypper;

use std::collections::HashSet;

use crate::Adapter;

pub use apt::AptAdapter;
pub use dnf::DnfAdapter;
pub use pacman::PacmanAdapter;
pub use yum::YumAdapter;
pub use zypper::ZypperAdapter;

static APT: AptAdapter = AptAdapter;
static DNF: DnfAdapter = DnfAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static YUM: YumAdapter = YumAdapter;
static ZYPPER: ZypperAdapter = ZypperAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![&APT, &DNF, &YUM, &PACMAN, &ZYPPER]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
