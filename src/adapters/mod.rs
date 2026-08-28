mod apk;
mod apt;
mod dnf;
mod nix;
mod pacman;
mod portage;
mod xbps;
mod yum;
mod zypper;

use std::collections::HashSet;

use crate::Adapter;

pub use apk::ApkAdapter;
pub use apt::AptAdapter;
pub use dnf::DnfAdapter;
pub use nix::NixAdapter;
pub use pacman::PacmanAdapter;
pub use portage::PortageAdapter;
pub use xbps::XbpsAdapter;
pub use yum::YumAdapter;
pub use zypper::ZypperAdapter;

static APK: ApkAdapter = ApkAdapter;
static APT: AptAdapter = AptAdapter;
static DNF: DnfAdapter = DnfAdapter;
static NIX: NixAdapter = NixAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static PORTAGE: PortageAdapter = PortageAdapter;
static XBPS: XbpsAdapter = XbpsAdapter;
static YUM: YumAdapter = YumAdapter;
static ZYPPER: ZypperAdapter = ZypperAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![
        &APT, &DNF, &YUM, &PACMAN, &ZYPPER, &PORTAGE, &APK, &XBPS, &NIX,
    ]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
