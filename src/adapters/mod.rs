mod apk;
mod apt;
mod dnf;
mod flatpak;
mod guix;
mod nix;
mod npm;
mod opkg;
mod pacman;
mod pip;
mod portage;
mod xbps;
mod yarn;
mod yum;
mod zypper;

use std::collections::HashSet;

use crate::Adapter;

pub use apk::ApkAdapter;
pub use apt::AptAdapter;
pub use dnf::DnfAdapter;
pub use flatpak::FlatpakAdapter;
pub use guix::GuixAdapter;
pub use nix::NixAdapter;
pub use npm::NpmAdapter;
pub use opkg::OpkgAdapter;
pub use pacman::PacmanAdapter;
pub use pip::PipAdapter;
pub use portage::PortageAdapter;
pub use xbps::XbpsAdapter;
pub use yarn::YarnAdapter;
pub use yum::YumAdapter;
pub use zypper::ZypperAdapter;

static APK: ApkAdapter = ApkAdapter;
static APT: AptAdapter = AptAdapter;
static DNF: DnfAdapter = DnfAdapter;
static FLATPAK: FlatpakAdapter = FlatpakAdapter;
static GUIX: GuixAdapter = GuixAdapter;
static NIX: NixAdapter = NixAdapter;
static NPM: NpmAdapter = NpmAdapter;
static OPKG: OpkgAdapter = OpkgAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static PIP: PipAdapter = PipAdapter;
static PORTAGE: PortageAdapter = PortageAdapter;
static XBPS: XbpsAdapter = XbpsAdapter;
static YARN: YarnAdapter = YarnAdapter;
static YUM: YumAdapter = YumAdapter;
static ZYPPER: ZypperAdapter = ZypperAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![
        &APT, &DNF, &YUM, &PACMAN, &ZYPPER, &PORTAGE, &APK, &XBPS, &NIX, &GUIX, &FLATPAK, &OPKG,
        &PIP, &NPM, &YARN,
    ]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
