mod apk;
mod apt;
mod conda;
mod dnf;
mod flatpak;
mod fnm;
mod gradle;
mod guix;
mod maven;
mod nix;
mod npm;
mod nvm;
mod opkg;
mod pacman;
mod pdm;
mod pip;
mod pnpm;
mod poetry;
mod portage;
mod uv;
mod xbps;
mod yarn;
mod yum;
mod zypper;

use std::collections::HashSet;

use crate::Adapter;

pub use apk::ApkAdapter;
pub use apt::AptAdapter;
pub use conda::CondaAdapter;
pub use dnf::DnfAdapter;
pub use flatpak::FlatpakAdapter;
pub use fnm::FnmAdapter;
pub use gradle::GradleAdapter;
pub use guix::GuixAdapter;
pub use maven::MavenAdapter;
pub use nix::NixAdapter;
pub use npm::NpmAdapter;
pub use nvm::NvmAdapter;
pub use opkg::OpkgAdapter;
pub use pacman::PacmanAdapter;
pub use pdm::PdmAdapter;
pub use pip::PipAdapter;
pub use pnpm::PnpmAdapter;
pub use poetry::PoetryAdapter;
pub use portage::PortageAdapter;
pub use uv::UvAdapter;
pub use xbps::XbpsAdapter;
pub use yarn::YarnAdapter;
pub use yum::YumAdapter;
pub use zypper::ZypperAdapter;

static APK: ApkAdapter = ApkAdapter;
static APT: AptAdapter = AptAdapter;
static CONDA: CondaAdapter = CondaAdapter;
static DNF: DnfAdapter = DnfAdapter;
static FLATPAK: FlatpakAdapter = FlatpakAdapter;
static FNM: FnmAdapter = FnmAdapter;
static GRADLE: GradleAdapter = GradleAdapter;
static GUIX: GuixAdapter = GuixAdapter;
static MAVEN: MavenAdapter = MavenAdapter;
static NIX: NixAdapter = NixAdapter;
static NVM: NvmAdapter = NvmAdapter;
static NPM: NpmAdapter = NpmAdapter;
static OPKG: OpkgAdapter = OpkgAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static PDM: PdmAdapter = PdmAdapter;
static PIP: PipAdapter = PipAdapter;
static PNPM: PnpmAdapter = PnpmAdapter;
static POETRY: PoetryAdapter = PoetryAdapter;
static PORTAGE: PortageAdapter = PortageAdapter;
static UV: UvAdapter = UvAdapter;
static XBPS: XbpsAdapter = XbpsAdapter;
static YARN: YarnAdapter = YarnAdapter;
static YUM: YumAdapter = YumAdapter;
static ZYPPER: ZypperAdapter = ZypperAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![
        &APT, &DNF, &YUM, &PACMAN, &ZYPPER, &PORTAGE, &APK, &XBPS, &NIX, &GUIX, &FLATPAK, &OPKG,
        &PIP, &PDM, &POETRY, &UV, &NPM, &YARN, &PNPM, &CONDA, &GRADLE, &MAVEN, &NVM, &FNM,
    ]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
