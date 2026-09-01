mod apk;
mod apt;
mod bazel;
mod bioconductor;
mod bundler;
mod cabal;
mod cargo;
mod composer;
mod conda;
mod cpan;
mod cran;
mod dart_pub;
mod dnf;
mod flatpak;
mod flutter;
mod fnm;
mod ghcup;
mod go;
mod gradle;
mod guix;
mod leiningen;
mod maven;
mod nix;
mod npm;
mod nuget;
mod nvm;
mod opkg;
mod pacman;
mod pdm;
mod pip;
mod pnpm;
mod poetry;
mod portage;
mod pyenv;
mod rubygems;
mod rustup;
mod sbt;
mod stack;
mod tlmgr;
mod uv;
mod xbps;
mod yarn;
mod yum;
mod zypper;

use std::collections::HashSet;

use crate::Adapter;

pub use apk::ApkAdapter;
pub use apt::AptAdapter;
pub use bazel::BazelAdapter;
pub use bioconductor::BioconductorAdapter;
pub use bundler::BundlerAdapter;
pub use cabal::CabalAdapter;
pub use cargo::CargoAdapter;
pub use composer::ComposerAdapter;
pub use conda::CondaAdapter;
pub use cpan::CpanAdapter;
pub use cran::CranAdapter;
pub use dart_pub::DartPubAdapter;
pub use dnf::DnfAdapter;
pub use flatpak::FlatpakAdapter;
pub use flutter::FlutterAdapter;
pub use fnm::FnmAdapter;
pub use ghcup::GhcupAdapter;
pub use go::GoAdapter;
pub use gradle::GradleAdapter;
pub use guix::GuixAdapter;
pub use leiningen::LeiningenAdapter;
pub use maven::MavenAdapter;
pub use nix::NixAdapter;
pub use npm::NpmAdapter;
pub use nuget::NugetAdapter;
pub use nvm::NvmAdapter;
pub use opkg::OpkgAdapter;
pub use pacman::PacmanAdapter;
pub use pdm::PdmAdapter;
pub use pip::PipAdapter;
pub use pnpm::PnpmAdapter;
pub use poetry::PoetryAdapter;
pub use portage::PortageAdapter;
pub use pyenv::PyenvAdapter;
pub use rubygems::RubyGemsAdapter;
pub use rustup::RustupAdapter;
pub use sbt::SbtAdapter;
pub use stack::StackAdapter;
pub use tlmgr::TlmgrAdapter;
pub use uv::UvAdapter;
pub use xbps::XbpsAdapter;
pub use yarn::YarnAdapter;
pub use yum::YumAdapter;
pub use zypper::ZypperAdapter;

static APK: ApkAdapter = ApkAdapter;
static APT: AptAdapter = AptAdapter;
static BAZEL: BazelAdapter = BazelAdapter;
static BIOCONDUCTOR: BioconductorAdapter = BioconductorAdapter;
static BUNDLER: BundlerAdapter = BundlerAdapter;
static CABAL: CabalAdapter = CabalAdapter;
static CARGO: CargoAdapter = CargoAdapter;
static CONDA: CondaAdapter = CondaAdapter;
static COMPOSER: ComposerAdapter = ComposerAdapter;
static CPAN: CpanAdapter = CpanAdapter;
static CRAN: CranAdapter = CranAdapter;
static DNF: DnfAdapter = DnfAdapter;
static DART_PUB: DartPubAdapter = DartPubAdapter;
static FLATPAK: FlatpakAdapter = FlatpakAdapter;
static FNM: FnmAdapter = FnmAdapter;
static FLUTTER: FlutterAdapter = FlutterAdapter;
static GO: GoAdapter = GoAdapter;
static GRADLE: GradleAdapter = GradleAdapter;
static GHCUP: GhcupAdapter = GhcupAdapter;
static GUIX: GuixAdapter = GuixAdapter;
static LEININGEN: LeiningenAdapter = LeiningenAdapter;
static MAVEN: MavenAdapter = MavenAdapter;
static NIX: NixAdapter = NixAdapter;
static NVM: NvmAdapter = NvmAdapter;
static NPM: NpmAdapter = NpmAdapter;
static NUGET: NugetAdapter = NugetAdapter;
static OPKG: OpkgAdapter = OpkgAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static PDM: PdmAdapter = PdmAdapter;
static PIP: PipAdapter = PipAdapter;
static PNPM: PnpmAdapter = PnpmAdapter;
static POETRY: PoetryAdapter = PoetryAdapter;
static PORTAGE: PortageAdapter = PortageAdapter;
static PYENV: PyenvAdapter = PyenvAdapter;
static RUBYGEMS: RubyGemsAdapter = RubyGemsAdapter;
static RUSTUP: RustupAdapter = RustupAdapter;
static SBT: SbtAdapter = SbtAdapter;
static STACK: StackAdapter = StackAdapter;
static TLMGR: TlmgrAdapter = TlmgrAdapter;
static UV: UvAdapter = UvAdapter;
static XBPS: XbpsAdapter = XbpsAdapter;
static YARN: YarnAdapter = YarnAdapter;
static YUM: YumAdapter = YumAdapter;
static ZYPPER: ZypperAdapter = ZypperAdapter;

pub fn compiled_adapters() -> Vec<&'static dyn Adapter> {
    vec![
        &APT,
        &DNF,
        &YUM,
        &PACMAN,
        &ZYPPER,
        &PORTAGE,
        &APK,
        &XBPS,
        &NIX,
        &GUIX,
        &FLATPAK,
        &OPKG,
        &PIP,
        &PDM,
        &POETRY,
        &UV,
        &NPM,
        &YARN,
        &PNPM,
        &CONDA,
        &BIOCONDUCTOR,
        &DART_PUB,
        &GRADLE,
        &MAVEN,
        &NVM,
        &FNM,
        &GO,
        &RUBYGEMS,
        &BUNDLER,
        &CARGO,
        &RUSTUP,
        &COMPOSER,
        &NUGET,
        &CABAL,
        &SBT,
        &LEININGEN,
        &STACK,
        &GHCUP,
        &TLMGR,
        &FLUTTER,
        &CPAN,
        &CRAN,
        &PYENV,
        &BAZEL,
    ]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
