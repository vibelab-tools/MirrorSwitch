mod apk;
mod apt;
mod bazel;
mod bioconductor;
mod bundler;
mod cabal;
mod cargo;
mod composer;
mod conda;
mod containerd;
mod cpan;
mod cran;
mod dart_pub;
mod dnf;
mod docker_ce;
mod elasticstack;
mod elpa;
mod flatpak;
mod flutter;
mod fnm;
mod ghcup;
mod go;
mod gradle;
mod guix;
mod influxdb;
mod julia;
mod kubernetes_images;
mod kubernetes_packages;
mod leiningen;
mod mariadb;
mod maven;
mod mongodb;
mod mysql;
mod nix;
mod npm;
mod nuget;
mod nvm;
mod opam;
mod opkg;
mod pacman;
mod pdm;
mod pip;
mod pnpm;
mod podman_registry;
mod poetry;
mod portage;
mod postgresql;
mod pyenv;
mod ros;
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
pub use containerd::ContainerdAdapter;
pub use cpan::CpanAdapter;
pub use cran::CranAdapter;
pub use dart_pub::DartPubAdapter;
pub use dnf::DnfAdapter;
pub use docker_ce::DockerCeAdapter;
pub use elasticstack::ElasticStackAdapter;
pub use elpa::ElpaAdapter;
pub use flatpak::FlatpakAdapter;
pub use flutter::FlutterAdapter;
pub use fnm::FnmAdapter;
pub use ghcup::GhcupAdapter;
pub use go::GoAdapter;
pub use gradle::GradleAdapter;
pub use guix::GuixAdapter;
pub use influxdb::InfluxDbAdapter;
pub use julia::JuliaAdapter;
pub use kubernetes_images::KubernetesImagesAdapter;
pub use kubernetes_packages::KubernetesPackagesAdapter;
pub use leiningen::LeiningenAdapter;
pub use mariadb::MariaDbAdapter;
pub use maven::MavenAdapter;
pub use mongodb::MongoDbAdapter;
pub use mysql::MySqlAdapter;
pub use nix::NixAdapter;
pub use npm::NpmAdapter;
pub use nuget::NugetAdapter;
pub use nvm::NvmAdapter;
pub use opam::OpamAdapter;
pub use opkg::OpkgAdapter;
pub use pacman::PacmanAdapter;
pub use pdm::PdmAdapter;
pub use pip::PipAdapter;
pub use pnpm::PnpmAdapter;
pub use podman_registry::PodmanRegistryAdapter;
pub use poetry::PoetryAdapter;
pub use portage::PortageAdapter;
pub use postgresql::PostgreSqlAdapter;
pub use pyenv::PyenvAdapter;
pub use ros::RosAdapter;
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
static CONTAINERD: ContainerdAdapter = ContainerdAdapter;
static CPAN: CpanAdapter = CpanAdapter;
static CRAN: CranAdapter = CranAdapter;
static DNF: DnfAdapter = DnfAdapter;
static DOCKER_CE: DockerCeAdapter = DockerCeAdapter;
static ELPA: ElpaAdapter = ElpaAdapter;
static ELASTICSTACK: ElasticStackAdapter = ElasticStackAdapter;
static DART_PUB: DartPubAdapter = DartPubAdapter;
static FLATPAK: FlatpakAdapter = FlatpakAdapter;
static FNM: FnmAdapter = FnmAdapter;
static FLUTTER: FlutterAdapter = FlutterAdapter;
static GO: GoAdapter = GoAdapter;
static GRADLE: GradleAdapter = GradleAdapter;
static GHCUP: GhcupAdapter = GhcupAdapter;
static GUIX: GuixAdapter = GuixAdapter;
static INFLUXDB: InfluxDbAdapter = InfluxDbAdapter;
static JULIA: JuliaAdapter = JuliaAdapter;
static KUBERNETES_IMAGES: KubernetesImagesAdapter = KubernetesImagesAdapter;
static KUBERNETES_PACKAGES: KubernetesPackagesAdapter = KubernetesPackagesAdapter;
static LEININGEN: LeiningenAdapter = LeiningenAdapter;
static MARIADB: MariaDbAdapter = MariaDbAdapter;
static MAVEN: MavenAdapter = MavenAdapter;
static MONGODB: MongoDbAdapter = MongoDbAdapter;
static MYSQL: MySqlAdapter = MySqlAdapter;
static NIX: NixAdapter = NixAdapter;
static NVM: NvmAdapter = NvmAdapter;
static NPM: NpmAdapter = NpmAdapter;
static NUGET: NugetAdapter = NugetAdapter;
static OPKG: OpkgAdapter = OpkgAdapter;
static OPAM: OpamAdapter = OpamAdapter;
static PACMAN: PacmanAdapter = PacmanAdapter;
static PDM: PdmAdapter = PdmAdapter;
static PIP: PipAdapter = PipAdapter;
static PNPM: PnpmAdapter = PnpmAdapter;
static PODMAN_REGISTRY: PodmanRegistryAdapter = PodmanRegistryAdapter;
static POETRY: PoetryAdapter = PoetryAdapter;
static PORTAGE: PortageAdapter = PortageAdapter;
static POSTGRESQL: PostgreSqlAdapter = PostgreSqlAdapter;
static PYENV: PyenvAdapter = PyenvAdapter;
static RUBYGEMS: RubyGemsAdapter = RubyGemsAdapter;
static ROS: RosAdapter = RosAdapter;
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
        &DOCKER_CE,
        &ELPA,
        &ELASTICSTACK,
        &YUM,
        &PACMAN,
        &ZYPPER,
        &PORTAGE,
        &POSTGRESQL,
        &APK,
        &XBPS,
        &NIX,
        &GUIX,
        &INFLUXDB,
        &FLATPAK,
        &OPKG,
        &PIP,
        &PDM,
        &POETRY,
        &UV,
        &NPM,
        &YARN,
        &PNPM,
        &PODMAN_REGISTRY,
        &CONDA,
        &BIOCONDUCTOR,
        &DART_PUB,
        &GRADLE,
        &MARIADB,
        &MAVEN,
        &MONGODB,
        &MYSQL,
        &NVM,
        &FNM,
        &GO,
        &JULIA,
        &KUBERNETES_IMAGES,
        &KUBERNETES_PACKAGES,
        &RUBYGEMS,
        &ROS,
        &BUNDLER,
        &CARGO,
        &RUSTUP,
        &COMPOSER,
        &CONTAINERD,
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
        &OPAM,
    ]
}

pub fn compiled_adapter_allowlist() -> HashSet<String> {
    compiled_adapters()
        .into_iter()
        .map(|adapter| adapter.key().to_owned())
        .collect()
}
