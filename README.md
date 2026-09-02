# MirrorSwitch

[![Linux CI](https://github.com/vibelab-tools/MirrorSwitch/actions/workflows/ci.yml/badge.svg)](https://github.com/vibelab-tools/MirrorSwitch/actions/workflows/ci.yml)

MirrorSwitch is a Rust terminal tool for selecting and applying compatible
China-hosted mirrors for software-development repositories.

The first release targets Linux on `x86_64` and `arm64`. It provides three
front ends backed by the same core engine:

- a non-interactive CLI;
- an optional declarative configuration file;
- an interactive TUI.

Mirror selection is performed per tool and per upstream repository. A fast
mirror for APT is not automatically considered suitable for PyPI, Cargo, or a
container registry. Candidates must pass platform, version, architecture,
protocol, and content checks before latency is compared.

## Project status

The current release is [v0.1.0 — Linux MVP](https://github.com/vibelab-tools/MirrorSwitch/releases/tag/v0.1.0).
The authoritative delivery plan is [milestone 1](https://github.com/vibelab-tools/MirrorSwitch/milestone/1).
No adapter is considered supported until its issue acceptance criteria and
real-boundary checks have passed.

## Design baseline

- [Linux installation and upgrades](docs/install-linux.md)
- [Product boundary](docs/product-boundary.md)
- [Linux support matrix](docs/support-matrix.md)
- [Supported adapter reference](docs/adapter-reference.md)
- [Six-provider inventory](docs/provider-inventory.md)
- [Runtime catalog and safe updates](docs/catalog-updates.md)
- [Linux CLI, configuration, and TUI](docs/cli.md)
- [Testing and Docker matrix](docs/testing.md)
- [Linux packaging](docs/packaging.md)
- [Contribution guide](CONTRIBUTING.md)
- [Per-repository mirror selection](docs/mirror-selection.md)
- [APT adapter](docs/adapters/apt.md)
- [DNF adapter](docs/adapters/dnf.md)
- [YUM adapter](docs/adapters/yum.md)
- [Pacman adapter](docs/adapters/pacman.md)
- [Zypper adapter](docs/adapters/zypper.md)
- [Portage adapter](docs/adapters/portage.md)
- [APK adapter](docs/adapters/apk.md)
- [XBPS adapter](docs/adapters/xbps.md)
- [Nix adapter](docs/adapters/nix.md)
- [GNU Guix adapter](docs/adapters/guix.md)
- [Flatpak adapter](docs/adapters/flatpak.md)
- [opkg adapter](docs/adapters/opkg.md)
- [pip adapter](docs/adapters/pip.md)
- [npm adapter](docs/adapters/npm.md)
- [pnpm adapter](docs/adapters/pnpm.md)
- [Yarn adapter](docs/adapters/yarn.md)
- [Conda/Mamba adapter](docs/adapters/conda.md)
- [PDM adapter](docs/adapters/pdm.md)
- [Poetry adapter](docs/adapters/poetry.md)
- [uv adapter](docs/adapters/uv.md)
- [Gradle adapter](docs/adapters/gradle.md)
- [Maven adapter](docs/adapters/maven.md)
- [nvm adapter](docs/adapters/nvm.md)
- [fnm adapter](docs/adapters/fnm.md)
- [Go Modules adapter](docs/adapters/go.md)
- [RubyGems adapter](docs/adapters/rubygems.md)
- [Bundler adapter](docs/adapters/bundler.md)
- [Cargo adapter](docs/adapters/cargo.md)
- [rustup adapter](docs/adapters/rustup.md)
- [Composer adapter](docs/adapters/composer.md)
- [NuGet adapter](docs/adapters/nuget.md)
- [Cabal adapter](docs/adapters/cabal.md)
- [Stack/Stackage adapter](docs/adapters/stack.md)
- [GHCup adapter](docs/adapters/ghcup.md)
- [sbt adapter](docs/adapters/sbt.md)
- [v0.1.0 tracking issue](https://github.com/vibelab-tools/MirrorSwitch/issues/1)

## License

[MIT](LICENSE)
