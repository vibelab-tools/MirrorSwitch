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

The current release is [v0.2.0 — macOS & Windows](https://github.com/vibelab-tools/MirrorSwitch/releases/tag/v0.2.0),
which also retains the verified Linux packages from the
[v0.1.0 Linux MVP](https://github.com/vibelab-tools/MirrorSwitch/releases/tag/v0.1.0).
The v0.2 support matrix and per-tool native evidence are recorded in the
[delivery milestone](https://github.com/vibelab-tools/MirrorSwitch/milestone/2).
No adapter is considered supported until its issue acceptance criteria and
real-boundary checks have passed.

Linux mirror surfaces without a safe complete candidate remain visible in the
[v0.1.x follow-up milestone](https://github.com/vibelab-tools/MirrorSwitch/milestone/3).
macOS and Windows sources without a complete six-provider candidate remain in the
[v0.2.x follow-up milestone](https://github.com/vibelab-tools/MirrorSwitch/milestone/4).

## Design baseline

- [Linux installation and upgrades](docs/install-linux.md)
- [macOS and Windows installation, upgrade, and recovery](docs/install-macos-windows.md)
- [Product boundary](docs/product-boundary.md)
- [Linux support matrix](docs/support-matrix.md)
- [macOS and Windows mirror inventory](docs/macos-windows-inventory.md)
- [macOS and Windows support matrix](docs/macos-windows-support-matrix.md)
- [Supported adapter reference](docs/adapter-reference.md)
- [Reviewed provider inventory](docs/provider-inventory.md)
- [Runtime catalog and safe updates](docs/catalog-updates.md)
- [Linux CLI, configuration, and TUI](docs/cli.md)
- [Testing and Docker matrix](docs/testing.md)
- [Linux packaging](docs/packaging.md)
- [Contribution guide](CONTRIBUTING.md)
- [Homebrew adapter](docs/adapters/homebrew.md)
- [CocoaPods adapter](docs/adapters/cocoapods.md)
- [MacPorts adapter](docs/adapters/macports.md)
- [Scoop adapter](docs/adapters/scoop.md)
- [MSYS2 adapter](docs/adapters/msys2.md)
- [WinGet adapter](docs/adapters/winget.md)
- [Cygwin adapter](docs/adapters/cygwin.md)
- [Windows host and WSL boundary](docs/wsl.md)
- [Per-repository mirror selection](docs/mirror-selection.md)
- [APT adapter](docs/adapters/apt.md)
- [DNF adapter](docs/adapters/dnf.md)
- [YUM adapter](docs/adapters/yum.md)
- [Docker daemon Registry Mirrors adapter](docs/adapters/docker-registry.md)
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
- [v0.2.0 release notes](docs/releases/v0.2.0.md)

## License

[MIT](LICENSE)
