# MirrorSwitch

MirrorSwitch is a Rust terminal tool for selecting and applying compatible
China-hosted mirrors for software-development repositories.

The first release targets Linux on `x86_64` and `arm64`. It will provide three
front ends backed by the same core engine:

- a non-interactive CLI;
- an optional declarative configuration file;
- an interactive TUI.

Mirror selection is performed per tool and per upstream repository. A fast
mirror for APT is not automatically considered suitable for PyPI, Cargo, or a
container registry. Candidates must pass platform, version, architecture,
protocol, and content checks before latency is compared.

## Project status

The project is currently pre-alpha. The authoritative delivery plan is
[v0.1.0 — Linux MVP](https://github.com/vibelab-tools/MirrorSwitch/milestone/1).
No adapter is considered supported until its issue acceptance criteria and
real-boundary checks have passed.

## Design baseline

- [Product boundary](docs/product-boundary.md)
- [Linux support matrix](docs/support-matrix.md)
- [Six-provider inventory](docs/provider-inventory.md)
- [Runtime catalog and safe updates](docs/catalog-updates.md)
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
- [v0.1.0 tracking issue](https://github.com/vibelab-tools/MirrorSwitch/issues/1)

## License

[MIT](LICENSE)
