# Linux support matrix

This document defines the v0.1.0 support contract. It is deliberately stricter
than the provider catalog: a listed mirror is only a candidate, while an
adapter becomes supported after its own issue and boundary tests pass.

## Matrix dimensions

Every adapter/candidate result is keyed by:

`OS family × distribution × release × architecture × host/container × tool × upstream repository × provider × content type × operation`

The catalog stores explicit values or constrained patterns for every relevant
dimension. Missing compatibility data means “not eligible”, not “works
everywhere”.

## Platform baseline

| Distribution family | Release policy | Package tool | Architectures | Host | Container | Important configuration variants |
| --- | --- | --- | --- | --- | --- | --- |
| Debian | Current stable and oldstable while upstream repositories remain signed and available | APT | `x86_64`, `arm64` | Required | Required | legacy `.list`, deb822 `.sources`, security/updates/backports |
| Ubuntu | Supported LTS releases; other releases only when explicitly present in the catalog | APT | `x86_64`, `arm64` | Required | Required | archive vs ports, security/updates/backports, minimal images |
| Fedora | Current and previous supported release | DNF/DNF5 | `x86_64`, `arm64` | Required | Representative image | metalink/mirrorlist/baseurl, modular repositories |
| Rocky Linux / AlmaLinux | Upstream-supported major releases represented by the catalog | DNF | `x86_64`, `arm64` | Required | Representative image | BaseOS/AppStream/CRB, EPEL kept as a distinct upstream |
| CentOS Stream | Upstream-supported streams represented by the catalog | DNF/YUM compatibility | `x86_64`, `arm64` | Required | Representative image | Stream vs Vault/Archive is never inferred |
| Arch Linux | Rolling snapshot used by CI | Pacman | `x86_64` | Required | Representative image | mirrorlist and repository order |
| Arch Linux ARM | Rolling snapshot used by CI | Pacman | `arm64` | Representative host | Representative image | distinct upstream and paths from Arch Linux |
| openSUSE | Supported Leap and Tumbleweed snapshots represented by the catalog | Zypper | `x86_64`, `arm64` where upstream provides it | Required | Representative image | base/updates/ports/Packman kept distinct |
| Alpine Linux | Current and previous stable branch represented by the catalog | APK | `x86_64`, `arm64` | Required | Required | main/community/testing, minimal container layout |
| Gentoo | Rolling snapshot | Portage/emerge | `x86_64`, `arm64` | Extended | Not a release gate | distfiles vs repository sync |
| Void Linux | Rolling snapshot | XBPS | `x86_64`, `arm64` where upstream provides it | Extended | Not a release gate | glibc/musl and architecture paths |
| Nix / Guix | Client versions in the CI support range | Nix/Guix | `x86_64`, `arm64` | Extended | Not a release gate | binary cache/substitute signatures |
| OpenWrt / ImmortalWrt | Exact releases and targets present in the catalog | opkg | Explicit target architectures only | Extended | Not applicable | release + target + subtarget + architecture |

“Required” participates in the release gate. “Representative” requires at
least one real configuration boundary fixture or environment. “Extended” is
implemented and reported independently but does not broaden the minimum distro
release gate.

## Operation and scope contract

| Scope | Default | Permission behavior | Configuration rule |
| --- | --- | --- | --- |
| System | Selected only for a detected supported system tool | Plan without privilege; request elevation only for apply/restore | Preserve unrelated repositories and security settings |
| User | Selected for a detected supported user tool | No elevation unless the tool requires it | Prefer the tool’s supported user-level API/config file |
| Project | Off | Explicit opt-in for each project | Show exact project diff; never change lock files |
| Environment/session | Off unless supplied by the user | No persistence by default | Report precedence over persistent settings |

## System package managers

| Tool | Issue | Default selection | Scope / permission | Formats or configuration surface | Verification boundary | v0.1 status |
| --- | --- | --- | --- | --- | --- | --- |
| APT | [#27](https://github.com/vibelab-tools/MirrorSwitch/issues/27) | Installed and supported Debian-family OS | System / elevated apply | `.list`, deb822 `.sources`, keyrings | `apt-get update` and effective source parse | Planned |
| DNF | [#28](https://github.com/vibelab-tools/MirrorSwitch/issues/28) | Installed DNF/DNF5 | System / elevated apply | `.repo`, variables, metalink/mirrorlist/baseurl | metadata refresh/query | Planned |
| YUM | [#29](https://github.com/vibelab-tools/MirrorSwitch/issues/29) | Real YUM environment, not a duplicate DNF alias | System / elevated apply | `.repo`, releasever/basearch, Vault rules | metadata refresh/query | Planned |
| Pacman | [#30](https://github.com/vibelab-tools/MirrorSwitch/issues/30) | Installed on a supported Arch-family upstream | System / elevated apply | `pacman.conf`, Include, mirrorlist | database refresh/query | Planned |
| Zypper | [#31](https://github.com/vibelab-tools/MirrorSwitch/issues/31) | Installed on supported SUSE-family OS | System / elevated apply | repository definitions, priority, refresh | repository refresh/query | Planned |
| APK | [#33](https://github.com/vibelab-tools/MirrorSwitch/issues/33) | Installed on Alpine | System / elevated apply | `/etc/apk/repositories` | index refresh/query | Planned |
| Portage/emerge | [#32](https://github.com/vibelab-tools/MirrorSwitch/issues/32) | Installed; extended scope | System / elevated apply | `GENTOO_MIRRORS`, repos.conf | emerge/emaint query | Planned |
| XBPS | [#34](https://github.com/vibelab-tools/MirrorSwitch/issues/34) | Installed; extended scope | System / elevated apply | repository config | index refresh/query | Planned |
| Nix | [#35](https://github.com/vibelab-tools/MirrorSwitch/issues/35) | Installed; extended scope | User or daemon-specific | substituters, trusted keys, channels/flakes | effective config and real query | Planned |
| GNU Guix | [#36](https://github.com/vibelab-tools/MirrorSwitch/issues/36) | Installed daemon on a foreign Linux distribution; extended scope | System daemon / elevated apply | systemd substitute URLs; authorized keys and channels are read-only | effective unit/ACL parse and `guix weather` | Supported |
| Flatpak | [#37](https://github.com/vibelab-tools/MirrorSwitch/issues/37) | Installed with an existing mapped Flathub remote | System or user / scope-specific elevation | OSTree remote URL; GPG policy, priority and custom remotes preserved | architecture-specific `remote-ls` | Supported |
| opkg | [#38](https://github.com/vibelab-tools/MirrorSwitch/issues/38) | OpenWrt / ImmortalWrt with exact release, target, subtarget and package architecture | System / elevated apply | mapped `distfeeds.conf` roots; custom feeds, order and signature policy preserved | per-feed `Packages.gz` + `Packages.sig`, then `opkg update` and `opkg list` | Supported |

## Language and build tools

| Ecosystem | Tools and implementation issues | Default scope | Required compatibility/validation | v0.1 status |
| --- | --- | --- | --- | --- |
| Python packages | [pip #39](https://github.com/vibelab-tools/MirrorSwitch/issues/39), [uv #46](https://github.com/vibelab-tools/MirrorSwitch/issues/46), [Poetry #45](https://github.com/vibelab-tools/MirrorSwitch/issues/45), [PDM #43](https://github.com/vibelab-tools/MirrorSwitch/issues/43) | User; project off | Client version, Simple API, metadata and artifact download; client-specific multi-index rules | Planned |
| Python distributions | [Conda/Mamba #42](https://github.com/vibelab-tools/MirrorSwitch/issues/42), [pyenv #69](https://github.com/vibelab-tools/MirrorSwitch/issues/69) | User | channel/subdir/architecture or exact source release and checksum | Planned |
| Node packages | [npm #40](https://github.com/vibelab-tools/MirrorSwitch/issues/40), [pnpm #44](https://github.com/vibelab-tools/MirrorSwitch/issues/44), [Yarn #41](https://github.com/vibelab-tools/MirrorSwitch/issues/41) | User; project off | client version, metadata, tarball, scopes/auth preservation | Planned |
| Node distributions | [nvm #49](https://github.com/vibelab-tools/MirrorSwitch/issues/49), [fnm #50](https://github.com/vibelab-tools/MirrorSwitch/issues/50) | User environment | version index, checksum, `x64`/`arm64` assets | Planned |
| JVM/build | [Maven #48](https://github.com/vibelab-tools/MirrorSwitch/issues/48), [Gradle #47](https://github.com/vibelab-tools/MirrorSwitch/issues/47), [sbt #61](https://github.com/vibelab-tools/MirrorSwitch/issues/61), [Leiningen #62](https://github.com/vibelab-tools/MirrorSwitch/issues/62), [Bazel #70](https://github.com/vibelab-tools/MirrorSwitch/issues/70) | User; project off | Maven/Ivy layout, plugin/artifact/distribution separation, exact resolver semantics | Planned |
| Go | [Go Modules #51](https://github.com/vibelab-tools/MirrorSwitch/issues/51) | User environment | proxy protocol and private-module/checksum exclusions | Planned |
| Rust | [Cargo #53](https://github.com/vibelab-tools/MirrorSwitch/issues/53), [rustup #54](https://github.com/vibelab-tools/MirrorSwitch/issues/54) | User | sparse/git index vs crate download; toolchain manifest/components/targets | Planned |
| Ruby | [RubyGems #52](https://github.com/vibelab-tools/MirrorSwitch/issues/52), [Bundler #58](https://github.com/vibelab-tools/MirrorSwitch/issues/58) | User; project off | client-specific source identity, index, gem download, credentials | Planned |
| PHP | [Composer #55](https://github.com/vibelab-tools/MirrorSwitch/issues/55) | User/global; project off | provider metadata plus dist/source download | Planned |
| .NET | [NuGet #56](https://github.com/vibelab-tools/MirrorSwitch/issues/56) | User; project off | v3 service index, registration, flat container, source mapping | Planned |
| Haskell | [Cabal #57](https://github.com/vibelab-tools/MirrorSwitch/issues/57), [Stack #59](https://github.com/vibelab-tools/MirrorSwitch/issues/59), [GHCup #60](https://github.com/vibelab-tools/MirrorSwitch/issues/60) | User; project off | security metadata, Hackage/Stackage distinction, toolchain assets by architecture | Planned |
| Perl | [CPAN clients #67](https://github.com/vibelab-tools/MirrorSwitch/issues/67) | User | client-specific config, indexes, distributions and checksum | Planned |
| R | [CRAN #68](https://github.com/vibelab-tools/MirrorSwitch/issues/68), [Bioconductor #64](https://github.com/vibelab-tools/MirrorSwitch/issues/64) | User; project off | R/Bioconductor version pairing, all required repository classes | Planned |
| TeX | [tlmgr/CTAN #65](https://github.com/vibelab-tools/MirrorSwitch/issues/65) | User/system install-specific | TeX Live release year, tlpkg metadata, platform assets | Planned |
| Dart/Flutter | [Dart Pub #63](https://github.com/vibelab-tools/MirrorSwitch/issues/63), [Flutter #66](https://github.com/vibelab-tools/MirrorSwitch/issues/66) | User | registry vs SDK/engine artifacts, channel/version/architecture | Planned |
| Julia | [Julia Pkg #72](https://github.com/vibelab-tools/MirrorSwitch/issues/72) | User | package server protocol, registry, source and artifacts | Planned |
| OCaml | [opam #71](https://github.com/vibelab-tools/MirrorSwitch/issues/71) | User; project off | repository protocol vs archive cache | Planned |
| Emacs | [package.el/ELPA #80](https://github.com/vibelab-tools/MirrorSwitch/issues/80) | User | each archive independently mapped, metadata/package/signature | Planned |
| C/C++ | [Conan #73](https://github.com/vibelab-tools/MirrorSwitch/issues/73) | User | Conan 1/2 API, recipe and profile-compatible binary | Planned |

## Container and development infrastructure

| Configuration surface | Issues | Scope / permission | Required validation | v0.1 status |
| --- | --- | --- | --- | --- |
| Docker packages vs Registry | [Docker CE #78](https://github.com/vibelab-tools/MirrorSwitch/issues/78), [Docker daemon #75](https://github.com/vibelab-tools/MirrorSwitch/issues/75) | System / elevated apply | APT/RPM metadata is distinct from Registry v2 manifest/blob | Planned |
| Container runtimes | [containerd #79](https://github.com/vibelab-tools/MirrorSwitch/issues/79), [Podman #76](https://github.com/vibelab-tools/MirrorSwitch/issues/76) | System or rootless user | versioned config syntax, Registry resolve/pull, no implicit insecure mode | Planned |
| Kubernetes | [packages #77](https://github.com/vibelab-tools/MirrorSwitch/issues/77), [control-plane images #74](https://github.com/vibelab-tools/MirrorSwitch/issues/74), [Helm #82](https://github.com/vibelab-tools/MirrorSwitch/issues/82) | System/user according to tool | package channels, exact image set, Chart/OCI protocol kept separate | Planned |
| Robotics | [ROS 1 #81](https://github.com/vibelab-tools/MirrorSwitch/issues/81), [ROS 2 #84](https://github.com/vibelab-tools/MirrorSwitch/issues/84) | System / elevated apply | Linux release + ROS distribution + architecture | Planned |
| CI tooling | [Jenkins #83](https://github.com/vibelab-tools/MirrorSwitch/issues/83), [GitLab Runner #93](https://github.com/vibelab-tools/MirrorSwitch/issues/93) | System; service restart never implicit | update metadata/plugin or package chain, product/version-specific | Planned |
| Databases | [MySQL #85](https://github.com/vibelab-tools/MirrorSwitch/issues/85), [MariaDB #88](https://github.com/vibelab-tools/MirrorSwitch/issues/88), [PostgreSQL #89](https://github.com/vibelab-tools/MirrorSwitch/issues/89), [MongoDB #86](https://github.com/vibelab-tools/MirrorSwitch/issues/86), [InfluxDB #87](https://github.com/vibelab-tools/MirrorSwitch/issues/87) | System / elevated apply | exact product/edition/major/channel and signed package metadata | Planned |
| Observability/search | [Elastic Stack #90](https://github.com/vibelab-tools/MirrorSwitch/issues/90), [Grafana #91](https://github.com/vibelab-tools/MirrorSwitch/issues/91), [Zabbix #92](https://github.com/vibelab-tools/MirrorSwitch/issues/92) | System / elevated apply | product component/version/channel and package metadata | Planned |
| Server/storage packages | [Nginx #95](https://github.com/vibelab-tools/MirrorSwitch/issues/95), [Ceph #94](https://github.com/vibelab-tools/MirrorSwitch/issues/94) | System / elevated apply | upstream identity, release/channel, package metadata; no service/data mutation | Planned |

## Provider coverage

The initial providers and authoritative discovery endpoints are maintained by
[the six-provider inventory issue](https://github.com/vibelab-tools/MirrorSwitch/issues/16).
The checked-in catalog must record provider coverage separately for every
normalized upstream and content type. Until that catalog entry and its adapter
probe pass, the matrix status remains `cataloged` or `planned` rather than
`supported`.

## Release-gate scenarios

At minimum, v0.1.0 must prove:

- APT on Debian and Ubuntu using both legacy and deb822 configuration, on a
  host fixture and minimal container, including the Ubuntu `arm64` ports path;
- one supported DNF-family host/container path on each architecture;
- Pacman on Arch `x86_64` and Arch Linux ARM `arm64` without conflating their
  upstreams;
- Zypper and APK representative environments;
- user-level package managers from Python, Node.js, JVM, Go, and Rust;
- Docker/containerd registry configuration without an implicit service restart;
- no-compatible-candidate, invalid remote catalog, apply-validation failure,
  rollback, and repeated-idempotent-run behavior;
- CLI, configuration-file, and TUI requests producing the same internal plan.
