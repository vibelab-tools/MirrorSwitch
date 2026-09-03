# Supported adapter reference

This index is the operator contract for catalog entries currently marked `supported`. The
checked-in catalog remains authoritative for exact versions, distributions, architectures,
upstreams, candidates, and content probes.

All rows use the same lifecycle: detect and plan are read-only; compatible candidates must pass
hard filters and content probes before latency ordering; apply writes through a private atomic
transaction; the adapter verifies through its public client boundary; verification failure
restores the transaction; an explicit transaction ID can be restored later. System scope requires
an elevated apply/restore, user scope runs as the owning user, and project/site scopes are explicit.
Unsupported versions, ambiguous/private-only sources, unsafe trust policy, and incomplete mirror
content remain unchanged and are reported.

## System package and host configuration

| Adapter | Scope | Verification boundary and key limit |
| --- | --- | --- |
| `apt` | system | `apt-get update`; Debian/Ubuntu list and deb822 only ([details](adapters/apt.md)) |
| `dnf` | system | DNF/DNF5 metadata refresh; reviewed Fedora/Rocky/Alma/Stream layouts ([details](adapters/dnf.md)) |
| `yum` | system | YUM refresh; true legacy CentOS only, never a duplicate DNF path ([details](adapters/yum.md)) |
| `pacman` | system | Pacman database query; Arch and Arch Linux ARM stay distinct ([details](adapters/pacman.md)) |
| `zypper` | system | Zypper refresh/query; Leap/Tumbleweed/Packman remain separate ([details](adapters/zypper.md)) |
| `apk` | system | APK index refresh/query; exact stable branch and architecture ([details](adapters/apk.md)) |
| `portage` | system | Portage/emerge read-only validation; distfiles and repository sync are independent ([details](adapters/portage.md)) |
| `xbps` | system | XBPS index refresh/query; glibc/musl and override order preserved ([details](adapters/xbps.md)) |
| `nix` | system/user | Nix store query; daemon/single-user mode and cache signatures must match ([details](adapters/nix.md)) |
| `nix-macos` | system/user | Darwin NAR/signature validation; launchd daemon state is reloaded and restored transactionally ([details](adapters/nix.md)) |
| `guix` | system | `guix weather`; daemon substitutes only, channels/keys remain read-only ([details](adapters/guix.md)) |
| `flatpak` | system/user | Architecture-specific `remote-ls`; existing mapped Flathub remote only ([details](adapters/flatpak.md)) |
| `opkg` | system | Feed signature/update/query; exact release/target/subtarget/package architecture ([details](adapters/opkg.md)) |
| `macports` | system | Paired signed ports tree and binary archive; Darwin/architecture-specific `archivefetch` ([details](adapters/macports.md)) |
| `msys2` | system | Installation-local signed MSYS/MinGW databases and package download; never Arch Linux paths ([details](adapters/msys2.md)) |
| `winget` | system | Signed pre-indexed source plus architecture-specific hash-checked download; msstore/custom sources preserved ([details](adapters/winget.md)) |
| `cygwin` | system | x86_64 signed setup metadata and download-only package verification; Windows ARM64 rejected ([details](adapters/cygwin.md)) |

## Language, build, and editor tools

| Adapter | Scope | Verification boundary and key limit |
| --- | --- | --- |
| `pip` | system/user/site | Linux/macOS/Windows `pip config` hierarchy plus fixed package query; native paths, text layout and environment/auth policy are preserved ([details](adapters/pip.md)) |
| `pdm` | user/project | Linux/macOS/Windows PDM source query; native config roots, explicit project scope and source ordering preserved ([details](adapters/pdm.md)) |
| `poetry` | project | Linux/macOS/Windows Poetry resolver; package sources are explicit project state, not publishing repositories ([details](adapters/poetry.md)) |
| `uv` | user/project | Linux/macOS/Windows no-cache dry-run resolution; native config roots and named/private project sources preserved ([details](adapters/uv.md)) |
| `npm` | system/user/project | Linux/macOS/Windows registry metadata, tarball and client query; npm-reported paths, scopes and auth preserved ([details](adapters/npm.md)) |
| `pnpm` | user | Linux/macOS/Windows registry metadata/tarball and `pnpm view`; native pnpm 10/11 config roots and project/auth/TLS policy preserved ([details](adapters/pnpm.md)) |
| `yarn` | user/project | Linux/macOS/Windows Classic/Berry query; native paths, generations and configuration formats never cross ([details](adapters/yarn.md)) |
| `conda` | user | Linux/macOS/Windows Conda/Mamba/Micromamba search; native channel/subdir completeness required ([details](adapters/conda.md)) |
| `pyenv` | user | Exact Python release/archive query; custom definitions and runtime overrides preserved ([#69](https://github.com/vibelab-tools/MirrorSwitch/issues/69)) |
| `maven` | user | Linux/macOS/Windows fixed dependency resolution; Maven-reported home plus private mirrors/servers/proxies preserved ([details](adapters/maven.md)) |
| `gradle` | user/project | Linux/macOS/Windows dependency and Wrapper verification; native `gradlew`/`gradlew.bat` and explicit project scope ([details](adapters/gradle.md)) |
| `sbt` | user | Linux/macOS/Windows Maven/Ivy dependency resolution; native launcher/JVM and distinct layouts preserved ([details](adapters/sbt.md)) |
| `leiningen` | user | Linux/macOS/Windows Clojars/Maven dependency resolution; native launcher, profiles and credentials preserved ([details](adapters/leiningen.md)) |
| `bazel` | system/user | Bazelisk release or signed APT path; project files and checksum policy preserved ([#70](https://github.com/vibelab-tools/MirrorSwitch/issues/70)) |
| `nvm` | user | Remote version query; one initialized shell profile and Node/io.js roots ([details](adapters/nvm.md)) |
| `fnm` | user | Remote protocol query; persistent shell environment must be explicit ([details](adapters/fnm.md)) |
| `go` | user | Linux/macOS/Windows fixed module download with checksum; reported GOENV plus GOPROXY fallback/private rules preserved ([details](adapters/go.md)) |
| `cargo` | user | Linux/macOS/Windows sparse/git index and checksum/archive query; native CARGO_HOME and private registries preserved ([details](adapters/cargo.md)) |
| `rustup` | user | Linux/macOS shell or Windows HKCU environment plus `rustup check`; platform triples and dist/update roots stay paired ([details](adapters/rustup.md)) |
| `rubygems` | user | Linux/macOS/Windows RubyGems-reported gemrc plus fixed dependency query; ordered private sources, credentials, TLS options, encoding and native permissions preserved ([details](adapters/rubygems.md)) |
| `bundler` | user/project | Linux/macOS/Windows native config hierarchy and fixed lock query; private/auth/TLS settings, BOM/newlines, Gemfile and lockfile are preserved ([details](adapters/bundler.md)) |
| `composer` | user | Linux/macOS/Windows native COMPOSER_HOME plus isolated diagnose/query; auth, private/project priority, TLS config, BOM/newlines and native permissions preserved ([details](adapters/composer.md)) |
| `cocoapods` | user/project | Existing Specs Git repo or explicit Podfile source; CDN and dependency assets remain distinct ([details](adapters/cocoapods.md)) |
| `scoop` | user | Installed official bucket origins plus architecture-specific `scoop download`; manifest assets are not rewritten ([details](adapters/scoop.md)) |
| `nuget` | user | Linux and Windows NuGet/dotnet config hierarchy and fixed restore/install; shared Windows config, encoding, mappings and auth preserved ([details](adapters/nuget.md)) |
| `cabal` | user | Secure index/package query; project configuration remains read-only ([details](adapters/cabal.md)) |
| `stack` | user/project | Snapshot/Hackage/toolchain query; project scope explicit ([details](adapters/stack.md)) |
| `ghcup` | user | Signed metadata and bindist checks; custom channels and keys preserved ([details](adapters/ghcup.md)) |
| `cpan` | user | CPAN/CPANM index and distribution query; client-specific config preserved ([#67](https://github.com/vibelab-tools/MirrorSwitch/issues/67)) |
| `cran` | user | Fixed R package query; named repositories and Bioconductor policy preserved ([#68](https://github.com/vibelab-tools/MirrorSwitch/issues/68)) |
| `bioconductor` | user | Version-paired repository/package query; project/renv configuration stays read-only ([#64](https://github.com/vibelab-tools/MirrorSwitch/issues/64)) |
| `tlmgr` | system/user | TeX Live remote query; release year and installation platform must match ([#65](https://github.com/vibelab-tools/MirrorSwitch/issues/65)) |
| `dart-pub` | user | Linux/macOS shell profile or Windows HKCU environment plus isolated fixed-package resolution; token/project state preserved and Flutter SDK artifacts excluded ([details](adapters/dart-pub.md)) |
| `flutter` | user | Flutter storage plus Pub query; both repository classes must validate ([#66](https://github.com/vibelab-tools/MirrorSwitch/issues/66)) |
| `julia` | user | Isolated Pkg resolve; depot/registries/projects remain read-only ([#72](https://github.com/vibelab-tools/MirrorSwitch/issues/72)) |
| `opam` | user | Repository/package archive query; project switches remain read-only ([#71](https://github.com/vibelab-tools/MirrorSwitch/issues/71)) |
| `elpa` | user | Batch archive refresh; GNU/NonGNU/MELPA selected independently ([#80](https://github.com/vibelab-tools/MirrorSwitch/issues/80)) |

## Containers and development infrastructure

| Adapter | Scope | Verification boundary and key limit |
| --- | --- | --- |
| `docker-ce` | system | Signed APT/RPM refresh; package repository only, not daemon registry ([#78](https://github.com/vibelab-tools/MirrorSwitch/issues/78)) |
| `containerd` | system | Effective config plus real registry pull; service restart is reported, never automatic ([#79](https://github.com/vibelab-tools/MirrorSwitch/issues/79)) |
| `podman-registry` | system/user | Registries.conf parse plus real pull; TLS/auth/custom policy preserved ([#76](https://github.com/vibelab-tools/MirrorSwitch/issues/76)) |
| `kubernetes-packages` | system | Signed APT/RPM refresh for exact maintained minor channel ([#77](https://github.com/vibelab-tools/MirrorSwitch/issues/77)) |
| `kubernetes-images` | user | Exact kubeadm image manifest/pull plan; CoreDNS mapping is explicit ([#74](https://github.com/vibelab-tools/MirrorSwitch/issues/74)) |
| `ros` | system | Signed ROS 1 Noetic/Focal snapshot refresh; ROS 2 is a separate unsupported adapter ([#81](https://github.com/vibelab-tools/MirrorSwitch/issues/81)) |
| `gitlab-runner` | system | Signed package metadata refresh; runner registration/executor/server config untouched ([#93](https://github.com/vibelab-tools/MirrorSwitch/issues/93)) |
| `mysql` | system | Signed MySQL Community 8.4 APT/RPM refresh; server/data untouched ([#85](https://github.com/vibelab-tools/MirrorSwitch/issues/85)) |
| `mariadb` | system | Signed MariaDB 11.8 repository refresh; server/data untouched ([#88](https://github.com/vibelab-tools/MirrorSwitch/issues/88)) |
| `postgresql` | system | Signed PGDG 17 repository refresh; server/data untouched ([#89](https://github.com/vibelab-tools/MirrorSwitch/issues/89)) |
| `mongodb` | system | Signed MongoDB Community 8.0 repository refresh; server/data untouched ([#86](https://github.com/vibelab-tools/MirrorSwitch/issues/86)) |
| `influxdb` | system | Signed stable 2.x package repository refresh; service/data untouched ([#87](https://github.com/vibelab-tools/MirrorSwitch/issues/87)) |
| `elasticstack` | system | Signed Elastic 9.x package repository refresh; service/data untouched ([#90](https://github.com/vibelab-tools/MirrorSwitch/issues/90)) |
| `grafana` | system | Signed Grafana 13.x stable repository refresh; service/data untouched ([#91](https://github.com/vibelab-tools/MirrorSwitch/issues/91)) |
| `zabbix` | system | Signed Zabbix 7.4 stable repository refresh; service/data untouched ([#92](https://github.com/vibelab-tools/MirrorSwitch/issues/92)) |
| `ceph` | system | Signed Ceph Squid package repository refresh; cluster/config/data untouched ([#94](https://github.com/vibelab-tools/MirrorSwitch/issues/94)) |
| `nginx` | system | Signed Nginx stable/mainline repository refresh; service/config/data untouched ([#95](https://github.com/vibelab-tools/MirrorSwitch/issues/95)) |

## Not supported in v0.1.0

The Linux catalog keeps Conan, Docker daemon registry mirrors, Helm, Jenkins Update Center, and
ROS 2 in `planned` state because their v0.1 acceptance evidence is incomplete. They are not
compiled adapters and cannot write configuration. macOS and Windows entries are deferred to the
v0.2.0 milestone and are likewise inert in the Linux binary.
