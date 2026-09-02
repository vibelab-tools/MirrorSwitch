# macOS and Windows mirror inventory

Last reviewed: 2026-09-02. This document is the research input for the v0.2.0 support matrix. It
records what a tool can configure and what the six initial providers actually publish. A directory
or Git clone is not treated as a usable mirror until the relevant metadata, representative package
or binary, integrity data, platform, and architecture all pass the tool-specific Issue.

## Capability types

The inventory keeps these surfaces separate:

| Surface | What must be verified |
| --- | --- |
| Repository metadata | Native client can parse/search it and resolve a representative version. |
| Package or binary | The selected OS/architecture payload exists and its native integrity check passes. |
| Git index | Refs and required history exist; URLs embedded in manifests are separate download surfaces. |
| Binary cache | Cache metadata, object path, platform identity, hash, and signature all agree. |
| Download cache | A file is reachable, but this alone cannot replace a package repository. |
| Generic proxy | It remains inert unless the tool has an explicit, testable mapping and trust model. |

## Native macOS tools

| Tool | Configuration and restore boundary | Architecture/version notes | Issue |
| --- | --- | --- | --- |
| Homebrew | User shell profile variables for Brew Git, JSON API, bottles/artifacts; preserve custom taps and restore exact assignments. Verify with `brew update`, API reads, bottle manifest/blob and a fixed formula. | Homebrew currently requires macOS 14+ and supports `/opt/homebrew` on Apple Silicon and `/usr/local` on Intel. Each surface is selected independently. | [#96](https://github.com/vibelab-tools/MirrorSwitch/issues/96) |
| MacPorts | `${prefix}/etc/macports/sources.conf` and `macports.conf`; system write normally needs elevation. Verify ports tree sync, search, archive metadata and a platform package. | Intel and Apple Silicon use different Darwin/platform archive paths. A ports tarball does not prove binary package coverage. | [#99](https://github.com/vibelab-tools/MirrorSwitch/issues/99) |
| CocoaPods | User Specs repos and explicit Podfile sources; source order changes resolution and project files remain opt-in. Verify spec index/CDN metadata, podspec and the pod source declared by that spec. | CocoaPods runs on macOS through Ruby. The six-provider evidence currently covers legacy Specs data, not a complete modern CDN plus every pod source. | [#98](https://github.com/vibelab-tools/MirrorSwitch/issues/98) |
| Nix | User or daemon `nix.conf` substituters and trusted public keys; restore exact ordered values. Verify Darwin `.narinfo`, NAR hash/signature and `nix path-info`. | `x86_64-darwin` and `aarch64-darwin` are distinct systems. Linux cache success cannot prove Darwin coverage. | [#97](https://github.com/vibelab-tools/MirrorSwitch/issues/97) |

Homebrew exposes four independent settings in current releases:
`HOMEBREW_BREW_GIT_REMOTE`, `HOMEBREW_API_DOMAIN`, `HOMEBREW_BOTTLE_DOMAIN`, and
`HOMEBREW_ARTIFACT_DOMAIN`. The USTC help currently documents Brew Git plus API and both legacy
and OCI bottle layouts. MirrorSwitch must not enable a provider for all four merely because one
directory responds.

## Native Windows tools

| Tool | Configuration and restore boundary | Architecture/version notes | Issue |
| --- | --- | --- | --- |
| WinGet | `winget source list/add/remove/reset`; replacing the default source requires an elevated terminal. Verify source agreement, search, manifest and installer hash. | Windows 10 1809+ and Windows 11. Package manifests independently declare x64/arm64 installers. | [#103](https://github.com/vibelab-tools/MirrorSwitch/issues/103) |
| Chocolatey | `choco source list/add/remove` with priority, disabled state, credentials and certificates preserved. Verify OData `Packages` and a `.nupkg`. | Native Windows; machine configuration normally needs administrator access. No compatible six-provider OData feed was found. | [#101](https://github.com/vibelab-tools/MirrorSwitch/issues/101) |
| Scoop | User bucket Git remotes and Scoop config. Verify bucket refs, a manifest, its architecture branch, external URL and hash before changing a bucket. | Scoop manifests can define 64bit and arm64 separately. Mirrored bucket Git does not mirror installer URLs. | [#100](https://github.com/vibelab-tools/MirrorSwitch/issues/100) |
| MSYS2 Pacman | The active MSYS2 installation's `/etc/pacman.d/mirrorlist.*`; never Windows host paths for Arch Linux. Verify signed database and a representative package with native `pacman`. | x64 supports Windows 10 1809+. ARM64 is preliminary, requires Windows 11 ARM64 and has incomplete package coverage. | [#102](https://github.com/vibelab-tools/MirrorSwitch/issues/102) |
| Cygwin setup | `setup-x86_64.exe` site argument and the installation's remembered mirror; verify `setup.xz`, signatures/checksums and a package archive. | Cygwin's current installer is x86_64 only. It must report Windows arm64 as unsupported rather than using emulation as native evidence. | [#104](https://github.com/vibelab-tools/MirrorSwitch/issues/104) |
| PowerShell Gallery | PowerShellGet and PSResourceGet registrations are separate. Preserve trust, priority, credentials and private repositories; verify NuGet metadata and a module package. | Windows PowerShell 5.1 ships an older PowerShellGet; current PSResourceGet stores per-user registrations. No six-provider PSGallery feed was found. | [#105](https://github.com/vibelab-tools/MirrorSwitch/issues/105) |
| NuGet | Windows user, additional and computer config hierarchy; only the main user config is mutable by default. Verify v3 service index, registration, package hash and a native restore. | Windows x64/arm64; project/solution config and credential providers remain read-only unless explicitly scoped. | [#107](https://github.com/vibelab-tools/MirrorSwitch/issues/107) |
| Windows host/WSL | Treat the Windows host and every WSL distribution as different roots, homes, executable namespaces and transaction stores. | WSL remains Linux and must not be used as proof of a native Windows adapter. | [#106](https://github.com/vibelab-tools/MirrorSwitch/issues/106) |

## Six-provider coverage

`Candidate` means there is enough current evidence to enter the tool Issue's validation work.
`Partial` means only some required surfaces are present. `None` means no matching public entry was
found in the provider inventory. Nothing in this table is `supported` yet.

| Tool/surface | Alibaba | Huawei | USTC | TUNA | NJU | SJTUG |
| --- | --- | --- | --- | --- | --- | --- |
| Homebrew Git/API/bottles | Partial static tree | None | Candidate: Brew Git, signed API, legacy/OCI bottles | Candidate API/bottles; Git layout still to verify | Partial Git/bottles | Partial bottles/auxiliary Git |
| MacPorts ports/packages | Partial | None | None | None | Partial | Partial |
| CocoaPods Specs/CDN/source | None | Partial archive | None | Partial legacy Specs | Partial Git/static | None |
| Nix Darwin cache/channels | None | None | Partial channels | Candidate cache/channels, Darwin objects still to verify | Candidate cache/channels, Darwin objects still to verify | Partial store/channel data |
| WinGet pre-indexed source | None | None | Candidate `source.msix` | None | Candidate `source.msix` | None |
| Chocolatey OData feed | None | None | None | None | None | None |
| Scoop bucket Git/installers | None | None | None | None | Partial bucket Git only | None |
| MSYS2 repositories | Candidate | Candidate | Candidate | Candidate | Candidate | Candidate, newly confirmed by the MSYS2 mirror list |
| Cygwin setup repository | Directory, not on current official list | Candidate and current official mirror | None | Candidate at `/sourceware/cygwin/` and current official mirror | Directory, not on current official list | None |
| PowerShell Gallery feed | None | None | None | None; PowerShell release cache only | None; PowerShell release cache only | None |
| NuGet v3 feed | None | Candidate | None | None | None | None |

Representative live checks on 2026-09-02 returned HTTP 200 for both USTC and NJU
`winget-source/source.msix`; USTC and TUNA `mingw/clangarm64/clangarm64.db`; Huawei Cygwin
`x86_64/setup.xz`; USTC/TUNA Homebrew `api/formula.jws.json`; all three cataloged MacPorts
`release/tarballs/ports.tar.gz`; Huawei's NuGet v3 index; and TUNA's Nix cache-info. The old
catalog path `https://mirrors.tuna.tsinghua.edu.cn/cygwin/` now returns 404; Cygwin's current
official link is `https://mirrors.tuna.tsinghua.edu.cn/sourceware/cygwin/`. CocoaPods sample paths
under the cataloged static roots returned 404, so those candidates remain partial pending #98.

## Existing adapters that need native extension

The network protocols below already have a Linux adapter, but config discovery, executable names,
path rules, encoding, and OS/architecture evidence must be revalidated. Each tool now has its own
v0.2.0 Issue.

| Ecosystem | Issues |
| --- | --- |
| Python | [pip #109](https://github.com/vibelab-tools/MirrorSwitch/issues/109), [uv #110](https://github.com/vibelab-tools/MirrorSwitch/issues/110), [PDM #111](https://github.com/vibelab-tools/MirrorSwitch/issues/111), [Poetry #112](https://github.com/vibelab-tools/MirrorSwitch/issues/112), [Conda/Mamba #113](https://github.com/vibelab-tools/MirrorSwitch/issues/113), [pyenv macOS #141](https://github.com/vibelab-tools/MirrorSwitch/issues/141) |
| Node.js | [npm #114](https://github.com/vibelab-tools/MirrorSwitch/issues/114), [pnpm #115](https://github.com/vibelab-tools/MirrorSwitch/issues/115), [Yarn #116](https://github.com/vibelab-tools/MirrorSwitch/issues/116), [fnm #139](https://github.com/vibelab-tools/MirrorSwitch/issues/139), [nvm macOS #140](https://github.com/vibelab-tools/MirrorSwitch/issues/140) |
| JVM | [Maven #117](https://github.com/vibelab-tools/MirrorSwitch/issues/117), [Gradle #118](https://github.com/vibelab-tools/MirrorSwitch/issues/118), [sbt #119](https://github.com/vibelab-tools/MirrorSwitch/issues/119), [Leiningen #120](https://github.com/vibelab-tools/MirrorSwitch/issues/120) |
| Go and Rust | [Go #121](https://github.com/vibelab-tools/MirrorSwitch/issues/121), [Cargo #122](https://github.com/vibelab-tools/MirrorSwitch/issues/122), [rustup #123](https://github.com/vibelab-tools/MirrorSwitch/issues/123) |
| Ruby and PHP | [RubyGems #124](https://github.com/vibelab-tools/MirrorSwitch/issues/124), [Bundler #125](https://github.com/vibelab-tools/MirrorSwitch/issues/125), [Composer #126](https://github.com/vibelab-tools/MirrorSwitch/issues/126) |
| Dart and Julia | [Dart Pub #127](https://github.com/vibelab-tools/MirrorSwitch/issues/127), [Flutter #128](https://github.com/vibelab-tools/MirrorSwitch/issues/128), [Julia #129](https://github.com/vibelab-tools/MirrorSwitch/issues/129) |
| R | [CRAN #130](https://github.com/vibelab-tools/MirrorSwitch/issues/130), [Bioconductor #131](https://github.com/vibelab-tools/MirrorSwitch/issues/131) |
| OCaml and Haskell | [opam #132](https://github.com/vibelab-tools/MirrorSwitch/issues/132), [GHCup #133](https://github.com/vibelab-tools/MirrorSwitch/issues/133), [Cabal #134](https://github.com/vibelab-tools/MirrorSwitch/issues/134), [Stack #135](https://github.com/vibelab-tools/MirrorSwitch/issues/135) |
| Other language tools | [CPAN #136](https://github.com/vibelab-tools/MirrorSwitch/issues/136), [tlmgr #137](https://github.com/vibelab-tools/MirrorSwitch/issues/137), [ELPA #138](https://github.com/vibelab-tools/MirrorSwitch/issues/138), [NuGet macOS #142](https://github.com/vibelab-tools/MirrorSwitch/issues/142) |

## Investigated but not added as v0.2 adapters

- Swift Package Manager can register an HTTPS package registry in
  `~/.swiftpm/configuration/registries.json`, but none of the six providers publishes a compatible
  Swift registry. Arbitrary package Git URLs remain project data.
- Carthage is decentralized: dependencies are GitHub repositories, arbitrary Git repositories, or
  per-project binary specification URLs. No six-provider central repository can be mapped without
  rewriting each Cartfile.
- Microsoft Store's `msstore` source is a special WinGet source, not a replaceable six-provider
  package mirror.
- Visual Studio Installer supports an administrator-created local/network layout. This is a
  deployment cache owned by the organization, not a public mirror endpoint supplied by the six
  providers.
- `nvm-windows` and `pyenv-win` are separate tools with different configuration and release
  models. Their Unix adapter state is not reused; no complete six-provider source was confirmed.
- Bazel release/package candidates in the current catalog cover Linux only. No macOS/Windows
  platform binary chain from the six providers has been validated.

## Primary references

- [GitHub-hosted runner labels](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
- [Homebrew configuration](https://docs.brew.sh/Manpage) and [support tiers](https://docs.brew.sh/Support-Tiers)
- [USTC Homebrew](https://mirrors.ustc.edu.cn/help/brew.git.html), [bottles](https://mirrors.ustc.edu.cn/help/homebrew-bottles.html), and [WinGet](https://mirrors.ustc.edu.cn/help/winget-source.html)
- [MacPorts configuration files](https://guide.macports.org/chunked/internals.configuration-files.html)
- [CocoaPods source ordering](https://guides.cocoapods.org/syntax/podfile)
- [Nix substituters and signatures](https://releases.nixos.org/nix/nix-2.32.3/manual/command-ref/conf-file.html)
- [WinGet source command](https://learn.microsoft.com/windows/package-manager/winget/source)
- [Chocolatey source command](https://docs.chocolatey.org/en-us/choco/commands/source/)
- [Scoop buckets](https://github.com/ScoopInstaller/Scoop/wiki/Buckets)
- [MSYS2 mirrors](https://www.msys2.org/dev/mirrors/), [ARM64 boundary](https://www.msys2.org/docs/arm64/), and [Windows support](https://www.msys2.org/docs/windows_support/)
- [Cygwin current mirrors](https://www.cygwin.com/mirrors.html)
- [PSResourceGet repositories](https://learn.microsoft.com/powershell/gallery/powershellget/supported-repositories)
- [NuGet configuration hierarchy](https://learn.microsoft.com/nuget/consume-packages/configuring-nuget-behavior)
- [Swift package registries](https://docs.swift.org/swiftpm/documentation/packagemanagerdocs/swiftpackageregistrycommands/), [Carthage origins](https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md), and [Visual Studio offline layouts](https://learn.microsoft.com/visualstudio/install/create-an-offline-installation-of-visual-studio)
