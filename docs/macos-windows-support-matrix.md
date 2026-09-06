# v0.2.0 macOS and Windows support matrix

This document defines what MirrorSwitch must prove before a macOS or Windows result can be called
supported. The six-provider inventory lists candidates; it does not override the native tool's OS,
architecture, permission, signature, or repository rules.

## Release platform baseline

| Product target | Release status | Native verification gate | Notes |
| --- | --- | --- | --- |
| macOS 14+ Apple Silicon arm64 | Required | `macos-15` arm64 GitHub runner plus tool-specific native checks | Homebrew default prefix `/opt/homebrew`; no container result substitutes for macOS. |
| macOS 14+ Intel x86_64 | Required | `macos-15-intel` GitHub runner plus tool-specific native checks | Homebrew default prefix `/usr/local`; Intel support follows each upstream tool. |
| Windows 10 1809+ x86_64 | Required | Windows x64 native build/tests plus an explicit Windows 10 compatibility check | WinGet and MSYS2 use 1809 as their current minimum client baseline. |
| Windows 11 x86_64 | Required | Windows x64 native build/tests | Paths, ACLs, UAC, PowerShell and CRLF/UTF-16 behavior are native boundaries. |
| Windows 11 arm64 | Required | `windows-11-arm` native runner | Tool/package ARM64 support is filtered independently; x64 emulation is not native proof. |
| Windows 10 arm64 | Not yet a release claim | Build may be produced, but native client verification is missing | MSYS2 explicitly requires Windows 11 ARM64. Other tools remain per-Issue until a Windows 10 ARM64 host is available. |

Rust's four release targets are `x86_64-apple-darwin`, `aarch64-apple-darwin`,
`x86_64-pc-windows-msvc`, and `aarch64-pc-windows-msvc`. Rust treats both Windows MSVC targets as
Windows 10+ targets, but that compiler contract does not prove any package manager, mirror, or
installer works on a particular Windows client release.

## Scope and permission rules

| Scope | macOS | Windows | Default behavior |
| --- | --- | --- | --- |
| User | Home directory, `~/Library` or tool-reported path; no elevation | `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%` or tool-reported path; no elevation | May be selected after the exact tool is detected. |
| System/machine | `/Library`, `/opt/local` or daemon config; elevated write | `%ProgramData%`, Program Files or machine source registration; UAC/elevated write | Plan is read-only; apply/restore must already have the required authority. |
| Project/solution | Repository-local config | Repository/solution-local config on any drive | Off by default and requires an explicit scope. Lock files remain read-only. |
| Environment/session | Shell profile or tool-owned persistent environment | PowerShell/profile or tool-owned persistent environment | Never writes a process-only override as if it were persistent configuration. |

macOS launch services and Windows services are never restarted automatically. A plan reports any
reload/restart impact. Windows ACLs, hidden attributes, CRLF/UTF-16 encodings, case-insensitive paths,
drive/UNC roots, and atomic replacement behavior are part of the transaction test, not formatting
details.

## macOS-native tool matrix

| Tool | Architectures | Configuration type | Six-provider state | Verification | Issue |
| --- | --- | --- | --- | --- | --- |
| Homebrew | x86_64, arm64 | User shell variables; Git, signed JSON API, bottle/artifact endpoints | USTC is the first complete candidate to validate; TUNA/NJU/SJTUG/Alibaba are partial by surface | `brew update`, API read, bottle manifest/blob and fixed formula | [#96](https://github.com/vibelab-tools/MirrorSwitch/issues/96) |
| Nix | `x86_64-darwin`, `aarch64-darwin` | User or daemon substituters plus trusted keys | TUNA/NJU verified; USTC/SJTUG partial | Darwin `.narinfo`, NAR hash/signature and `nix path-info` | [#97](https://github.com/vibelab-tools/MirrorSwitch/issues/97) |
| CocoaPods | x86_64, arm64 | Existing user Specs Git repository; project Podfile only when explicit | TUNA/NJU Specs Git verified; Huawei archive and all CDN replacements partial | Git metadata, podspec, Podfile parsing and declared source tag | [#98](https://github.com/vibelab-tools/MirrorSwitch/issues/98) |
| MacPorts | x86_64, arm64 | System `/opt/local/etc/macports` sources and archive sites | Alibaba/NJU/SJTUG paired tree and package candidates verified | Signed `port sync`, `info` and matching Darwin `archivefetch` | [#99](https://github.com/vibelab-tools/MirrorSwitch/issues/99) |

## Windows-native tool matrix

| Tool | OS/architecture | Configuration type and authority | Six-provider state | Verification | Issue |
| --- | --- | --- | --- | --- | --- |
| WinGet | Windows 10 1809+/11 x64; Windows 11 arm64 | Command-managed `Microsoft.PreIndexed.Package`; replacing `winget` requires elevation | USTC and NJU source v1/v2 verified | signed source update, jq manifest and architecture-specific hash-checked download | [#103](https://github.com/vibelab-tools/MirrorSwitch/issues/103) |
| Chocolatey | Windows 10/11 x64; arm64 not claimed | Machine OData source, priority/auth/certificate; elevation | No compatible six-provider feed | `choco source list` plus OData and `.nupkg` | [#101](https://github.com/vibelab-tools/MirrorSwitch/issues/101) |
| Scoop | Windows 10/11 x64; Windows 11 arm64 | User bucket Git; global app state remains read-only | Seven NJU bucket Git mirrors verified; manifest installer URLs are not mirrored | refs, jq architecture branch, search and hash-checked download | [#100](https://github.com/vibelab-tools/MirrorSwitch/issues/100) |
| MSYS2 | Windows 10 1809+/11 x64; Windows 11 arm64 preliminary | Installation-local signed Pacman mirrorlists | All six verified for MSYS/UCRT64/CLANGARM64; 32-bit subsystems use their own probes | signed DB/package, `pacman -Syy`, query and `-Sw` | [#102](https://github.com/vibelab-tools/MirrorSwitch/issues/102) |
| Cygwin | Windows 10/11 x86_64 only | `setup.rc` last mirror; root/cache/package selection read-only | Huawei/TUNA current official candidates; Alibaba/NJU partial | signed `setup.xz` and download-only dash archive | [#104](https://github.com/vibelab-tools/MirrorSwitch/issues/104) |
| PowerShell Gallery | Windows 10/11 x64/arm64 where PowerShell supports it | PowerShellGet/PSResourceGet user repository registrations | No compatible six-provider feed | repository list/find/save and module `.nupkg` | [#105](https://github.com/vibelab-tools/MirrorSwitch/issues/105) |
| NuGet | Windows 10/11 x64/arm64 | Shared `%APPDATA%` user config mutable; Visual Studio/additional/project/computer configs read-only | Huawei v3 candidate verified in the catalog | service index, registration, package hash, dotnet/nuget query, native restore and UTF-16/ACL preservation | [#107](https://github.com/vibelab-tools/MirrorSwitch/issues/107) |
| Host/WSL isolation | x64/arm64 host; each WSL distro separately | Host default; one explicit `--wsl NAME` child with matching Linux CLI | Not a mirror candidate | inventory plus independent two-distro apply/restore | [#106](https://github.com/vibelab-tools/MirrorSwitch/issues/106) |

## Cross-platform adapter matrix

The protocol may be shared with Linux, but native configuration and tool execution are not.
Every tool has an independent Issue listed in the
[platform inventory](macos-windows-inventory.md#existing-adapters-that-need-native-extension).

| Group | macOS | Windows | Typical scope | Candidate/validation rule |
| --- | --- | --- | --- | --- |
| pip | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | System/user; site explicit | Six complete Simple API candidates; native config precedence, virtual-environment path, encoding and client query are revalidated. |
| uv | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User; project explicit | Six Simple API/wheel candidates; native system/user paths, project precedence and dry-run resolver are revalidated. |
| PDM | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User; project explicit | Six Simple API/wheel candidates; native site/user paths, initialized venv or PEP 582 context and client query are revalidated. |
| Poetry | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | Project explicit | Six Simple API/wheel candidates; native read-only global credential paths and project resolver are revalidated. |
| Conda | Implemented for `osx-64`/`osx-arm64`; native release gate required | Implemented for `win-64`; no native `win-arm64` repository | User | NJU/TUNA/USTC default plus conda-forge repodata and representative package checks for each native subdir. |
| npm | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | System/user; project explicit | Huawei metadata/tarball chain; npm-reported native paths, scopes, auth and real `npm view` are revalidated. |
| pnpm | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User; project read-only | pnpm 10 `.npmrc` and pnpm 11 native `auth.ini`/`config.yaml`; Huawei metadata/tarball and `pnpm view`. |
| Yarn | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User; project explicit | Classic `.yarnrc` and Berry `.yarnrc.yml` remain separate; Huawei metadata/tarball and generation-specific query. |
| fnm | Implemented on native x86_64/arm64 | Implemented on native x64; reviewed fnm release has no Windows arm64 binary | User shell profile | Five Node.js release candidates; exact Darwin/Windows archive, checksum manifest, Unix/PowerShell initialization, private policy, encoding and native `list-remote --arch` are revalidated ([#139](https://github.com/vibelab-tools/MirrorSwitch/issues/139)). |
| nvm | Implemented on native x86_64/arm64; Apple Silicon configures Node only because legacy io.js has no Darwin arm64 artifact | Unix adapter not applicable | One POSIX user shell environment | Five Node candidates plus Huawei io.js where platform-applicable; exact Darwin archive, profile policy, encoding and native `ls-remote` are revalidated ([#140](https://github.com/vibelab-tools/MirrorSwitch/issues/140)). nvm-windows remains a different tool. |
| pyenv | Implemented on native x86_64/arm64 | Unix adapter not applicable | One user shell environment | Three complete Python source candidates; macOS `shasum`, pyenv root/definition, profile policy, encoding and fixed CPython archive are revalidated ([#141](https://github.com/vibelab-tools/MirrorSwitch/issues/141)). pyenv-win remains a different tool. |
| Maven | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Three POM/metadata/JAR/checksum candidates; native launcher/JDK, Maven home, effective settings and dependency goal. |
| Gradle | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User; Wrapper project explicit | Three Maven candidates plus Huawei/NJU Wrapper distributions; native JVM and `gradlew`/`gradlew.bat`. |
| sbt | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Paired Huawei Maven/Ivy metadata, artifact and checksum probes; native JVM/launcher and plugin resolution. |
| Leiningen | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Six independently probed Maven/Clojars candidates; native JVM, `lein`/`lein.bat`, plugin/dependency resolution and recovery. |
| Go Modules | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Aliyun module + checksum-database protocol; native `go env GOENV`, private patterns, module download and h1 checksums. |
| Cargo | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Aliyun/NJU/USTC sparse index, crate SHA-256 and real `cargo info`; native CARGO_HOME and project hierarchy. |
| rustup | Implemented through the existing adapter; native release gate required | Implemented with HKCU user-environment recovery; native release gate required | User | Huawei/USTC manifest, host-triple components and checksum-pinned `rustup-init`; Windows never writes Unix profiles. |
| RubyGems | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Four classic-index/gemspec/gem candidates; RubyGems-reported gem home/gemrc/credentials and certificate inventory, UTF-8 BOM/newlines, private sources and real dependency query are revalidated. |
| Bundler | Implemented through the existing adapter; native release gate required | Implemented with native PATHEXT launcher and per-command environment isolation; native release gate required | User; project explicit | Four Compact/classic-index candidates; native global/local config hierarchy, BOM/newlines, private/auth/TLS settings and real lock query are revalidated. |
| Composer | Implemented on x86_64/arm64; native release gate required | Implemented on x64; native Windows arm64 PHP is unavailable | User; project read-only | Huawei metadata/dist/VCS chain; native COMPOSER_HOME/launcher, isolated query, auth, project priority, BOM/newlines and permissions are revalidated. |
| Dart Pub | Implemented through native shell profiles; native release gate required | Implemented through HKCU user-environment recovery; native release gate required | User | TUNA/SJTUG metadata and archive candidates; native token/cache paths, private/project state and fixed `dart pub` resolution are revalidated without Flutter SDK settings. |
| Flutter | Implemented on x86_64/arm64 through native profiles; native release gate required | Implemented on x64 through HKCU pair recovery; no native Windows arm64 SDK archive | User | NJU/SJTUG platform release and engine provenance plus TUNA/SJTUG Pub chain must both pass before native precache/doctor/query. |
| Julia Pkg | Implemented on x86_64/arm64 through native profiles; native release gate required | Implemented on x64 through HKCU recovery; no reviewed native Windows arm64 Julia runtime | User | NJU General/package chain plus OS/architecture-specific JLL artifact; depot, private registries, auth and project files remain read-only. |
| CRAN | Implemented on x86_64/arm64 with native R 4.6 binary trees; native release gate required | Implemented on x64 with native R 4.6 binary tree; no reviewed Windows arm64 R runtime | User | Four source/binary-complete candidates; Rprofile.site/user/project/renv priority and target package archive are revalidated. |
| Bioconductor | Implemented on x86_64/arm64 with native BioCsoft binary plus data-source classes; native release gate required | Implemented on x64 with native BioCsoft binary plus data-source classes; no reviewed Windows arm64 R runtime | User | NJU/TUNA CRAN-preserving repository set; R/Bioc versions, all classes, auth/project state and target archive types are revalidated. |
| opam | Implemented on x86_64/arm64 with official native binaries; native release gate required | Implemented on x64 with official opam 2.2+ executable; no native Windows arm64 release | User | NJU Git revision plus SJTUG checksum cache; native reported root, private trust, switches and project state are revalidated without WSL/Cygwin. |
| GHCup | Implemented on x86_64/arm64 with official native executables; native release gate required | Implemented on x64; no native Windows arm64 GHC toolchain in reviewed metadata | User | Signed NJU metadata plus GHC/Cabal/HLS/Stack platform bindists; native path, GPG/checksum policy, encoding and recovery are revalidated ([#133](https://github.com/vibelab-tools/MirrorSwitch/issues/133)). |
| Cabal | Implemented on x86_64/arm64 with native cabal-install; native release gate required | Implemented on x64; no native Windows arm64 cabal-install in the reviewed toolchain | User | NJU/TUNA/USTC Hackage Security metadata, index and fixed source package; native user-config hierarchy, encoding, project policy and real update/info/get are revalidated ([#134](https://github.com/vibelab-tools/MirrorSwitch/issues/134)). |
| Stack | Implemented on x86_64/arm64 with native Stack and GHC; native release gate required | Implemented on x64; no native Windows arm64 GHC toolchain in reviewed setup metadata | User; project explicit | NJU/TUNA/USTC Stackage snapshot/global hints/platform bindists plus Hackage Security index/package; native roots, direct process environment, project policy and build are revalidated ([#135](https://github.com/vibelab-tools/MirrorSwitch/issues/135)). |
| CPAN clients | Implemented on x86_64/arm64 with native CPAN.pm and cpanminus; native release gate required | Implemented on x64 through CPAN.pm plus HKCU cpanminus recovery; no reviewed native Windows arm64 Perl runtime | User | Four complete CPAN candidates; interpreter-reported config, private/proxy/project state, native query, encoding and recovery are revalidated ([#136](https://github.com/vibelab-tools/MirrorSwitch/issues/136)). |
| tlmgr | Implemented on x86_64/arm64 using `universal-darwin`; native release gate required | Implemented on x64 using the `windows` TeX Live platform; no native Windows arm64 infrastructure package | System; initialized user tree preferred | Four complete CTAN candidates; release, installation tree, exact platform archive, verification policy and native info/platform query are revalidated ([#137](https://github.com/vibelab-tools/MirrorSwitch/issues/137)). |
| ELPA | Implemented on native x86_64/arm64 Emacs; native release gate required | Implemented on native Windows x64 Emacs; reviewed GNU build has no Windows arm64 binary | User | GNU, NonGNU and MELPA are selected independently; Emacs-reported home/init hierarchy, private archives, priorities, signature policy, encoding and batch refresh are revalidated ([#138](https://github.com/vibelab-tools/MirrorSwitch/issues/138)). |
| NuGet | Implemented for native x86_64/arm64 dotnet plus Mono/NuGet CLI; native release gate required | Implemented through the existing adapter; native release gate required | User; project/computer read-only | Huawei v3 service/registration/package chain; separate macOS dotnet and Mono user paths, `/Library/Application Support`, encoding, mappings, credentials and real restore/install are revalidated ([#142](https://github.com/vibelab-tools/MirrorSwitch/issues/142)); Windows remains [#107](https://github.com/vibelab-tools/MirrorSwitch/issues/107). |

## Status terms

- `supported`: native detection, plan, candidate content, application, public client verification,
  rollback, idempotency, both frontends, and the declared runner/architecture all passed.
- `partial`: only explicitly listed OS/version/architecture/repository surfaces passed; every other
  combination returns a reason and no plan.
- `no-compatible-mirror`: the tool can configure a repository, but none of the six providers has a
  complete safe candidate. The adapter/catalog entry remains inert.
- `not-configurable`: the tool exposes no central repository mapping suitable for this product.
- `planned`: an Issue and evidence boundary exist, but implementation has not passed acceptance.

## Release and CI gates

1. Compile and run the native binary on all four Rust targets.
2. On macOS Intel and Apple Silicon, run CLI/config/TUI smoke tests and every supported adapter's
   real file/tool boundary.
3. On Windows x64 and ARM64, use native PowerShell/Windows paths and execute CLI/config/TUI smoke
   tests. Windows 10 x64 needs an explicit compatibility result in addition to hosted server CI.
4. Re-run Linux quality, adapter, Docker, package and release gates without forking the core
   transaction implementation.
5. Publish only artifacts whose exact bytes were exercised on the corresponding native runner.

GitHub currently provides `macos-15-intel`, arm64 `macos-15`, Windows x64 hosted runners, and the
`windows-11-arm` public-preview runner. Preview availability is a CI scheduling risk, not permission
to replace native tests with cross-compilation.
