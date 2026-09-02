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
| fnm | Planned on x86_64/arm64 | Planned on x64/arm64 | User | Node release asset must match client generation and architecture. |
| nvm, pyenv | Planned for macOS only | Unix adapter not applicable | One user shell environment | nvm-windows/pyenv-win are different tools and have no validated six-provider source. |
| Maven | Implemented through the existing adapter; native release gate required | Implemented through the existing adapter; native release gate required | User | Three POM/metadata/JAR/checksum candidates; native launcher/JDK, Maven home, effective settings and dependency goal. |
| Gradle, sbt, Leiningen | Planned on x86_64/arm64 | Planned on x64/arm64 | User; project explicit | Repository layouts and wrapper/tool distributions remain distinct; use native scripts and JVM. |
| Go, Cargo, rustup | Planned on x86_64/arm64 | Planned on x64/arm64 | User | Registry/proxy config is shared only after native path, target asset and checksum checks. |
| RubyGems, Bundler, Composer | Planned on x86_64/arm64 | Planned on x64/arm64 | User; project explicit | Preserve auth/private sources and validate through native executable conventions. |
| Dart Pub, Flutter, Julia | Planned on x86_64/arm64 | Planned on x64/arm64 | User | Registry and SDK/toolchain artifacts are separate and platform-specific where applicable. |
| CRAN, Bioconductor | Planned on x86_64/arm64 | Planned on x64/arm64 | User | R/Bioconductor version and source/binary package type must match the platform. |
| opam, GHCup, Cabal, Stack | Planned where upstream tool supports the native OS | Planned where upstream tool supports the native OS | User; project explicit | Toolchain/platform bindists must pass separately from package indexes. |
| CPAN, tlmgr, ELPA | Planned on x86_64/arm64 | Planned on supported native architectures | User or install-specific system | Client-specific config, platform packages and native batch/query commands are required. |
| NuGet | Planned through the existing adapter | Implemented through the existing adapter; native release gate required | User; project/computer read-only | macOS #142 and Windows #107 use their real config hierarchies. |

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
