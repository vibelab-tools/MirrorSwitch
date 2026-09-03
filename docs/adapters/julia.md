# Julia Pkg adapter

Issues [#72](https://github.com/vibelab-tools/MirrorSwitch/issues/72) and
[#129](https://github.com/vibelab-tools/MirrorSwitch/issues/129) implement Julia
Pkg server selection for Julia/Pkg 1.6 through 1.x on Linux and macOS
`x86_64`/`arm64`, plus Windows x64. macOS and Windows require native hosts.
Windows arm64 remains unsupported because the reviewed Julia distribution has
no native Windows arm64 runtime.

Linux and macOS persist one managed `JULIA_PKG_SERVER` assignment in an explicit
profile, container `BASH_ENV`, or selected bash, zsh, or fish profile. Windows
persists the variable as a user `REG_SZ` under `HKCU\Environment`, with the exact
original stored in a private `%LOCALAPPDATA%\MirrorSwitch\julia` recovery file.
Apply failure, verification failure, explicit restore, and repeated apply keep
the registry and recovery state consistent without a compatibility shell.

The adapter discovers the native Julia and Pkg versions, effective depot count,
first depot, active project, reachable registries, and non-General registry
count. `JULIA_DEPOT_PATH`, project `Project.toml`/`Manifest.toml`, non-General
registries, package-server authentication, proxy/certificate environment, UTF-8
BOM, newlines, and native permissions remain unchanged. Empty, dynamic,
duplicate, private, or unrepresented process-level Pkg server policy stops the
plan.

NJU is the only complete six-provider candidate. Its content gate checks the
General registry pointer and archive, fixed Example and HelloWorldC_jll package
trees, and the target-specific HelloWorldC artifact. Artifact tree and locked
response SHA-256 are selected by OS/architecture, so Linux artifacts cannot
qualify macOS or Windows latency.

After apply, native Julia runs Pkg with startup/history disabled, a leading
isolated depot, conservative registry preference, and the selected server. It
must update General, resolve the fixed Example and HelloWorldC_jll versions, and
materialize the expected native artifact. CLI, versioned configuration, and TUI
share one plan.

The native release boundary uses Julia 1.11.7 on GitHub-hosted macOS Intel,
macOS Apple Silicon, and Windows x64 runners. It validates launcher and path
behavior, depot/project/registry observations, live Pkg resolution, frontend
equality, idempotence, authentication/project immutability, permissions, and
exact recovery.
