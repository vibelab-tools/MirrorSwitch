# MSYS2 adapter

The `msys2` adapter is a native Windows adapter for MSYS2's own Pacman configuration. It does not
reuse Arch Linux paths or repository identities. The default installation is `C:\msys64`; an
absolute `MSYS2_ROOT` may select another installation. MirrorSwitch reads `etc/pacman.conf`,
`mirrorlist.msys`, `mirrorlist.mingw`, the Pacman version, host architecture, and `MSYSTEM` before
planning.

Windows x64 supports MSYS, MINGW32, MINGW64, UCRT64, CLANG32, and CLANG64. Windows 11 ARM64 uses
the preliminary CLANGARM64 repository while the MSYS userland runs as x86_64 through Windows
emulation. Windows 10 ARM64 is rejected. The adapter also enforces the current MSYS2 minimum of
Windows 10 1809 for the GUI-installation baseline.

Alibaba Cloud, Huawei Cloud, NJU, SJTUG, TUNA, and USTC all passed the paired repository boundary.
Before latency ranking, each candidate must expose signed `msys/x86_64` and effective MinGW
databases, the fixed filesystem package, an environment-specific jq package, and both detached
signatures. Package and signature bodies are checked against reviewed SHA-256 values. The SJTUG
endpoint is recorded from MSYS2's upstream mirror list because it was absent from the older SJTUG
inventory snapshot.

## Managed state

The plan changes only the two installation-local mirrorlists. It inserts the selected provider
before the first recognized official MSYS2 anchor, removes a duplicate of that selected line, and
keeps custom entries, comments, and every remaining fallback in its original order. The MSYS list
retains `$arch`; the MinGW list retains `$repo`, so repository namespaces are never crossed.

`pacman.conf`, `SigLevel`, custom repository sections, package cache, and installed packages are
not rewritten. A global policy without `Required`, a `Never`/`TrustAll` policy, missing MSYS or
active subsystem section, unsupported subsystem/architecture pair, or malformed active server
blocks the plan. The two files are treated as installation/system scope and require elevation.

## Verification and recovery

After apply, MirrorSwitch confirms that both lists prioritize a reviewed mirror, then runs
`pacman -Syy`, queries `filesystem` and the effective MinGW jq package, and uses `pacman -Sw
--noconfirm` to download the signed architecture-specific package without installing it. Pacman
therefore remains the signature-verification boundary.

Any refresh, query, download, or signature failure restores both mirrorlists. Repeated planning is
idempotent, and explicit transaction restore returns their exact previous bytes and Windows file
attributes.
