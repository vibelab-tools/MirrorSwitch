# Install and use MirrorSwitch on macOS and Windows

MirrorSwitch v0.2 has passed its tool-specific and four-platform native gates.
The tagged macOS and Windows archives are not published until the v0.2.0 release
workflow also passes, so use the commands below with assets from that release,
not an arbitrary workflow artifact.

The commands below use `VERSION` as a placeholder. Replace it with the version
shown on the GitHub Release page, and download that release's `SHA256SUMS` file
alongside the archive.

## macOS

MirrorSwitch targets macOS 14 or newer. Choose the archive from `uname -m`:

| `uname -m` | Archive |
| --- | --- |
| `arm64` | `mirrorswitch-VERSION-macos-arm64.tar.gz` |
| `x86_64` | `mirrorswitch-VERSION-macos-x86_64.tar.gz` |

Verify only the archive you downloaded, then install its executable:

```bash
asset=mirrorswitch-VERSION-macos-arm64.tar.gz
grep "  $asset$" SHA256SUMS | shasum -a 256 -c -
tar -xzf "$asset"
sudo install -m 0755 "${asset%.tar.gz}/mirrorswitch" /usr/local/bin/mirrorswitch
mirrorswitch --version
```

Use the Intel archive name on an `x86_64` Mac. The v0.2 archive workflow
does not apply a Developer ID signature or notarization. If a browser adds the
quarantine attribute, inspect it after verifying the checksum:

```bash
xattr -p com.apple.quarantine /usr/local/bin/mirrorswitch
```

If Gatekeeper blocks the verified binary, remove only that attribute and try
the version command again:

```bash
sudo xattr -d com.apple.quarantine /usr/local/bin/mirrorswitch
mirrorswitch --version
```

Upgrade by verifying the new archive and installing its executable over the old
one. Uninstall the program with:

```bash
sudo rm /usr/local/bin/mirrorswitch
```

Uninstalling the executable does not delete transaction receipts or the cached
catalog. They remain under `~/Library/Application Support/MirrorSwitch` and
`~/Library/Caches/MirrorSwitch` so a previous change can still be inspected or
restored before those directories are removed deliberately.

## Windows 10 and Windows 11

Use 64-bit PowerShell in Windows Terminal. Windows 10 and Windows 11 x64 use the
`windows-x86_64` archive. Windows 11 arm64 uses `windows-arm64`; Windows 10
arm64 is not currently a release claim.

The following installs for the current user and does not require an
administrator terminal:

```powershell
$Version = 'VERSION'
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x86_64' }
if ($Arch -eq 'arm64' -and [Environment]::OSVersion.Version.Build -lt 22000) {
  throw 'MirrorSwitch does not claim Windows 10 arm64 support'
}
$Asset = "mirrorswitch-$Version-windows-$Arch.zip"
$Expected = ((Get-Content SHA256SUMS | Where-Object { $_ -match "  $([regex]::Escape($Asset))$" }) -split '\s+')[0]
$Actual = (Get-FileHash $Asset -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected.ToLowerInvariant()) { throw 'MirrorSwitch checksum mismatch' }

$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\MirrorSwitch'
New-Item -ItemType Directory -Force $InstallDir | Out-Null
Expand-Archive $Asset -DestinationPath $env:TEMP -Force
Copy-Item (Join-Path $env:TEMP "mirrorswitch-$Version-windows-$Arch\mirrorswitch.exe") $InstallDir -Force
& (Join-Path $InstallDir 'mirrorswitch.exe') --version
```

Add `%LOCALAPPDATA%\Programs\MirrorSwitch` to the current user's `Path` through
Windows Settings, or use this idempotent PowerShell update:

```powershell
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\MirrorSwitch'
$Entries = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ })
if ($InstallDir -notin $Entries) {
  [Environment]::SetEnvironmentVariable('Path', (($Entries + $InstallDir) -join ';'), 'User')
}
```

Open a new terminal after changing `Path`. Upgrade by verifying and copying the
new executable to the same directory. To uninstall, remove the executable and
then remove that exact directory from the user `Path` in Windows Settings:

```powershell
Remove-Item (Join-Path $env:LOCALAPPDATA 'Programs\MirrorSwitch\mirrorswitch.exe')
```

The catalog cache and transaction receipts remain under
`%LOCALAPPDATA%\MirrorSwitch`. Keep them until any required restore is complete.
User-scope adapters should run as the owning user. Open Windows Terminal as
Administrator only when a reviewed plan says `requires_elevation: true`, such
as a machine-level WinGet source change.

## First read-only run

The CLI is the same on both platforms. `status`, `detect`, and `plan` do not
apply configuration changes:

```text
mirrorswitch status --json
mirrorswitch detect --offline --json
mirrorswitch plan --category language
mirrorswitch tui
```

Without `--tool`, `--category`, or `--all`, MirrorSwitch selects only adapters
whose clients are installed, operable, and compatible with the detected OS,
architecture, environment, and default scope. Finding Python or Java alone is
not enough; the corresponding package client must also be callable.

`--offline` skips the GitHub Raw catalog update. It does not skip the content
and compatibility probes used to decide whether a mirror is actionable.

## CLI, configuration file, and TUI

All three entry points normalize to the same plan. A direct CLI request looks
like this:

```text
mirrorswitch plan --tool pip --tool cargo --scope pip=user --scope cargo=user
mirrorswitch apply --tool pip --tool cargo --scope pip=user --scope cargo=user --yes --json
```

The equivalent versioned configuration file is:

```json
{
  "version": 1,
  "tools": [
    { "id": "pip", "scope": "user" },
    { "id": "cargo", "scope": "user" }
  ]
}
```

```text
mirrorswitch plan --config request.json --json
mirrorswitch apply --config request.json --yes --json
```

`mirrorswitch tui` starts with the detected defaults and lets the user toggle
tools before viewing candidates, latency, target paths, digests, permissions,
service impact, and skipped reasons. An explicit candidate override still has
to pass every platform and content check.

## What each adapter changes

The table is a location index, not a support claim. A row is actionable only
for the OS/architecture combinations marked implemented in the
[v0.2 support matrix](macos-windows-support-matrix.md), and is supported only
after its linked native workflow has passed.

| Tools | Writable boundary | Preserved/read-only boundary |
| --- | --- | --- |
| Homebrew | Selected user shell variables | Custom taps and unrelated shell policy |
| Nix | User or daemon `nix.conf` | Substituter order, trusted keys, channels, daemon ownership |
| CocoaPods | Existing user Specs Git remote; explicit Podfile only when requested | Other repos, source order, lockfile, pod source URLs |
| MacPorts | `/opt/local/etc/macports/sources.conf` and archive policy | Keys, variants, custom sources; system scope requires elevation |
| WinGet | Command-managed selected source | `msstore`, custom sources, agreements, installer hashes |
| Scoop | Installed user bucket Git remotes and reviewed Scoop config | Bucket identity/order and external installer URLs |
| MSYS2 | Active installation's subsystem mirrorlists | Signatures, unrelated subsystems, Windows host package managers |
| Cygwin | `setup.rc` remembered mirror | Root, cache, package selection; x86_64 only |
| WSL | One explicitly named distribution | Windows host and every other distribution |
| pip | Client-reported system/user/site config | Virtual environments, credentials, extra indexes and TLS policy |
| uv, PDM, Poetry | Native user/project config selected by each client | Private sources, credentials, certificates, lockfiles and non-selected scopes |
| Conda/Mamba | User `.condarc` channel roots | Channel order, private channels, custom subdirs and TLS policy |
| npm, pnpm, Yarn | Generation-specific user or explicit project config | Scopes, auth, TLS, plugins, lockfiles and other generations |
| fnm | bash/zsh/fish profile or Windows PowerShell profile | Existing `fnm env`, hooks, private variables and project version files |
| nvm | One initialized POSIX profile on macOS | nvm-windows, private headers, other profiles and project `.nvmrc` |
| pyenv | One POSIX profile plus private verification manifest on macOS | pyenv-win, custom definitions, `pyenv init`, project version files |
| Maven, Gradle, sbt, Leiningen | Native user config; explicit project scope where documented | Servers, proxies, credentials, plugins, wrapper/checksum and project files |
| Go | Client-reported `GOENV` | Private patterns, fallback chain, workspace and module files |
| Cargo, rustup | Native Cargo/Rustup home or selected shell/Windows user environment | Private registries, credentials, toolchains, project config and checksum policy |
| RubyGems, Bundler | Client-reported gemrc/config and explicit Bundler project scope | Credentials, certificates, private sources, Gemfile and lockfile |
| Composer | Native `COMPOSER_HOME` user config | `auth.json`, private repositories and project priority |
| Dart Pub, Flutter | Selected profile or Windows user environment | Token/cache paths, project state; Flutter storage and Pub are separate chains |
| Julia | Selected profile or Windows user environment | Depot, private registries, authentication and project files |
| CRAN, Bioconductor | User/site R profile selected by the adapter | Named repositories, data classes, renv, authentication and project profiles |
| opam | Client-reported root configuration | Repository order/trust, switches and project state |
| GHCup, Cabal, Stack | Native user roots/configs; explicit Stack project scope | GPG/checksum policy, private channels/repos and project definitions |
| CPAN clients | CPAN.pm/cpanm user policy or Windows user environment | Private mirrors, proxies, credentials and `cpanfile` |
| tlmgr | Installation or initialized user TLPDB | Tagged/private repositories, pinning, verification and project state |
| ELPA | Emacs-selected init file | Custom/private archives, priorities, proxy/certificate policy and other Lisp |
| NuGet | macOS dotnet/Mono user configs or shared Windows user config | Machine/additional/project configs, credentials, mappings, disabled sources and lockfiles |

The [adapter reference](adapter-reference.md) links to each detailed contract,
including exact paths, supported versions, candidate probes, and reasons a plan
can be rejected.

## Apply and restore

Review the complete plan before applying it. A non-interactive write requires
`--yes`:

```text
mirrorswitch apply --config request.json --yes --json
```

The JSON result includes a transaction ID for every applied adapter. Restore
one exact transaction with:

```text
mirrorswitch restore TRANSACTION_ID --yes --json
```

File adapters restore the recorded bytes and permissions. Command-managed
adapters such as WinGet first restore their external source state through the
adapter, then restore the private recovery record. Unknown, corrupt, already
restored, or multi-adapter transaction identities fail without bypassing the
transaction checks.

On macOS, receipts are stored under
`~/Library/Application Support/MirrorSwitch/transactions`. On Windows they are
under `%LOCALAPPDATA%\MirrorSwitch\transactions`. Do not copy a receipt between
machines, users, Windows and WSL, or architectures.

## Current support categories

These are native-verified adapter categories. The linked matrix is the source
of truth for architecture-specific limits; final archive publication remains a
separate tagged release gate.

| Platform | Native-verified adapters | No compatible six-provider source or separate tool |
| --- | --- | --- |
| macOS | Homebrew, Nix, CocoaPods, MacPorts, pip, uv, PDM, Poetry, Conda, npm, pnpm, Yarn, fnm, nvm, pyenv, Maven, Gradle, sbt, Leiningen, Go, Cargo, rustup, RubyGems, Bundler, Composer, Dart Pub, Flutter, Julia, CRAN, Bioconductor, opam, GHCup, Cabal, Stack, CPAN, tlmgr, ELPA, NuGet | Swift Package Manager registry, Carthage, and other decentralized Git-only inputs have no compatible public six-provider mapping |
| Windows | WinGet, Scoop, MSYS2, Cygwin, host/WSL isolation, NuGet, pip, uv, PDM, Poetry, Conda, npm, pnpm, Yarn, fnm, Maven, Gradle, sbt, Leiningen, Go, Cargo, rustup, RubyGems, Bundler, Composer, Dart Pub, Flutter, Julia, CRAN, Bioconductor, opam, GHCup, Cabal, Stack, CPAN, tlmgr, ELPA | Chocolatey and PowerShell Gallery have no compatible six-provider feed; nvm-windows and pyenv-win are separate tools; Microsoft Store and Visual Studio layouts are not public mirror adapters |

Some listed tools are x64-only on Windows; some have no Windows arm64 runtime or
package tree. MirrorSwitch reports those combinations as unsupported instead of
using x64 emulation as native evidence.

## Native verification evidence

The current four-platform product gate is
[run 34292702579](https://github.com/vibelab-tools/MirrorSwitch/actions/runs/34292702579):
macOS Intel, Apple Silicon, Windows x86_64, and Windows arm64 all built and ran
the native Rust boundaries plus CLI/TUI smoke checks. Issue
[#21](https://github.com/vibelab-tools/MirrorSwitch/issues/21) records the audit
showing that all 44 tool-specific native workflows have a successful latest run.
The current Linux regression and package gate is
[run 34294032031](https://github.com/vibelab-tools/MirrorSwitch/actions/runs/34294032031).
Each adapter row links to its own closed Issue for the real client commands,
platform skips, and artifact evidence behind that support statement.

## Troubleshooting

- `no actionable plan` means at least one required upstream had no candidate
  that passed compatibility and content probes. It is not a permission error.
- A plan with `requires_elevation: true` must be applied and restored from an
  already elevated terminal. Keep user-scope work in the normal user terminal.
- If a tool-specific environment variable, credential, custom source, project
  override, or disabled trust/checksum policy has precedence, MirrorSwitch
  preserves it and may refuse the plan rather than guess.
- Windows host and WSL are separate targets. Use the explicit WSL option and
  distribution name documented in [the WSL boundary](wsl.md).
- Use `status --json` to record the catalog source/version, detected context,
  unavailable reasons, and selected scopes without exposing configuration
  contents.

See the [CLI contract](cli.md), [transaction model](transactions.md),
[support matrix](macos-windows-support-matrix.md), and
[release packaging rules](packaging.md) before the first apply.
