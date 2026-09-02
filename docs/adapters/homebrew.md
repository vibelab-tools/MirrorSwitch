# Homebrew adapter

The Homebrew adapter supports native macOS hosts running reviewed Homebrew 4.x through 6.x in the
standard prefix: `/usr/local` on Intel and `/opt/homebrew` on Apple Silicon. It is user-scoped and
does not run in Linux, Windows, containers, custom prefixes, or a different user's home.

Current API-mode Homebrew has three independent mirror surfaces:

- the Homebrew/brew Git origin;
- the signed formula/cask JSON API;
- OCI bottle manifests and blobs.

MirrorSwitch requires all three from the same validated provider. The first supported candidate is
USTC: `brew.git`, `homebrew-bottles/api`, and the `homebrew-bottles` OCI/artifact root. Other
cataloged provider directories remain inert until their complete surface passes the same checks.

Before latency comparison, the catalog probes the Git repository HEAD, the signed API representation
for the fixed `jq` formula, and an architecture-specific bottle blob. The current fixtures are the
Sonoma Intel bottle and the arm64 Sequoia bottle for `jq` 1.8.2, including the API-published blob
digest in each probe context.

## Managed state

The plan writes one marked block to an explicitly selected profile, or the owning user's default
`.zprofile`, `.bash_profile`, or Fish conf.d file. It sets:

```text
HOMEBREW_BREW_GIT_REMOTE
HOMEBREW_API_DOMAIN
HOMEBREW_ARTIFACT_DOMAIN
```

The same transaction changes only the `origin` URL in the Homebrew/brew `.git/config`. This is
necessary because `brew update` persists `HOMEBREW_BREW_GIT_REMOTE` into that repository. The
profile and Git config are therefore backed up, applied, verified, and restored together.

Unrelated shell content, Git settings/remotes, taps, credentials, and project files are preserved.
An unmanaged Homebrew mirror assignment or custom Brew origin blocks the plan. So does
`HOMEBREW_NO_INSTALL_FROM_API`: that mode needs complete core/cask Git mirrors, which the current
six-provider evidence does not supply. MirrorSwitch does not set legacy `HOMEBREW_BOTTLE_DOMAIN`
alongside OCI artifact mode.

## Verification and recovery

After apply, the adapter rereads the marked profile and Brew origin, then runs Homebrew with the
selected environment through `brew config`, `brew info --json=v2 jq`, `brew update --quiet`, and an
architecture-specific `brew fetch --force --bottle-tag=... jq`. Any failure restores both files.
Repeating the same successful plan produces no file changes. An explicit transaction restore also
returns the profile and Brew origin to their exact previous bytes and attributes.

## Continuous validation

The scheduled `homebrew-live.yml` workflow exercises Intel and Apple Silicon runners separately.
Each job uses the native release binary and a temporary profile to run status, plan, apply, verify,
TUI planning, and restore against the installed Homebrew. It compares both the profile and the
Homebrew/brew Git config before and after restore, and uploads only redacted JSON evidence.

The ordinary platform smoke workflow runs the deterministic adapter boundary tests on both macOS
architectures. Linux CI keeps the catalog and adapter registration covered without treating Linux
Homebrew as a supported host.
