# Cabal adapter

Issues [#57](https://github.com/vibelab-tools/MirrorSwitch/issues/57) and
[#134](https://github.com/vibelab-tools/MirrorSwitch/issues/134) implement the
Hackage boundary for cabal-install 2.4 through 3.16. Linux supports `x86_64`
and `arm64` hosts and containers; macOS supports native Intel and Apple Silicon
hosts; Windows supports native x86_64 hosts. Windows arm64 is rejected because
the reviewed toolchain has no native Windows arm64 cabal-install executable.
GHC is detected when present, but the Hackage metadata and source packages are
architecture independent.

The adapter follows cabal-install's versioned user-config discovery. On Linux
and macOS, Cabal 2.4–3.8 uses `~/.cabal/config`; on Windows it uses
`%APPDATA%\cabal\config`. Cabal 3.10 and later honors `CABAL_CONFIG`,
`CABAL_DIR`, the legacy directory, and XDG config paths. The XDG default is
`~/.config/cabal/config` on Linux/macOS and `%APPDATA%\cabal\config` on
Windows. Explicit environment paths remain constrained to the selected user
location. Project files and imports are read-only policy inputs. UTF-8 BOMs,
CRLF/LF line endings, private repositories, proxy/certificate environment,
comments, and unknown unrelated fields remain unchanged.

The repository id remains `hackage.haskell.org`, and MirrorSwitch changes its
URL only after validating the effective policy. A clean cabal-install 3.8
client cannot bootstrap the current Hackage root from the mirror URL alone, so
MirrorSwitch adds the six reviewed root-v8 key IDs and threshold 3 when the
target has no explicit root policy. Existing complete root-key policy remains
unchanged and is validated by the real client; legacy `remote-repo` syntax is
migrated to an equivalent secure repository stanza. Private repositories,
`active-repositories`, `index-state`, transport, cache and store settings,
comments, and ordering remain unchanged. MirrorSwitch does not act on
`secure: False`, credential-bearing URLs, custom-only or ambiguous public
repositories, incomplete root-key policy, or a project/import override that
makes the effective repository uncertain.

## Reviewed provider boundary

NJU, TUNA, and USTC publish complete Hackage Security layouts. Before latency
counts, the runtime catalog checks `root.json`, `timestamp.json`,
`snapshot.json`, `mirrors.json`, `01-index.tar.gz`, and the exact SHA-256 of
`StateVar` 1.2.2. Huawei Cloud publishes package files without the security
metadata or package index required by secure Cabal clients; Alibaba Cloud and
SJTUG do not currently publish Hackage. Those three providers stay inert.

After apply, an isolated credential-free config always runs a real
`cabal update` and fixed-package `cabal get`; it also runs `cabal info` when GHC
is installed. Cabal therefore validates the Hackage Security signatures and
expiry chain itself even on a source-only Cabal installation. The catalog gate
independently enforces the reviewed source-tarball digest. Verification failure
restores the user config, and reapplying the same selection is a no-op.

The scheduled native boundary installs checksum-pinned Cabal 3.14.2.0
executables from the signed GHCup bindist set on macOS Intel, macOS Apple
Silicon, and Windows x86_64. It compares CLI/configuration/TUI plans, runs the
real secure `update`, `info`, and `get` verification, parses the applied user
config with the native client, proves idempotence, and restores the original
bytes, permissions or ACL, and read-only project fixture.
