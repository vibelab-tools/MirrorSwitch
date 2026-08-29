# Cabal adapter

Issue [#57](https://github.com/vibelab-tools/MirrorSwitch/issues/57) implements
the Linux Hackage boundary for cabal-install 2.4 through 3.16 on `x86_64` and
`arm64`. GHC is detected when present, but the Hackage metadata and source
packages themselves are architecture independent.

The adapter follows cabal-install's versioned user-config discovery. Cabal
2.4–3.8 uses `~/.cabal/config`; Cabal 3.10 and later honors `CABAL_CONFIG`,
`CABAL_DIR`, the legacy `~/.cabal` fallback, and XDG config paths. An explicit
environment path is writable only when it remains inside the user's home.
Project files and imports are read-only policy inputs.

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

After apply, an isolated credential-free config runs a real `cabal update`,
`cabal info`, and fixed-package `cabal get`. Cabal therefore validates the
Hackage Security signatures and expiry chain itself. The catalog gate
independently enforces the reviewed source-tarball digest. Verification failure
restores the user config, and reapplying the same selection is a no-op.
