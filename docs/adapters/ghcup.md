# GHCup adapter

Issues [#60](https://github.com/vibelab-tools/MirrorSwitch/issues/60) and
[#133](https://github.com/vibelab-tools/MirrorSwitch/issues/133) implement the
user-scope boundary for reviewed GHCup 0.1.50.2 and 0.2.x releases. Linux
supports `x86_64` and `arm64` hosts and containers, macOS supports native Intel
and Apple Silicon hosts, and Windows supports native x86_64 hosts. Windows
arm64 is rejected because the reviewed upstream metadata has no native Windows
arm64 GHC toolchain. The adapter records the GHCup version, native platform and
architecture, configuration path, release-channel count, metadata GPG and
bindist checksum policy, and the locally cached installed-tool view.

On Linux and macOS, configuration follows GHCup's own directory rules:
`~/.ghcup/config.yaml` by default,
`${XDG_CONFIG_HOME:-~/.config}/ghcup/config.yaml` when
`GHCUP_USE_XDG_DIRS` is set, or the explicit `GHCUP_INSTALL_BASE_PREFIX` in
non-XDG mode. Windows uses `C:\ghcup\config.yaml` by default, or
`${GHCUP_INSTALL_BASE_PREFIX}\ghcup\config.yaml` when the prefix is set, and
does not infer an XDG path. MirrorSwitch replaces only the default `GHCupURL` or its previous
managed equivalent, preserving the order and contents of prerelease, cross,
vanilla, third-party, and private release channels. It also manages only the
`downloads.haskell.org` child of `mirrors`. Other host mappings, comments,
`gpg-setting`, `no-verify`, unrelated policy, UTF-8 BOMs, and native line
endings remain unchanged. Project files are read-only by default. Aliases, flow
values, nested channel objects, duplicate keys, and unsafe indentation fail
before a plan is produced.

## Signed metadata and bindist boundary

The six-provider review keeps three GHCup inventory records visible, but only
Nanjing University is actionable. Its `yaml_v2` copy of
`ghcup-0.0.9.yaml` and detached signature passed a real GPG verification with
the official GHCup metadata signing key. Its separate `packages` tree serves
the fixed GHC 9.10.3, Cabal 3.14.2.0, HLS 2.13.0.0, and Stack 3.7.1 bindists
for Linux x86_64/arm64, macOS x86_64/arm64, and Windows x86_64.

The URL-rewritten metadata published in the reviewed NJU legacy tree, SJTUG
tree, and USTC tree did not verify against their concurrently published
detached signatures. Those records remain inert, as do providers without a
complete GHCup chain. MirrorSwitch does not combine metadata from one provider
with bindists from another.

Before latency counts, the NJU candidate must pass the pinned metadata and
signature digests. The signed metadata must contain the architecture-specific
SHA-256 for all four fixed tools, and every corresponding bindist must be
reachable. Large bindists use bounded HEAD probes rather than routine
downloads.

After apply, the adapter reloads and canonicalizes the managed YAML and runs
real GHCup strict metadata-fetching `list --raw-format` queries for all four
fixed versions. The user's GPG and checksum settings remain effective. Any
failure restores the exact prior file; repeating the same selection produces
no changes, and CLI, configuration-file, and TUI entry points consume the same
plan.

The scheduled native boundary downloads checksum-pinned GHCup 0.2.6.2
executables for macOS Intel, macOS Apple Silicon, and Windows x86_64. It imports
the reviewed metadata signing key, retains strict GPG and checksum policy,
compares CLI/configuration/TUI plans, resolves all four platform-specific
bindist plans through the native client, proves idempotence and restores the
original bytes, permissions or ACL, and read-only project fixture. Linux tests
remain in the same deterministic boundary suite.

Research references: the official GHCup
[guide](https://www.haskell.org/ghcup/guide/),
[release channels](https://www.haskell.org/ghcup/guide/channels/),
[configuration paths](https://www.haskell.org/ghcup/guide/config/), and
[metadata repository](https://github.com/haskell/ghcup-metadata).
