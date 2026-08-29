# GHCup adapter

Issue [#60](https://github.com/vibelab-tools/MirrorSwitch/issues/60) implements
the Linux user-scope boundary for reviewed GHCup 0.1.50.2 and 0.2.x releases on
`x86_64` and `arm64`, in host and container environments. The adapter records
the GHCup version, configuration path, release-channel count, metadata GPG and
bindist checksum policy, and the locally cached installed-tool view.

Configuration follows GHCup's own directory rules: `~/.ghcup/config.yaml` by
default, `${XDG_CONFIG_HOME:-~/.config}/ghcup/config.yaml` when
`GHCUP_USE_XDG_DIRS` is set, or the explicit `GHCUP_INSTALL_BASE_PREFIX` in
non-XDG mode. MirrorSwitch replaces only the default `GHCupURL` or its previous
managed equivalent, preserving the order and contents of prerelease, cross,
vanilla, third-party, and private release channels. It also manages only the
`downloads.haskell.org` child of `mirrors`. Other host mappings, comments,
`gpg-setting`, `no-verify`, and unrelated policy remain unchanged. Aliases,
flow values, nested channel objects, duplicate keys, and unsafe indentation
fail before a plan is produced.

## Signed metadata and bindist boundary

The six-provider review keeps three GHCup inventory records visible, but only
Nanjing University is actionable. Its `yaml_v2` copy of
`ghcup-0.0.9.yaml` and detached signature passed a real GPG verification with
the official GHCup metadata signing key. Its separate `packages` tree serves
the fixed GHC 9.10.3, Cabal 3.14.2.0, HLS 2.13.0.0, and Stack 3.7.1 Linux
bindists for both architectures.

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

Research references: the official GHCup
[guide](https://www.haskell.org/ghcup/guide/),
[release channels](https://www.haskell.org/ghcup/guide/channels/),
[configuration paths](https://www.haskell.org/ghcup/guide/config/), and
[metadata repository](https://github.com/haskell/ghcup-metadata).
