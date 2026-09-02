# Conda/Mamba adapter

The adapter supports Linux `x86_64`/`arm64`, macOS `osx-64`/`osx-arm64`, and native Windows
`win-64`. It probes `conda`, `mamba`, and `micromamba` independently, reports each installed client
and version, and produces one shared user-scope plan because all three clients consume the same
home-directory `.condarc` model. The presence of one client never implies that either of the others
is installed. Windows arm64 is explicitly unsupported because the providers expose no native
`win-arm64` repository; x64 emulation is not treated as native proof.

Configuration discovery uses `conda config --show-sources --json` for Conda and `config sources`
for Mamba and Micromamba. All reported sources are read in addition to `~/.condarc`. The adapter
parses `channels`, `default_channels`, `custom_channels`, `channel_alias`, `channel_priority`, and
`ssl_verify`. Environment-level overrides, disabled TLS verification, unsupported inline or aliased
YAML shapes, and configurations containing only private or unmapped channels are non-actionable.

Planning changes only the selected user `.condarc`. Official or previously managed
`default_channels` entries for `pkgs/main` and `pkgs/r` are redirected to one provider, and a public
`custom_channels.conda-forge` mapping is redirected to that provider's `cloud` tree. Private channel
URLs, embedded tokens, channel order, `channel_alias`, `channel_priority`, and unrelated settings
remain unchanged. A private `conda-forge` mapping is not overwritten. Single-provider composition
keeps Conda's strict and flexible priority semantics intact instead of mixing independently ranked
repositories.

Candidates must pass `noarch` plus the native `linux-64`, `linux-aarch64`, `osx-64`, `osx-arm64`,
or `win-64` repodata checks for the default and conda-forge trees, followed by a platform-specific
representative package download, before latency ranking. USTC, TUNA, and NJU currently satisfy the
complete contract. SJTUG remains non-actionable because its published paths return an access-denied
response to the required probes.

Applying uses the shared atomic transaction engine. Verification re-reads the effective settings
through every installed client, then runs a real Python 3.12 repodata query with `conda search` or
`mamba`/`micromamba repoquery search`. Failure restores the previous file, and repeated planning is
idempotent. UTF-8 BOM and LF/CRLF layout are preserved; other reported client sources stay read-only.
