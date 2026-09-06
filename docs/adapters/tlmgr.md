# tlmgr/CTAN adapter

Issues [#65](https://github.com/vibelab-tools/MirrorSwitch/issues/65) and
[#137](https://github.com/vibelab-tools/MirrorSwitch/issues/137) implement the
TeX Live 2026 repository boundary. Linux supports `x86_64-linux`,
`x86_64-linuxmusl`, and `aarch64-linux` hosts and containers. macOS Intel and
Apple Silicon use TeX Live's current `universal-darwin` platform. Windows x64
uses the `windows` platform; Windows arm64 is rejected because TeX Live 2026
does not publish a native Windows arm64 infrastructure package.

MirrorSwitch asks native `tlmgr` for the release, revision, installation root,
and platform, and asks `kpsewhich` for `TEXMFHOME`. It therefore reads the
actual installation and user `tlpkg/texlive.tlpdb` files instead of assuming a
Linux layout. The system scope is selected by default; an initialized user tree
takes precedence and remains unprivileged. Project directories are recorded as
read-only context and are never changed.

Only the main `opt_location` token is replaced. Tagged supplemental/private
repositories, their order and pinning identity, automatic backup settings,
download/signature verification options, unknown TLPDB records, UTF-8 BOMs,
native line endings, permissions, and ACLs remain unchanged. A private main,
ambiguous tags, release mismatch, unreviewed platform, missing user tree, or
disagreement between `tlmgr repository list` and the TLPDB stops the plan.

## Reviewed provider boundary

Alibaba Cloud, Huawei Cloud, NJU, and TUNA publish the complete TeX Live 2026
`tlnet` surface. Each candidate must pass the TLPDB checksum index, the fixed
`texlive.infra` archive SHA-256, and the exact current platform archive SHA-256
before latency counts. The platform archive probe is selected at runtime, so a
macOS host checks `texlive.infra.universal-darwin.tar.xz`, Windows checks
`texlive.infra.windows.tar.xz`, and each Linux installation checks only its
reported platform. USTC and SJTUG do not have the same reviewed current
candidate in the six-provider inventory and remain inert.

After apply, the native client lists the configured main repository, queries
the remote `texlive.infra` package, and confirms that the repository publishes
the installation's exact platform. Verification failure restores the original
TLPDB bytes; repeated application is a no-op.

The manual native workflow installs a minimal TeX Live 2026 through the
project's setup action on macOS Intel, macOS Apple Silicon, and Windows x86_64.
It initializes a real user tree, compares CLI/configuration/TUI plans, runs the
native package and platform queries, proves idempotence, and restores the user
TLPDB, system TLPDB, project fixture, permissions, and ACLs.
