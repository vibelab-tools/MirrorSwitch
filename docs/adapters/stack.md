# Stack/Stackage adapter

Issues [#59](https://github.com/vibelab-tools/MirrorSwitch/issues/59) and
[#135](https://github.com/vibelab-tools/MirrorSwitch/issues/135) implement the
boundary for officially released Stack 3.1.1 through 3.11.x. Linux supports
`x86_64` and `arm64` hosts and containers; macOS supports native Intel and
Apple Silicon hosts; Windows supports native x86_64 hosts. Windows arm64 is
rejected because the reviewed setup metadata has no native Windows arm64 GHC
toolchain. Stack 2.x is not rewritten because it predates the reviewed native
`global-hints-location` configuration, and unreleased major versions are not
assumed compatible.

The adapter discovers the system, user, Stack root, and active project
configuration using Stack's documented `STACK_GLOBAL_CONFIG`, `STACK_CONFIG`,
`STACK_ROOT`, `STACK_XDG`, `STACK_YAML`, XDG, legacy system-file, and upward
project search precedence. Unix defaults to `~/.stack/config.yaml`; Windows
defaults to `%APPDATA%\stack\config.yaml` and has no implicit system-wide
configuration. Redirected roaming directories and an explicit short Windows
`STACK_ROOT` such as `C:\sr` are accepted as user state.
User scope is the default and never writes `stack.yaml`. Project scope must be
selected explicitly and changes only non-project repository settings;
`snapshot`/`resolver`, packages, extra dependencies, flags, comments, UTF-8
BOMs, CRLF/LF, and unrelated ordering remain unchanged.

MirrorSwitch manages only `urls.latest-snapshot`,
`snapshot-location-base`, `global-hints-location.url`,
`setup-info-locations`, and `package-index.download-prefix`. It declines an
automatic rewrite when a project overrides user-level repository settings, a
managed endpoint is private or unknown, or the relevant YAML uses includes,
anchors, merges, duplicate keys, inline setup metadata, deprecated
`package-indices`, or disabled transport/checksum/expiry validation. Private
archive and VCS locations stay opaque in reports.

## Independent upstream boundary

A Stack plan requires one complete `stackage--language-registry` candidate and
one complete `hackage--language-registry` candidate. They are selected by their
own measured latency and may come from different providers. NJU, TUNA, and USTC
currently publish both required services; Alibaba Cloud, Huawei Cloud, and
SJTUG remain inert for this adapter because their reviewed inventories do not
provide the complete pair.

Before latency counts, each Stackage candidate must pass the latest-snapshot
index, the exact SHA-256 of `lts-22.43`, the exact global-hints digest, and the
corresponding platform and architecture's GHC 9.6.6 filename, checksum, and
downloadable bindist from `stack-setup.yaml`. This covers Linux x86_64/arm64,
macOS x86_64/arm64, and Windows x86_64. Each Hackage candidate separately passes the
signed root/timestamp/snapshot/mirror metadata, package index, and the exact
`StateVar` 1.2.2 source digest.

After apply, an isolated credential-free Stack root resolves a minimal local
package against `lts-22.43` with `--global-hints`, confirming `StateVar` 1.2.2
and the GHC 9.6.6 base package set. A real `stack unpack StateVar-1.2.2` then
exercises the selected Hackage Security/index/package path. Any failure restores
all managed files, and repeating the same selection produces no changes.

Verification launches Stack directly with a per-command environment rather
than relying on the Unix `env` executable, so the same isolation works with
native `stack.exe`. The manual native workflow installs checksum-pinned Stack
3.7.1 and GHC 9.6.6 on macOS Intel, macOS Apple Silicon, and Windows x86_64. It
compares CLI/configuration/TUI plans, runs the real snapshot/Hackage checks and
a native build, proves idempotence, and restores the original bytes,
permissions or ACL, and read-only project configuration.
