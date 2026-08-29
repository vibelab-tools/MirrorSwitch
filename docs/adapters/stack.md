# Stack/Stackage adapter

Issue [#59](https://github.com/vibelab-tools/MirrorSwitch/issues/59) implements
the Linux boundary for officially released Stack 3.1.1 through 3.11.x on
`x86_64` and `arm64`, in host and container environments. Stack 2.x is not
rewritten because it predates the reviewed native `global-hints-location`
configuration, and unreleased major versions are not assumed compatible.

The adapter discovers the system, user, and active project configuration using
Stack's documented `STACK_GLOBAL_CONFIG`, `STACK_CONFIG`, `STACK_ROOT`,
`STACK_XDG`, `STACK_YAML`, XDG, legacy system-file, and upward project search
precedence. User scope is the default and never writes `stack.yaml`. Project
scope must be selected explicitly and changes only non-project repository
settings; `snapshot`/`resolver`, packages, extra dependencies, flags, comments,
and unrelated ordering remain unchanged.

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
corresponding architecture's GHC 9.6.6 filename, checksum, and downloadable
bindist from `stack-setup.yaml`. Each Hackage candidate separately passes the
signed root/timestamp/snapshot/mirror metadata, package index, and the exact
`StateVar` 1.2.2 source digest.

After apply, an isolated credential-free Stack root resolves a minimal local
package against `lts-22.43` with `--global-hints`, confirming `StateVar` 1.2.2
and the GHC 9.6.6 base package set. A real `stack unpack StateVar-1.2.2` then
exercises the selected Hackage Security/index/package path. Any failure restores
all managed files, and repeating the same selection produces no changes.
