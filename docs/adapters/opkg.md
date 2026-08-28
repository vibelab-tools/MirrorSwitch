# opkg adapter

The opkg adapter is extended Linux support for OpenWrt and ImmortalWrt devices; it is not an
automatic target on Debian, Ubuntu or other general-purpose distributions. It supports detected
`x86_64` and `arm64` systems and reads `VERSION_ID`, `OPENWRT_BOARD` (`target/subtarget`) and
`OPENWRT_ARCH` from the device's os-release metadata. The opkg-reported architecture priorities
must include that exact package architecture.

Only active `src/gz` entries in `/etc/opkg/distfeeds.conf` whose root maps explicitly to the
detected distribution are mutable. Every mapped path must match the exact release (or snapshot),
target, subtarget and package architecture. Feed names, ordering, kernel-build paths, comments,
unknown entries, `/etc/opkg/customfeeds.conf` and `/etc/opkg.conf` remain unchanged. OpenWrt and
ImmortalWrt repositories are never mixed.

Before latency ranking, each candidate must expose both `Packages.gz` and `Packages.sig` for every
configured mapped feed path. The runtime catalog evaluates OpenWrt and ImmortalWrt candidates
separately and requires Linux, the detected CPU architecture and the matching distribution.
Missing or lagging release/target content makes that candidate ineligible without producing a
partial plan.

The adapter requires `option check_signature` before planning and never adds a bypass flag or
changes `/etc/opkg/keys`. Applying atomically replaces only reviewed distribution roots. It then
runs `opkg update` to download and verify signed indexes and `opkg list` as a real query. Any
failure restores the original distfeeds file, and repeated planning is idempotent.
