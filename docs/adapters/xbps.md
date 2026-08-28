# XBPS adapter

The XBPS adapter supports Void Linux x86_64 and aarch64 with either glibc or musl at system scope.
It asks `xbps-uhelper arch` for the effective target (`x86_64`, `x86_64-musl`, `aarch64` or
`aarch64-musl`) and rejects a configuration whose repository layout belongs to a different
architecture or libc variant.

XBPS reads package defaults from `/usr/share/xbps.d` and overrides from `/etc/xbps.d`. The adapter
implements the same filename override rule and lexicographic order. A changed package default is
copied to the matching `/etc/xbps.d` name; the package-owned file is never edited. Existing custom
repositories, local paths, comments, filenames and effective ordering remain unchanged.

Recognized official layouts are `current` for x86_64 glibc, `current/musl` for x86_64 musl, and
`current/aarch64` for both aarch64 variants. Compatible nonfree and debug subrepositories are
retained; multilib is accepted only for x86_64 glibc. Planning replaces only the mirror root and
never changes one of these paths.

Before latency ranking, each candidate must match Void, the host/container environment and system
architecture. Every configured official path must answer a bounded HEAD request for its exact
`{xbps_arch}-repodata` file, which distinguishes glibc from musl even where their URL path is shared.

Applying uses the shared atomic transaction engine without changing XBPS keys or signature policy.
Verification runs `xbps-install -S` to refresh signed indexes and `xbps-query -L` to query the
effective repositories. Either failure immediately attempts restoration; explicit restore verifies
the original bytes and removes override files created by the transaction. Repeated planning is
idempotent.
