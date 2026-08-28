# YUM adapter

The YUM adapter supports the legacy YUM 3 implementation on CentOS Linux 6 and 7 at system
scope. A `yum` command reporting DNF/YUM 4 is deliberately ignored so the same `.repo` files are
not planned twice. Exact RHEL installations and unknown compatible derivatives are not redirected
to CentOS content because their repository identities are not interchangeable.

CentOS Linux 6 and 7 are archived distributions. Their x86_64 repositories are therefore mapped
to the final Vault releases `6.10` and `7.9.2009`, rather than to the removed normal mirror paths.
CentOS 7 arm64 uses the distinct CentOS AltArch upstream and its verified `7` path. CentOS Stream
is handled by the DNF adapter only when an enabled official repository uses the `$stream`
identity; it is never inferred from a CentOS Linux release number.

Only enabled `base`, `updates` and `extras` sections at recognized CentOS or six-provider
locations are eligible for rewrites. EPEL, CentOS Plus, unknown and disabled repositories remain
unchanged. GPG keys, `gpgcheck`, repository priority and unrelated variables are preserved. The
archive version in a rewritten location is intentionally pinned because `$releasever` no longer
resolves to a live Vault directory.

Before latency ranking, every enabled archive path must return `repodata/repomd.xml` containing a
`<repomd` marker for the detected architecture. The adapter accepts HTTPS metadata endpoints only.
Applying uses the shared atomic transaction engine. Verification expires YUM metadata and runs
`yum makecache`; any non-zero verification result attempts immediate restoration, and explicit
restore verifies the original bytes.
