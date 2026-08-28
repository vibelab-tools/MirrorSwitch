# Portage adapter

The Portage adapter supports Gentoo Linux on x86_64 (`amd64` in Gentoo profiles) and arm64 at
system scope. It reads `/etc/portage/make.conf`, the active `repos.conf` file or directory, the
packaged default repository configuration when no override exists, and available profile-parent
metadata.

Distfiles and repository synchronization are independent selection units. `GENTOO_MIRRORS` uses
an HTTPS Gentoo source-mirror endpoint. A main repository with `sync-type = rsync` uses only a
published rsync endpoint for `sync-uri`. HTTP repository copies and Git mirrors are never written
into an rsync field. A Git-configured main repository remains Git-configured and unchanged.

Only the section named by `main-repo` (defaulting to `gentoo`) can be rewritten. User overlays,
their locations and sync URIs, `auto-sync`, OpenPGP keys, signature verification, rsync verification
and every other repository option remain byte-for-byte unchanged. When the system uses Portage's
packaged default `repos.conf`, the adapter creates a system override instead of editing the
package-owned file.

Before latency ranking, a distfiles candidate must expose `/distfiles/` and a current stage3 index
for the detected `amd64` or `arm64` architecture. An rsync repository candidate must expose the
Gentoo repository name and the matching profile-architecture directory over its companion HTTPS
metadata endpoint; only candidates with a separately published rsync endpoint are eligible.

Applying uses the shared atomic transaction engine. Verification first runs the read-only
`emerge --info` parser, then uses `rsync --list-only` with bounded connection and I/O timeouts to
check `profiles/repo_name` on the selected main repository. Either failure immediately attempts
restoration. Explicit restore verifies the original bytes, including removal of a generated
override that did not exist before the transaction.
