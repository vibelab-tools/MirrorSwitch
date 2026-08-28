# Flatpak adapter

The Flatpak adapter supports existing Flathub remotes in the default system and per-user
installations on Linux `x86_64` and `arm64`. System and user scope are independent: system is the
automatic default when both contain a mapped remote, while configuration and TUI selection can
choose either scope. System plans require elevation; user plans do not.

Only remotes whose current URL maps explicitly to Flathub are mutable. Remote names, enabled
state, filters, collection metadata, priority, custom remotes and all unrelated key-file fields
remain byte-for-byte unchanged. The adapter never adds, deletes, disables or recreates a remote.
Both commit and summary GPG verification must already be enabled; keyring material is never
changed.

The runtime catalog exposes the SJTUG and USTC Flathub caches as proxy candidates. Before latency
ranking, each candidate must return the Flathub OSTree collection config and a bounded
`summary.idx` containing the detected `x86_64` or `aarch64` architecture marker. A cache may still
redirect an uncached object to Flathub, so it is not represented as a complete static mirror.

Planning atomically changes only mapped `url` values in Flatpak's OSTree config and is idempotent.
Post-apply verification re-parses the effective URL, GPG flags and priority, then asks Flatpak to
list refs for the detected architecture from every enabled changed-scope remote. Disabled remotes
stay disabled and are validated from configuration without being refreshed. A failed query
restores the transaction immediately.
