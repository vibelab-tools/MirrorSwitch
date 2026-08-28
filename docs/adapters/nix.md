# Nix adapter

The Nix adapter supports standalone Nix installations on Linux for `x86_64-linux` and
`aarch64-linux`. It detects the daemon profile/socket to choose system scope for a multi-user
installation and user scope for a single-user installation. System configuration is
`/etc/nix/nix.conf`; user configuration is the detected home directory's
`.config/nix/nix.conf`.

The adapter reads effective settings with Nix itself and requires `require-sigs = true`, the
canonical `cache.nixos.org-1` public key, and a `system` value matching the detected architecture.
It never adds or changes a public key. A current-architecture store path is discovered from the
installed Nix closure and supplies the exact narinfo hash used to validate candidates.

Only the nixpkgs binary-cache surface is mutable. Channel registrations and the flake registry
are reported as distinct read-only sources. Nix release archives, nixpkgs Git mirrors and
architecture-specific third-party caches are not treated as substituters. NixOS-generated
`nix.conf` is also not edited; NixOS must retain ownership through `nix.settings`.

The runtime catalog exposes the verified `nix-channels/store` endpoints from NJU, SJTUG, TUNA and
USTC. Before latency ranking, a candidate must return a valid `/nix/store` cache descriptor and a
narinfo for the current system whose signature is identified as `cache.nixos.org-1`. Missing
dynamic-cache content therefore excludes only that candidate and allows another verified cache to
win.

Planning preserves comments, trusted keys, the official fallback, custom caches and their relative
order. Existing reviewed mirror URLs are consolidated to the selected endpoint, and a missing base
setting is created without changing channel or flake state. Includes and ambiguous duplicate
assignments are rejected instead of guessed. Repeated planning is idempotent.

Verification asks Nix to reload the effective configuration, checks the signature policy again,
pings the selected store and queries the discovered current-system store path from that store.
Failure restores the transaction immediately. Multi-user system changes report that a daemon
restart is required; MirrorSwitch does not restart it implicitly.
