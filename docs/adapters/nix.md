# Nix adapters

MirrorSwitch exposes `nix` for standalone Linux installations and `nix-macos` for native macOS
hosts. Both support Intel and ARM systems. The Linux adapter recognizes `x86_64-linux` and
`aarch64-linux`; the macOS adapter requires `x86_64-darwin` or `aarch64-darwin` and never treats a
Linux cache object as Darwin evidence.

The adapters detect the daemon profile and socket to distinguish multi-user from single-user
installations. On macOS, the multi-user path also requires exactly one known launchd service:
`org.nixos.nix-daemon` for the upstream installer or `systems.determinate.nix-daemon` for the
Determinate installer. Finding both is an invalid installation state. System configuration is
`/etc/nix/nix.conf`; user configuration follows `XDG_CONFIG_HOME/nix/nix.conf`, with
`~/.config/nix/nix.conf` as the default.

The adapter reads effective settings with Nix itself and requires `require-sigs = true`, the
canonical `cache.nixos.org-1` public key, and a `system` value matching the detected architecture.
It never adds or changes a public key. A current-architecture store path is discovered from the
installed Nix closure and supplies the exact narinfo hash used to validate candidates.

Only the nixpkgs binary-cache surface is mutable. Channel registrations and the flake registry
are reported as distinct read-only sources. Nix release archives, nixpkgs Git mirrors and
architecture-specific third-party caches are not treated as substituters. NixOS-generated
`nix.conf` is also not edited; NixOS must retain ownership through `nix.settings`.

`NIX_CONFIG`, `NIX_CONF_DIR`, and `NIX_USER_CONF_FILES` can change precedence or move the effective
configuration outside the one file represented by a plan. The adapter rejects the applicable
override instead of editing a file that may have no effect.

For Linux, the runtime catalog exposes the verified `nix-channels/store` endpoints from NJU,
SJTUG, TUNA, and USTC. For macOS, only NJU and TUNA are actionable: both passed fixed
`x86_64-darwin` and `aarch64-darwin` narinfo and NAR checks. SJTUG and USTC remain partial and
cannot enter latency ranking until the same Darwin evidence passes.

Every Linux candidate must return a valid `/nix/store` cache descriptor and a signed narinfo for a
store path discovered from the installed system. A macOS candidate instead uses the exact
architecture-specific `hello` store path from the 25.11 Darwin channel: its narinfo must identify
that path and carry the `cache.nixos.org-1` signature, and its complete NAR must match the reviewed
SHA-256. This avoids requiring a channel mirror to retain unrelated closure objects from the Nix
installer itself.

Planning preserves comments, trusted keys, the official fallback, custom caches and their relative
order. Existing reviewed mirror URLs are consolidated to the selected endpoint, and a missing base
setting is created without changing channel or flake state. Includes and ambiguous duplicate
assignments are rejected instead of guessed. Repeated planning is idempotent.

Verification asks Nix to reload the effective configuration, checks the signature policy again,
pings the selected store, and queries a matching store path from that store. On macOS it also uses
`nix store ls --long --recursive` against the reviewed Darwin store path so
Nix validates the signed NAR through the selected cache.

A macOS system-scope apply restarts the detected launchd daemon with `launchctl kickstart -k`
before verification. If the restart or verification fails, MirrorSwitch restores `nix.conf` and
restarts the daemon against the restored configuration. Explicit restore does the same. Linux
keeps its existing behavior and reports the daemon restart as required rather than controlling a
distribution-specific service manager.
