# Pacman adapter

The Pacman adapter supports Arch Linux on x86_64 and Arch Linux ARM on arm64 at system scope. It
reads `/etc/pacman.conf`, follows exact-file `Include` directives recursively for recognized
repositories, and preserves repository section order. An include shared by different upstream
identities is rejected instead of being rewritten ambiguously.

Repository identities and layouts remain distinct:

- Arch Linux uses `$repo/os/$arch` and is eligible only on x86_64.
- Arch Linux ARM uses `$arch/$repo` and is eligible only on arm64 (`aarch64` in repository paths).
- Arch Linux CN uses `$arch` and is selected independently on either architecture when configured.
- BlackArch uses `$repo/os/$arch`, is selected independently, and is eligible only on x86_64.

Manjaro, unknown sections, disabled/commented servers and third-party include files are left
unchanged. The adapter never changes `SigLevel`, `Architecture`, repository order or other Pacman
options. Globbed or variable-based Include paths are reported as unsupported because they cannot
be resolved to a deterministic transaction target.

For every enabled recognized section, candidates must answer a bounded HEAD request for the exact
repository database path before latency ranking. This avoids downloading multi-megabyte database
archives during selection. Applying collapses each selected active mirror group to the fastest
validated server while retaining prior active lines as `# MirrorSwitch original:` comments.
Repeated planning is idempotent.

Applying uses the shared atomic transaction engine across `pacman.conf` and all selected included
mirror lists. Verification runs `pacman -Syy --noconfirm`, which refreshes every enabled database
under the unchanged effective `SigLevel`; a non-zero result immediately attempts restoration.
Explicit restore verifies the original bytes.
