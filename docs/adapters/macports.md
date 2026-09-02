# MacPorts adapter

The `macports` adapter supports the standard `/opt/local` installation on native macOS hosts.
Darwin 23 and 24 are covered on Intel and Apple Silicon; Darwin 25 is covered on Apple Silicon.
It reads the MacPorts version, macOS and Darwin versions, `macports.conf`, `sources.conf`,
`archive_sites.conf`, `pubkeys.conf`, and the effective binary-build policy before proposing a
change.

Alibaba Cloud, NJU, and SJTUG each expose a complete pair for this adapter: signed ports tree
tarballs and PortIndex files under `release/tarballs`, plus signed binary archives under
`packages`. Candidate selection keeps those two endpoints on the same provider. It checks the
target Darwin major and index architecture, then downloads the matching zlib 1.3.2 archive and
its rmd160 signature file with reviewed SHA-256 values before latency ranking.

## Managed state

The adapter changes only the one `[default]` public tree URI in `sources.conf`. Local and custom
trees keep their order and flags. The selected HTTPS `ports.tar.gz` retains MacPorts' signed
tarball behavior; a default source marked `nosync`, multiple defaults, or an unknown default is
not rewritten.

For binary packages, MirrorSwitch creates a marked `macports_archives` entry when no override
exists, or replaces the URL of an existing override only when all of its URLs are reviewed public
MacPorts archive sites. Other named archive groups remain untouched. A custom
`macports_archives` policy, non-`tbz2` type, nonstandard prefix, missing official public key, or
`buildfromsource=always` blocks the plan.

`macports.conf`, `pubkeys.conf`, `variants.conf`, installed ports, and selected variants are never
modified. Both managed files are system-scoped, so apply and restore require elevation. The plan
reports a reload/synchronization impact rather than treating a static packages directory as a
ports tree.

## Verification and recovery

After apply, MirrorSwitch rereads both configuration files, runs `port sync`, reads `port info
zlib`, and runs `port archivefetch zlib`. MacPorts itself therefore verifies the signed tree and
the target platform's binary archive without installing the port or changing variants. Any
failure restores both configuration files, repeated planning is idempotent, and explicit restore
returns their exact previous bytes and modes.
