# Flutter adapter

Issues [#66](https://github.com/vibelab-tools/MirrorSwitch/issues/66) and
[#128](https://github.com/vibelab-tools/MirrorSwitch/issues/128) implement a
single Flutter plan that requires both the Flutter storage mirror and Dart Pub
registry to be complete. Supported targets are Linux and macOS
`x86_64`/`arm64`, plus Windows x64. macOS and Windows require native hosts.
Windows arm64 remains unsupported because the reviewed stable channel has no
native Windows arm64 Flutter SDK archive.

Detection uses `flutter --version --machine`, validates the stable/beta channel,
framework revision, engine artifact revision and SDK repository, and checks the
platform-specific `flutter precache` command (`--linux`, `--macos`, or
`--windows`). Candidate probes use the matching release manifest and one
architecture-specific engine artifact plus its locked in-toto provenance
digest. A Linux artifact cannot qualify a macOS or Windows candidate.

Linux and macOS persist `FLUTTER_STORAGE_BASE_URL` and `PUB_HOSTED_URL` together
in one managed bash, zsh, or fish profile block. Windows persists the pair as
user `REG_SZ` values under `HKCU\Environment`, with exact originals stored in a
private `%LOCALAPPDATA%\MirrorSwitch\flutter` recovery file before mutation.
Partial apply, verification failure, explicit restore, and repeated apply keep
the pair and recovery files consistent. No compatibility shell is used.

UTF-8 BOM, LF/CRLF, unrelated shell policy, native mode/ACL, Pub tokens, proxy
and certificate environment, cache policy, and project `pubspec.yaml`/lock
content are preserved. Token discovery follows Dart's XDG, macOS Application
Support, and Windows AppData paths. A profile block owned by the standalone Dart
Pub adapter is treated as a conflict so the two adapters never compete for the
same variables.

## Reviewed provider boundary

NJU and SJTUG provide the fixed Flutter release manifests and engine artifact
trees. Their candidate must match Flutter 3.47.2's framework and engine
revisions, the target OS/architecture provenance digest, and the corresponding
artifact before latency counts. TUNA and SJTUG provide the independently gated
Dart Pub metadata/archive chain for `retry` 3.1.2. Selection is actionable only
when one storage candidate and one Pub candidate both pass; no partial plan is
produced.

After apply, MirrorSwitch runs native platform precache and `flutter doctor`,
then resolves and queries `retry` 3.1.2 in an isolated Pub cache. The managed
lockfile must bind the package to the selected Pub endpoint. CLI, versioned
configuration, and TUI share this plan.

The native release boundary uses Flutter 3.47.2 on GitHub-hosted macOS Intel,
macOS Apple Silicon, and Windows x64 runners. It validates native launcher and
path behavior, both repository classes, real precache/doctor/Pub commands,
frontend equality, token/project immutability, idempotence, permissions, and
exact recovery.
