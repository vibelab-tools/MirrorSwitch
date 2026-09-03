# Dart Pub adapter

Issues [#63](https://github.com/vibelab-tools/MirrorSwitch/issues/63) and
[#127](https://github.com/vibelab-tools/MirrorSwitch/issues/127) implement Dart
Pub registry selection for Dart SDK 2.12 through 3.x on Linux, macOS, and Windows
`x86_64`/`arm64`. macOS and Windows require native hosts.

On Linux and macOS, MirrorSwitch writes one managed `PUB_HOSTED_URL` block to an
explicit `PROFILE`, a container `BASH_ENV`, or the selected bash, zsh, or fish
profile. Existing literal public assignments can be adopted; dynamic, duplicate,
private, or process-level conflicting assignments stop the plan. UTF-8 BOM,
LF/CRLF newlines, unrelated shell policy, and file modes are preserved.

Windows persists `PUB_HOSTED_URL` as a user `REG_SZ` value under
`HKCU\Environment`. Before changing it, MirrorSwitch stores the exact prior value
in a private recovery file below `%LOCALAPPDATA%\MirrorSwitch\dart-pub`. Apply,
verification failure, explicit restore, and repeated apply cover the registry and
recovery file as one logical transaction; no Unix shell or compatibility layer is
used. The process environment may remain stale until a new terminal starts, so
verification supplies the selected URL directly to the native Dart process.

Project `pubspec.yaml`, `pubspec.lock`, hosted/private declarations, publish
targets, Git/path/SDK dependencies, `PUB_CACHE`, proxies, certificates, and token
files are read-only. Token inventory follows Dart's native configuration roots:
XDG on Linux, `~/Library/Application Support/dart` on macOS, and `%APPDATA%\dart`
on Windows. Windows' default package cache remains `%LOCALAPPDATA%\Pub\Cache`.
`FLUTTER_STORAGE_BASE_URL` is neither persisted nor inherited by the isolated
verification process; Flutter SDK artifacts belong to the separate Flutter
adapter.

## Reviewed provider boundary

TUNA and SJTUG are actionable. Each candidate must return package metadata for
`retry` 3.1.2, expose the metadata's archive SHA-256, and serve the complete
archive with the same locked digest before latency can count. The SJTUG hosted
API points to the China Flutter storage service's Dart package archive export;
this is a Pub package artifact endpoint, not a Flutter SDK distribution source.
Other inventoried providers remain visible but inert when the complete chain is
absent.

After apply, MirrorSwitch runs native `dart pub get` and `dart pub deps` against a
managed verification pubspec and cache. The resulting lockfile must bind `retry`
3.1.2 to the selected hosted URL. CLI, versioned configuration, and TUI use the
same plan; failure restores the persistent setting and managed files.

The native release boundary uses Dart 3.9.3 on GitHub-hosted macOS Intel, macOS
Apple Silicon, Windows x64, and Windows arm64 runners. The corresponding Dart SDK
archives exist for all four target pairs. Jobs verify native executable and
configuration paths, token/project immutability, frontend equality, live package
resolution, idempotence, native mode or ACL preservation, and exact recovery.
