# APK adapter

The APK adapter supports Alpine Linux hosts and containers on x86_64 and arm64 (`aarch64` in APK
repository paths) at system scope. It reads `/etc/apk/repositories`, including optional repository
tags, stable version branches, edge, main, community, testing, comments and local/custom entries.

Only active repositories whose existing URL matches the Alpine CDN or one of the six cataloged
mirror providers are eligible. Planning replaces the mirror root while retaining the exact branch,
repository and optional tag from every recognized line. It never enables a commented repository,
adds edge or testing, changes a stable branch, removes a local path, or rewrites an unknown custom
server.

Before latency ranking, each candidate must match Alpine, the host/container environment and the
detected architecture. It must answer a bounded HEAD request for every configured
`{branch}/{repository}/{architecture}/APKINDEX.tar.gz` path. A single provider is selected only
after all active recognized repositories pass, preventing partial mirror changes.

Applying uses the shared atomic transaction engine and does not touch `/etc/apk/keys` or pass an
untrusted/signature-bypass option. Verification runs `apk update --no-progress`, which downloads
and verifies the configured indexes; a non-zero result immediately attempts restoration. Explicit
restore verifies the original repository file bytes, and repeated planning is idempotent.
