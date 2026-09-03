# Bundler adapter

Issues [#58](https://github.com/vibelab-tools/MirrorSwitch/issues/58) and
[#125](https://github.com/vibelab-tools/MirrorSwitch/issues/125) implement
source-specific RubyGems mirrors for Bundler 2.x through 4.x with Ruby 2.6
through 4.x on Linux, macOS, and Windows `x86_64`/`arm64`. Linux hosts and
containers are supported; macOS and Windows require native hosts.

The default scope is the user's global Bundler config. MirrorSwitch follows
Bundler's local, environment, global, and default precedence when it discovers
`~/.bundle/config`, `BUNDLE_USER_HOME`, `BUNDLE_USER_CONFIG`,
`BUNDLE_APP_CONFIG`, and `BUNDLE_GEMFILE` using the runtime's native home and
project paths. Windows drive prefixes are accepted without weakening normalized-path
checks. Project-local config is changed only
for an explicitly selected project scope. Gemfile, `gems.rb`, and lockfiles are
always read-only.

Only the exact `mirror.SOURCE_URL` setting for one statically identified public
RubyGems source is changed. MirrorSwitch never sets `mirror.all`, rewrites
private sources, or persists credential values in display or transaction
metadata. It preserves private mirrors, credentials, fallback timeout, comments,
ordering, quoting, UTF-8 BOM, LF/CRLF newlines, proxy/TLS/certificate settings,
and unrelated config bytes. Dynamic or conflicting source
identity, unsafe transport/checksum overrides, catch-all mirrors, and effective
environment overrides stop the operation before mutation.

## Reviewed provider boundary

Alibaba Cloud and NJU serve Bundler's classic full index. Their candidates must
return `specs.4.8.gz`, the SHA-256-pinned `net-protocol` 0.3.0 gemspec containing
the reviewed dependency metadata, and the SHA-256-pinned gem artifact. TUNA and
USTC serve `/versions`; their `/info/net-protocol` response currently redirects
to RubyGems.org, so the followed metadata chain and its `net-protocol` version
and `timeout` dependency markers are part of the gate. Huawei Cloud lacks the
fixed version, while SJTUG does not list RubyGems, so both remain inert. Content
validation completes before candidate latency is compared.

After apply, an isolated credential-free managed config runs a real
`bundle config get mirror.SOURCE_URL`, followed by `bundle lock --print` against
a fixed Gemfile for `net-protocol` 0.3.0. The lock result must include its
`timeout` dependency. The catalog separately checks the exact gem SHA-256.
Failure restores every managed file, and repeating an applied selection is a
no-op.

Isolation is provided by the native process runtime rather than a Unix `env`
executable. Windows therefore resolves and launches the installed `bundle.bat` or
`bundle.cmd` through PATHEXT, while macOS launches its native executable. The release
boundary runs Bundler 4.0.19 with Ruby 3.4.10 on GitHub-hosted macOS Intel, macOS
Apple Silicon, Windows x64, and Windows arm64 runners. Each job verifies native
paths, CLI/config/TUI plan equality, the real lock query, idempotence, native mode
or ACL preservation, and exact restoration of global/local configs, Gemfile, and
lockfile.
