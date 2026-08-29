# Bundler adapter

Issue [#58](https://github.com/vibelab-tools/MirrorSwitch/issues/58) implements
source-specific RubyGems mirrors for Bundler 2.x through 4.x with Ruby 2.6
through 4.x on Linux `x86_64` and `arm64` hosts and containers.

The default scope is the user's global Bundler config. MirrorSwitch follows
Bundler's local, environment, global, and default precedence when it discovers
`~/.bundle/config`, `BUNDLE_USER_HOME`, `BUNDLE_USER_CONFIG`,
`BUNDLE_APP_CONFIG`, and `BUNDLE_GEMFILE`. Project-local config is changed only
for an explicitly selected project scope. Gemfile, `gems.rb`, and lockfiles are
always read-only.

Only the exact `mirror.SOURCE_URL` setting for one statically identified public
RubyGems source is changed. MirrorSwitch never sets `mirror.all`, rewrites
private sources, or persists credential values in display or transaction
metadata. It preserves private mirrors, credentials, fallback timeout, comments,
ordering, quoting, and unrelated config bytes. Dynamic or conflicting source
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
