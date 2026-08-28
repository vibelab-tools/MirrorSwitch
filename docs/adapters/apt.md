# APT adapter

The APT adapter supports Debian and Ubuntu on Linux at system scope. It detects `apt-get`, the
legacy `/etc/apt/sources.list` and `.list` fragments, and deb822 `.sources` files. Host and
container layouts use the same parser but retain their detected environment in mirror
compatibility checks.

Only recognized Debian/Ubuntu archive records are eligible for rewrites. Third-party repositories,
disabled and commented entries, `deb-src`, APT options, `Signed-By`, architecture restrictions,
unknown deb822 fields, comments, suites and components are preserved. A malformed active entry
stops planning instead of triggering a string replacement.

Before latency ranking, each candidate must match the distribution, host/container environment and
architecture. Ubuntu `x86_64` uses the Ubuntu archive candidates; Ubuntu `arm64` uses Ubuntu Ports.
For every detected suite/component pair, the candidate must provide both:

- `dists/{suite}/InRelease` with the clear-signed OpenPGP marker;
- `dists/{suite}/{component}/binary-{architecture}/Release` with architecture metadata.

The placeholders are filled only from parsed APT configuration and detected architecture, and are
restricted to safe path-segment characters. The adapter accepts HTTPS metadata endpoints only and
does not disable TLS or APT signature validation.

Plans contain complete original/new file snapshots but their debug and JSON forms expose only byte
counts and SHA-256 digests. Applying uses the shared atomic transaction engine. Verification runs
`apt-get update -o Acquire::Retries=0`; a non-zero result immediately attempts restoration from the
transaction receipt. Explicit restore verifies the original bytes after replacement.
