# DNF adapter

The DNF adapter supports Fedora, Rocky Linux, AlmaLinux and CentOS Stream on Linux at system
scope. It detects DNF5 before DNF4, reads enabled `.repo` files from `/etc/yum.repos.d`, and derives
`$releasever`, `$stream` and `$basearch` from the detected system context. Rocky Linux and
AlmaLinux use the major release for their repository paths; arm64 maps to DNF's `aarch64` base
architecture. CentOS Linux repositories are not treated as Stream repositories merely because a
DNF command is installed.

Only recognized distribution-owned sections and known mirror locations are eligible for rewrites.
Fedora `fedora`, `updates` and `updates-testing` sections are kept separate from Rocky Linux and
AlmaLinux `baseos`, `appstream`, `crb`/`powertools` and `extras` sections, and from CentOS Stream
`baseos`, `appstream` and `crb`. EPEL, COPR, CentOS Stream add-on/SIG, unknown and disabled
repositories remain unchanged. Existing signature, GPG key, module and policy fields are
preserved.

An active `baseurl` is replaced in place. An active `metalink` or `mirrorlist` is retained as a
`# MirrorSwitch original:` comment and followed by the selected `baseurl`, making the resulting
file auditable and the next plan idempotent.

Before latency ranking, each candidate must match the distribution, host/container environment
and architecture. Every detected repository path must return `repodata/repomd.xml` containing a
`<repomd` marker. Probe path placeholders accept only safe segments and cannot traverse outside
the selected mirror endpoint. The adapter accepts HTTPS metadata endpoints only and never changes
TLS, `gpgcheck`, `repo_gpgcheck` or `gpgkey` settings.

Plans contain complete original/new file snapshots, while their debug and JSON forms expose only
byte counts and SHA-256 digests. Applying uses the shared atomic transaction engine. Verification
runs `dnf5 makecache --refresh` or `dnf makecache --refresh`; a non-zero result immediately
attempts restoration from the transaction receipt. Explicit restore verifies the original bytes.
