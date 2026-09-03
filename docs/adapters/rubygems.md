# RubyGems adapter

The RubyGems adapter supports the reviewed Ruby 2.6+ and RubyGems 3.x/4.x user
configuration model on Linux, macOS, and Windows x86_64/arm64. Non-Linux targets must be native
hosts. Detection requires both ruby and gem, records their versions and the detected platform,
checks the runtime-provided user and project directories, and asks RubyGems for its gem home,
selected user configuration, credentials path, trusted-certificate inventory, and ordered source
list. This follows the
official RubyGems [configuration precedence](https://guides.rubygems.org/configuration/) and
[gem sources command](https://guides.rubygems.org/command-reference/#gem-sources).

The only writable scope is the user gemrc selected by RubyGems; it may therefore be `.gemrc` or an
XDG/native path rather than a path guessed from the operating system. MirrorSwitch replaces exactly one
recognized public source inside a simple YAML :sources sequence and preserves every private
source, its position, embedded credentials, comments, quoting, proxy and TLS/certificate options,
and unrelated gem options. UTF-8 BOM and LF/CRLF newlines are preserved. When no
user :sources key exists, a user key is created only if the effective source list is exactly one
recognized public default. Multiple public sources, a source order that differs from the user
file, inline/aliased/otherwise complex YAML, a GEMRC process override, and configuration outside
the selected home are reported as unsupported. The adapter never reads or changes the credentials
file or certificate store and never edits a project Gemfile; Bundler remains a separate adapter.

The six-provider inventory contains RubyGems records for Alibaba Cloud, Huawei Cloud, Nanjing
University, Tsinghua TUNA, and USTC; the Shanghai Jiao Tong listing has no RubyGems record.
Protocol review found that the public mirrors do not expose one uniform complete Compact Index:
some omit versions or info, and some redirect info to RubyGems.org. The official
[Compact Index guide](https://guides.rubygems.org/rubygems-org-compact-index-api/) identifies that
API as Bundler's dependency-resolution surface, so v0.1 does not treat a Bundler-only redirect as
proof that the RubyGems CLI mirror is complete.

Before latency ranking, an actionable RubyGems candidate must instead pass the actual gem CLI
source protocol: the classic specs.4.8.gz index, the compressed
net-protocol-0.3.0.gemspec.rz dependency metadata, and the complete
net-protocol-0.3.0.gem download. The downloaded artifact must match the cataloged SHA-256
ba310c3d4f1cad46bb1ab20336b06669b1ff8f7c568d9cb9342b32a718547472 before its latency can
contribute to selection. Alibaba Cloud, NJU, TUNA, and USTC currently pass that flow. Huawei
Cloud's public index did not contain the reviewed current gem version, so it remains visible but
inert.

After apply, MirrorSwitch checks that the RubyGems-reported gemrc is part of the transaction, compares its
ordered sources with gem sources --list, and runs
gem dependency net-protocol --remote --version 0.3.0 --clear-sources --source MIRROR. The real
client must return both the gem version and its timeout (>= 0) dependency. Failure restores the
exact prior file, replanning is idempotent, and CLI, configuration-file, and TUI entry points
consume the same plan.

The native release boundary runs Ruby 3.4.10 on GitHub-hosted macOS Intel, macOS Apple Silicon,
Windows x64, and Windows arm64 runners. Each job discovers paths from the real RubyGems process,
uses the target platform's newline and permission/ACL conventions, exercises all three frontends,
runs the public dependency query, and checks exact recovery of gemrc, credentials, certificate
inventory, and the read-only project Gemfile.
