# CPAN client adapter

Issues [#67](https://github.com/vibelab-tools/MirrorSwitch/issues/67) and
[#136](https://github.com/vibelab-tools/MirrorSwitch/issues/136) implement the
user-scoped CPAN boundary. Linux supports `x86_64` and `arm64` hosts and
containers; macOS supports native Intel and Apple Silicon hosts; Windows
supports native x86_64 hosts. Windows arm64 is rejected because the reviewed
Perl distribution has no native Windows arm64 runtime.

MirrorSwitch discovers Perl and CPAN.pm with the running interpreter. It uses
the CPAN home, user `MyConfig.pm`, system config, Perl version, and `archname`
reported by that interpreter instead of assuming a Unix path. An initialized
system CPAN.pm config remains read-only and can seed an unprivileged user
override. The adapter replaces only recognized public entries in `urllist`,
keeps private and local mirrors in their original order, and pins
`pushy_https` and `randomize_urllist` to deterministic safe values. Other
CPAN.pm fields, proxy/certificate environment, comments, UTF-8 BOMs, native
line endings, and permissions or ACLs remain unchanged.

cpanminus is configured independently. Linux and macOS use one selected bash,
zsh, or fish profile and preserve unrelated `PERL_CPANM_OPT` flags and private
mirrors. Native Windows stores `PERL_CPANM_OPT` as a user `REG_SZ` value under
`HKCU\Environment`; a private recovery file records the previous value before
the registry changes. A conflicting process override, dynamic shell
assignment, exclusive private `--from`, or malformed registry value makes only
that client inert. Project `cpanfile` content is always read-only and is
redacted from previews.

## Reviewed provider boundary

Alibaba Cloud, NJU, TUNA, and USTC publish complete CPAN layouts. Before
latency counts, each candidate must expose `02packages.details.txt.gz`, the
Try-Tiny 0.32 metadata, its author `CHECKSUMS` entry, and the distribution
archive whose SHA-256 is pinned in the catalog. Huawei Cloud and SJTUG do not
provide the same complete reviewed surface and remain inert. CPAN indexes and
source distributions are architecture independent, but the candidate still
declares the supported native OS and CPU contexts.

After apply, CPAN.pm loads its effective config in an isolated CPAN home and
resolves the exact `E/ET/ETHER/Try-Tiny-0.32.tar.gz` path. cpanminus runs its
native `--info Try::Tiny` command with an isolated home and the selected
options. The two clients must resolve through the same selected mirror. A
failure restores every changed file and, on Windows, the previous registry
value; repeated application is a no-op.

The manual native workflow uses Perl 5.40 with CPAN.pm and cpanminus on macOS
Intel, macOS Apple Silicon, and Windows x86_64. It compares
CLI/configuration/TUI plans, checks both native client commands, preserves a
read-only private `cpanfile`, proves idempotence, and restores original bytes,
permissions or ACL, and Windows user-environment state.
