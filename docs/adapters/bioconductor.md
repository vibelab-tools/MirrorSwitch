# Bioconductor adapter

Issues [#64](https://github.com/vibelab-tools/MirrorSwitch/issues/64) and
[#131](https://github.com/vibelab-tools/MirrorSwitch/issues/131) implement the
R 4.6.x, BiocManager 1.30.12+, and Bioconductor 3.23 repository pairing on Linux
and macOS `x86_64`/`arm64`, plus Windows x64. macOS and Windows require native
hosts; Windows arm64 has no reviewed native R runtime.

MirrorSwitch writes only `BioC_mirror` in the selected user `.Rprofile` or
explicit `R_PROFILE_USER`. CRAN, named/private repositories, all non-mirror R
options, `.Renviron`, project `.Rprofile`, and `renv.lock` remain read-only. A
project profile that precedes the user profile blocks the plan. UTF-8 BOM,
LF/CRLF, credentials, proxy/certificate settings, unknown R code, and native
mode/ACL are preserved.

Detection requires native Rscript and BiocManager, records R and BiocManager
versions, `R.version$platform`, `R_ARCH`, the BiocManager library, release
identity, mirror, and every repository class. The reported platform must match
the host OS and architecture. Verification uses an isolated leading library but
retains the detected BiocManager library so it does not install or replace the
user's package manager.

NJU and TUNA are complete candidates. Linux verifies source packages for all
five Bioconductor classes. macOS and Windows verify the target R 4.6 binary
BiocVersion package for BioCsoft, while BioCann, BioCexp, BioCworkflows, and
BioCbooks remain source packages because those classes do not publish the
required platform binaries. All five indexes and archives must pass, and each
archive has a locked SHA-256 before latency counts.

After apply, native R loads the changed user profile while site/project startup
and environment repository overrides are isolated. BiocManager must report the
selected BioCsoft, BioCann, BioCexp, BioCworkflows, and BioCbooks roots and
download the exact package type for each class. Archives are verified with `sha256sum`, `shasum`, or
`certutil.exe` on the corresponding OS. CLI, versioned configuration, and TUI
share one plan; failure restores the profile and verification script.

The native release boundary uses R 4.6.1 on GitHub-hosted macOS Intel, macOS
Apple Silicon, and Windows x64 runners. It covers native binary/data-source
resolution, frontend equality, CRAN/project/auth immutability, BOM/newlines,
idempotence, permissions, and exact recovery.
