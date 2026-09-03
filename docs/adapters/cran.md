# CRAN adapter

Issues [#68](https://github.com/vibelab-tools/MirrorSwitch/issues/68) and
[#130](https://github.com/vibelab-tools/MirrorSwitch/issues/130) implement CRAN
selection for R 3.3+ on Linux and macOS `x86_64`/`arm64`, plus Windows x64.
macOS and Windows require native hosts. Windows arm64 remains unsupported because
the reviewed R distribution has no native Windows arm64 runtime.

MirrorSwitch writes only the selected user `.Rprofile` or explicit
`R_PROFILE_USER`. `Rprofile.site`, `.Renviron`, `R_REPOSITORIES`, named private
repositories, Bioconductor settings, RStudio preferences, project `.Rprofile`,
and `renv.lock` remain read-only. A project profile that takes precedence over
the selected user file blocks the plan. UTF-8 BOM, LF/CRLF, unknown R code,
repository order, credentials, proxy/certificate settings, and native mode/ACL
are preserved.

Detection records the native R version, `R.version$platform`, `R_ARCH`, site and
user profile selection, effective ordered repositories, and project precedence.
The reported OS/architecture must match the host context. Windows drive paths
and both `~/` and `~\` user-profile forms are accepted after normalization.

All four actionable providers—Alibaba Cloud, NJU, TUNA, and USTC—use the same
fixed `digest` 0.6.39 identity, but the actual package gate is platform-specific.
Linux checks `src/contrib` source metadata and `.tar.gz`; macOS checks the R 4.6
Big Sur x86_64 or Sonoma arm64 binary tree and `.tgz`; Windows checks the R 4.6
x64 binary tree and `.zip`. Each downloaded archive must match its target's
locked SHA-256 before latency counts.

After apply, native R loads the changed user profile while site/project startup
and `R_REPOSITORIES` overrides are isolated. It queries `available.packages`,
downloads the target-native package type, and verifies the archive with
`sha256sum` on Linux, `shasum` on macOS, or `certutil.exe` on Windows. CLI,
versioned configuration, and TUI share one plan; failures restore the profile
and managed verification script.

The native release boundary runs R 4.6.0 on GitHub-hosted macOS Intel, macOS
Apple Silicon, and Windows x64 runners. It covers real binary resolution,
frontend equality, project/auth/RStudio immutability, BOM/newline handling,
idempotence, native permissions, and exact recovery.
