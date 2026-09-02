# Linux packaging

The Linux release matrix contains predictable per-architecture files:

| Architecture | Generic archive | Debian package | RPM package |
| --- | --- | --- | --- |
| `x86_64` | `mirrorswitch-0.1.0-linux-x86_64.tar.gz` | `mirrorswitch_0.1.0_amd64.deb` | `mirrorswitch-0.1.0-1.x86_64.rpm` |
| `arm64` | `mirrorswitch-0.1.0-linux-arm64.tar.gz` | `mirrorswitch_0.1.0_arm64.deb` | `mirrorswitch-0.1.0-1.aarch64.rpm` |

Each matrix branch first builds and exercises a native static-musl binary. The packaging job
downloads that exact verified artifact, validates its SHA-256, and creates the archive, deb, and
rpm without compiling again. `SHA256SUMS` covers all three final files. Archives and packages carry
the project license; deb and rpm metadata carry the project version.

The generic archive and deb are installed and removed in the pinned Debian container. The rpm is
installed and removed in the pinned Fedora container. Both architectures run these checks on a
matching native GitHub runner. Tests execute version and help commands and prove that package
installation does not change APT or DNF repository configuration.

Tag builds use the same workflow graph, so a release job can consume the package artifacts created
after these checks. It must not invoke Cargo or rebuild the binary.

The artifact handoff and package gates are defined in [Linux CI](../.github/workflows/ci.yml).
