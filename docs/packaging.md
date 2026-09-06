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

## v0.2 native terminal archives

Tags in the `v0.2.*` line add four native archives to the six Linux packages:

| Platform | Architecture | Archive |
| --- | --- | --- |
| macOS 14+ | Intel `x86_64` | `mirrorswitch-VERSION-macos-x86_64.tar.gz` |
| macOS 14+ | Apple Silicon `arm64` | `mirrorswitch-VERSION-macos-arm64.tar.gz` |
| Windows 10/11 | `x86_64` | `mirrorswitch-VERSION-windows-x86_64.zip` |
| Windows 11 | `arm64` | `mirrorswitch-VERSION-windows-arm64.zip` |

Each branch builds on the matching native runner, checks the Rust host triple,
runs the host/transaction/restore boundaries, and exercises version, help, and
read-only detection both before and after packaging. The package artifact then
moves unchanged into the release job; Cargo is not invoked there. The final
release contains ten platform files plus one aggregate `SHA256SUMS`.

The current macOS archives are not notarized or Developer ID signed. The native
runner records the actual executable architecture, while installation guidance
must describe checksum verification and the user-visible Gatekeeper/quarantine
step explicitly. A successfully built archive is not marked supported until
the corresponding native tool workflows and release checklist also pass.
