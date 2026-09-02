# Testing MirrorSwitch

All local and CI verification enters through `scripts/test.sh`:

```bash
bash scripts/test.sh quality
bash scripts/test.sh unit
bash scripts/test.sh cli
bash scripts/test.sh language
bash scripts/test.sh distro debian
bash scripts/test.sh docker
```

`quality` runs rustfmt and Clippy with warnings denied. `unit` enforces that every catalog tool
marked `supported` has an adapter boundary test, then runs the complete Rust suite serially. `cli`
builds the release executable and runs version, help, and read-only detection checks while proving
that `/etc/apt` did not change. `language` runs representative Python, Node.js, JVM, Go, and Rust
adapters. `distro` pairs the relevant public adapter boundary test with an isolated container that
asks the distribution's real package manager to parse a fixture. `docker` runs Debian, Ubuntu,
Fedora, Rocky Linux, AlmaLinux, CentOS Stream, Arch Linux, openSUSE, and Alpine.

The exact release tags are centralized in `tests/docker/images.env`; image updates require an
Issue-backed review because they can change compatibility conclusions. Containers run with no
network, write only under their own `/tmp`, and mount the scenario script read-only. They never
mount host package-manager configuration or a container daemon socket.

Pass `arm64` as the third `distro` argument to request `--platform linux/arm64`. On an x86_64
host this may use binfmt/QEMU and proves user-space parsing only. It does not prove native arm64
kernel, systemd, rootless runtime, service restart, daemon socket, or host privilege behavior.
Those boundaries require an arm64 runner or an explicitly controlled host/service test.

GitHub Actions runs `cli` on native `x86_64` and arm64 Linux runners. The tested release binary
and its SHA-256 file are uploaded directly from that job for downstream packaging; release jobs
must consume this artifact instead of rebuilding it. The deterministic distribution matrix runs
on x86_64, while Debian also runs natively on arm64 to cover APT's host/container boundary there.

Deterministic fixture and Docker checks are release gates. Live mirror probes are catalog-review
evidence and must not be mixed into them as allowed failures. External availability monitoring
belongs in a separately labelled scheduled workflow. Failure output records the scenario,
architecture, catalog version/revision, candidate state, and failing phase.
