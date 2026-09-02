# Install MirrorSwitch on Linux

MirrorSwitch v0.1.0 ships static Linux binaries for `x86_64` and `arm64`, both as generic
archives and as deb/rpm packages. Installation places only the `mirrorswitch` terminal program
and license/readme files; it does not configure a mirror or start a service.

## Verify a download

Download one complete architecture artifact so its `SHA256SUMS` sits beside the three packages,
then run:

```bash
sha256sum -c SHA256SUMS
```

Do not install a package whose checksum or architecture name does not match the machine. Use
`uname -m`: `x86_64` selects the x86_64/amd64 files, while `aarch64` selects the arm64/aarch64
files.

## Generic archive

```bash
tar -xzf mirrorswitch-0.1.0-linux-x86_64.tar.gz
sudo install -m 0755 mirrorswitch-0.1.0-linux-x86_64/mirrorswitch /usr/local/bin/mirrorswitch
mirrorswitch --version
```

Use the `linux-arm64` archive on an aarch64 machine. Upgrade by verifying and installing the new
binary over `/usr/local/bin/mirrorswitch`. Uninstall only that file:

```bash
sudo rm /usr/local/bin/mirrorswitch
```

## Debian and Ubuntu

```bash
sudo dpkg -i mirrorswitch_0.1.0_amd64.deb
mirrorswitch --help
```

Use the `_arm64.deb` file on arm64. `dpkg -i` installs or upgrades the package. Uninstall it with:

```bash
sudo dpkg -r mirrorswitch
```

## Fedora, Rocky, AlmaLinux, and CentOS Stream

```bash
sudo rpm -Uvh mirrorswitch-0.1.0-1.x86_64.rpm
mirrorswitch --help
```

Use the `.aarch64.rpm` file on arm64. Uninstall it with:

```bash
sudo rpm -e mirrorswitch
```

## First safe run

Start with read-only inspection. `status`, `detect`, and `plan` never apply a configuration:

```bash
mirrorswitch status --json
mirrorswitch detect --offline --json
mirrorswitch plan --category system
mirrorswitch tui
```

Review every selected provider, target path, digest, permission requirement, service impact, and
skipped reason. A non-interactive mutation requires `apply --yes`; recovery requires an exact
transaction ID and `restore TRANSACTION_ID --yes`.

System adapters mark their plans as requiring elevation, but v0.1.0 does not contain a privilege
broker. Run a system-only apply/restore from an already elevated shell. Do not combine user-scope
and system-scope changes under `sudo`, because the effective home and user configuration can
change. User and project scopes should run as the owning user.

See [CLI/config/TUI usage](cli.md), the [support matrix](support-matrix.md), and the
[transaction model](transactions.md) before applying changes.
