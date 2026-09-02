# Windows host and WSL boundary

MirrorSwitch treats the native Windows host and every WSL distribution as separate machines. A
normal Windows command detects and configures only native Windows adapters. If `wsl.exe` is
available, status and TUI output list each distribution as unchecked, including its WSL generation,
kernel, default Linux UID/home, and whether a compatible Linux `mirrorswitch` is installed.

Use `--wsl NAME` to select exactly one distribution:

```text
mirrorswitch detect --wsl Ubuntu-24.04 --offline --json
mirrorswitch plan --wsl Ubuntu-24.04 --tool apt --offline --json
mirrorswitch apply --wsl Ubuntu-24.04 --tool apt --offline --yes --json
mirrorswitch restore --wsl Ubuntu-24.04 TRANSACTION_ID --yes --json
mirrorswitch tui --wsl Ubuntu-24.04 --offline
```

The Windows binary validates the distribution name, invokes `wsl.exe` with separate arguments, and
first requires the distribution's native Linux `mirrorswitch` to have the exact same program
version. It then forwards the original command after removing only `--wsl NAME`. The child binary
performs normal Linux detection, selection, transaction, verification, and restore inside that
distribution.

This design does not mount or edit an ext4 VHD from Windows and does not translate Linux paths into
Windows paths. Each child sees its own `/`, `$HOME`, executable namespace, permissions, catalog
cache, and `/var/lib/mirrorswitch/transactions`. A transaction ID is meaningful only inside the
distribution where it was created; selecting another distribution cannot find or restore it.

WSL distributions are never selected merely because they are installed. A distribution without the
matching Linux CLI remains visible but unavailable, so deployment of the Linux package is an
explicit prerequisite rather than an implicit cross-environment write.
