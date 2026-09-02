# Cygwin adapter

The `cygwin` adapter supports the x86_64 Cygwin setup client on native Windows 10 and 11. Cygwin
does not publish a native ARM64 setup repository, so Windows ARM64 is reported as unsupported even
when x64 emulation could launch the installer.

MirrorSwitch discovers `CYGWIN_ROOT` or the standard `C:\cygwin64` installation, plus an explicit
`CYGWIN_SETUP` or `setup-x86_64.exe` in the user's Downloads directory. It reads
`etc\setup\setup.rc` for `last-mirror` and `last-cache`, and records the setup version. The local
package directory must be absolute.

Huawei Cloud and TUNA are the two actionable candidates because both appear on Cygwin's current
official mirror list. TUNA uses the current `/sourceware/cygwin` path. Alibaba and NJU still expose
historical directories, but remain partial because they are absent from that list. Each candidate
must expose `x86_64/setup.xz`, its detached signature, `setup.ini`, and the fixed dash 0.5.12-5
archive with the reviewed SHA-256.

## Managed state

The plan changes only the value line following `last-mirror` in `setup.rc`. It preserves the file's
CRLF or LF representation, cache path, network method, installation root, `installed.db`, selected
packages, and all Cygwin system files. A custom current mirror, duplicate keys, missing setup
executable, relative cache/root path, or incomplete setup state blocks the plan. The installation
state is treated as system scope and requires elevation for apply/restore.

## Verification and recovery

After apply, MirrorSwitch rereads `setup.rc` and runs `setup-x86_64.exe` in quiet, unattended,
download-only, no-admin mode with the existing root and local package directory. It selects only
`dash`; the signed setup metadata verifies the package's published SHA-512 while `--download`
prevents installation or package-selection changes. No signature-bypass option is used.

Any setup failure restores `setup.rc`. Repeated planning is idempotent, and explicit transaction
restore returns the previous mirror and Windows file attributes without changing the cache or
installed package database.
