# pyenv/python-build adapter

Issues [#69](https://github.com/vibelab-tools/MirrorSwitch/issues/69) and
[#141](https://github.com/vibelab-tools/MirrorSwitch/issues/141) implement the
python-build source mirror boundary on Linux and native macOS x86_64/arm64.
Windows is excluded because pyenv-win is a different tool with a different
configuration and definition model.

MirrorSwitch calls native `pyenv` to obtain its version and root, calls the
bundled python-build plugin for its version and definition list, and reads the
actual CPython definition under that root. The reviewed definition must name
CPython 3.14.7's official source URL and exact SHA-256. Detection also records
the native OS/architecture, selected home and project directory, shell profile,
and existing active `pyenv init` count without reading project contents.

The writable boundary is one bash, zsh, or fish user profile plus a private
verification manifest under the user's home. MirrorSwitch only manages
`PYTHON_BUILD_MIRROR_URL` and the URL-layout switch
`PYTHON_BUILD_MIRROR_URL_SKIP_CHECKSUM`; the latter stops python-build from
appending the checksum as a path component but does not disable python-build's
post-download checksum verification. Custom definition roots, forced official
fallback, a private mirror, dynamic assignments, checksum-policy conflicts,
and process precedence conflicts stop the plan. Existing pyenv initialization,
private variables, unknown shell content, UTF-8 BOMs, native line endings,
permissions, and project files are preserved.

Huawei Cloud, NJU, and TUNA currently expose the reviewed Python source tree.
Each candidate must pass the release directory, detached signature digest,
archive presence, and full archive SHA-256 before latency comparison. The
source archive and python-build definition are identical on Linux and macOS;
the local checksum command is not: Linux uses `sha256sum`, while macOS uses the
native `shasum -a 256`. The bounded selection response budget is 24 MiB so the
fixed 24,053,924-byte source archive can be hashed without making downloads
unbounded.

After apply, pyenv re-reads the bundled definition with the selected mirror,
then MirrorSwitch downloads the fixed archive, verifies the definition's exact
SHA-256, and removes the verification archive on both success and failure.
Any verification error restores the profile and manifest; repeated application
is a no-op.

The manual native workflow installs a commit-pinned pyenv 2.8.4 tree on macOS
Intel and Apple Silicon. It checks native discovery, CLI/configuration/TUI plan
equality, the real definition and archive boundary, shell loading, cleanup,
idempotence, and exact restoration.
