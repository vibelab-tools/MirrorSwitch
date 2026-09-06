# nvm adapter

The nvm adapter supports Linux and native macOS `x86_64`/`arm64` with nvm loaded by a reviewed POSIX shell
(`bash`, `zsh`, `sh`, `dash`, Alpine `ash`, or `ksh`). It detects `NVM_DIR` (including the XDG default), the
`nvm.sh` installation, git versus script/source installation, nvm version, active Node.js/io.js
selection, locally available versions, native OS/architecture, user and project directories, the
active `SHELL`, and the shell initialization file. Windows remains unsupported because
nvm-windows is a different tool with a different configuration and release model.
This follows nvm's official [installation and profile contract](https://github.com/nvm-sh/nvm#installing-and-updating)
and its documented [`NVM_NODEJS_ORG_MIRROR` and `NVM_IOJS_ORG_MIRROR` variables](https://github.com/nvm-sh/nvm#use-a-mirror-of-node-binaries).

The only writable scope is one explicitly selected user shell environment. `PROFILE` selects a
profile directly; a containerized bash environment may select `BASH_ENV`; otherwise exactly one
profile for the active shell must already load `nvm.sh`. MirrorSwitch rejects ambiguous profiles,
paths outside the user's home, and `PROFILE=/dev/null`. It adds one replaceable managed block and
does not rewrite, reorder, source, or execute the rest of the user's shell initialization. An
existing unmanaged mirror assignment is preserved and blocks the plan. `NVM_AUTH_HEADER` also
blocks a public-mirror plan so an existing credential is never redirected. UTF-8 BOMs, native
newlines, permissions, and project files are preserved.

Node.js release artifacts are independent from the npm Registry. A Node.js candidate must expose
`index.tab`, the target version's `SHASUMS256.txt`, and only the current native archive: Linux
`x64`/`arm64` `tar.xz` or Darwin `x64`/`arm64` `tar.gz`.
The target is the active semantic Node.js version when available; otherwise the reviewed common
baseline is `v24.1.0`. The separate io.js candidate must expose the same surfaces for the final
io.js release, `v3.3.1`, on Linux and macOS Intel. io.js 3.3.1 predates Apple Silicon and has no
Darwin arm64 archive, so native macOS arm64 plans configure only Node.js and leave any io.js
policy untouched rather than substituting an x64 artifact. The runtime catalog currently contains five
Node.js mirrors (Alibaba Cloud, Huawei Cloud, NJU, TUNA, and USTC) and Huawei Cloud's io.js mirror.

Incomplete candidates are filtered before latency ranking. There is no silent official-source
fallback: if either the Node.js or io.js upstream lacks a candidate that passes every target,
checksum, and architecture probe, the joint selection is non-actionable and no shell file is
changed. This makes stale mirrors visible instead of silently mixing origins.

After apply, MirrorSwitch parses the canonical managed block and runs real, non-colored
`nvm ls-remote` queries for Node.js `v24.1.0` and io.js `v3.3.1` with the selected endpoints. It
sources `nvm.sh` directly and does not execute unrelated user profile contents. Any query or
policy failure restores the original profile. Replanning the verified state produces no changes,
and CLI, configuration-file, and TUI selection paths consume the same user-scope plan.

The manual native workflow installs the pinned nvm 0.40.6 script on macOS Intel and Apple Silicon,
then exercises the real zsh profile hierarchy, platform-specific catalog probes, native
`nvm ls-remote`, plan frontends, idempotence, and exact restoration.
