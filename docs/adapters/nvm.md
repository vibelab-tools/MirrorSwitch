# nvm adapter

The nvm adapter supports Linux `x86_64` and `arm64` with nvm loaded by a reviewed POSIX shell
(`bash`, `zsh`, `sh`, `dash`, Alpine `ash`, or `ksh`). It detects `NVM_DIR` (including the XDG default), the
`nvm.sh` installation, git versus script/source installation, nvm version, active Node.js/io.js
selection, locally available versions, the active `SHELL`, and the shell initialization file.
This follows nvm's official [installation and profile contract](https://github.com/nvm-sh/nvm#installing-and-updating)
and its documented [`NVM_NODEJS_ORG_MIRROR` and `NVM_IOJS_ORG_MIRROR` variables](https://github.com/nvm-sh/nvm#use-a-mirror-of-node-binaries).

The only writable scope is one explicitly selected user shell environment. `PROFILE` selects a
profile directly; a containerized bash environment may select `BASH_ENV`; otherwise exactly one
profile for the active shell must already load `nvm.sh`. MirrorSwitch rejects ambiguous profiles,
paths outside the user's home, and `PROFILE=/dev/null`. It adds one replaceable managed block and
does not rewrite, reorder, source, or execute the rest of the user's shell initialization. An
existing unmanaged mirror assignment is preserved and blocks the plan. `NVM_AUTH_HEADER` also
blocks a public-mirror plan so an existing credential is never redirected.

Node.js release artifacts are independent from the npm Registry. A Node.js candidate must expose
`index.tab`, the target version's `SHASUMS256.txt`, and the exact Linux `x64` and `arm64` tarballs.
The target is the active semantic Node.js version when available; otherwise the reviewed common
baseline is `v24.1.0`. The separate io.js candidate must expose the same surfaces for the final
io.js release, `v3.3.1`, on both architectures. The runtime catalog currently contains five
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
