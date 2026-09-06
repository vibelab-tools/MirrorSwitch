# fnm adapter

The fnm adapter supports the reviewed fnm `1.x` command model on Linux and native macOS
`x86_64`/`arm64`, plus native Windows x64. The reviewed fnm 1.39.0 release publishes one x64
Windows binary, so Windows arm64 is rejected rather than treated as native through emulation.
Detection records the fnm version, native OS/architecture, selected home and project directory,
active `bash`, `zsh`, `fish`, or PowerShell initialization file, current Node.js version,
installed versions, and whether `FNM_NODE_DIST_MIRROR`, `FNM_DIR`, or `FNM_ARCH` is already
present in the environment. The supported initialization forms follow fnm's official
[shell setup](https://github.com/Schniz/fnm#shell-setup) and
[`list-remote` configuration](https://github.com/Schniz/fnm/blob/master/docs/commands.md#fnm-list-remote).

The only writable scope is one explicitly selected persistent user environment. MirrorSwitch uses
`PROFILE` when supplied, container bash's `BASH_ENV`, or fnm's canonical Unix profile for the
active shell: `.bashrc`, `${ZDOTDIR:-$HOME}/.zshrc`, or
`.config/fish/conf.d/fnm.fish`. On Windows it asks native `pwsh` or Windows PowerShell for
`$PROFILE.CurrentUserCurrentHost`. An inferred file must already initialize fnm. The adapter
appends one replaceable managed block using `export FNM_NODE_DIST_MIRROR=...` for bash/zsh,
`set -gx FNM_NODE_DIST_MIRROR ...` for fish, or `$env:FNM_NODE_DIST_MIRROR = ...` for PowerShell.
It never writes nvm variables or changes the existing `fnm env` command, flags, hooks, aliases,
or unrelated shell policy. UTF-8 BOMs, native newlines, permissions, ACLs, and project files are
preserved.

Existing non-managed `FNM_NODE_DIST_MIRROR` assignments and explicit `--node-dist-mirror` command
flags are preserved and block the plan because they would make precedence ambiguous. Environment
values are detected, while the selected persistent shell assignment deliberately becomes the
effective value when that environment is loaded.

Every candidate must expose `index.tab`, the active target version's `SHASUMS256.txt`, and the
exact current platform archive: Linux `tar.xz`, macOS `darwin-x64`/`darwin-arm64` `tar.gz`, or
Windows `win-x64.zip`. Other platforms cannot satisfy the current host's probe. When no active
semantic Node.js version exists, selection uses the reviewed common baseline `v24.1.0`. Alibaba
Cloud, Huawei Cloud, NJU, TUNA, and USTC are
eligible only after all protocol and content probes pass; incomplete or stale history is filtered
before latency ranking. There is no silent official-source fallback and no partial plan.

After apply, MirrorSwitch parses the canonical shell-specific block and runs
`fnm list-remote --filter v24.1.0 --latest --node-dist-mirror <selected> --arch <native>` so the
real fnm client, not only an HTTP probe, confirms protocol and architecture compatibility. Failure
restores the exact prior profile.
Replanning a verified profile is empty, and CLI, configuration-file, and TUI paths consume the
same plan.
