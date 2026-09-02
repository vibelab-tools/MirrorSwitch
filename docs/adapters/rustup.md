# rustup adapter

The rustup adapter supports the reviewed rustup 1.24+ environment model on Linux, macOS, and
native Windows hosts using `x86_64` or `arm64`. It records the rustup version and home, active
toolchain, default installation profile,
installed components, installed targets, project-aware toolchain selection, and the effective
mirror environment. This follows the official rustup documentation for
[environment variables](https://rust-lang.github.io/rustup/environment-variables.html),
[toolchain overrides](https://rust-lang.github.io/rustup/overrides.html),
[profiles](https://rust-lang.github.io/rustup/concepts/profiles.html), and
[components](https://rust-lang.github.io/rustup/concepts/components.html).

rustup has no persistent mirror configuration file. On Linux and macOS, MirrorSwitch writes one
managed block to an explicitly selected or shell-specific user environment file: `.bashrc`,
`.zshrc`, `.profile`, a container `BASH_ENV`, or a dedicated fish `conf.d` file. The block keeps
`RUSTUP_DIST_SERVER` and `RUSTUP_UPDATE_ROOT` as a provider-matched pair. Existing assignments
outside that block, conflicting process overrides, complex shell expressions, a profile outside
the selected home, and deprecated `RUSTUP_DIST_ROOT` configuration block the plan. Toolchains,
project `rust-toolchain` files, profile, components, targets, and unrelated shell content are never
changed.

Windows never receives Unix shell syntax. The adapter manages the two `REG_SZ` values under
`HKCU\Environment`, records the previous pair in a private `%LOCALAPPDATA%` recovery file before
calling `reg.exe`, verifies through a clean `cmd.exe` invocation, and restores both registry values
through the adapter-aware transaction path. Partial, unreviewed, expanded, or process-conflicting
values are left unchanged.

Distribution and self-update roots are independent catalog endpoints. A complete candidate must
serve the reviewed Rust 1.98.0 channel manifest and its SHA-256 sidecar; the `rustc`, `cargo`, and
`rust-std` assets for the Linux, Darwin, or Windows host triples; the rustup release pointer; and
rustup 1.29.0 `rustup-init` or `rustup-init.exe` installers plus their architecture-specific checksums.
Those checks run before latency contributes to selection.

The six-provider inventory includes rustup or rust-static records from Alibaba Cloud, Huawei
Cloud, Nanjing University, Shanghai Jiao Tong University, Tsinghua TUNA, and USTC. In the
2026-08-29 review, Huawei Cloud and USTC passed the complete distribution/update flow. Alibaba
Cloud and SJTUG exposed an older stable channel snapshot, while Alibaba Cloud, NJU, and TUNA did
not expose the reviewed rustup-init checksum files. Those records remain visible but inert rather
than being combined across providers. The endpoint pairs follow the providers' published
[Huawei Cloud inventory](https://mirrors.huaweicloud.com/v1/repositories),
[TUNA rustup instructions](https://mirrors.tuna.tsinghua.edu.cn/help/rustup/), and
[USTC rust-static instructions](https://mirrors.ustc.edu.cn/help/rust-static.html).

After apply, MirrorSwitch reloads and canonicalizes the managed block, injects the selected pair
into a real `rustup check`, and confirms the active installation profile through
`rustup show profile`. Both the up-to-date and update-available rustup exit statuses are valid;
other failures restore the exact prior environment file. Replanning is idempotent, and CLI,
configuration-file, and TUI entry points consume the same plan.
