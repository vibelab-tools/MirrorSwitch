# Cargo adapter

The Cargo adapter supports the reviewed Cargo 1.68+ sparse-registry model on Linux `x86_64`
and `arm64`. Detection records the Cargo and Rust versions, resolves `CARGO_HOME`, applies
Cargo's project-to-user configuration hierarchy, and gives an extensionless `config` precedence
over `config.toml` in the same directory. The behavior follows Cargo's official
[configuration hierarchy](https://doc.rust-lang.org/cargo/reference/config.html),
[source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html), and
[registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html) contracts.

The only writable scope is the selected user Cargo configuration. MirrorSwitch either adds a
dedicated source replacement for crates.io or updates the terminal registry in an existing,
unambiguous crates.io replacement chain. It preserves private registries, authentication,
unrelated sources, and project configuration. Credentials files are located for evidence but are
never read, copied, or changed. A project crates.io override, an unknown or private terminal
replacement, a source-name collision, a replacement cycle, `include`, offline mode, an effective
process-level registry protocol override, or a `CARGO_HOME` outside the selected home blocks the
plan rather than changing configuration whose effect cannot be proven.

Sparse candidates keep index and crate-download endpoints separate. Before latency ranking, each
candidate must return a valid `config.json`, an index entry containing the reviewed crate checksum,
and the exact crate archive with the same SHA-256. Alibaba Cloud, Nanjing University, and USTC
currently pass that complete flow. Tsinghua TUNA's sparse index directs downloads to the official
crates.io static host, so it remains cataloged but is not actionable as a complete China-hosted
mirror. Huawei Cloud's reviewed Rust listing does not expose a compatible crates.io registry.

Cargo 1.39 through 1.67 is recognized as using the git-index model. None of the six reviewed
providers currently supplies both a compatible git index and China-hosted crate artifacts, so
MirrorSwitch reports no compatible candidate and makes no change. Cargo older than 1.39 is outside
the reviewed configuration model.

After apply, MirrorSwitch reloads the effective source chain and runs
`cargo info itoa@1.0.18 --registry crates-io --verbose --color never`. The real Cargo client must
resolve the reviewed version and checksum-verify its downloaded crate. Failure restores the exact
prior user file, replanning is idempotent, and CLI, configuration-file, and TUI entry points
consume the same plan.
