# Linux terminal interface

MirrorSwitch provides one Linux executable with `detect`, `plan`, `apply`, `status`, `restore`,
and `tui` commands. `detect`, `plan`, and `status` are read-only. Non-interactive changes require
`apply --yes`; transaction recovery requires `restore TRANSACTION_ID --yes`.

```bash
mirrorswitch detect --offline --json
mirrorswitch plan --tool pip --tool cargo
mirrorswitch plan --category system
mirrorswitch apply --config request.json --yes --json
mirrorswitch tui
```

The optional configuration format is versioned JSON; see `config.example.json`. Unknown fields,
unknown versions, duplicate tools, unavailable tools, unsupported scopes, and unreviewed candidate
overrides are errors. Command-line tool/scope/mirror selections override the file while explicit
disabled tools remain disabled.

The TUI starts from detected defaults, shows unavailable reasons, and lets users toggle tools.
After compatibility probes it shows every candidate result, measured latency, selected provider,
redacted old/new digests, permissions, elevation, service impact, and skipped reasons. It asks for
confirmation before using the same apply/verify/restore path as the CLI.

`--json` is stable machine output. Exit code `0` means success, `2` means a usage/configuration
error, and `3` means no actionable plan or a partial apply. Apply failures report the adapter,
stage, error, and recovery state. Status output always identifies host/container context and the
active catalog version/source. `--offline` disables the GitHub Raw catalog update but does not turn
off mirror compatibility probes used by `plan` and `apply`.
