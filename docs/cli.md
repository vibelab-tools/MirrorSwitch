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

With no selection flag, detection supplies the defaults: only installed, operable adapters for the
observed Linux distribution, architecture, host/container context, and default scope are checked.
Python or Java runtime presence alone does not select pip, Maven, or Gradle; each client must be
detected independently. Supplying `--all`, `--category`, or `--tool` starts an explicit selection;
`--disable` removes a tool. Categories are `system`, `language`, `container`, and
`infrastructure`.

```bash
mirrorswitch plan --all
mirrorswitch plan --category language --disable npm
mirrorswitch plan --tool pip --scope pip=user
mirrorswitch plan --tool cargo \
  --mirror cargo:crates.io-index--language-registry=a28a105114ee2c65783f71a2
```

An explicit candidate ID is still subject to every compatibility and content probe; it cannot
force an incompatible mirror. System, user, site, project, and environment scopes are accepted by
the parser, but each adapter rejects scopes outside its catalog/compiled contract.

The optional configuration format is versioned JSON; see `config.example.json`. Unknown fields,
unknown versions, duplicate tools, unavailable tools, unsupported scopes, and unreviewed candidate
overrides are errors. Command-line tool/scope/mirror selections override the file while explicit
disabled tools remain disabled.

`status --json` reports catalog source/update/cache state, host/container context, permissions,
detected tools, defaults, and unavailable notices. `restore` accepts exactly one recorded
transaction ID. Configuration bytes and credential-bearing URL parts are not present in plan,
status, or apply JSON; file changes use redacted sizes, SHA-256 values, and modes.

The TUI starts from detected defaults, shows unavailable reasons, and lets users toggle tools.
After compatibility probes it shows every candidate result, measured latency, selected provider,
redacted old/new digests, permissions, elevation, service impact, and skipped reasons. It asks for
confirmation before using the same apply/verify/restore path as the CLI.

`--json` is stable machine output. Exit code `0` means success, `2` means a usage/configuration
error, and `3` means no actionable plan or a partial apply. Apply failures report the adapter,
stage, error, and recovery state. Status output always identifies host/container context and the
active catalog version/source. `--offline` disables the GitHub Raw catalog update but does not turn
off mirror compatibility probes used by `plan` and `apply`.
