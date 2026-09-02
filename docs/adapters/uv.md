# uv adapter

The uv adapter supports the reviewed `0.4.23` through `0.12.x` configuration model on Linux,
macOS, and native Windows hosts using `x86_64` or `arm64`. It reads uv's own system, user, and
project configuration; pip configuration is never treated as a complete uv model. User scope is
the automatic default, while project scope must be selected explicitly.

Configuration discovery follows uv's merge rules: system `uv.toml`, user
`$XDG_CONFIG_HOME/uv/uv.toml` (or `~/.config/uv/uv.toml`), then the nearest project configuration.
A project `uv.toml` takes precedence over `[tool.uv]` in `pyproject.toml`. Environment variables and
`UV_CONFIG_FILE`/`UV_NO_CONFIG` take precedence over discovered files and therefore block a
persistent plan. See the official
[configuration-file contract](https://docs.astral.sh/uv/concepts/configuration-files/).

macOS follows the same XDG paths as Linux. Windows uses `%PROGRAMDATA%\uv\uv.toml` and
`%APPDATA%\uv\uv.toml`; Unix XDG variables are not reused there. Existing UTF-8 BOM and LF/CRLF
layout are preserved, and an undecodable TOML file is left unchanged. The project path always
comes from the native current directory, including Windows drive-qualified paths.

MirrorSwitch writes exactly one `[[index]]` entry with `default = true`, replacing implicit PyPI.
It preserves named `explicit = true` indexes and `[tool.uv.sources]` package pins. Searchable
additional indexes, `extra-index-url`, a project default overriding user scope, multiple defaults
in the selected file, `uv.pip` index overrides, and the `unsafe-first-match` /
`unsafe-best-match` strategies are non-actionable. The safe default `first-index` policy and the
difference between default and additional indexes follow uv's
[package index documentation](https://docs.astral.sh/uv/concepts/indexes/).

Candidates must pass a PEP 503 Simple page and a real wheel probe before latency ranking.
Verification performs a non-mutating, no-cache `uv pip install --dry-run --system` resolution for
`sampleproject==4.0.0`. A failed resolution restores the previous file, and repeated planning is
idempotent across the CLI, configuration-file, and TUI entry points.
