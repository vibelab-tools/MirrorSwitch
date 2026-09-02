# Poetry adapter

Poetry package sources are project-local on Linux, macOS, and native Windows `x86_64`/`arm64`.
Poetry's global `repositories.*` settings are publishing destinations, not installation sources,
so MirrorSwitch never treats pip's index or Poetry's global publishing configuration as a
completed Poetry mirror setup. The adapter exposes only explicit project scope and never selects a
Poetry project automatically.

The reviewed range is Poetry `1.5.0+` and Poetry `2.0` through `2.4`. Both use project
`[[tool.poetry.source]]` tables and the `primary`, `supplemental`, and `explicit` priorities.
Priorities omitted from a source are primary. A configured primary disables implicit PyPI;
supplemental sources are fallbacks; explicit sources are used only by dependencies that name them.
Deprecated `default`/`secondary` priorities and unreviewed versions are reported instead of being
silently reinterpreted. These semantics follow Poetry's
[package-source documentation](https://python-poetry.org/docs/repositories/) and
[source command reference](https://python-poetry.org/docs/cli/#source-add).

For a project that has no configured primary source, MirrorSwitch inserts a uniquely named primary
source and thereby replaces implicit PyPI. Existing supplemental and explicit private sources,
source-constrained dependencies, ordering, comments, and unrelated project metadata are preserved.
An existing public primary can be retargeted only when credentials, source-specific certificates,
and possible keyring credentials have been ruled out. Private or multiple primary sources and an
explicit reserved `PyPI` source require manual resolution because an automatic edit could change
dependency provenance or break source constraints.

Discovery reads the project `pyproject.toml`, project-local `poetry.toml`, global `config.toml`,
global `auth.toml`, relevant `POETRY_*` credential/certificate variables, and effective keyring
state. Configuration paths honor `POETRY_CONFIG_DIR` and `XDG_CONFIG_HOME` as documented in
[Poetry configuration sources](https://python-poetry.org/docs/configuration/#configuration-sources).
Secret values and private URLs remain redacted in observations and previews; global publishing and
credential files are never modified.

Without `POETRY_CONFIG_DIR`, global read-only files come from `~/.config/pypoetry` on Linux,
`~/Library/Application Support/pypoetry` on macOS, and `%APPDATA%\pypoetry` on Windows. Existing
project UTF-8 BOM and LF/CRLF layout are preserved, while an undecodable TOML file is left unchanged.

Each selectable provider must pass a PEP 503 Simple page probe and a real wheel probe before
latency ranking. Verification then uses `poetry source show` and the non-mutating
`poetry debug resolve --no-cache sampleproject==4.0.0` boundary. Failed verification restores the
original `pyproject.toml`, and repeated planning is idempotent on all supported OS/architecture
combinations.
