# PDM adapter

The PDM adapter supports PDM 2.x on Linux `x86_64` and `arm64` and invokes only the `pdm` client. It does not
read or write pip or Poetry configuration. User scope is the automatic default; project scope must
be selected explicitly and changes `pyproject.toml` only after exposing the complete file diff.

Discovery follows PDM's real precedence model. It reads site configuration below the selected user
configuration (`PDM_CONFIG_FILE`, `XDG_CONFIG_HOME`, or `~/.config/pdm/config.toml`), then a
project's `pdm.toml` and `[[tool.pdm.source]]` entries. `PDM_PYPI_URL`, TLS, credential and JSON API
environment overrides are modeled separately. The adapter also asks PDM for its version and
effective `pypi.url`; private URLs and credential values are redacted from observations.

User planning changes only `[pypi].url` and refuses to emit an ineffective change when an
environment variable, project-local config, or project source named `pypi` has higher precedence.
Project planning changes an existing public source named `pypi`, or inserts one before existing
project sources to retain PDM's original default-first ordering. Private indexes, credentials,
source order, `respect-source-order`, `include_packages`, `exclude_packages`, custom certificates,
and unrelated TOML formatting remain intact. A private default, default-source credentials,
disabled TLS verification, or `pypi.json_api` bypass is non-actionable.
Unknown major versions fail closed, while optional fields introduced across PDM 2.x remain
untouched by the format-preserving TOML edit.

Each candidate must pass the `sampleproject` Simple API page and download the matching wheel with a
ZIP signature before latency ranking. Aliyun, Huawei Cloud, NJU, SJTUG, TUNA, and USTC currently
satisfy both checks on both supported architectures. Provider-specific index and artifact roots are
paired, so endpoints from different providers cannot be combined.

Verification first re-reads the effective default through PDM, then runs an uncached
`pdm show sampleproject` and requires version 4.0.0. To keep this check from initializing files in an
unrelated directory, planning requires an existing PDM project with `pyproject.toml`, `.pdm-python`,
and an initialized `.venv` or `__pypackages__` environment. A failed query restores the selected
configuration, and repeated planning is idempotent.
