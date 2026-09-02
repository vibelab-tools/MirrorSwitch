# pip adapter

The pip adapter supports Linux, macOS, and native Windows hosts on `x86_64` and `arm64`. It asks
pip itself for its version, Python environment and `pip config debug` layout, then reads global,
user, site and `PIP_CONFIG_FILE` sources in pip's real precedence order. `PIP_INDEX_URL`,
`PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST` and `PIP_CONFIG_FILE` are detected without exposing
embedded credentials.

Global (`/etc/pip.conf`), user and pip-reported site configuration are explicit scopes. User is the
automatic default. Site is never selected automatically, and project files or virtual-environment
configuration are not changed unless the user explicitly selects the site scope. Environment
variables and `PIP_CONFIG_FILE` are read-only higher-precedence sources; an active primary-index
override blocks a persistent-file plan instead of producing a change that would not take effect.

Native paths come from `pip config debug`; fallbacks follow pip's platform contract:
`/Library/Application Support/pip/pip.conf` and
`~/Library/Application Support/pip/pip.conf` on macOS, or `%ProgramData%\pip\pip.ini` and
`%APPDATA%\pip\pip.ini` on Windows. UTF-8 BOMs and LF/CRLF layout are preserved. The adapter
never substitutes a Linux path and rejects undecodable configuration instead of rewriting it.

The adapter configures exactly one reviewed, complete Simple API endpoint as
`global.index-url`. It never adds an `extra-index-url` or `trusted-host`. Existing extra indexes are
preserved and surfaced because pip searches all configured indexes without treating one as a
strictly safer fallback. Private or command-specific primary indexes are not overwritten.

Before latency ranking, each candidate must pass normal HTTPS certificate validation and return a
PEP 503-compatible `sampleproject` page containing distribution links. The catalog exposes the
Aliyun, Huawei Cloud, NJU, SJTUG, TUNA and USTC Simple API endpoints; specialized Jetson and
package-blob surfaces remain non-actionable inventory entries.

Applying uses the shared atomic transaction engine. Verification runs `pip config debug`,
`pip config list` and a real `pip index versions sampleproject` query, which exercises the client's
PEP 503/691 content negotiation. A failed effective-config or index check restores the previous
file, and repeated planning is idempotent.
