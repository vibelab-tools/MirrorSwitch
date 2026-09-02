# pnpm adapter

The pnpm adapter supports Linux, macOS, and native Windows hosts on `x86_64` and `arm64`, detects
`pnpm` independently from npm, and defaults to user scope. Project configuration is discovered and
reported but remains read-only. A project default registry blocks a user-level plan because the
resulting setting would not be effective.

The reviewed compatibility ranges intentionally follow pnpm's configuration split:

- pnpm `10.34.2` through `10.x` uses the npm-compatible user `.npmrc` model. An absolute
  `npm_config_userconfig` selects another file, and `npm_config_registry` is treated as a
  higher-precedence environment override.
- pnpm `11.22.0` through `11.x` stores registry and authentication settings in
  `$XDG_CONFIG_HOME/pnpm/auth.ini` (or `~/.config/pnpm/auth.ini`) and keeps other global settings in
  `config.yaml`. It uses `pnpm_config_*`; npm-prefixed registry environment variables are not
  treated as pnpm 11 inputs. An explicit absolute `pnpm_config_config_dir` or
  `pnpm_config_userconfig` is honored.

For pnpm 11, the default config directory is `~/.config/pnpm` on Linux,
`~/Library/Preferences/pnpm` on macOS, and `%LOCALAPPDATA%\pnpm\config` on Windows. pnpm 10 keeps
using the home `.npmrc` on all three platforms. Existing UTF-8 BOM and LF/CRLF layout are preserved.

Older releases and pnpm 12 are reported as outside the reviewed range instead of guessing their
precedence. These boundaries account for pnpm 10.34.2's project-registry hardening and pnpm 11.22's
machine-level path restrictions. The upstream configuration contracts are documented in the
[pnpm 10 configuration reference](https://pnpm.io/10.x/cli/config),
[current configuration reference](https://pnpm.io/cli/config), and
[pnpm settings reference](https://pnpm.io/settings).

For both models, MirrorSwitch reads the selected user file, user fallback/settings files, project
`.npmrc`, and `pnpm-workspace.yaml`. It changes only the unscoped `registry` entry in the selected
user INI file. Private scope registries, scoped authentication, store configuration, workspace
settings, comments, quoting, and unrelated options remain byte-for-byte unchanged. It never copies
credentials from npm-compatible files into `auth.ini`.

Private default registries are not overwritten. Environment registry overrides, project default
registries, unscoped credentials, authentication scoped to the selected public mirror, disabled
`strict-ssl`, and ambiguous workspace registry YAML are non-actionable. Credential values stay in
the configuration and private transaction backup; observations and plan previews redact contents.

Candidates must pass HTTPS package metadata and tarball probes before latency ranking. Huawei Cloud
currently satisfies this complete contract. Verification runs `pnpm config get registry` and a real
`pnpm view is-number@7.0.0 --json`, then checks the package identity, version, and HTTPS tarball host.
A failed query restores the prior file, and repeated planning is idempotent.
