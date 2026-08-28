# Yarn adapter

The Yarn adapter supports Linux `x86_64` and `arm64` and selects its configuration model from the
invoked Yarn major version. Yarn 1 is Classic and uses `registry` in `.yarnrc`; Yarn 2 and newer are
Berry and use `npmRegistryServer` in `.yarnrc.yml`. The two parsers and renderers are separate, so a
Classic command can never rewrite Berry YAML or vice versa.

User scope is the automatic default and project scope is explicit. Classic reads discovered system,
home and project `.yarnrc` files plus user/project `.npmrc` scope and authentication settings, but
only changes the selected `.yarnrc`. Berry reads home and project `.yarnrc.yml` and preserves
`yarnPath`, plugins, `npmScopes`, `npmRegistries`, authentication and unrelated YAML. A Berry user
change requires a detected project context because the real `yarn npm info` verification command is
project-bound; without one, planning reports the limitation instead of producing an unverifiable
change. A project registry override similarly blocks a lower-precedence user plan.

Private default registries are not overwritten. Unscoped credentials, credentials that would be
sent to the selected public mirror, disabled TLS certificate verification, environment overrides,
and inline or aliased registry-map shapes that cannot be edited without restructuring YAML are
non-actionable. Credential values remain only in the configuration and private transaction backup;
catalog data, logs, serialized observations, plan previews and backup metadata do not contain them.

Candidates must pass HTTPS Registry API metadata and package tarball probes before latency ranking.
Huawei Cloud currently satisfies the complete contract. Aliyun's old endpoint returns 404, and NJU
advertises an HTTP tarball URL to Yarn/npm clients, so both remain visible but non-actionable.

Verification re-reads `registry` or `npmRegistryServer` through the invoked Yarn generation. Classic
then runs a real `yarn info is-number@7.0.0 --json`; Berry runs
`yarn npm info is-number@7.0.0 --fields name,version,dist --json`. The package, version and HTTPS
tarball host must match. Failures restore the previous file, and repeated planning is idempotent.
