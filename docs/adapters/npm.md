# npm adapter

The npm adapter supports Linux `x86_64` and `arm64`. It detects npm and Node.js versions, asks npm
for the effective registry and global/user configuration paths, and reads the current project's
`.npmrc` when a project directory is available.

Global, user and project npmrc files are distinct explicit scopes. User is the automatic default;
project scope is never automatic. Environment configuration is read-only. A higher-precedence
project or environment default registry blocks a lower-scope plan so the displayed change always
matches the registry npm will actually use.

The adapter changes only the unscoped `registry` option in the selected file. Scoped registries,
authentication, comments and unrelated npm settings are preserved byte for byte. A private default
registry is not overwritten. Unscoped credentials, credentials scoped to the selected public
mirror, or an effective `strict-ssl=false` setting make the plan non-actionable. Tokens remain only
in the selected configuration and the private backup content needed for an exact restore; logs,
catalog data, plan previews and transaction metadata contain no token values.

Candidates must pass ordinary HTTPS validation, an `is-number` Registry API metadata request and a
real package tarball request before latency ranking. Huawei Cloud currently passes the complete
HTTPS contract. The obsolete Aliyun `/NPM/` endpoint returns 404, while NJU metadata advertises an
HTTP tarball URL to the npm client. Both remain visible as non-actionable inventory instead of being
ranked.

Applying uses the shared atomic transaction engine. Verification runs `npm config get registry`
and a real `npm view is-number@7.0.0 name version dist.tarball --json` request from the selected
project context. Failed effective-config or metadata checks restore the previous file, and repeated
planning is idempotent.
