# NuGet adapter

Issues [#56](https://github.com/vibelab-tools/MirrorSwitch/issues/56) and
[#107](https://github.com/vibelab-tools/MirrorSwitch/issues/107) implement the
NuGet v3 boundary for `dotnet` SDK 6.x through 10.x and NuGet CLI 6.x/7.x on
Linux and native Windows hosts using `x86_64` or `arm64`.

The adapter distinguishes the user config used by dotnet
(`~/.nuget/NuGet/NuGet.Config`) from the Mono/NuGet CLI path
(`~/.config/NuGet/NuGet.Config`). It reads machine configs, additional user
configs, and every `NuGet.Config` from the filesystem root to the current
project in precedence order. Only the installed client's main user config is
writable. Project configs, project files, lock files, machine configs, and
additional user configs remain read-only.

On Windows, dotnet and `nuget.exe` share
`%APPDATA%\NuGet\NuGet.Config`; MirrorSwitch therefore plans one write even when
both clients are installed. It also reads `%APPDATA%\NuGet\config`,
`%ProgramFiles(x86)%\NuGet\Config`, `%ProgramData%\NuGet\Config`, and each
project hierarchy. Visual Studio offline and machine-wide sources remain
read-only. The transaction preserves UTF-8 or BOM-marked UTF-16 encoding,
CRLF, Windows file attributes, and the existing file security descriptor. UNC
and drive-qualified paths stay native and are never converted to Linux paths.

One effective NuGet.org v3 source key is retargeted without changing its key.
This preserves package source mappings, disabled-source records, credentials,
private feeds, comments, and XML ordering. MirrorSwitch does not act when a
read-only config overrides the public source, a public source is disabled or
credential-bound, multiple public sources are effective, the mapping excludes
the public key, a NuGet.org key points to an unreviewed endpoint, or the active
configuration is v2 or custom-only. A v2 package endpoint is never rewritten as
a v3 service index.

## Reviewed provider boundary

The current inventories and live protocol review of the six selected sites
found one complete candidate:

- Huawei Cloud publishes a v3 service index whose search, registration, and
  flat-container resources remain on Huawei Cloud. The runtime catalog checks
  the service index, registration index and fixed registration page, flat
  container version list, and the exact SHA-256 of `NuGet.Versioning` 6.12.1
  before latency counts.
- Alibaba Cloud's current public mirror list has no NuGet service, and the
  historical guessed v3 endpoint returns 404.
- USTC, TUNA, SJTUG, and NJU do not list NuGet in their current public
  inventories; their guessed v3 service-index paths return 404.

After apply, each installed client parses the shared or client-specific user
config through `dotnet nuget list source` or `nuget sources List`. An isolated
managed config then drives a real `dotnet restore` or `nuget install` of the
fixed package.
MirrorSwitch checks that client metadata records the selected source and that
the result is a package archive. The catalog gate independently enforces the
reviewed nupkg SHA-256. Any verification failure restores the configuration;
reapplying an unchanged selection is a no-op.
