# v0.1.0 product boundary

## Outcome

v0.1.0 delivers one Rust executable that can detect supported tools on a Linux
machine, build a per-tool mirror plan, apply it safely, verify the resulting
configuration, report status, and restore a previous configuration.

The release is complete only when the same core behavior is available through
the CLI, an optional configuration file, and the TUI on Linux `x86_64` and
`arm64`.

## In scope

- Mainstream Linux hosts and Linux containers listed in
  [the support matrix](support-matrix.md).
- System package managers, language/build tools, and development
  infrastructure repositories that have an implemented adapter.
- The initial provider set: Alibaba Cloud, Huawei Cloud, USTC, Tsinghua TUNA,
  Nanjing University, and SJTUG.
- A repository-owned, versioned, declarative mirror catalog with a bundled
  baseline and an optional GitHub Raw update.
- Compatibility filtering before latency measurement.
- Preview, backup, atomic application where the target format permits it,
  verification, rollback, and idempotent repeated runs.

## Out of scope

- macOS and Windows support; these are tracked by the v0.2.0 milestone.
- A desktop GUI, web UI, tray application, or mobile application.
- Treating every directory exposed by a mirror site as configurable support.
- Rewriting arbitrary download URLs, Git URLs, project files, or lock files.
- Disabling TLS, repository signatures, package checksums, or client trust
  policies to make a candidate appear compatible.
- Downloading or executing code supplied by the remote catalog.
- Automatically restarting services that may carry production workloads.

## What “all development mirrors” means

The set cannot be statically exhaustive. Mirror sites add, remove, rename, and
partially synchronize repositories. MirrorSwitch therefore separates four
states:

1. `cataloged`: the provider publicly lists the entry;
2. `planned`: an adapter issue exists but has not passed acceptance;
3. `partial`: the adapter works only for recorded OS, version, architecture, or
   content subsets;
4. `supported`: the adapter and candidate have passed their declared boundary
   checks.

Unknown and unsupported entries remain visible in the catalog. They are never
silently rewritten.

## Default target selection

The default plan is derived from observable state:

1. identify Linux distribution, release, architecture, and host/container
   context;
2. detect installed tools and read their effective configuration;
3. use runtime presence only as a prompt for further detection—Python does not
   prove pip is installed, and Java does not prove Maven or Gradle is installed;
4. select only detected adapters that support the current context;
5. allow the user to add or remove targets explicitly through configuration or
   the TUI.

Project-repository configuration is excluded by default. System and user
configuration may be selected according to the adapter’s declared scope and
permission requirements.

## Command behavior

| Command | Writes configuration | Observable result |
| --- | --- | --- |
| `detect` | No | Environment, detected tools, effective configuration source, and unsupported reasons |
| `plan` | No | Per-tool compatible candidates, probes, latency result, intended diff, permissions, restart impact, and fallback |
| `apply` | Yes | Verified transaction identifier, applied targets, backups, validation results, and any rollback |
| `status` | No | Host/container context, permissions, detected tools, default selections, notices, and catalog version/origin |
| `restore` | Yes | Selected transaction restored and verified, with conflicts or unsupported state reported |

The configuration file and TUI produce the same internal request and plan as
the equivalent CLI invocation. TUI confirmation does not bypass validation.

## Selection rules

- Candidates are grouped by normalized upstream repository and adapter.
- OS, distribution/release, architecture, protocol, configuration syntax, and
  required content are hard filters.
- A probe targets real metadata or a representative package/manifest, not the
  provider homepage.
- Latency is compared only between candidates that pass all hard filters.
- A single provider is never selected globally for unrelated tools.
- Multiple mirrors are composed only when that client has defined fallback or
  priority semantics and the adapter has tests for them.
- If no candidate qualifies, the current configuration is preserved and the
  reason is reported.

## Safety invariants

- Display a complete plan before a mutating operation.
- Preserve unrelated repositories, comments, credentials, signatures, and
  tool-specific options.
- Never persist secrets in logs, the public catalog, status metadata, or issue
  evidence.
- Back up the exact affected state before writing.
- Validate with the tool’s public configuration/query boundary after writing.
- Restore the backup when validation fails.
- Repeating the same successful plan produces no further change.
- A remote catalog update is schema-validated, size-limited, time-limited, and
  atomically promoted; failure falls back to the last-known-good or bundled
  catalog.

## Release acceptance

The Linux MVP must pass representative host/container tests, build and run on
`x86_64` and `arm64`, publish generic archives plus `.deb` and `.rpm` packages,
and document every supported, partially supported, and unsupported adapter.
