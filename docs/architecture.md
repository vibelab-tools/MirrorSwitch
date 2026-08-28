# Core architecture

The v0.1.0 binary has one core request and plan pipeline shared by CLI,
configuration-file, and TUI front ends:

```text
request
  -> platform and installed-tool detection
  -> compiled adapter registry
  -> checked-in or last-known-good catalog
  -> compatibility and content probes
  -> per-tool selection
  -> adapter plan
  -> transaction apply
  -> adapter verification
  -> status or restore
```

## Module boundaries

- `context`: OS, distribution, architecture, and host/container facts.
- `catalog`: declarative providers, normalized upstream repositories, tools,
  endpoints, compatibility constraints, and HTTP probes.
- `adapter`: object-safe operations implemented by a tool integration.
- `selection`: per-tool compatibility filtering, repository-content probes,
  deterministic latency ranking, overrides, and composition-policy enforcement.
- `plan`: detected state, effective configuration, per-tool selection, file
  changes, transaction receipts, and verification/restore results.
- `platform`: compile-time OS boundary; Linux runtime detection is implemented
  by #5.

The catalog contains no command or script field and uses strict
`deny_unknown_fields` deserialization. An entry can name an `adapter_key`, but
only an adapter registered in the compiled binary can detect, plan, apply,
verify, or restore a tool. Unknown keys remain inventory only.

## State separation

Catalog inventory and runtime support are not the same state:

- `CatalogEntryState` records that a provider publicly lists a complete or
  partial entry.
- The compiled adapter registry decides whether the binary implements the
  referenced tool.
- The system context and adapter decide whether the current OS, release,
  architecture, environment, and tool version are compatible.
- `CandidateEvaluation` records the final probe failure or eligible latency.

This prevents a provider directory entry or low homepage latency from becoming
an unsupported configuration change.

## Scope precedence

Adapters explicitly declare supported system, user, project, and environment
scopes. Project scope is never selected by default. Detection reads all
relevant sources so the plan can report the effective value, but apply only
touches the user-selected scope and preserves higher-priority overrides.

## Composition policy

Each tool declares one of three policies:

- `single`: choose one compatible endpoint;
- `ordered-fallback`: preserve an adapter-tested fallback order;
- `priority`: configure multiple candidates with explicit client priority.

The selection engine cannot turn `single` into a multi-source configuration.

## APT example

1. Linux detection identifies Debian/Ubuntu, release, `amd64`/`arm64`, and
   host/container state.
2. The APT adapter detects legacy `.list` and deb822 `.sources` files and reads
   suites, components, options, keyrings, and third-party repositories.
3. Catalog filtering keeps Debian and Ubuntu upstreams separate, including
   security and Ubuntu ports endpoints.
4. Probes require the exact `InRelease`/`Release`, suite, component, and
   architecture metadata before latency is compared.
5. The adapter plans minimal edits for selected official upstreams while
   preserving third-party entries, signatures, comments, and options.
6. The transaction engine backs up and applies files; the adapter verifies via
   APT metadata refresh. Failure restores the transaction.

## pip example

1. Python presence causes a pip probe; it does not imply pip is installed.
2. The pip adapter reads effective global, user, site, environment, and project
   configuration, but defaults to user scope.
3. A PyPI candidate must provide the required Simple API and representative
   project/artifact path. A provider homepage is not a probe.
4. `single` is the default because generic `extra-index-url` composition can
   change dependency resolution and expose private package names.
5. The adapter plans the user configuration without copying credentials or
   changing a project virtual environment.
6. Verification uses pip’s public configuration and index-query boundary;
   failure restores the previous user configuration.
