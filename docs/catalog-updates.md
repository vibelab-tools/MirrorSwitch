# Runtime catalog and updates

`catalog/mirrors.json` is the single runtime catalog consumed by MirrorSwitch. It is generated
from the reviewed six-provider discovery snapshot in `catalog/provider-inventory.json`; the
inventory remains provenance input and is not a second runtime manifest.

Regenerate the catalog deterministically after reviewing an inventory change:

```bash
python3 -B scripts/build_catalog.py \
  --content-revision 202608290011 \
  --generated-at 2026-08-28T20:15:00Z
cargo run --bin catalogctl -- validate catalog/mirrors.json
```

Schema version 2 records its content version and monotonic content revision. It covers
providers, upstream repository families, tools, operating systems, distributions, versions,
architectures, host/container compatibility, mirror/proxy delivery mode, endpoints, role-bound
probes and implementation Issue links.

## Update behavior

The release binary embeds `catalog/mirrors.json` as an offline baseline. Every catalog load asks
the following GitHub Raw URL for a newer document with a five-second timeout and an 8 MiB response
limit:

```text
https://raw.githubusercontent.com/vibelab-tools/MirrorSwitch/main/catalog/mirrors.json
```

JSON parsing, strict schema validation and reference/adapter validation all complete before a
newer revision replaces the last-known-good cache atomically. A timeout, oversized or truncated
response, unknown schema, semantic error, revision conflict, older revision or cache write error
does not replace the current data. A valid newer cache is preferred over the embedded baseline
when the network is unavailable. Corrupt caches are reported and left untouched for diagnosis.

`CatalogStatus` is serializable machine output containing the active schema/content version,
revision, generation time, source, cache condition and update result. Inspect it without changing
configuration:

```bash
mirrorswitch status --json | jq '.catalog'
mirrorswitch status --offline --json | jq '.catalog'
```

`source` is `fresh-remote`, `last-known-good-cache`, or `embedded-baseline`. The `update.status`
field distinguishes `updated`, `no-update`, `fetch-failed`, invalid data, stale data, revision
conflicts, and cache-write failures. `--offline` reports `update.status` as `offline` and performs
no Raw request. The cache is `$XDG_CACHE_HOME/mirrorswitch/catalog.json`, or
`~/.cache/mirrorswitch/catalog.json` when `XDG_CACHE_HOME` is unset.

The Raw URL is anonymous. It therefore requires this repository and the file to be publicly
readable; a private repository returns HTTP 404 and the status records that exact fallback reason.
This does not disable the embedded catalog, but a newer remote revision cannot arrive until the
URL is public or a different public distribution endpoint is implemented.

Remote data is declarative. The schema rejects unknown executable fields, and a tool may become
`supported` only when its ID matches an adapter compiled into the binary and present in the
caller's allowlist. The current generated catalog therefore keeps all not-yet-implemented tools
in the inert `planned` state.
