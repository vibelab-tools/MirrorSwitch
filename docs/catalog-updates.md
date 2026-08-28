# Runtime catalog and updates

`catalog/mirrors.json` is the single runtime catalog consumed by MirrorSwitch. It is generated
from the reviewed six-provider discovery snapshot in `catalog/provider-inventory.json`; the
inventory remains provenance input and is not a second runtime manifest.

Regenerate the catalog deterministically after reviewing an inventory change:

```bash
python3 -B scripts/build_catalog.py \
  --content-revision 202608280001 \
  --generated-at 2026-08-28T00:00:00Z
cargo run --bin catalogctl -- validate catalog/mirrors.json
```

The schema records its schema version, content version and monotonic content revision. It covers
providers, upstream repository families, tools, operating systems, distributions, versions,
architectures, host/container compatibility, endpoints, probes and implementation Issue links.

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
revision, generation time, source, cache condition and update result. Until the main CLI/TUI lands,
the same status is available with:

```bash
cargo run --bin catalogctl -- status /path/to/catalog-cache.json
```

Remote data is declarative. The schema rejects unknown executable fields, and a tool may become
`supported` only when its ID matches an adapter compiled into the binary and present in the
caller's allowlist. The current generated catalog therefore keeps all not-yet-implemented tools
in the inert `planned` state.
