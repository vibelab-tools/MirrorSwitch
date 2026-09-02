# Contributing to MirrorSwitch

Every independently reviewable adapter or catalog expansion starts with a GitHub Issue. An entry
is not `supported` merely because a provider lists a directory: the implementation, compatibility
rules, content probes, real client boundary, rollback, and documentation must pass together.

## Development baseline

- Rust 1.88 or newer with rustfmt and Clippy.
- Python 3 and `jq` for catalog/test tooling.
- Docker for the pinned Linux distribution matrix.
- `musl-tools`, `dpkg-deb`, and `rpmbuild` only when changing release packaging.

Run the existing release gates before and after a change:

```bash
bash scripts/test.sh quality
bash scripts/test.sh unit
bash scripts/test.sh cli
bash scripts/test.sh docker
```

Use `bash scripts/test.sh distro debian` for one system-package scenario and
`bash scripts/test.sh language` for the representative language-tool set.

## Add one adapter

1. Define one adapter key and tool entry in the reviewed provider inventory. Keep package
   registries, distributions, metadata, artifacts, Git, OCI, and update channels as distinct
   upstreams when clients treat them differently.
2. Implement `Adapter` in `src/adapters/<adapter_key>.rs`. Detection must prove the executable and
   supported version/configuration; `plan` must be read-only and preserve unrelated state;
   `apply`, `verify`, and `restore` must use the shared transaction/runtime boundary.
3. Register the module, public type, static instance, and instance in `compiled_adapters()` in
   `src/adapters/mod.rs`. Remote catalog data cannot register or execute code.
4. Add `tests/<adapter_key>_adapter_boundary.rs`. Cover meaningful version, OS, architecture,
   host/container, scope, composition, idempotency, preservation, real client query, verification
   failure, and exact restore decisions. Use temporary real files and executable fixtures instead
   of mocking internal call order.
5. Add or update the adapter documentation and the support/reference matrix. Record unsupported
   versions and ambiguous/private configuration as explicit read-only outcomes.
6. Change the catalog state to `supported` only after the adapter and boundary test exist. The
   coverage gate rejects a supported adapter without the matching test file.

## Add or change mirror data

Edit the provenance inventory, not generated `catalog/mirrors.json` alone. Each candidate needs
the provider/upstream/tool identities, exact endpoints, explicit OS/version/architecture and
host/container compatibility, source URLs, observation time, and content-specific probes. Never
add executable commands, credentials, disabled trust checks, or a provider-homepage-only probe.

After review, choose a monotonically increasing revision and deterministic UTC time:

```bash
python3 -B scripts/build_catalog.py \
  --content-revision 20260902130000 \
  --generated-at 2026-09-02T13:00:00Z
cargo run --bin catalogctl -- validate catalog/mirrors.json
python3 -B scripts/check_adapter_coverage.py
```

Inspect the generated diff and verify representative metadata/artifact boundaries. External live
availability belongs in the scheduled monitor; deterministic tests must not become allowed
failures merely because a public mirror is temporarily unavailable.

## Delivery checklist

- Keep the change scoped to its Issue and include `Closes #N` only after every acceptance item is
  verified.
- Run the narrowest relevant boundary test, then the shared gate affected by the change.
- Preserve catalog provenance, license notices, unrelated configuration, and user changes.
- Never include credentials or unredacted private repository URLs in tests, logs, docs, Issues, or
  commit messages.
- Push the verified commit and confirm the GitHub Issue closes only after the commit is visible.
