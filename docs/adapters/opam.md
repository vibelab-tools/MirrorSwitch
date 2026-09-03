# opam adapter

Issues [#71](https://github.com/vibelab-tools/MirrorSwitch/issues/71) and
[#132](https://github.com/vibelab-tools/MirrorSwitch/issues/132) implement opam
repository and archive-cache selection on Linux/macOS `x86_64`/`arm64` and
Windows x64. macOS and Windows require native hosts; Windows requires opam 2.2+
and has no official arm64 executable.

The adapter asks native `opam var root --safe` for the active root unless
`OPAMROOT` is explicit. It changes only the official `default` repository in
`repo/repos-config` and the official archive cache entry in `config`. Private
repositories, trust anchors, ordering, private archive mirrors, solver/download
policy, current switch, OCaml version, project `.opam-switch`, and `opam.locked`
remain unchanged. Custom fetch commands and `OPAMFETCH` stop the plan.

UTF-8 BOM, LF/CRLF, unknown fields, credentials, proxy/certificate environment,
and native mode/ACL are preserved. All opam commands receive `OPAMROOT` through
the native process API rather than a Unix `env` executable. Windows therefore
runs the official `opam-2.5.2-x86_64-windows.exe` directly, without WSL or
Cygwin.

NJU's Git mirror is pinned by the reviewed opam-repository revision, advertised
refs, HEAD and pack inventory. SJTUG's checksum-addressed cache object must
match both its path digest and downloaded SHA-256. Both upstreams must pass
before a plan is produced.

After apply, native opam lists and updates `default`, extracts fixed package
`stdio.v0.16.0`, and verifies the cache with Linux `sha256sum`, macOS `shasum`,
or Windows `certutil.exe`. CLI, versioned configuration, and TUI share one plan;
failure restores both opam configs and the managed verification manifest.

The native release boundary downloads checksum-pinned official opam 2.5.2
binaries on GitHub-hosted macOS Intel, macOS Apple Silicon, and Windows x64. It
initializes a bare native root and validates discovery, both upstreams, frontend
equality, project immutability, idempotence, permissions, and exact recovery.
