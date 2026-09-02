# Scoop adapter

The `scoop` adapter supports user installations on native Windows 10 and 11, including x64 and
Windows 11 ARM64. It reads Scoop's version, root and configuration paths, effective architecture,
and ordered bucket objects through PowerShell. Proxy, GitHub token, custom repository, and global
installation settings are detected only as policy and are never emitted or changed.

NJU is currently the only one of the six reviewed providers with Scoop bucket mirrors. The catalog
keeps seven repositories independent: main, extras, versions, java, nerd-fonts, nonportable, and
nirsoft. Each installed official bucket is required separately, and its mirror must expose a Git
HEAD and pack inventory before latency selection. Scoop's own update repository is a different
surface and remains partial.

## Managed state

MirrorSwitch changes only `remote "origin".url` in each installed official bucket's
`<Scoop root>/buckets/<alias>/.git/config`. Bucket aliases and order come from `scoop bucket list`,
so a user-defined alias stays intact. Unknown, private, and local buckets remain in place and their
URLs are redacted from status output. Other Git remotes/settings and Scoop's `config.json` are
preserved byte-for-byte.

The main bucket is required as the representative download boundary. Its checked-out `jq.json`
must contain an anonymous HTTPS URL and a 64-character SHA-256 for the host's effective `64bit` or
`arm64` architecture. A conflicting `default_architecture`, missing main bucket, ambiguous Git
origin, or malformed manifest blocks the plan.

## Verification and recovery

After apply, every official bucket must resolve to its reviewed NJU URL and pass `git ls-remote`.
The adapter runs `scoop search jq`, followed by `scoop download --no-update-scoop --arch ... jq`.
Scoop therefore downloads the architecture-specific asset referenced by the manifest and checks
its hash without installing it or changing any manifest.

The bucket mirror accelerates Git metadata only. The current jq manifest still points to a GitHub
Release, and MirrorSwitch neither rewrites that URL nor claims NJU hosts the installer. Any Git,
search, download, or hash failure restores all changed bucket configs. Repeated planning is
idempotent, and explicit transaction restore returns every origin to its exact previous bytes.
