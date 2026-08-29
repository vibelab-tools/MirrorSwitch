# Composer adapter

Issue [#55](https://github.com/vibelab-tools/MirrorSwitch/issues/55) implements the
Linux Composer/Packagist boundary for Composer 1.10+ and 2.x on `x86_64` and
`arm64`.

The adapter changes only `$COMPOSER_HOME/config.json`. It discovers Composer and
PHP versions, the effective Composer home, global and current-project repository
definitions, `COMPOSER` project-file overrides, and the presence of global,
project, or `COMPOSER_AUTH` authentication sources. Project `composer.json`,
`composer.lock`, project/global `auth.json`, inline repository credentials,
private Composer repositories, and VCS repositories are read-only.

Composer repository order is semantic: the first canonical repository that
contains a package normally wins. MirrorSwitch therefore maps one existing or
implicit global Packagist definition instead of adding an ordered fallback or
rewriting private repositories. An explicit Packagist disable, multiple public
Packagist definitions, or a Packagist-named private endpoint is treated as a
conflict. Composer 1 receives its native object form; Composer 2 retains its
native ordered-array form and pairs the selected mirror with an explicit
`packagist.org: false` entry so the implicit official fallback cannot bypass
selection. Existing private repository priority remains unchanged.

## Reviewed provider boundary

The six-site review found one complete current candidate:

- Huawei Cloud serves Composer 1 provider metadata, Composer 2 `p2` metadata,
  mirror-hosted dist archives, and the original VCS source reference. The
  runtime catalog checks both metadata protocols, the exact `psr/log` 3.0.2
  dist SHA-256, and a SHA-256-checked source archive before latency counts.
- Alibaba publishes Composer instructions and describes a full mirror, but its
  reviewed `packages.json` reported `2025-09-01` and its package metadata was
  behind Packagist/Huawei during this review, so it remains non-actionable.
- SJTUG explicitly describes its service as metadata-only; it cannot satisfy
  the dist-chain requirement.
- TUNA's historical Packagist service was index-only and the reviewed endpoint
  is no longer present in its current enabled inventory.
- USTC's current help inventory has no Composer/Packagist service.
- NJU's listed `php` tree is a PHP source-distribution mirror, not a Packagist
  repository.

Composer 1 public Packagist metadata was retired in 2025. It is supported here
only because the selected Huawei candidate still passes the reviewed v1
provider protocol; candidates that only implement Composer 2 are filtered by
the detected repository protocol.

After apply, MirrorSwitch asks the real client to load its global config, runs
`composer diagnose`, and resolves `psr/log` 3.0.2 while checking the reviewed
dist and VCS references. Any verification failure restores the transaction;
reapplying an unchanged selection is a no-op.
