# Jenkins Update Center adapter

The `jenkins` adapter connects Jenkins 2.581 on Linux to an immutable, signed Update Center
snapshot whose plugin URLs point at public China-hosted mirrors. It does not treat a Jenkins WAR
or plugin directory alone as a complete Update Center.

## Explicit trust decision

Jenkins is never selected automatically. The user must name `jenkins` in the CLI, configuration
file, or TUI and confirm the system-scope plan. That plan installs the lework Update Center root
certificate with SHA-256 fingerprint:

```text
6786622eed42b1b141f79397521438b4e6f1cc314563652d7c28adf6878fc8c4
```

The certificate is valid from 2020-03-05 through 2030-03-03. MirrorSwitch verifies the embedded
PEM digest and validity window before detection, planning and post-apply verification. An existing
different certificate at the managed path is never overwritten.

Signature checking remains enabled. MirrorSwitch does not set
`hudson.model.DownloadService.noSignatureCheck` and does not change TLS or plugin checksum policy.

## Candidate boundary

Every candidate combines three independently pinned parts from immutable lework commit
`3df56b0ada4fc57ca1329946697eb0f896389047`:

- the exact root certificate;
- the variant-specific signed `update-center.json`;
- `git.hpi` 5.10.1 from the corresponding Alibaba Cloud, Huawei Cloud, Tencent Cloud, TUNA, or
  USTC mirror.

All three bodies must match reviewed SHA-256 values before latency is compared. The signed
metadata targets Jenkins 2.581 exactly; other Jenkins versions receive no actionable candidate.

## Configuration and recovery

`JENKINS_HOME` comes from the environment, `/etc/default/jenkins`,
`/etc/sysconfig/jenkins`, or the default `/var/lib/jenkins`. MirrorSwitch changes only the `default`
site in `hudson.model.UpdateCenter.xml` and preserves every other site and credential-bearing URL.
A custom/private default site blocks the plan.

The root certificate is written to
`$JENKINS_HOME/update-center-rootCAs/update-center.crt`. Both files share one transaction and are
restored together after verification failure. The plan reports `restart-required`, but
MirrorSwitch never restarts Jenkins. After the user restarts the service, Jenkins performs its
normal Update Center signature and plugin checksum verification with the added trust root.
