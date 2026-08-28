# GNU Guix adapter

The GNU Guix adapter supports daemon-based Guix installations on foreign Linux distributions for
`x86_64-linux` and `aarch64-linux`. It manages only systemd's `guix-daemon` command line. Guix
System remains declarative and is rejected with guidance to keep ownership in
`guix-service-type`.

The adapter reads the effective `ExecStart`, `/etc/guix/acl`, the Guix version, and the detected
user's `channels.scm`. Channels and Git mirrors are reported as separate, read-only sources. They
are never treated as substitute servers. Existing custom substitute URLs retain their relative
order, while the official CI and Bordeaux URLs are independently replaced by their matching
reviewed SJTUG mirrors.

No key is imported. Before selection, the adapter requires the existing ACL to contain the
official Berlin and/or Bordeaux Ed25519 key for each configured substitute family. Candidate
probes use an architecture-specific Guix store path and require the expected narinfo signature
identity before latency is ranked.

For a vendor unit, planning creates
`/etc/systemd/system/guix-daemon.service.d/mirrorswitch.conf` and resets only `ExecStart`. A local
unit or an existing MirrorSwitch drop-in is edited in place. Unknown drop-ins, ambiguous commands,
and invalid quoting are rejected instead of merged speculatively. Applying the same selection is
idempotent and reports a daemon restart requirement without restarting it implicitly.

Post-apply verification re-parses the daemon command and ACL, then runs `guix weather` for `hello`
against the selected substitute URLs and detected Guix system. It requires complete substitute
availability; any failure restores the transaction immediately.
