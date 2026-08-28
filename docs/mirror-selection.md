# Per-repository mirror selection

MirrorSwitch selects a mirror independently for each required upstream of one tool. An adapter
builds a `SelectionRequest` from the detected system and effective configuration; it must name the
exact upstreams being replaced, its compiled adapter identity, supported protocols, required
endpoint roles, compatibility dimensions that require explicit evidence, accepted delivery modes
and tested composition policy. This prevents an APT result from influencing pip or npm and
prevents a tool from configuring repositories it did not detect.

For each required upstream, the selector follows this order:

1. Reject partial inventory records, missing required compatibility evidence, and mismatched
   delivery mode, OS, architecture, host/container environment, distribution, release/codename,
   tool/repository version, protocol or endpoint role.
2. Require one or more declarative repository-content probes. A candidate without a metadata or
   representative-content path cannot compete on latency.
3. Fetch the probe path relative to its declared repository endpoint with a finite timeout and
   bounded body. Validate status, content type and marker before accepting the measured latency.
4. Sort eligible candidates by total probe latency, then provider ID and candidate ID so ties are
   deterministic.
5. Apply the adapter's compiled composition policy. `single` selects one candidate;
   `ordered-fallback` and `priority` may return multiple candidates only when the catalog and
   adapter policies agree.

A user override maps one required upstream to one catalog candidate ID. It bypasses automatic
ranking only: compatibility and content probes still run. A missing, incompatible, timed-out or
incomplete override is rejected.

The serializable `SelectionOutcome` records a Unix-millisecond timestamp, every candidate's
eligibility or failure reason, provisional per-repository decisions and the final selections. If
any required upstream has no validated candidate, `actionable` is false and the adapter receives
an empty selection list, so no partial tool change can be planned.

Catalog `delivery_mode: unknown` is deliberate for inventory records where the provider did not
publish whether the service is a synchronized mirror or proxy. A tool adapter must explicitly
accept a mode, and its implementation Issue is responsible for adding the content probes and
delivery evidence needed to promote candidates from inert inventory to runtime support.
