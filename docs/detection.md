# Linux detection

Detection is a read-only input to CLI, configuration-file, and TUI requests.
It returns one serializable report containing the Linux context, configuration
layout, privilege context, runtime associations, operable adapters, normalized
current sources, default selections, and structured skip notices.

The Linux context is derived from `/etc/os-release` with
`/usr/lib/os-release` as fallback, the compiled architecture, and container
evidence from the `container` environment hint, `/.dockerenv`,
`/run/.containerenv`, and `/proc/1/cgroup`. A container uses the distribution
inside its own filesystem namespace as its base distribution; host service
behavior is never inferred for that result.

Python and Java are runtime triggers only. Their presence causes explicit
checks for pip/uv/Poetry/PDM and Maven/Gradle/sbt/Leiningen respectively.
Missing related clients are reported but never installed and never become
operable targets. Every compiled adapter still performs its own independent
callable-tool or valid-configuration detection.

For a detected adapter, the core reads each declared scope through the adapter
and preserves normalized sources plus their source paths. System or user scope
may be selected automatically according to the adapter contract. Project and
environment scope remain off by default. Configuration-file and TUI decisions
apply the same keyed override operation and cannot enable an unavailable tool.
Machine-readable and debug output redact URL credentials, query values, and
fragments while retaining the unmodified value only inside the in-memory plan.

Unsupported distributions, architectures, missing related tools, adapter
errors, configuration parse/read failures, invalid default scopes, and explicit
requests for unavailable tools have distinct machine-readable outcomes.
