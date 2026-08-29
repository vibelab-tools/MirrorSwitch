# sbt adapter

The Linux sbt adapter manages only the user's `~/.sbt/repositories` launcher
configuration. It supports the reviewed sbt 1.x and 2.x repository-file model
on x86_64 and arm64. It never edits a launcher script, `build.sbt`,
`project/*.sbt`, `project/build.properties`, `.sbtopts`, `.jvmopts`, or a lock
file.

## Repository semantics

The actionable catalog contains one reviewed pair from Huawei Cloud:

- Maven layout: `https://repo.huaweicloud.com/repository/maven/`
- Ivy plugin layout: `https://repo.huaweicloud.com/repository/ivy/`

The adapter writes separate named entries after `local`. The Ivy entry uses
sbt's plugin pattern with both the Scala and sbt binary-version segments. A
Maven-only mirror is not considered a complete sbt candidate. Other public
Maven surfaces in the six-provider inventory remain inert until a compatible
Ivy surface is verified.

Unknown and private resolvers, comments, ordering, and credentials remain
unchanged. Resolver URLs containing credentials are not included in reports.
MirrorSwitch does not set `sbt.override.build.repos=true`, because that would
discard project-defined private resolvers. Existing repository precedence
overrides in environment options, `.sbtopts`, or `.jvmopts` stop the plan so a
user-level write cannot silently become ineffective.

## Verification and recovery

Before latency ranking, each half of the pair must pass independent metadata,
artifact, checksum, and layout probes. The fixed Maven sample is Apache Commons
Lang 3.14.0. The fixed Ivy sample is sbt-native-packager 1.7.6 for Scala 2.12
and sbt 1.0.

After apply, MirrorSwitch creates a user-owned isolated project under
`~/.mirrorswitch/verification/sbt`. It uses sbt 1.13.0 and Scala 2.13.16, an
isolated launcher/Ivy/Coursier cache, and explicit verification-only repository
properties. A real sbt invocation must list both selected resolvers, update the
Maven dependency, load the Ivy-layout plugin, and evaluate a plugin-provided
setting. Any failure restores every file in the transaction. A successful
second plan is empty, and explicit restore returns the original repository file
and removes verification files that did not previously exist.

## Sources

- [sbt 1.x proxy repositories](https://www.scala-sbt.org/1.x/docs/Proxy-Repositories.html)
- [sbt 1.x launcher configuration](https://www.scala-sbt.org/1.x/docs/Launcher-Configuration.html)
- [sbt 2.x repository override](https://www.scala-sbt.org/2.x/docs/en/reference/sbt-update.html)
- [sbt 2.x plugin convention](https://www.scala-sbt.org/2.x/docs/en/reference/plugin.html)
