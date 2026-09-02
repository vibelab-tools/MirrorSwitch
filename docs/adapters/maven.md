# Maven adapter

The Maven adapter supports the reviewed Maven `3.6.3` through `3.x` settings model on Linux,
macOS, and native Windows hosts using `x86_64` or `arm64`. Maven 4 remains outside this adapter
until its project-settings and settings 2.0 precedence model receives separate acceptance coverage.
Detection records Maven and launcher JDK versions, Maven home, global and user settings, project
POM repositories, plugin repositories, and project or environment settings overrides.

The default scope expresses repository policy only in `${user.home}/.m2/settings.xml`; project POM
files and global Maven settings are read-only. MirrorSwitch adds one exact `mirrorOf=central`
entry, or retargets an existing exact Central mirror only when its URL is Maven Central or one of
the reviewed public mirrors and no same-ID `server` entry exists. Exact matching takes precedence
over wildcard mirror rules, so existing private, plugin, wildcard, exclusion, proxy, profile, and
server policy remains in place. Private or ambiguous uses of the `central` repository identity,
settings precedence overrides, credential-bound Central mirrors, and duplicate exact matches are
rejected. These rules
follow Maven's official [mirror selection](https://maven.apache.org/guides/mini/guide-mirror-settings)
and [settings merge](https://maven.apache.org/settings.html) contracts.

Each actionable candidate must return a representative POM, artifact metadata, JAR, and the JAR's
published SHA-1 before latency ranking. The post-apply boundary runs the pinned Maven Help Plugin's
`effective-settings` goal with passwords hidden, then the pinned Maven Dependency Plugin under
strict-checksum mode in an isolated per-provider local repository. It verifies both the resolved
JAR and Maven's `_remote.repositories` identity record. The small POM under
`${user.home}/.m2/mirrorswitch/verification/` contains no repository or dependency policy and is
covered by the same transaction and restore boundary as `settings.xml`.

CLI, configuration-file, and TUI entry points consume the same user-scope plan. The complete plan
is idempotent, and a failed effective-settings, plugin, checksum, or dependency check restores the
prior settings and verification POM.

The user path is `${user.home}/.m2/settings.xml` on every supported OS. Maven reports its global
settings root through `mvn` or `mvn.cmd`; MirrorSwitch never derives it from a Unix installation
prefix. Existing UTF-8 BOM and LF/CRLF XML layout are preserved.
