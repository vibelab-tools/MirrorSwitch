# Gradle adapter

The Gradle adapter supports the reviewed Gradle `7.6` through `9.x` model on Linux, macOS, and
native Windows hosts using `x86_64` or `arm64`. It detects the Gradle executable, `gradlew` or
`gradlew.bat`, Wrapper distribution version and checksum, launcher JVM, user and installation init
scripts, and project settings/build repository definitions.

The default user scope expresses repository configuration only through
`$GRADLE_USER_HOME/init.d/zz-mirrorswitch.init.gradle`. The managed init script changes the URL of
existing Maven Central repository objects in place. It does not clear or reorder repositories, add
a normal-build repository, change plugin repositories, or edit project files. Consequently custom
and private repositories, `content` filters, and `exclusiveContent` objects remain attached to the
same repository instances. Gradle's init-script locations and ordering follow the official
[initialization scripts](https://docs.gradle.org/current/userguide/init_scripts.html) contract.

Gradle dependency repositories and Gradle distributions are independent catalog upstreams. A
dependency candidate must return the `commons-lang3` POM and JAR before latency ranking. The
post-apply check starts a no-daemon Gradle build with a verification-only detached configuration
and resolves that JAR through the selected endpoint. An inert settings file under
`$GRADLE_USER_HOME/mirrorswitch/verification/` makes this check independent of the user's current
project; it contains no repository or dependency configuration and is covered by the same
transaction and restore boundary as the init script.

There is no user-level init-script setting that changes the Wrapper bootstrap URL. Distribution
switching is therefore a separate, explicit project scope. It changes only `distributionUrl` in
`gradle/wrapper/gradle-wrapper.properties`, preserves the version, `bin`/`all` flavor and every
other property, and requires `distributionSha256Sum`. Candidate probing checks the selected
mirror's checksum text against that configured digest and then checks the exact ZIP. Huawei Cloud
and Nanjing University currently satisfy that contract; cataloged distribution entries without an
automatable checksum/ZIP pair remain inert. This follows Gradle's official
[Wrapper configuration and checksum](https://docs.gradle.org/current/userguide/gradle_wrapper.html)
model.

Both scopes are transactional, idempotent, and restore the prior file on verification failure.
CLI, configuration-file, and TUI entry points consume the same scope-specific plan.

`GRADLE_USER_HOME` remains the authoritative user root on every OS. Existing Wrapper properties
preserve UTF-8 BOM and LF/CRLF layout; project build files, init scripts, credentials and
`gradle.properties` remain read-only unless they are the exact selected surface.
