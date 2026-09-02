# Leiningen adapter

The Leiningen adapter supports the reviewed 2.x profile model on Linux, macOS, and native Windows
hosts using x86_64 or arm64. It discovers `lein` or `lein.bat`, the launcher JVM, the native user
home, and an explicit `LEIN_HOME`. It changes only the user's `profiles.clj`; system and project
profiles, repository overrides, encrypted credentials and launcher files remain read-only.

Maven and Clojars are separate required upstreams. The catalog pairs complete metadata, artifact
and checksum probes from the six-provider inventory before latency ranking. A plan may combine one
reviewed Maven candidate and one reviewed Clojars candidate, but it never treats a Maven-only
mirror as complete.

The format-preserving Clojure reader updates or inserts only `:user :mirrors` entries named
`central` and `clojars`. Private repositories, credentials, plugins, profiles, comments, ordering,
UTF-8 BOM and LF/CRLF layout are preserved. Dynamic forms, precedence overrides and unreviewed
same-name mirrors stop the plan.

Verification creates an isolated managed project and profile, then resolves Apache Commons Lang
and the `lein-pprint` plugin. Unix hosts use `env`; Windows uses `cmd.exe` to set the same
verification-only environment before invoking `lein.bat`. Failure restores the transaction, a
second plan is empty, and explicit restore returns the original profile.
