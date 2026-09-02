# CocoaPods adapter

The `cocoapods` adapter supports CocoaPods 1.8 and later on native Intel and Apple Silicon macOS
hosts. It records the CocoaPods and Ruby versions, parses `pod repo list`, and reports project
Podfile sources without exposing private repository URLs or credentials.

The six-provider review found two current Specs Git mirrors: TUNA and NJU both publish
`CocoaPods/Specs.git`. Their bare repository HEAD and pack inventory must pass before latency
ranking. The Huawei entry is a historical archive, while the old TUNA and NJU static paths are no
longer current endpoints. None of the six providers exposes a validated replacement for the modern
`https://cdn.cocoapods.org/` protocol, so trunk CDN remains read-only and cannot be silently
converted to Git mode.

## Managed state

User scope is the default. It is actionable only when `pod repo list` reports exactly one public
Git Specs repository under `~/.cocoapods/repos/<name>`, its Git origin agrees with CocoaPods, and
the checked-out repository contains the reviewed AFNetworking 4.0.1 podspec. MirrorSwitch changes
only that repository's `origin` URL. It does not create a large Specs checkout, remove trunk, update
the repository, or touch any private/local repo.

Project scope must be selected explicitly. The Podfile must contain exactly one simple public
Specs Git `source` declaration. MirrorSwitch changes only the quoted URL and preserves source
order, private sources, comments, targets, dependencies, and `Podfile.lock`. Dynamic, compound,
CDN-only, and duplicate public source declarations remain unchanged because their precedence
cannot be represented safely by a one-line rewrite.

## Verification and recovery

After a user-scope apply, CocoaPods must report the selected mirror, Git must read its HEAD, the
representative podspec must still match its name, version, source repository, and tag, and
`pod ipc spec` must parse the checked-out file. Project verification runs `git ls-remote` against
the selected Specs URL and asks `pod ipc podfile` to parse the changed Podfile. Both scopes also
query the AFNetworking 4.0.1 source tag at its declared upstream URL. This last check proves the
actual dependency download remains reachable; it does not claim that the Specs mirror hosts pod
source code or binary assets.

Any verification failure restores the exact previous file. Repeating a successful plan is
idempotent, and explicit transaction restore returns the Git config or Podfile to its original
bytes and mode.
