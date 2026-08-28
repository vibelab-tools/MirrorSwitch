# Zypper adapter

The Zypper adapter supports openSUSE Leap and openSUSE Tumbleweed on x86_64 and arm64 at system
scope. It reads enabled and disabled `.repo` files from `/etc/zypp/repos.d`, preserving repository
aliases, order, `enabled`, `autorefresh`, `priority`, `gpgcheck`, `repo_gpgcheck`, `type` and all
other policy fields.

Repository families remain independent selection units:

- Leap distribution repositories use `distribution/leap/$releasever/repo/...`.
- Leap updates, Backports and SLE updates use their distinct `update/leap/$releasever/...` paths.
- Tumbleweed x86_64 repositories use `tumbleweed/repo/...`.
- Tumbleweed arm64 ports repositories use `ports/aarch64/tumbleweed/repo/...`.
- Tumbleweed updates use `update/tumbleweed/`.
- Packman uses its own Leap or Tumbleweed layout and is never replaced by an openSUSE endpoint.

Only recognized canonical aliases at the official download service or one of the cataloged mirror
providers are eligible. OpenH264, NVIDIA and unknown third-party repositories remain unchanged.
The adapter derives eligibility from the configured URL as well as the system distribution, so an
arm64 system is not assumed to use the ports layout when its repository URL says otherwise.

Before latency ranking, each candidate must match the distribution, host/container environment
and architecture. Every configured repository path must return `repodata/repomd.xml` containing a
`<repomd` marker. The adapter accepts HTTPS metadata endpoints only.

Plans replace only the active location field and retain every other byte in the file. Applying uses
the shared atomic transaction engine. Verification runs `zypper --non-interactive refresh --force`,
which checks repository metadata and the existing GPG policy; a non-zero result immediately
attempts restoration. Explicit restore verifies the original bytes.
