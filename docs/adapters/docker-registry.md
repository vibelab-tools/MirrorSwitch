# Docker daemon Registry Mirrors adapter

The `docker-registry` adapter configures Docker Hub pull-through mirrors on Linux without
mixing them with Docker CE package repositories.

## Detection and scope

The adapter asks the Docker CLI for the effective context, endpoint, daemon information and
running-container count. Remote SSH/TCP contexts are rejected because a local file change cannot
configure their daemon. The target follows Docker's documented backend layout:

| Backend | Scope | Configuration |
| --- | --- | --- |
| Docker Engine | system | `/etc/docker/daemon.json`, or an absolute `--config-file` from the systemd unit |
| Rootless Docker Engine | user | `$XDG_CONFIG_HOME/docker/daemon.json`, falling back to `~/.config/docker/daemon.json` |
| Docker Desktop for Linux | user | `~/.docker/daemon.json` |

If the daemon already receives `--registry-mirror` as a startup flag, planning stops because the
same option in `daemon.json` would prevent dockerd from starting.

## Candidate selection

DaoCloud and 1Panel are independently probed before latency is compared. For the current
architecture, each candidate must return a pinned Alpine manifest that references the expected
config and layer digests, and both blobs must be readable. Registry Bearer challenges are followed
without using or storing user credentials.

## Apply, verification and recovery

The selected HTTPS mirror is placed first in `registry-mirrors`. Existing mirrors retain their
relative order, and `insecure-registries`, proxy settings, authentication files and every unrelated
daemon key remain unchanged.

Applying the plan only writes the selected daemon JSON transactionally. It never reloads or
restarts Docker. Verification runs `dockerd --validate` for Docker Engine when the binary is
available, then performs a digest-pinned `docker pull` directly through the selected mirror for
the current architecture. Docker Desktop validates its engine JSON when the user later restarts
Desktop. A failed validation or pull restores the exact previous file automatically.

The verification pull may leave the small Alpine image in the local image cache. A restart remains
required before ordinary `docker.io` pulls use the new daemon setting.
