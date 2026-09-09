# ROS 2 package repository adapter

The `ros2` adapter configures ROS 2 binary package repositories without treating rosdistro Git
metadata or ROS container images as package mirrors.

## Supported matrix

| Package manager | Operating-system release | ROS distribution | Architecture |
| --- | --- | --- | --- |
| APT | Ubuntu 22.04 Jammy | Humble | amd64, arm64 |
| APT | Ubuntu 24.04 Noble | Jazzy, Kilted | amd64, arm64 |
| APT | Ubuntu 26.04 Resolute | Lyrical | amd64, arm64 |
| DNF | RHEL 8 | Humble | x86_64 |
| DNF | RHEL 9 | Jazzy, Kilted | x86_64 |
| DNF | RHEL 10 or AlmaLinux 10 | Lyrical | x86_64 |

ROS upstream does not publish RPM binaries for arm64. MirrorSwitch therefore returns an explicit
unsupported result for that combination before reading or changing repository files.

`ROS_DISTRO` wins when it agrees with the active installation. Otherwise the adapter asks
`ros2 pkg prefix rclcpp`; an uninstalled repository defaults to the stable distribution for its
operating-system release. A disagreement or cross-release combination is rejected.

## Repository handling

APT supports legacy `.list`, deb822 `.sources`, and the current `ros2-apt-source` package layout.
When `/etc/apt/sources.list.d/ros2.sources` is a symlink, MirrorSwitch changes the regular
`/usr/share/ros-apt-source/ros2.sources` target transactionally instead of replacing the symlink.
Path-based and embedded `Signed-By` keys are preserved.

DNF rewrites only the active ROS 2 `baseurl`. Disabled debug/source sections, `gpgcheck`,
`repo_gpgcheck`, the GPG key, other repositories and package-manager pinning remain unchanged.
Custom-only ROS 2 repositories are preserved and block creation of a competing managed source.

## Candidate and apply verification

Nine APT candidates independently prove Release metadata, Release signature, the target
architecture index and a distribution-specific `ros-*-ros-base` package before latency ranking.
The RHEL path uses NJU and proves `repomd.xml`, its detached signature and the exact x86_64 RPM.

Apply changes one repository file, runs the native package-manager refresh and queries the target
ROS package. Failed verification restores the exact previous file; repeated planning is
idempotent. No service is restarted.
