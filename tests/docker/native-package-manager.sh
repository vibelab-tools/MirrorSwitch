#!/bin/sh
set -eu

scenario=${MIRRORSWITCH_SCENARIO:?missing scenario}
root=/tmp/mirrorswitch-matrix
mkdir -p "$root"

case "$scenario" in
  debian|ubuntu)
    test -x /usr/bin/apt-get
    printf '%s\n' 'deb [trusted=yes] file:/nonexistent stable main' > "$root/sources.list"
    apt-get -o "Dir::Etc::sourcelist=$root/sources.list" -o Dir::Etc::sourceparts=- indextargets >/dev/null
    ;;
  fedora|rocky|almalinux|centos-stream)
    command -v dnf >/dev/null
    mkdir -p "$root/repos"
    printf '%s\n' '[fixture]' 'name=fixture' 'baseurl=file:///nonexistent' 'enabled=0' 'gpgcheck=1' > "$root/repos/fixture.repo"
    dnf --setopt="reposdir=$root/repos" --disablerepo='*' repolist >/dev/null
    ;;
  arch)
    command -v pacman-conf >/dev/null
    printf '%s\n' 'Server = https://mirror.invalid/archlinux/$repo/os/$arch' > "$root/mirrorlist"
    printf '%s\n' '[options]' 'Architecture = auto' '[core]' "Include = $root/mirrorlist" > "$root/pacman.conf"
    pacman-conf --config "$root/pacman.conf" --repo core Server | grep -F 'mirror.invalid' >/dev/null
    ;;
  opensuse)
    command -v zypper >/dev/null
    mkdir -p "$root/etc/zypp/repos.d" "$root/var/cache/zypp" "$root/var/lib/zypp"
    printf '%s\n' '[fixture]' 'name=fixture' 'enabled=0' 'autorefresh=0' 'baseurl=https://mirror.invalid/opensuse/' 'gpgcheck=1' 'priority=90' > "$root/etc/zypp/repos.d/fixture.repo"
    zypper --root "$root" --non-interactive repos >/dev/null
    ;;
  alpine)
    command -v apk >/dev/null
    printf '%s\n' 'https://mirror.invalid/alpine/v3.22/main' 'https://mirror.invalid/alpine/v3.22/community' > "$root/repositories"
    apk --repositories-file "$root/repositories" --no-network policy >/dev/null 2>&1
    ;;
  *)
    echo "unknown scenario: $scenario" >&2
    exit 64
    ;;
esac

printf 'scenario=%s arch=%s os=%s package_manager_config=ok\n' \
  "$scenario" "$(uname -m)" "$(. /etc/os-release; printf '%s' "$ID")"
