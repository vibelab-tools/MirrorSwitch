#!/bin/sh
set -eu

scenario=${MIRRORSWITCH_SCENARIO:?missing scenario}
catalog_version=${MIRRORSWITCH_CATALOG_VERSION:?missing catalog version}
catalog_revision=${MIRRORSWITCH_CATALOG_REVISION:?missing catalog revision}
root=/tmp/mirrorswitch-matrix
phase=initialization
tool_version=not-detected

failure() {
  status=$?
  if [ "$status" -ne 0 ]; then
    printf 'FAILED scenario=%s architecture=%s tool_version=%s catalog=%s revision=%s candidate=not-selected phase=%s status=%s\n' \
      "$scenario" "$(uname -m)" "$tool_version" "$catalog_version" "$catalog_revision" "$phase" "$status" >&2
  fi
}
trap failure EXIT

mkdir -p "$root"

case "$scenario" in
  debian|ubuntu)
    phase=detect-package-manager
    test -x /usr/bin/apt-get
    tool_version=$(apt-get --version | sed -n '1p' | tr ' ' '_')
    phase=parse-fixture
    printf '%s\n' 'deb [trusted=yes] file:/nonexistent stable main' > "$root/sources.list"
    apt-get -o "Dir::Etc::sourcelist=$root/sources.list" -o Dir::Etc::sourceparts=- indextargets >/dev/null
    ;;
  fedora|rocky|almalinux|centos-stream)
    phase=detect-package-manager
    command -v dnf >/dev/null
    tool_version=$(dnf --version | sed -n '1p' | tr ' ' '_')
    phase=parse-fixture
    mkdir -p "$root/repos"
    printf '%s\n' '[fixture]' 'name=fixture' 'baseurl=file:///nonexistent' 'enabled=0' 'gpgcheck=1' > "$root/repos/fixture.repo"
    dnf --setopt="reposdir=$root/repos" --disablerepo='*' repolist >/dev/null
    ;;
  arch)
    phase=detect-package-manager
    command -v pacman-conf >/dev/null
    tool_version=$(pacman --version | sed -n '/Pacman v/{s/^.*Pacman/Pacman/;p;q;}' | tr ' ' '_')
    phase=parse-fixture
    printf '%s\n' 'Server = https://mirror.invalid/archlinux/$repo/os/$arch' > "$root/mirrorlist"
    printf '%s\n' '[options]' 'Architecture = auto' '[core]' "Include = $root/mirrorlist" > "$root/pacman.conf"
    pacman-conf --config "$root/pacman.conf" --repo core Server | grep -F 'mirror.invalid' >/dev/null
    ;;
  opensuse)
    phase=detect-package-manager
    command -v zypper >/dev/null
    tool_version=$(zypper --version | sed -n '1p' | tr ' ' '_')
    phase=parse-fixture
    mkdir -p "$root/etc/zypp/repos.d" "$root/var/cache/zypp" "$root/var/lib/zypp"
    printf '%s\n' '[fixture]' 'name=fixture' 'enabled=0' 'autorefresh=0' 'baseurl=https://mirror.invalid/opensuse/' 'gpgcheck=1' 'priority=90' > "$root/etc/zypp/repos.d/fixture.repo"
    zypper --root "$root" --non-interactive repos >/dev/null
    ;;
  alpine)
    phase=detect-package-manager
    command -v apk >/dev/null
    tool_version=$(apk --version | sed -n '1p' | tr ' ' '_')
    phase=parse-fixture
    printf '%s\n' 'https://mirror.invalid/alpine/v3.22/main' 'https://mirror.invalid/alpine/v3.22/community' > "$root/repositories"
    apk --repositories-file "$root/repositories" --no-network policy >/dev/null 2>&1
    ;;
  *)
    echo "unknown scenario: $scenario" >&2
    exit 64
    ;;
esac

phase=complete
printf 'scenario=%s arch=%s os=%s tool_version=%s package_manager_config=ok\n' \
  "$scenario" "$(uname -m)" "$(. /etc/os-release; printf '%s' "$ID")" "$tool_version"
