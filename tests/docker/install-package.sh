#!/bin/sh
set -eu

architecture=${MIRRORSWITCH_PACKAGE_ARCH:?missing package architecture}
format=${MIRRORSWITCH_PACKAGE_FORMAT:?missing package format}
version=${MIRRORSWITCH_VERSION:?missing package version}

tree_hash() {
  directory=$1
  if [ -d "$directory" ]; then
    find "$directory" -type f -exec sha256sum {} \; | LC_ALL=C sort | sha256sum | awk '{print $1}'
  else
    printf '%s\n' absent
  fi
}

case "$format" in
  archive)
    work=/tmp/mirrorswitch-archive
    mkdir -p "$work"
    tar -xzf "/packages/mirrorswitch-$version-linux-$architecture.tar.gz" -C "$work"
    root="$work/mirrorswitch-$version-linux-$architecture"
    test -f "$root/LICENSE"
    "$root/mirrorswitch" --version | grep -F "mirrorswitch $version" >/dev/null
    "$root/mirrorswitch" --help | grep -F 'mirrorswitch detect' >/dev/null
    ;;
  deb)
    case "$architecture" in x86_64) package_arch=amd64 ;; arm64) package_arch=arm64 ;; esac
    before=$(tree_hash /etc/apt)
    dpkg -i "/packages/mirrorswitch_${version}_${package_arch}.deb" >/dev/null
    mirrorswitch --version | grep -F "mirrorswitch $version" >/dev/null
    mirrorswitch --help | grep -F 'mirrorswitch detect' >/dev/null
    dpkg -r mirrorswitch >/dev/null
    test ! -e /usr/bin/mirrorswitch
    after=$(tree_hash /etc/apt)
    test "$before" = "$after"
    ;;
  rpm)
    case "$architecture" in x86_64) package_arch=x86_64 ;; arm64) package_arch=aarch64 ;; esac
    before=$(tree_hash /etc/yum.repos.d)
    rpm -i "/packages/mirrorswitch-${version}-1.${package_arch}.rpm"
    mirrorswitch --version | grep -F "mirrorswitch $version" >/dev/null
    mirrorswitch --help | grep -F 'mirrorswitch detect' >/dev/null
    rpm -e mirrorswitch
    test ! -e /usr/bin/mirrorswitch
    after=$(tree_hash /etc/yum.repos.d)
    test "$before" = "$after"
    ;;
  *)
    echo "unknown package format: $format" >&2
    exit 64
    ;;
esac

printf 'format=%s architecture=%s version=%s install_test=ok\n' "$format" "$architecture" "$version"
