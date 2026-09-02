#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${1:?usage: package-linux.sh BINARY x86_64|arm64 OUTPUT_DIRECTORY}
architecture=${2:?usage: package-linux.sh BINARY x86_64|arm64 OUTPUT_DIRECTORY}
output=${3:?usage: package-linux.sh BINARY x86_64|arm64 OUTPUT_DIRECTORY}
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | sed -n '1p')

case "$architecture" in
  x86_64)
    deb_arch=amd64
    rpm_arch=x86_64
    file_pattern='x86-64'
    ;;
  arm64)
    deb_arch=arm64
    rpm_arch=aarch64
    file_pattern='ARM aarch64'
    ;;
  *)
    echo "architecture must be x86_64 or arm64" >&2
    exit 64
    ;;
esac

[[ -f "$binary" && -x "$binary" ]]
file "$binary" | grep -F "$file_pattern" >/dev/null
"$binary" --version | grep -F "mirrorswitch $version" >/dev/null
command -v dpkg-deb >/dev/null
command -v rpmbuild >/dev/null

mkdir -p "$output"
output=$(cd "$output" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/mirrorswitch-package.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/mirrorswitch-package.*) find "$work" -depth -delete ;;
    *) echo "refusing to remove unexpected temporary path: $work" >&2 ;;
  esac
}
trap cleanup EXIT

archive_name="mirrorswitch-$version-linux-$architecture.tar.gz"
archive_root="$work/mirrorswitch-$version-linux-$architecture"
install -d "$archive_root"
install -m 0755 "$binary" "$archive_root/mirrorswitch"
install -m 0644 "$repo_root/LICENSE" "$archive_root/LICENSE"
install -m 0644 "$repo_root/README.md" "$archive_root/README.md"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
  -C "$work" -czf "$output/$archive_name" "$(basename "$archive_root")"

deb_name="mirrorswitch_${version}_${deb_arch}.deb"
deb_root="$work/deb"
install -d "$deb_root/DEBIAN" "$deb_root/usr/bin" "$deb_root/usr/share/doc/mirrorswitch"
install -m 0755 "$binary" "$deb_root/usr/bin/mirrorswitch"
install -m 0644 "$repo_root/LICENSE" "$deb_root/usr/share/doc/mirrorswitch/copyright"
printf '%s\n' \
  'Package: mirrorswitch' \
  "Version: $version" \
  'Section: utils' \
  'Priority: optional' \
  "Architecture: $deb_arch" \
  'Maintainer: MirrorSwitch contributors' \
  'Description: Safe per-tool mirror selection for development repositories' \
  > "$deb_root/DEBIAN/control"
dpkg-deb --root-owner-group --build "$deb_root" "$output/$deb_name" >/dev/null

rpm_name="mirrorswitch-${version}-1.${rpm_arch}.rpm"
rpm_top="$work/rpm"
install -d "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"
install -m 0755 "$binary" "$rpm_top/SOURCES/mirrorswitch"
install -m 0644 "$repo_root/LICENSE" "$rpm_top/SOURCES/LICENSE"
cat > "$rpm_top/SPECS/mirrorswitch.spec" <<EOF
Name: mirrorswitch
Version: $version
Release: 1
Summary: Safe per-tool mirror selection for development repositories
License: MIT
BuildArch: $rpm_arch
Source0: mirrorswitch
Source1: LICENSE

%description
MirrorSwitch selects and safely applies compatible development repository mirrors.

%prep

%build

%install
install -Dpm 0755 %{SOURCE0} %{buildroot}/usr/bin/mirrorswitch
install -Dpm 0644 %{SOURCE1} %{buildroot}/usr/share/licenses/mirrorswitch/LICENSE

%files
/usr/bin/mirrorswitch
%license /usr/share/licenses/mirrorswitch/LICENSE
EOF
rpmbuild --quiet --define "_topdir $rpm_top" --define '_build_id_links none' \
  --target "$rpm_arch" -bb "$rpm_top/SPECS/mirrorswitch.spec" >/dev/null
install -m 0644 "$rpm_top/RPMS/$rpm_arch/mirrorswitch-$version-1.$rpm_arch.rpm" \
  "$output/$rpm_name"

(
  cd "$output"
  sha256sum "$archive_name" "$deb_name" "$rpm_name" > SHA256SUMS
)

printf '%s\n' "$output/$archive_name" "$output/$deb_name" "$output/$rpm_name" "$output/SHA256SUMS"
