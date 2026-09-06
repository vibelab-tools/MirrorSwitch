#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
input=${1:?usage: prepare-release.sh INPUT_ROOT OUTPUT_DIRECTORY TAG}
output=${2:?usage: prepare-release.sh INPUT_ROOT OUTPUT_DIRECTORY TAG}
tag=${3:?usage: prepare-release.sh INPUT_ROOT OUTPUT_DIRECTORY TAG}
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | sed -n '1p')
[[ "$tag" == "v$version" ]]

mkdir -p "$output"
output=$(cd "$output" && pwd)

platforms=(linux-x86_64 linux-arm64)
if [[ "$tag" == v0.2.* ]]; then
  platforms+=(macos-x86_64 macos-arm64 windows-x86_64 windows-arm64)
fi

for platform in "${platforms[@]}"; do
  source_dir="$input/mirrorswitch-packages-$platform"
  [[ -d "$source_dir" ]]
  (cd "$source_dir" && sha256sum -c SHA256SUMS)
done

files=(
  "mirrorswitch-$version-linux-x86_64.tar.gz"
  "mirrorswitch-$version-linux-arm64.tar.gz"
  "mirrorswitch_${version}_amd64.deb"
  "mirrorswitch_${version}_arm64.deb"
  "mirrorswitch-$version-1.x86_64.rpm"
  "mirrorswitch-$version-1.aarch64.rpm"
)

if [[ "$tag" == v0.2.* ]]; then
  files+=(
    "mirrorswitch-$version-macos-x86_64.tar.gz"
    "mirrorswitch-$version-macos-arm64.tar.gz"
    "mirrorswitch-$version-windows-x86_64.zip"
    "mirrorswitch-$version-windows-arm64.zip"
  )
fi

for file in "${files[@]}"; do
  case "$file" in
    *-linux-x86_64.tar.gz|*_amd64.deb|*.x86_64.rpm) platform=linux-x86_64 ;;
    *-linux-arm64.tar.gz|*_arm64.deb|*.aarch64.rpm) platform=linux-arm64 ;;
    *-macos-x86_64.tar.gz) platform=macos-x86_64 ;;
    *-macos-arm64.tar.gz) platform=macos-arm64 ;;
    *-windows-x86_64.zip) platform=windows-x86_64 ;;
    *-windows-arm64.zip) platform=windows-arm64 ;;
    *) echo "unknown release asset: $file" >&2; exit 64 ;;
  esac
  install -m 0644 "$input/mirrorswitch-packages-$platform/$file" "$output/$file"
done

(
  cd "$output"
  sha256sum "${files[@]}" > SHA256SUMS
  sha256sum -c SHA256SUMS
)

test "$(find "$output" -maxdepth 1 -type f | wc -l)" -eq "$((${#files[@]} + 1))"
printf '%s\n' "${files[@]}" SHA256SUMS
