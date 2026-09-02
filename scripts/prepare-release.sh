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

for architecture in x86_64 arm64; do
  source_dir="$input/mirrorswitch-packages-linux-$architecture"
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

for file in "${files[@]}"; do
  case "$file" in
    *x86_64*|*_amd64.deb) architecture=x86_64 ;;
    *arm64*|*aarch64*) architecture=arm64 ;;
  esac
  install -m 0644 "$input/mirrorswitch-packages-linux-$architecture/$file" "$output/$file"
done

(
  cd "$output"
  sha256sum "${files[@]}" > SHA256SUMS
  sha256sum -c SHA256SUMS
)

test "$(find "$output" -maxdepth 1 -type f | wc -l)" -eq 7
printf '%s\n' "${files[@]}" SHA256SUMS
