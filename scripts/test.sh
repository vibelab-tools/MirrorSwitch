#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/tests/docker/images.env"

mode=${1:-unit}
scenario=${2:-}
architecture=${3:-native}
phase=initialization

catalog_version=$(jq -r '.content_version' "$repo_root/catalog/mirrors.json")
catalog_revision=$(jq -r '.content_revision' "$repo_root/catalog/mirrors.json")

failure() {
  status=$?
  printf 'FAILED scenario=%s architecture=%s catalog=%s revision=%s candidate=not-selected phase=%s status=%s\n' \
    "${scenario:-all}" "$architecture" "$catalog_version" "$catalog_revision" "$phase" "$status" >&2
  exit "$status"
}
trap failure ERR

unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY

adapter_test() {
  case "$1" in
    debian|ubuntu) printf '%s\n' apt_adapter_boundary ;;
    fedora|rocky|almalinux|centos-stream) printf '%s\n' dnf_adapter_boundary ;;
    arch) printf '%s\n' pacman_adapter_boundary ;;
    opensuse) printf '%s\n' zypper_adapter_boundary ;;
    alpine) printf '%s\n' apk_adapter_boundary ;;
  esac
}

image_for() {
  case "$1" in
    debian) printf '%s\n' "$DEBIAN_IMAGE" ;;
    ubuntu) printf '%s\n' "$UBUNTU_IMAGE" ;;
    fedora) printf '%s\n' "$FEDORA_IMAGE" ;;
    rocky) printf '%s\n' "$ROCKY_IMAGE" ;;
    almalinux) printf '%s\n' "$ALMALINUX_IMAGE" ;;
    centos-stream) printf '%s\n' "$CENTOS_STREAM_IMAGE" ;;
    arch) printf '%s\n' "$ARCH_IMAGE" ;;
    opensuse) printf '%s\n' "$OPENSUSE_IMAGE" ;;
    alpine) printf '%s\n' "$ALPINE_IMAGE" ;;
    *) trap - ERR; return 64 ;;
  esac
}

run_unit() {
  phase=adapter-coverage
  python3 -B "$repo_root/scripts/check_adapter_coverage.py"
  phase=rust-tests
  cargo test --locked --all-targets -- --test-threads=1
}

run_quality() {
  phase=rustfmt
  cargo fmt --check
  phase=clippy
  cargo clippy --locked --all-targets -- -D warnings
}

apt_tree_hash() {
  if [[ -d /etc/apt ]]; then
    find /etc/apt -type f -exec sha256sum {} + | LC_ALL=C sort | sha256sum | awk '{print $1}'
  else
    printf '%s\n' absent
  fi
}

run_cli() {
  local binary=${MIRRORSWITCH_BINARY:-$repo_root/target/release/mirrorswitch}
  local before after payload
  if [[ -z ${MIRRORSWITCH_BINARY:-} ]]; then
    phase=cli-build
    cargo build --locked --release --bin mirrorswitch
  fi
  [[ -x "$binary" ]]
  phase=cli-version
  "$binary" --version | grep -F "mirrorswitch " >/dev/null
  phase=cli-help
  "$binary" --help | grep -F "mirrorswitch detect" >/dev/null
  phase=cli-read-only-detect
  before=$(apt_tree_hash)
  payload=$("$binary" detect --offline --json --category system)
  after=$(apt_tree_hash)
  [[ "$before" == "$after" ]]
  python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["ok"] is True; assert data["report"]["context"]["os"] == "linux"' <<<"$payload"
}

run_language() {
  phase=language-adapters
  for test in pip npm gradle go cargo; do
    cargo test --test "${test}_adapter_boundary" -- --test-threads=1
  done
}

run_distro() {
  local name=$1 image test platform=()
  scenario=$name
  image=$(image_for "$name")
  test=$(adapter_test "$name")
  if [[ "$architecture" == arm64 ]]; then
    platform=(--platform linux/arm64)
  elif [[ "$architecture" != native ]]; then
    echo "architecture must be native or arm64" >&2
    return 64
  fi
  phase=adapter-boundary
  cargo test --test "$test" -- --test-threads=1
  phase=native-package-manager
  set +e
  docker run --rm --network none "${platform[@]}" \
    -e "MIRRORSWITCH_SCENARIO=$name" \
    -e "MIRRORSWITCH_CATALOG_VERSION=$catalog_version" \
    -e "MIRRORSWITCH_CATALOG_REVISION=$catalog_revision" \
    -v "$repo_root/tests/docker/native-package-manager.sh:/matrix.sh:ro" \
    "$image" /bin/sh /matrix.sh
  status=$?
  set -e
  if (( status != 0 )); then
    trap - ERR
    return "$status"
  fi
}

case "$mode" in
  quality) run_quality ;;
  unit) run_unit ;;
  cli) run_cli ;;
  language) run_language ;;
  distro)
    [[ -n "$scenario" ]] || { echo 'usage: scripts/test.sh distro NAME [native|arm64]' >&2; exit 64; }
    run_distro "$scenario"
    ;;
  docker)
    for item in debian ubuntu fedora rocky almalinux centos-stream arch opensuse alpine; do
      run_distro "$item"
    done
    ;;
  *)
    echo 'usage: scripts/test.sh {quality|unit|cli|language|distro NAME [native|arm64]|docker}' >&2
    exit 64
    ;;
esac
