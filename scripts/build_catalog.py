#!/usr/bin/env python3
"""Build the runtime catalog from the reviewed provider inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SYSTEM_TOOLS = {
    "apk",
    "apt",
    "ceph",
    "containerd",
    "cygwin",
    "dnf",
    "docker-ce",
    "docker-registry",
    "elasticstack",
    "gitlab-runner",
    "grafana",
    "guix",
    "influxdb",
    "jenkins",
    "kubernetes-images",
    "kubernetes-packages",
    "macports",
    "mariadb",
    "mongodb",
    "msys2",
    "mysql",
    "nginx",
    "opkg",
    "pacman",
    "podman-registry",
    "portage",
    "postgresql",
    "ros",
    "ros2",
    "xbps",
    "yum",
    "winget",
    "zabbix",
    "zypper",
}

USER_ONLY_TOOLS = {
    "cocoapods",
    "conda",
    "cargo",
    "fnm",
    "go",
    "homebrew",
    "nvm",
    "pyenv",
    "rustup",
    "rubygems",
    "scoop",
}

ROLE_BY_CONTENT = {
    "repository-metadata": "metadata",
    "language-registry": "index",
    "binary-cache": "artifacts",
    "container-registry": "registry",
    "git-mirror": "git",
    "release-artifacts": "releases",
    "release-proxy": "releases",
    "raw-proxy": "raw",
    "static-files": "artifacts",
}

CATALOG_FORMAT_REVISION = "78"

APT_RUNTIME_UPSTREAMS = {
    "debian--repository-metadata": ["x86_64", "arm64"],
    "debian-security--repository-metadata": ["x86_64", "arm64"],
    "ubuntu--repository-metadata": ["x86_64"],
    "ubuntu-ports--repository-metadata": ["arm64"],
}

DNF_RUNTIME_UPSTREAMS = {
    "fedora--repository-metadata": ["x86_64", "arm64"],
    "rocky--repository-metadata": ["x86_64", "arm64"],
    "almalinux--repository-metadata": ["x86_64", "arm64"],
    "centos-stream--repository-metadata": ["x86_64", "arm64"],
}

YUM_RUNTIME_UPSTREAMS = {
    "centos-vault--repository-metadata": ["x86_64"],
    "centos-altarch--repository-metadata": ["arm64"],
}

PACMAN_RUNTIME_UPSTREAMS = {
    "archlinux--repository-metadata": ["x86_64"],
    "archlinuxarm--repository-metadata": ["arm64"],
    "archlinuxcn--repository-metadata": ["x86_64", "arm64"],
    "blackarch--repository-metadata": ["x86_64"],
}

PACMAN_RUNTIME_DISTRIBUTIONS = {
    "archlinux--repository-metadata": ["arch"],
    "archlinuxarm--repository-metadata": ["archarm"],
    "archlinuxcn--repository-metadata": ["arch", "archarm"],
    "blackarch--repository-metadata": ["arch"],
}

ZYPPER_RUNTIME_UPSTREAMS = {
    "opensuse--repository-metadata": ["x86_64", "arm64"],
    "opensuse-update--repository-metadata": ["x86_64", "arm64"],
    "opensuse-tumbleweed--repository-metadata": ["x86_64", "arm64"],
    "opensuse-ports--repository-metadata": ["arm64"],
    "packman--repository-metadata": ["x86_64", "arm64"],
}

ZYPPER_RUNTIME_DISTRIBUTIONS = {
    "opensuse--repository-metadata": ["opensuse-leap"],
    "opensuse-update--repository-metadata": [
        "opensuse-leap",
        "opensuse-tumbleweed",
    ],
    "opensuse-tumbleweed--repository-metadata": ["opensuse-tumbleweed"],
    "opensuse-ports--repository-metadata": ["opensuse-tumbleweed"],
    "packman--repository-metadata": ["opensuse-leap", "opensuse-tumbleweed"],
}

PORTAGE_RUNTIME_UPSTREAMS = {
    "gentoo--repository-metadata",
    "gentoo-portage--repository-metadata",
}

APK_RUNTIME_UPSTREAM = "alpine--repository-metadata"
XBPS_RUNTIME_UPSTREAM = "void--repository-metadata"
NIX_RUNTIME_UPSTREAM = "nix-channels--binary-cache"
NIX_MACOS_ACTIONABLE_PROVIDERS = {"nju", "tuna"}
GUIX_RUNTIME_UPSTREAMS = {
    "guix--static-files": "Signature: 1;berlin.guix.gnu.org;",
    "guix-bordeaux--static-files": "Signature: 1;bayfront;",
}
FLATPAK_RUNTIME_UPSTREAM = "flathub--static-files"
OPKG_RUNTIME_UPSTREAMS = {
    "openwrt--repository-metadata": "openwrt",
    "immortalwrt--repository-metadata": "immortalwrt",
}
PIP_RUNTIME_UPSTREAM = "pypi--language-registry"
PIP_RUNTIME_ENTRY_NAMES = {"pypi", "pypi/web/simple"}
PIP_SIMPLE_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/pypi/simple/",
    "huaweicloud": "https://repo.huaweicloud.com/repository/pypi/simple/",
    "nju": "https://mirrors.nju.edu.cn/pypi/web/simple/",
    "sjtug": "https://mirror.sjtu.edu.cn/pypi/web/simple/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/",
    "ustc": "https://mirrors.ustc.edu.cn/pypi/simple/",
}
PDM_ARTIFACT_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/pypi/packages/",
    "huaweicloud": "https://repo.huaweicloud.com/repository/pypi/packages/",
    "nju": "https://mirrors.nju.edu.cn/pypi/web/packages/",
    "sjtug": "https://mirror.sjtu.edu.cn/pypi-packages/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages/",
    "ustc": "https://mirrors.ustc.edu.cn/pypi/packages/",
}
NPM_RUNTIME_UPSTREAM = "npm--language-registry"
NPM_RUNTIME_ENTRY_NAMES = {"npm", "NPM"}
NPM_ACTIONABLE_PROVIDERS = {"huaweicloud"}
NPM_REGISTRY_TOOLS = {"npm", "pnpm", "yarn"}
CONDA_RUNTIME_UPSTREAM = "anaconda--language-registry"
CONDA_ACTIONABLE_PROVIDERS = {"nju", "tuna", "ustc"}
GRADLE_MAVEN_UPSTREAM = "maven--language-registry"
GRADLE_DISTRIBUTION_UPSTREAM = "gradle-distributions--release-artifacts"
MAVEN_REGISTRY_ENDPOINTS = {
    "aliyun": "https://maven.aliyun.com/repository/public/",
    "huaweicloud": "https://repo.huaweicloud.com/repository/maven/",
    "nju": "https://repo.nju.edu.cn/maven/",
}
GRADLE_DISTRIBUTION_PROVIDERS = {"huaweicloud", "nju"}
NODE_DISTRIBUTION_TOOLS = {"fnm", "nvm"}
NODE_DISTRIBUTION_UPSTREAM = "nodejs--release-artifacts"
IOJS_RELEASE_UPSTREAM = "iojs--release-artifacts"
GO_PROXY_UPSTREAM = "goproxy--language-registry"
GO_PROXY_ACTIONABLE_PROVIDERS = {"aliyun"}
GO_PROXY_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/goproxy/",
    "huaweicloud": "https://repo.huaweicloud.com/repository/goproxy/",
    "nju": "https://repo.nju.edu.cn/go/",
}
RUBYGEMS_RUNTIME_UPSTREAM = "rubygems--language-registry"
RUBYGEMS_ACTIONABLE_PROVIDERS = {"aliyun", "nju", "tuna", "ustc"}
RUBYGEMS_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/rubygems/",
    "nju": "https://mirrors.nju.edu.cn/rubygems/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/rubygems/",
    "ustc": "https://mirrors.ustc.edu.cn/rubygems/",
}
RUBYGEMS_GEM_SHA256 = (
    "ba310c3d4f1cad46bb1ab20336b06669b1ff8f7c568d9cb9342b32a718547472"
)
BUNDLER_CLASSIC_GEMSPEC_SHA256 = (
    "19ecdd263f82ef67af89a112014f1905b4074d831b7ecfa67d64eb3fc6359229"
)
BUNDLER_ACTIONABLE_PROVIDERS = {"aliyun", "nju", "tuna", "ustc"}
BUNDLER_COMPACT_PROVIDERS = {"tuna", "ustc"}
CARGO_SPARSE_UPSTREAM = "crates.io-index--language-registry"
CARGO_SPARSE_ACTIONABLE_PROVIDERS = {"aliyun", "nju", "ustc"}
CARGO_SPARSE_INDEX_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/crates.io-index/",
    "nju": "https://mirrors.nju.edu.cn/crates.io-index/",
    "ustc": "https://mirrors.ustc.edu.cn/crates.io-index/",
}
CARGO_CRATE_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/crates/api/v1/crates/",
    "nju": "https://mirror.nju.edu.cn/crates.io/crates/",
    "ustc": "https://mirrors.ustc.edu.cn/crates.io/api/v1/crates/",
}
CARGO_CRATE_PATHS = {
    "aliyun": "/itoa/1.0.18/download",
    "nju": "/itoa/itoa-1.0.18.crate",
    "ustc": "/itoa/1.0.18/download",
}
CARGO_CRATE_SHA256 = (
    "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682"
)
RUSTUP_RUNTIME_UPSTREAM = "rust-toolchain--release-artifacts"
RUSTUP_ACTIONABLE_PROVIDERS = {"huaweicloud", "ustc"}
RUSTUP_DIST_ENDPOINTS = {
    "huaweicloud": "https://repo.huaweicloud.com/rustup/",
    "ustc": "https://mirrors.ustc.edu.cn/rust-static/",
}
RUSTUP_UPDATE_ENDPOINTS = {
    "huaweicloud": "https://repo.huaweicloud.com/rustup/rustup/",
    "ustc": "https://mirrors.ustc.edu.cn/rust-static/rustup/",
}
RUSTUP_MANIFEST_SHA256 = {
    "huaweicloud": "4a49195d2e5b4e5efd922e8a670ec40376c14b772233a46273ac9b8d5e810127",
    "ustc": "3f7d139b73bbbd0004ef6e58b430831c68cdad2b1f64ee2eb35d54c09199489a",
}
COMPOSER_RUNTIME_UPSTREAM = "packagist--language-registry"
COMPOSER_ACTIONABLE_PROVIDERS = {"huaweicloud"}
COMPOSER_REGISTRY_ENDPOINTS = {
    "huaweicloud": "https://repo.huaweicloud.com/repository/php/",
}
COMPOSER_SOURCE_ENDPOINT = "https://github.com/php-fig/log/"
COMPOSER_DIST_SHA256 = (
    "1e8dcf2df933fc3440b29146c5ca4e93ece51c5c7a9ac9653d926ec971c90892"
)
COMPOSER_SOURCE_SHA256 = (
    "c365225b9567800008110f8f7b2873bed86c5a0c40ce3ae399059ff3c22b778e"
)
NUGET_RUNTIME_UPSTREAM = "nuget--language-registry"
NUGET_ACTIONABLE_PROVIDERS = {"huaweicloud"}
NUGET_INDEX_ENDPOINT = "https://repo.huaweicloud.com/repository/nuget/v3/"
NUGET_REGISTRATION_ENDPOINT = (
    "https://repo.huaweicloud.com/artifactory/api/nuget/v3/"
    "nuget-remote/registration-semver2/"
)
NUGET_FLAT_ENDPOINT = (
    "https://repo.huaweicloud.com/artifactory/api/nuget/v3/nuget-remote/"
)
NUGET_NUPKG_SHA256 = (
    "7ff7a30aecc20302ace0de0473ac9fd91a2fae1053d278f48510cffb4dff232e"
)
CABAL_RUNTIME_UPSTREAM = "hackage--language-registry"
CABAL_ACTIONABLE_PROVIDERS = {"nju", "tuna", "ustc"}
CABAL_TARBALL_SHA256 = (
    "5e4b39da395656a59827b0280508aafdc70335798b50e5d6fd52596026251825"
)
CABAL_ROOT_SHA256 = (
    "f62e46cb51d4a499a8336894d7a46071b7e528135ad71614c7102c1de0aeeabc"
)
STACKAGE_RUNTIME_UPSTREAM = "stackage--language-registry"
STACK_HACKAGE_UPSTREAM = "hackage--language-registry"
STACK_ACTIONABLE_PROVIDERS = {"nju", "tuna", "ustc"}
STACKAGE_INDEX_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/stackage/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/stackage/",
    "ustc": "https://mirrors.ustc.edu.cn/stackage/",
}
STACKAGE_METADATA_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/github-raw/fpco/stackage-content/master/stack/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/github-raw/fpco/stackage-content/master/stack/",
    "ustc": "https://mirrors.ustc.edu.cn/stackage/stackage-content/stack/",
}
STACKAGE_ARTIFACT_ENDPOINTS = {
    "nju": "https://mirror.nju.edu.cn/stackage/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/stackage/",
    "ustc": "https://mirrors.ustc.edu.cn/stackage/",
}
STACK_SNAPSHOT_SHA256 = (
    "08bd13ce621b41a8f5e51456b38d5b46d7783ce114a50ab604d6bbab0d002146"
)
STACK_GLOBAL_HINTS_SHA256 = (
    "c26bcae5f588e370090d946cc79f57666c4cda31bb1f50c8ad4024f058289c96"
)
GHCUP_RUNTIME_UPSTREAM = "ghcup--release-artifacts"
GHCUP_ACTIONABLE_PROVIDERS = {"nju"}
GHCUP_METADATA_ENDPOINT = (
    "https://mirrors.nju.edu.cn/ghcup/yaml_v2/"
    "haskell/ghcup-metadata/master/"
)
GHCUP_ARTIFACT_ENDPOINT = "https://mirror.nju.edu.cn/ghcup/packages/"
GHCUP_METADATA_SHA256 = (
    "2e8eb78bafb9c8434c157923c1990542c9a969b0dec4b548537e4bd64d9b1e4d"
)
GHCUP_SIGNATURE_SHA256 = (
    "f0b2c00cef942acd720da81bfee57401ede4985cb239ccc04d6c6b05af7e1bee"
)
SBT_MAVEN_UPSTREAM = "maven--language-registry"
SBT_IVY_UPSTREAM = "sbt-plugins--language-registry"
SBT_ACTIONABLE_PROVIDERS = {"huaweicloud"}
SBT_MAVEN_ENDPOINT = "https://repo.huaweicloud.com/repository/maven/"
SBT_IVY_ENDPOINT = "https://repo.huaweicloud.com/repository/ivy/"
LEININGEN_CLOJARS_ENDPOINTS = {
    "huaweicloud": "https://repo.huaweicloud.com/artifactory/maven-clojars-remote/",
    "nju": "https://mirrors.nju.edu.cn/clojars/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/clojars/",
}
DART_PUB_RUNTIME_UPSTREAM = "dart-pub--language-registry"
DART_PUB_HOSTED_ENDPOINTS = {
    "sjtug": "https://mirror.sjtu.edu.cn/dart-pub/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/dart-pub/",
}
DART_PUB_ARTIFACT_ENDPOINTS = {
    "sjtug": "https://storage.flutter-io.cn/dartlang-pub-exported-api/latest/api/archives/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/dart-pub/packages/",
}
DART_PUB_RETRY_SHA256 = (
    "822e118d5b3aafed083109c72d5f484c6dc66707885e07c0fbcb8b986bba7efc"
)
FLUTTER_STORAGE_RUNTIME_UPSTREAM = "flutter--release-artifacts"
FLUTTER_STORAGE_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/flutter/",
    "sjtug": "https://mirror.sjtu.edu.cn/",
}
FLUTTER_RELEASE_IDENTITY = (
    "stable/3.47.2/d3b14c876900e553bc736ca19295fc09e3853e8e/"
    "a804b261645ef8c13eb3d5c44a5c2fb0340c5539"
)
FLUTTER_FRAMEWORK_VERSION = "3.47.2"
FLUTTER_FRAMEWORK_REVISION = "d3b14c876900e553bc736ca19295fc09e3853e8e"
FLUTTER_ENGINE_ARTIFACT_VERSION = "a804b261645ef8c13eb3d5c44a5c2fb0340c5539"
FLUTTER_X64_PROVENANCE_SHA256 = (
    "233a40905c350398edeb1eacad7ef43b68a8b84f0cf520201c27071dc3a70124"
)
FLUTTER_ARM64_PROVENANCE_SHA256 = (
    "d06ce9d4f7f1907523507c082e4511a0ce1d45a0853bde8e0aa0ab86b2d446cc"
)
CPAN_RUNTIME_UPSTREAM = "cpan--language-registry"
CPAN_TRY_TINY_SHA256 = (
    "ef2d6cab0bad18e3ab1c4e6125cc5f695c7e459899f512451c8fa3ef83fa7fc0"
)
CRAN_RUNTIME_UPSTREAM = "cran--language-registry"
CRAN_DIGEST_DESCRIPTION_SHA256 = (
    "07dcde79e44828236433e7de97be2e49b8f4e689b262160fff1a76b300a71043"
)
CRAN_DIGEST_ARCHIVE_SHA256 = (
    "8bf048b49b2d17077138fae758bda56bbd53278d9437f2fdeaedf979c90a13c9"
)
PYENV_RUNTIME_UPSTREAM = "python-releases--release-artifacts"
PYENV_ENDPOINTS = {
    "huaweicloud": "https://repo.huaweicloud.com/python/",
    "nju": "https://mirrors.nju.edu.cn/python/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/python/",
}
PYENV_RELEASE_IDENTITY = (
    "3.14.7/3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81"
)
PYENV_ARCHIVE_SHA256 = (
    "3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81"
)
PYENV_SIGNATURE_SHA256 = (
    "ae37dfde764ccb50a8ad649940bdeba47c93ef99be2501db9759894b7c2b5b9d"
)
BAZEL_RELEASE_UPSTREAM = "bazel--release-artifacts"
BAZEL_APT_UPSTREAM = "bazel-apt--repository-metadata"
BAZEL_VERSION = "9.2.0"
BAZEL_HUAWEI_ENDPOINT = "https://repo.huaweicloud.com/bazel/"
BAZEL_APT_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/bazel-apt/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/bazel-apt/",
}
BAZEL_X64_SHA256 = (
    "7668a95db1250f12c40407251e4e203b4ec8bf39bc495d2f485b2d8c99048694"
)
BAZEL_ARM64_SHA256 = (
    "049dd21f40ad979db11c3ee68c96a42ce75f1185e69ac61ab20de1501427a410"
)
BAZEL_X64_CHECKSUM_FILE_SHA256 = (
    "b1703900c78dfc49f1f332aeee87217fe49741035c086d6a2131889a8df92c00"
)
BAZEL_ARM64_CHECKSUM_FILE_SHA256 = (
    "e4e30d2abf88528f8046ffeeb2b1fd4e4abdc42c7db1f4de84f85856f93a1d80"
)
BAZEL_DEB_SHA256 = (
    "7c54a526c195f1b1a404372eb05cf1d7a5ede898bf6f8e791febd0f25bff8e0b"
)
OPAM_REPOSITORY_UPSTREAM = "opam-repository--git-mirror"
OPAM_CACHE_UPSTREAM = "opam-cache--binary-cache"
OPAM_REPOSITORY_ENDPOINT = "https://mirrors.nju.edu.cn/git/opam-repository.git"
OPAM_CACHE_ENDPOINT = "https://mirror.sjtu.edu.cn/opam-cache/"
OPAM_REPOSITORY_REVISION = "3884cbee403b0a4e2211b428d54928e6e69434cc"
OPAM_CACHE_SHA256 = (
    "61f0b75950614ac5378c6ec0d822cce6463402d919d5810b736fc46522b3a73e"
)
JULIA_RUNTIME_UPSTREAM = "julia--language-registry"
JULIA_NJU_ENDPOINT = "https://mirrors.nju.edu.cn/julia/"
JULIA_GENERAL_REGISTRY_UUID = "23338594-aafe-5451-b93e-139f81909106"
JULIA_GENERAL_REGISTRY_TREE = "c6e23649d0bda5ca27b700da3c569fe000639859"
JULIA_EXAMPLE_UUID = "7876af07-990d-54b4-ab0e-23690620f79a"
JULIA_EXAMPLE_TREE = "e1f0e1a832ccd8e97d6d0348dec33ee139a5aeaf"
JULIA_EXAMPLE_SOURCE_SHA256 = (
    "87dd4f0b8977bbdc95ce08fa896d635aafaa3e65ddd06af5e9a2c3eaa432cad8"
)
JULIA_HELLO_UUID = "dca1746e-5efc-54fc-8249-22745bc95a49"
JULIA_HELLO_TREE = "370059fde9f8b780a2335dcbcf05ba224053d45f"
JULIA_HELLO_SOURCE_SHA256 = (
    "1aec74638a21b3890c58763ff1bbe05ec26d48a567f5b5d87c7e68a2a7d9f51c"
)
JULIA_HELLO_ARTIFACTS = {
    "x86_64": (
        "c8aa41cab66118db2387696eba33856344935ce3",
        "ba2e68bc72a3e6cadefb8ff892bc7c76289b06b7606cc4d1f2613ce917c5425f",
    ),
    "arm64": (
        "a2368a2caae8074bdda6e71d51acb43553fcd076",
        "7b56d8aa960fe3e540f945126c942f4be1bcb1da66f4fd530450a70efcd76955",
    ),
}
KUBERNETES_IMAGES_UPSTREAM = "registry.k8s.io--container-registry"
KUBERNETES_IMAGES_ENDPOINT = "https://k8s.nju.edu.cn/"
OCI_MANIFEST_ACCEPT = (
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.oci.image.manifest.v1+json"
)
KUBERNETES_PACKAGES_UPSTREAM = "kubernetes--repository-metadata"
KUBERNETES_PACKAGES_ACTIONABLE_PROVIDERS = {"nju", "tuna", "ustc"}
KUBERNETES_PACKAGES_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/kubernetes/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/kubernetes/",
    "ustc": "https://mirrors.ustc.edu.cn/kubernetes/",
}
KUBERNETES_DEB_BASELINE = {
    "amd64": "amd64/kubeadm_1.35.8-1.1_amd64.deb",
    "arm64": "arm64/kubeadm_1.35.8-1.1_arm64.deb",
}
KUBERNETES_RPM_BASELINE = {
    "x86_64": "x86_64/kubeadm-1.35.8-150500.1.1.x86_64.rpm",
    "aarch64": "aarch64/kubeadm-1.35.8-150500.1.1.aarch64.rpm",
}
DOCKER_CE_UPSTREAM = "docker-ce--repository-metadata"
DOCKER_CE_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/docker-ce/",
    "huaweicloud": "https://repo.huaweicloud.com/docker-ce/",
    "nju": "https://mirrors.nju.edu.cn/docker-ce/",
    "sjtug": "https://mirror.sjtu.edu.cn/docker-ce/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/docker-ce/",
    "ustc": "https://mirrors.ustc.edu.cn/docker-ce/",
}
ELPA_ARCHIVES = {
    "gnu": ("gnu-elpa", "a68-mode-1.3.tar"),
    "nongnu": ("nongnu-elpa", "adoc-mode-0.9.0.tar"),
    "melpa": ("melpa", "dash-20260221.1346.tar"),
}
ROS1_UPSTREAM = "ros1-packages--repository-metadata"
ROS1_ACTIONABLE_PROVIDERS = {"huaweicloud", "nju", "sjtug", "tuna", "ustc"}
ROS1_ENDPOINTS = {
    "huaweicloud": "https://repo.huaweicloud.com/ros/",
    "nju": "https://mirrors.nju.edu.cn/ros/",
    "sjtug": "https://mirror.sjtu.edu.cn/ros/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/ros/",
    "ustc": "https://mirrors.ustc.edu.cn/ros/",
}
ROS1_BASELINE_PACKAGES = {
    "amd64": "ubuntu/pool/main/r/ros-noetic-ros-base/ros-noetic-ros-base_1.5.0-1focal.20250521.010531_amd64.deb",
    "arm64": "ubuntu/pool/main/r/ros-noetic-ros-base/ros-noetic-ros-base_1.5.0-1focal.20250521.024603_arm64.deb",
}
MYSQL_UPSTREAM = "mysql-community--repository-metadata"
MYSQL_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/mysql/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/mysql/",
    "ustc": "https://mirrors.ustc.edu.cn/mysql-repo/",
}
MYSQL_APT_REPOSITORY_VERSIONS = [
    "debian-bookworm-8.4-lts-amd64",
    "ubuntu-jammy-8.4-lts-amd64",
    "ubuntu-noble-8.4-lts-amd64",
]
MYSQL_RPM_REPOSITORY_VERSIONS = [
    "el-9-8.4-lts-x86_64",
    "el-9-8.4-lts-aarch64",
]
MONGODB_UPSTREAM = "mongodb-community--repository-metadata"
MONGODB_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/mongodb/",
    "huaweicloud": "https://repo.huaweicloud.com/mongodb/",
    "nju": "https://mirrors.nju.edu.cn/mongodb/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/mongodb/",
}
MONGODB_APT_REPOSITORY_VERSIONS = [
    "debian-bookworm-8.0-amd64",
    "ubuntu-jammy-8.0-amd64",
    "ubuntu-jammy-8.0-arm64",
    "ubuntu-noble-8.0-amd64",
    "ubuntu-noble-8.0-arm64",
]
MONGODB_RPM_REPOSITORY_VERSIONS = [
    "el-9-8.0-x86_64",
]
INFLUXDB_UPSTREAM = "influxdata-packages--repository-metadata"
INFLUXDB_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/influxdata/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/influxdata/",
    "ustc": "https://mirrors.ustc.edu.cn/influxdata/",
}
INFLUXDB_APT_REPOSITORY_VERSIONS = [
    f"{family}-stable-2-{architecture}"
    for family in ["debian", "ubuntu"]
    for architecture in ["amd64", "arm64"]
]
INFLUXDB_RPM_REPOSITORY_VERSIONS = ["el-9-stable-2-x86_64"]
MARIADB_UPSTREAM = "mariadb-packages--repository-metadata"
MARIADB_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/mariadb/",
    "huaweicloud": "https://repo.huaweicloud.com/mariadb/",
    "nju": "https://mirrors.nju.edu.cn/mariadb/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/mariadb/",
    "ustc": "https://mirrors.ustc.edu.cn/mariadb/",
}
MARIADB_APT_REPOSITORY_VERSIONS = [
    f"{family}-{release}-11.8-{architecture}"
    for family, release in [("debian", "bookworm"), ("ubuntu", "jammy"), ("ubuntu", "noble")]
    for architecture in ["amd64", "arm64"]
]
MARIADB_RPM_REPOSITORY_VERSIONS = ["el-9-11.8-x86_64", "el-9-11.8-aarch64"]
POSTGRESQL_UPSTREAM = "postgresql-pgdg--repository-metadata"
POSTGRESQL_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/postgresql/",
    "huaweicloud": "https://repo.huaweicloud.com/postgresql/",
    "nju": "https://mirrors.nju.edu.cn/postgresql/",
}
POSTGRESQL_APT_REPOSITORY_VERSIONS = [
    f"{family}-{release}-17-{architecture}"
    for family, release in [("debian", "bookworm"), ("ubuntu", "jammy"), ("ubuntu", "noble")]
    for architecture in ["amd64", "arm64"]
]
POSTGRESQL_RPM_REPOSITORY_VERSIONS = ["el-9-17-x86_64", "el-9-17-aarch64"]
ELASTICSTACK_UPSTREAM = "elastic-stack--repository-metadata"
ELASTICSTACK_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/elasticstack/",
    "nju": "https://mirrors.nju.edu.cn/elasticstack/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/elasticstack/",
}
ELASTICSTACK_APT_REPOSITORY_VERSIONS = ["apt-stable-9.x-amd64"]
ELASTICSTACK_RPM_REPOSITORY_VERSIONS = [
    "rpm-stable-9.x-x86_64",
    "rpm-stable-9.x-aarch64",
]
GRAFANA_UPSTREAM = "grafana-packages--repository-metadata"
GRAFANA_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/grafana/",
    "nju": "https://mirrors.nju.edu.cn/grafana/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/grafana/",
}
GRAFANA_APT_REPOSITORY_VERSIONS = ["apt-stable-13-amd64", "apt-stable-13-arm64"]
ZABBIX_UPSTREAM = "zabbix-packages--repository-metadata"
ZABBIX_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/zabbix/",
    "huaweicloud": "https://repo.huaweicloud.com/zabbix/",
    "nju": "https://mirrors.nju.edu.cn/zabbix/",
}
ZABBIX_APT_REPOSITORY_VERSIONS = [
    f"{family}-{release}-7.4-{architecture}"
    for family, release in [("debian", "bookworm"), ("ubuntu", "jammy"), ("ubuntu", "noble")]
    for architecture in ["amd64", "arm64"]
]
ZABBIX_RPM_REPOSITORY_VERSIONS = ["el-9-7.4-x86_64", "el-9-7.4-aarch64"]
GITLAB_RUNNER_UPSTREAM = "gitlab-runner-packages--repository-metadata"
GITLAB_RUNNER_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/gitlab-runner/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/gitlab-runner/",
}
GITLAB_RUNNER_APT_REPOSITORY_VERSIONS = [
    f"{family}-{release}-19-{architecture}"
    for family, release in [("debian", "bookworm"), ("ubuntu", "jammy"), ("ubuntu", "noble")]
    for architecture in ["amd64", "arm64"]
]
GITLAB_RUNNER_RPM_REPOSITORY_VERSIONS = ["el-9-19-x86_64", "el-9-19-aarch64"]
CEPH_UPSTREAM = "ceph-release--repository-metadata"
CEPH_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/ceph/",
    "nju": "https://mirrors.nju.edu.cn/ceph/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/ceph/",
    "ustc": "https://mirrors.ustc.edu.cn/ceph/",
}
CEPH_APT_REPOSITORY_VERSIONS = [
    f"{family}-{release}-squid-{architecture}"
    for family, release in [("debian", "bookworm"), ("ubuntu", "jammy")]
    for architecture in ["amd64", "arm64"]
]
CEPH_RPM_REPOSITORY_VERSIONS = ["el-9-squid-x86_64", "el-9-squid-aarch64"]
NGINX_UPSTREAM = "nginx-org--repository-metadata"
NGINX_ENDPOINTS = {"nju": "https://mirrors.nju.edu.cn/nginx/"}
BIOCONDUCTOR_RUNTIME_UPSTREAM = "bioconductor--language-registry"
BIOCONDUCTOR_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/bioconductor/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/bioconductor/",
}
BIOCONDUCTOR_PACKAGES = [
    (
        "bioc",
        "BiocVersion",
        "3.23.1",
        "7a9fdd2f50e69facc752a8d8aede12cdc872d1fb59fea2355f3b499ace6864f4",
    ),
    (
        "data/annotation",
        "AHCytoBands",
        "0.99.1",
        "7bb5a06b5a8c0c2024f317ed0c58b048550ba9ed6cc64266c4afc03a24ec7d6b",
    ),
    (
        "data/experiment",
        "adductData",
        "1.28.0",
        "d61d9759ccb6d48798484a178e8bbc3c02c4bcd70e0c9cfb11b0354566aa3654",
    ),
]
TLMGR_RUNTIME_UPSTREAM = "ctan--language-registry"
TLMGR_ENDPOINTS = {
    "aliyun": "https://mirrors.aliyun.com/CTAN/systems/texlive/tlnet/",
    "huaweicloud": "https://repo.huaweicloud.com/CTAN/systems/texlive/tlnet/",
    "nju": "https://mirrors.nju.edu.cn/CTAN/systems/texlive/tlnet/",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/CTAN/systems/texlive/tlnet/",
}
TLMGR_INFRA_SHA256 = (
    "c762f37bd7d99cba6d5b0799697768cd26028583d2f81ca2f630d8f403a5c491"
)
TLMGR_PLATFORM_SHA256 = {
    "x86_64-linux": "168ce3c58aa35cafaa38e1defb3c3e26553473b35951d64bf54b5b2f00fd086f",
    "x86_64-linuxmusl": "bd32c86e19c774b7715824fceab5fe92ca33f6110e8d9d84fc62589249d581ba",
    "aarch64-linux": "01ad1b1457f65d4717b969b7ca27e08a559831d2c0658581b9659cf93c3c10ff",
}
HOMEBREW_GIT_UPSTREAM = "homebrew--git-mirror"
HOMEBREW_BOTTLES_UPSTREAM = "homebrew-bottles--binary-cache"
COCOAPODS_GIT_UPSTREAM = "cocoapods--git-mirror"
COCOAPODS_SPECS_ENDPOINTS = {
    "nju": "https://mirrors.nju.edu.cn/git/CocoaPods/Specs.git",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/git/CocoaPods/Specs.git",
}
MACPORTS_ROOTS = {
    "aliyun": "https://mirrors.aliyun.com/macports",
    "nju": "https://mirrors.nju.edu.cn/macports",
    "sjtug": "https://mirror.sjtu.edu.cn/macports",
}
SCOOP_BUCKET_ENDPOINTS = {
    "scoop-main--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-main.git",
    "scoop-extras--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-extras.git",
    "scoop-versions--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-versions.git",
    "scoop-java--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-java.git",
    "scoop-nerd-fonts--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-nerd-fonts.git",
    "scoop-nonportable--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-nonportable.git",
    "scoop-nirsoft--git-mirror": "https://mirrors.nju.edu.cn/git/scoop-nirsoft.git",
}
MSYS2_ROOTS = {
    "aliyun": "https://mirrors.aliyun.com/msys2",
    "huaweicloud": "https://repo.huaweicloud.com/msys2",
    "nju": "https://mirror.nju.edu.cn/msys2",
    "sjtug": "https://mirrors.sjtug.sjtu.edu.cn/msys2",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/msys2",
    "ustc": "https://mirrors.ustc.edu.cn/msys2",
}
WINGET_ROOTS = {
    "nju": "https://mirrors.nju.edu.cn/winget-source",
    "ustc": "https://mirrors.ustc.edu.cn/winget-source",
}
CYGWIN_ROOTS = {
    "huaweicloud": "https://repo.huaweicloud.com/cygwin",
    "tuna": "https://mirrors.tuna.tsinghua.edu.cn/sourceware/cygwin",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def upstream_id(family: str, content_type: str) -> str:
    return f"{family}--{content_type}"


def runtime_upstream_identity(
    entry: dict[str, Any], tool_id: str
) -> tuple[str, str]:
    if (
        tool_id == "cocoapods"
        and entry["provider_id"] in COCOAPODS_SPECS_ENDPOINTS
        and entry["raw_name"] == "CocoaPods"
    ):
        return "cocoapods", "git-mirror"
    if tool_id in {"sbt", "leiningen"} and entry["raw_name"] == "maven":
        return "maven", "language-registry"
    if tool_id == "sbt" and entry["raw_name"] in {"sbt", "ivy"}:
        return "sbt-plugins", "language-registry"
    if tool_id == "composer" and entry["raw_name"] in {"composer", "php"}:
        return "packagist", "language-registry"
    if tool_id == "rustup" and entry["raw_name"] in {"rust-static", "rustup"}:
        return "rust-toolchain", "release-artifacts"
    if tool_id == "gradle" and entry["raw_name"] in {"gradle", "gradle/distributions"}:
        return "gradle-distributions", "release-artifacts"
    if tool_id == "nvm" and entry["raw_name"] == "iojs":
        return "iojs", "release-artifacts"
    if tool_id == "go" and entry["raw_name"] in {"go", "goproxy"}:
        return "goproxy", "language-registry"
    if tool_id == "flutter" and entry["raw_name"] == "dart-pub":
        return "dart-pub", "language-registry"
    if tool_id == "flutter" and entry["raw_name"] in {"flutter", "flutter_infra"}:
        return "flutter", "release-artifacts"
    if tool_id == "pyenv" and entry["raw_name"] in {"python", "python-release"}:
        return "python-releases", "release-artifacts"
    if tool_id == "bazel" and entry["raw_name"] == "bazel":
        return "bazel", "release-artifacts"
    if tool_id == "bazel" and entry["raw_name"] == "bazel-apt":
        return "bazel-apt", "repository-metadata"
    if tool_id == "opam" and entry["raw_name"] == "opam-cache":
        return "opam-cache", "binary-cache"
    if tool_id == "kubernetes-images" and entry["raw_name"] == "k8s":
        return "registry.k8s.io", "container-registry"
    if tool_id == "containerd" and entry["raw_name"] == "k8s":
        return "registry.k8s.io", "container-registry"
    if tool_id == "ros" and entry["raw_name"] == "ros":
        return "ros1-packages", "repository-metadata"
    if tool_id == "mysql" and entry["raw_name"].startswith(("mysql", "mysql-repo")):
        return "mysql-community", "repository-metadata"
    if tool_id == "mongodb" and entry["raw_name"].startswith("mongodb"):
        return "mongodb-community", "repository-metadata"
    if tool_id == "influxdb" and entry["raw_name"].startswith("influxdata"):
        return "influxdata-packages", "repository-metadata"
    if tool_id == "mariadb" and entry["raw_name"].startswith("mariadb"):
        return "mariadb-packages", "repository-metadata"
    if tool_id == "postgresql" and entry["raw_name"].startswith("postgresql"):
        return "postgresql-pgdg", "repository-metadata"
    if tool_id == "elasticstack" and entry["raw_name"].startswith("elasticstack"):
        return "elastic-stack", "repository-metadata"
    if tool_id == "grafana" and entry["raw_name"].startswith("grafana"):
        return "grafana-packages", "repository-metadata"
    if tool_id == "zabbix" and entry["raw_name"].startswith("zabbix"):
        return "zabbix-packages", "repository-metadata"
    if tool_id == "gitlab-runner" and entry["raw_name"].startswith("gitlab-runner"):
        return "gitlab-runner-packages", "repository-metadata"
    if tool_id == "ceph" and entry["raw_name"].startswith("ceph"):
        return "ceph-release", "repository-metadata"
    if tool_id == "nginx" and entry["raw_name"].startswith("nginx"):
        return "nginx-org", "repository-metadata"
    if tool_id == "podman-registry" and entry["raw_name"] in {"gcr", "ghcr", "quay"}:
        return f"{entry['raw_name']}.io", "container-registry"
    return entry["normalized_upstream"], entry["content_type"]


def tool_scopes(tool_id: str) -> list[str]:
    if tool_id == "homebrew":
        return ["user"]
    if tool_id == "cocoapods":
        return ["user", "project"]
    if tool_id == "scoop":
        return ["user"]
    if tool_id in {"bundler", "stack"}:
        return ["user", "project"]
    if tool_id in NODE_DISTRIBUTION_TOOLS or tool_id in {
        "cargo",
        "cabal",
        "composer",
        "go",
        "ghcup",
        "nuget",
        "rubygems",
        "rustup",
    }:
        return ["user"]
    if tool_id in {"flatpak", "nix", "nix-macos"}:
        return ["system", "user"]
    if tool_id == "pip":
        return ["system", "user", "site"]
    if tool_id == "npm":
        return ["system", "user", "project"]
    if tool_id == "pdm":
        return ["user", "project"]
    if tool_id == "pnpm":
        return ["user"]
    if tool_id == "poetry":
        return ["project"]
    if tool_id == "uv":
        return ["user", "project"]
    if tool_id == "gradle":
        return ["user", "project"]
    if tool_id == "tlmgr":
        return ["system", "user"]
    if tool_id == "flutter":
        return ["user"]
    if tool_id == "cpan":
        return ["user"]
    if tool_id == "cran":
        return ["user"]
    if tool_id == "pyenv":
        return ["user"]
    if tool_id == "bazel":
        return ["system", "user"]
    if tool_id == "opam":
        return ["user"]
    if tool_id == "julia":
        return ["user"]
    if tool_id == "kubernetes-images":
        return ["user"]
    if tool_id == "podman-registry":
        return ["system", "user"]
    if tool_id == "kubernetes-packages":
        return ["system"]
    if tool_id == "docker-ce":
        return ["system"]
    if tool_id == "elpa":
        return ["user"]
    if tool_id == "ros":
        return ["system"]
    if tool_id in {
        "maven",
        "sbt",
        "leiningen",
        "dart-pub",
        "bioconductor",
    }:
        return ["user"]
    if tool_id == "yarn":
        return ["user", "project"]
    if tool_id == "conda":
        return ["user"]
    if tool_id in SYSTEM_TOOLS:
        return ["system"]
    if tool_id in USER_ONLY_TOOLS:
        return ["user", "environment"]
    return ["user", "project", "environment"]


def candidate_compatibility(entry: dict[str, Any]) -> dict[str, Any]:
    source = entry["compatibility"]
    operating_systems = source["operating_systems"]
    environments = []
    if "linux" in operating_systems:
        environments.extend(["host", "container"])
    if any(os_name in operating_systems for os_name in ("macos", "windows")):
        environments.append("host")
    return {
        "operating_systems": operating_systems,
        "architectures": source["architectures"],
        "environments": sorted(set(environments)),
        "distributions": [
            {"id": distribution, "versions": source["versions"], "codenames": []}
            for distribution in source["distributions"]
        ],
        "repository_versions": source["versions"],
    }


def candidate_endpoints(
    entry: dict[str, Any], tool_id: str, upstream_key: str
) -> list[dict[str, str]]:
    if tool_id == "cygwin" and entry["provider_id"] in CYGWIN_ROOTS:
        endpoint = CYGWIN_ROOTS[entry["provider_id"]]
        return [
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if tool_id == "winget" and entry["provider_id"] in WINGET_ROOTS:
        endpoint = WINGET_ROOTS[entry["provider_id"]]
        return [
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if tool_id == "msys2" and entry["provider_id"] in MSYS2_ROOTS:
        endpoint = MSYS2_ROOTS[entry["provider_id"]]
        return [
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if tool_id == "scoop" and upstream_key in SCOOP_BUCKET_ENDPOINTS:
        return [
            {
                "role": "git",
                "protocol": "https",
                "url": SCOOP_BUCKET_ENDPOINTS[upstream_key],
            }
        ]
    if tool_id == "macports" and entry["provider_id"] in MACPORTS_ROOTS:
        root = MACPORTS_ROOTS[entry["provider_id"]]
        return [
            {
                "role": "metadata",
                "protocol": "https",
                "url": f"{root}/release/tarballs/",
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": f"{root}/packages/",
            },
        ]
    if (
        tool_id == "cocoapods"
        and upstream_key == COCOAPODS_GIT_UPSTREAM
        and entry["provider_id"] in COCOAPODS_SPECS_ENDPOINTS
    ):
        return [
            {
                "role": "git",
                "protocol": "https",
                "url": COCOAPODS_SPECS_ENDPOINTS[entry["provider_id"]],
            }
        ]
    if (
        tool_id == "homebrew"
        and entry["provider_id"] == "ustc"
        and upstream_key == HOMEBREW_GIT_UPSTREAM
    ):
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": "git", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if (
        tool_id == "homebrew"
        and entry["provider_id"] == "ustc"
        and upstream_key == HOMEBREW_BOTTLES_UPSTREAM
    ):
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if tool_id == "cpan" and upstream_key == CPAN_RUNTIME_UPSTREAM:
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if tool_id == "cran" and upstream_key == CRAN_RUNTIME_UPSTREAM:
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "pyenv"
        and upstream_key == PYENV_RUNTIME_UPSTREAM
        and entry["provider_id"] in PYENV_ENDPOINTS
        and entry["raw_name"] == "python"
    ):
        endpoint = PYENV_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if tool_id == "bazel" and upstream_key == BAZEL_RELEASE_UPSTREAM:
        return [
            {"role": role, "protocol": "https", "url": BAZEL_HUAWEI_ENDPOINT}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "bazel"
        and upstream_key == BAZEL_APT_UPSTREAM
        and entry["provider_id"] in BAZEL_APT_ENDPOINTS
    ):
        endpoint = BAZEL_APT_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "opam"
        and upstream_key == OPAM_REPOSITORY_UPSTREAM
        and entry["public_endpoints"][0]["url"].rstrip("/")
        == OPAM_REPOSITORY_ENDPOINT
    ):
        return [
            {"role": role, "protocol": "https", "url": OPAM_REPOSITORY_ENDPOINT}
            for role in ["index", "metadata", "artifacts"]
        ]
    if tool_id == "opam" and upstream_key == OPAM_CACHE_UPSTREAM:
        return [
            {"role": role, "protocol": "https", "url": OPAM_CACHE_ENDPOINT}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "julia"
        and upstream_key == JULIA_RUNTIME_UPSTREAM
        and entry["provider_id"] == "nju"
        and entry["raw_name"] == "julia"
    ):
        return [
            {"role": role, "protocol": "https", "url": JULIA_NJU_ENDPOINT}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "kubernetes-images"
        and upstream_key == KUBERNETES_IMAGES_UPSTREAM
        and entry["provider_id"] == "nju"
        and entry["raw_name"] == "k8s"
    ):
        return [
            {
                "role": "registry",
                "protocol": "https",
                "url": KUBERNETES_IMAGES_ENDPOINT,
            }
        ]
    if (
        tool_id == "containerd"
        and upstream_key == KUBERNETES_IMAGES_UPSTREAM
        and entry["provider_id"] == "nju"
        and entry["raw_name"] == "k8s"
    ):
        return [
            {
                "role": "registry",
                "protocol": "https",
                "url": KUBERNETES_IMAGES_ENDPOINT,
            }
        ]
    if (
        tool_id == "kubernetes-packages"
        and upstream_key == KUBERNETES_PACKAGES_UPSTREAM
        and entry["provider_id"] in KUBERNETES_PACKAGES_ACTIONABLE_PROVIDERS
        and entry["raw_name"] == "kubernetes"
    ):
        endpoint = KUBERNETES_PACKAGES_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if (
        tool_id == "docker-ce"
        and upstream_key == DOCKER_CE_UPSTREAM
        and entry["provider_id"] in DOCKER_CE_ENDPOINTS
        and entry["raw_name"] == "docker-ce"
    ):
        endpoint = DOCKER_CE_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if tool_id == "elpa" and entry["raw_name"].startswith("elpa/"):
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if (
        tool_id == "ros"
        and upstream_key == ROS1_UPSTREAM
        and entry["provider_id"] in ROS1_ACTIONABLE_PROVIDERS
        and entry["raw_name"] == "ros"
    ):
        endpoint = ROS1_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if (
        tool_id == "mysql"
        and upstream_key == MYSQL_UPSTREAM
        and entry["provider_id"] in MYSQL_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = MYSQL_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if (
        tool_id == "mongodb"
        and upstream_key == MONGODB_UPSTREAM
        and entry["provider_id"] in MONGODB_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = MONGODB_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if (
        tool_id == "influxdb"
        and upstream_key == INFLUXDB_UPSTREAM
        and entry["provider_id"] in INFLUXDB_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = INFLUXDB_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "packages"]
        ]
    if (
        tool_id == "mariadb"
        and upstream_key == MARIADB_UPSTREAM
        and entry["provider_id"] in MARIADB_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = MARIADB_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "postgresql"
        and upstream_key == POSTGRESQL_UPSTREAM
        and entry["provider_id"] in POSTGRESQL_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = POSTGRESQL_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "elasticstack"
        and upstream_key == ELASTICSTACK_UPSTREAM
        and entry["provider_id"] in ELASTICSTACK_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = ELASTICSTACK_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "grafana"
        and upstream_key == GRAFANA_UPSTREAM
        and entry["provider_id"] in GRAFANA_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        endpoint = GRAFANA_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "zabbix"
        and upstream_key == ZABBIX_UPSTREAM
        and entry["provider_id"] in ZABBIX_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = ZABBIX_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "gitlab-runner"
        and upstream_key == GITLAB_RUNNER_UPSTREAM
        and entry["provider_id"] in GITLAB_RUNNER_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = GITLAB_RUNNER_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "ceph"
        and upstream_key == CEPH_UPSTREAM
        and entry["provider_id"] in CEPH_ENDPOINTS
        and entry["raw_name"].endswith(("-apt-runtime", "-rpm-runtime"))
    ):
        endpoint = CEPH_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "nginx"
        and upstream_key == NGINX_UPSTREAM
        and entry["provider_id"] in NGINX_ENDPOINTS
        and entry["raw_name"].endswith("-runtime")
    ):
        endpoint = NGINX_ENDPOINTS[entry["provider_id"]]
        return [{"role": role, "protocol": "https", "url": endpoint} for role in ["index", "metadata", "packages"]]
    if (
        tool_id == "flutter"
        and upstream_key == FLUTTER_STORAGE_RUNTIME_UPSTREAM
        and (
            (entry["provider_id"] == "nju" and entry["raw_name"] == "flutter")
            or (
                entry["provider_id"] == "sjtug"
                and entry["raw_name"] == "flutter_infra"
            )
        )
    ):
        endpoint = FLUTTER_STORAGE_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "tlmgr"
        and upstream_key == TLMGR_RUNTIME_UPSTREAM
        and entry["raw_name"] == "CTAN"
        and entry["provider_id"] in TLMGR_ENDPOINTS
    ):
        endpoint = TLMGR_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "bioconductor"
        and upstream_key == BIOCONDUCTOR_RUNTIME_UPSTREAM
        and entry["raw_name"] == "bioconductor"
        and entry["provider_id"] in BIOCONDUCTOR_ENDPOINTS
    ):
        endpoint = BIOCONDUCTOR_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": role, "protocol": "https", "url": endpoint}
            for role in ["index", "metadata", "artifacts"]
        ]
    if (
        tool_id == "sbt"
        and upstream_key in {SBT_MAVEN_UPSTREAM, SBT_IVY_UPSTREAM}
        and entry["provider_id"] in SBT_ACTIONABLE_PROVIDERS
        and entry["raw_name"] in {"maven", "sbt"}
    ):
        endpoint = (
            SBT_MAVEN_ENDPOINT
            if upstream_key == SBT_MAVEN_UPSTREAM
            else SBT_IVY_ENDPOINT
        )
        return [
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if tool_id == "leiningen" and entry["raw_name"] in {"maven", "clojars"}:
        endpoint = (
            MAVEN_REGISTRY_ENDPOINTS.get(entry["provider_id"])
            if entry["raw_name"] == "maven"
            else LEININGEN_CLOJARS_ENDPOINTS.get(entry["provider_id"])
        )
        if endpoint:
            return [
                {"role": "index", "protocol": "https", "url": endpoint},
                {"role": "metadata", "protocol": "https", "url": endpoint},
                {"role": "artifacts", "protocol": "https", "url": endpoint},
            ]
    if (
        tool_id in {"dart-pub", "flutter"}
        and upstream_key == DART_PUB_RUNTIME_UPSTREAM
        and entry["raw_name"] == "dart-pub"
        and entry["provider_id"] in DART_PUB_HOSTED_ENDPOINTS
    ):
        hosted = DART_PUB_HOSTED_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": "index", "protocol": "https", "url": hosted},
            {"role": "metadata", "protocol": "https", "url": hosted},
            {
                "role": "artifacts",
                "protocol": "https",
                "url": DART_PUB_ARTIFACT_ENDPOINTS[entry["provider_id"]],
            },
        ]
    if (
        tool_id == "ghcup"
        and upstream_key == GHCUP_RUNTIME_UPSTREAM
        and entry["provider_id"] in GHCUP_ACTIONABLE_PROVIDERS
    ):
        return [
            {
                "role": "metadata",
                "protocol": "https",
                "url": GHCUP_METADATA_ENDPOINT,
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": GHCUP_ARTIFACT_ENDPOINT,
            },
        ]
    if (
        tool_id == "stack"
        and upstream_key == STACKAGE_RUNTIME_UPSTREAM
        and entry["provider_id"] in STACK_ACTIONABLE_PROVIDERS
    ):
        provider = entry["provider_id"]
        return [
            {
                "role": "index",
                "protocol": "https",
                "url": STACKAGE_INDEX_ENDPOINTS[provider],
            },
            {
                "role": "metadata",
                "protocol": "https",
                "url": STACKAGE_METADATA_ENDPOINTS[provider],
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": STACKAGE_ARTIFACT_ENDPOINTS[provider],
            },
        ]
    if (
        tool_id == "stack"
        and upstream_key == STACK_HACKAGE_UPSTREAM
        and entry["provider_id"] in STACK_ACTIONABLE_PROVIDERS
    ):
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if (
        tool_id == "bundler"
        and upstream_key == RUBYGEMS_RUNTIME_UPSTREAM
        and entry["provider_id"] in BUNDLER_ACTIONABLE_PROVIDERS
    ):
        endpoint = RUBYGEMS_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if (
        tool_id == "cabal"
        and upstream_key == CABAL_RUNTIME_UPSTREAM
        and entry["provider_id"] in CABAL_ACTIONABLE_PROVIDERS
    ):
        endpoint = entry["public_endpoints"][0]["url"]
        return [
            {"role": "metadata", "protocol": "https", "url": endpoint},
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if (
        tool_id == "nuget"
        and upstream_key == NUGET_RUNTIME_UPSTREAM
        and entry["provider_id"] in NUGET_ACTIONABLE_PROVIDERS
    ):
        return [
            {"role": "index", "protocol": "https", "url": NUGET_INDEX_ENDPOINT},
            {
                "role": "metadata",
                "protocol": "https",
                "url": NUGET_REGISTRATION_ENDPOINT,
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": NUGET_FLAT_ENDPOINT,
            },
        ]
    if (
        tool_id == "composer"
        and upstream_key == COMPOSER_RUNTIME_UPSTREAM
        and entry["provider_id"] in COMPOSER_ACTIONABLE_PROVIDERS
    ):
        endpoint = COMPOSER_REGISTRY_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
            {
                "role": "git",
                "protocol": "https",
                "url": COMPOSER_SOURCE_ENDPOINT,
            },
        ]
    if (
        tool_id == "rustup"
        and upstream_key == RUSTUP_RUNTIME_UPSTREAM
        and entry["provider_id"] in RUSTUP_ACTIONABLE_PROVIDERS
    ):
        provider = entry["provider_id"]
        return [
            {
                "role": "releases",
                "protocol": "https",
                "url": RUSTUP_DIST_ENDPOINTS[provider],
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": RUSTUP_UPDATE_ENDPOINTS[provider],
            },
        ]
    if (
        tool_id == "cargo"
        and upstream_key == CARGO_SPARSE_UPSTREAM
        and entry["provider_id"] in CARGO_SPARSE_ACTIONABLE_PROVIDERS
    ):
        provider = entry["provider_id"]
        return [
            {
                "role": "index",
                "protocol": "https",
                "url": CARGO_SPARSE_INDEX_ENDPOINTS[provider],
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": CARGO_CRATE_ENDPOINTS[provider],
            },
        ]
    if (
        tool_id == "rubygems"
        and upstream_key == RUBYGEMS_RUNTIME_UPSTREAM
        and entry["provider_id"] in RUBYGEMS_ACTIONABLE_PROVIDERS
    ):
        endpoint = RUBYGEMS_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if (
        tool_id == "go"
        and upstream_key == GO_PROXY_UPSTREAM
        and entry["provider_id"] in GO_PROXY_ACTIONABLE_PROVIDERS
    ):
        return [
            {
                "role": "index",
                "protocol": "https",
                "url": GO_PROXY_ENDPOINTS[entry["provider_id"]],
            }
        ]
    if (
        tool_id in NODE_DISTRIBUTION_TOOLS
        and upstream_key == NODE_DISTRIBUTION_UPSTREAM
    ) or (tool_id == "nvm" and upstream_key == IOJS_RELEASE_UPSTREAM):
        return [
            {
                "role": "releases",
                "protocol": item["protocol"],
                "url": item["url"],
            }
            for item in entry["public_endpoints"]
        ]
    if (
        tool_id in {"gradle", "maven"}
        and upstream_key == GRADLE_MAVEN_UPSTREAM
        and entry["raw_name"] == "maven"
        and entry["provider_id"] in MAVEN_REGISTRY_ENDPOINTS
    ):
        endpoint = MAVEN_REGISTRY_ENDPOINTS[entry["provider_id"]]
        return [
            {"role": "index", "protocol": "https", "url": endpoint},
            {"role": "artifacts", "protocol": "https", "url": endpoint},
        ]
    if tool_id == "gradle" and upstream_key == GRADLE_DISTRIBUTION_UPSTREAM:
        return [
            {
                "role": "releases",
                "protocol": item["protocol"],
                "url": item["url"],
            }
            for item in entry["public_endpoints"]
        ]
    if (
        tool_id in {"pdm", "poetry", "uv"}
        and upstream_key == PIP_RUNTIME_UPSTREAM
        and entry["raw_name"] in PIP_RUNTIME_ENTRY_NAMES
    ):
        provider = entry["provider_id"]
        return [
            {
                "role": "index",
                "protocol": "https",
                "url": PIP_SIMPLE_ENDPOINTS[provider],
            },
            {
                "role": "artifacts",
                "protocol": "https",
                "url": PDM_ARTIFACT_ENDPOINTS[provider],
            },
        ]
    role = ROLE_BY_CONTENT[entry["content_type"]]
    endpoints = []
    for item in entry["public_endpoints"]:
        url = item["url"]
        if tool_id in {"nix", "nix-macos"} and upstream_key == NIX_RUNTIME_UPSTREAM:
            url = url.replace("nix-channels%2Fstore", "nix-channels/store")
            if not url.rstrip("/").endswith("/store"):
                url = url.rstrip("/") + "/store/"
        if (
            tool_id == "pip"
            and upstream_key == PIP_RUNTIME_UPSTREAM
            and entry["raw_name"] in PIP_RUNTIME_ENTRY_NAMES
        ):
            url = PIP_SIMPLE_ENDPOINTS[entry["provider_id"]]
        endpoints.append({"role": role, "protocol": item["protocol"], "url": url})
    return endpoints


def candidate_probe(entry: dict[str, Any]) -> list[dict[str, Any]]:
    validation = entry["validation"]
    if validation["status"] != "passed":
        return []
    probe_url = validation["probe_url"]
    bases = sorted(
        (
            endpoint["url"]
            for endpoint in entry["public_endpoints"]
            if probe_url.startswith(endpoint["url"])
        ),
        key=len,
        reverse=True,
    )
    if not bases:
        return []
    path = "/" + probe_url.removeprefix(bases[0]).lstrip("/")
    role = ROLE_BY_CONTENT[entry["content_type"]]
    return [
        {
            "endpoint_role": role,
            "method": "get",
            "path": path,
            "expected_status": [200, 206],
            "expected_content_type": "application/octet-stream",
            "contains": "-----BEGIN PGP SIGNED MESSAGE-----",
        }
    ]


def runtime_properties(
    entry: dict[str, Any], tool_id: str, upstream_key: str
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    compatibility = candidate_compatibility(entry)
    delivery_mode = (
        "proxy"
        if entry["content_type"] in {"release-proxy", "raw-proxy"}
        else "unknown"
    )
    probes = candidate_probe(entry)
    if tool_id == "cygwin":
        compatibility["operating_systems"] = []
        compatibility["architectures"] = []
        compatibility["environments"] = []
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "unknown"
        probes = []
        if entry["provider_id"] in CYGWIN_ROOTS:
            compatibility["operating_systems"] = ["windows"]
            compatibility["architectures"] = ["x86_64"]
            compatibility["environments"] = ["host"]
            delivery_mode = "mirror"
            probes = [
                {
                    "endpoint_role": "metadata",
                    "method": "head",
                    "path": "/x86_64/setup.xz",
                    "expected_status": [200],
                },
                {
                    "endpoint_role": "metadata",
                    "method": "head",
                    "path": "/x86_64/setup.xz.sig",
                    "expected_status": [200],
                },
                {
                    "endpoint_role": "metadata",
                    "method": "head",
                    "path": "/x86_64/setup.ini",
                    "expected_status": [200],
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/x86_64/release/dash/dash-0.5.12-5.tar.xz",
                    "expected_status": [200, 206],
                    "expected_content_type": "application/octet-stream",
                    "sha256": "41a50947c79757b1bb5f49007c61c4dad4dd66bf814e9e054a48487acefb891e",
                },
            ]
    elif tool_id == "winget" and entry["provider_id"] in WINGET_ROOTS:
        compatibility["operating_systems"] = ["windows"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/source.msix",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/source2.msix",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/manifests/j/jqlang/jq/1.8.2/{winget_manifest_id}",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "contains": "PackageIdentifier: jqlang.jq",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/manifests/j/jqlang/jq/1.8.2/{winget_manifest_id}",
                "expected_status": [200],
                "contains": "Architecture: {winget_arch}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/manifests/j/jqlang/jq/1.8.2/{winget_manifest_id}",
                "expected_status": [200],
                "contains": "InstallerSha256: {winget_installer_hash}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/manifests/j/jqlang/jq/1.8.2/{winget_manifest_id}",
                "expected_status": [200],
                "contains": "https://github.com/jqlang/jq/releases/download/jq-1.8.2/",
            },
        ]
    elif tool_id == "msys2" and entry["provider_id"] in MSYS2_ROOTS:
        compatibility["operating_systems"] = ["windows"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/msys/{msys_arch}/msys.db",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/msys/{msys_arch}/msys.db.sig",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/msys/{msys_arch}/{msys_package}",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
                "sha256": "{msys_package_digest}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/msys/{msys_arch}/{msys_package}.sig",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "sha256": "{msys_signature_digest}",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/mingw/{mingw_repo}/{mingw_repo}.db",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/mingw/{mingw_repo}/{mingw_repo}.db.sig",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/mingw/{mingw_repo}/{mingw_package}",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
                "sha256": "{mingw_package_digest}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/mingw/{mingw_repo}/{mingw_package}.sig",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "sha256": "{mingw_signature_digest}",
            },
        ]
    elif tool_id == "scoop":
        compatibility["operating_systems"] = []
        compatibility["architectures"] = []
        compatibility["environments"] = []
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "unknown"
        probes = []
        if entry["provider_id"] == "nju" and upstream_key in SCOOP_BUCKET_ENDPOINTS:
            compatibility["operating_systems"] = ["windows"]
            compatibility["architectures"] = ["x86_64", "arm64"]
            compatibility["environments"] = ["host"]
            delivery_mode = "mirror"
            probes = [
                {
                    "endpoint_role": "git",
                    "method": "get",
                    "path": "/HEAD",
                    "expected_status": [200],
                    "contains": "ref: refs/heads/master",
                },
                {
                    "endpoint_role": "git",
                    "method": "get",
                    "path": "/objects/info/packs",
                    "expected_status": [200],
                    "contains": "P pack-",
                },
            ]
    elif tool_id == "macports" and entry["provider_id"] in MACPORTS_ROOTS:
        compatibility["operating_systems"] = ["macos"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/ports.tar.gz",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/ports.tar.gz.rmd160",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/PortIndex_darwin_{macports_os_major}_{macports_index_arch}/PortIndex",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/zlib/{macports_archive}",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
                "sha256": "{macports_archive_digest}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/zlib/{macports_archive}.rmd160",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "sha256": "{macports_signature_digest}",
            },
        ]
    elif tool_id == "cocoapods":
        compatibility["operating_systems"] = []
        compatibility["architectures"] = []
        compatibility["environments"] = []
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "unknown"
        probes = []
        if (
            upstream_key == COCOAPODS_GIT_UPSTREAM
            and entry["provider_id"] in COCOAPODS_SPECS_ENDPOINTS
        ):
            compatibility["operating_systems"] = ["macos"]
            compatibility["architectures"] = ["x86_64", "arm64"]
            compatibility["environments"] = ["host"]
            delivery_mode = "mirror"
            probes = [
                {
                    "endpoint_role": "git",
                    "method": "get",
                    "path": "/HEAD",
                    "expected_status": [200],
                    "contains": "ref: refs/heads/master",
                },
                {
                    "endpoint_role": "git",
                    "method": "get",
                    "path": "/objects/info/packs",
                    "expected_status": [200],
                    "contains": "P pack-",
                },
            ]
    elif (
        tool_id == "homebrew"
        and entry["provider_id"] == "ustc"
        and upstream_key in {HOMEBREW_GIT_UPSTREAM, HOMEBREW_BOTTLES_UPSTREAM}
    ):
        compatibility["operating_systems"] = ["macos"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["4", "5", "6"]
        delivery_mode = "mirror"
        if upstream_key == HOMEBREW_GIT_UPSTREAM:
            probes = [
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/HEAD",
                    "expected_status": [200],
                    "expected_content_type": "application/octet-stream",
                    "contains": "ref: refs/heads/",
                }
            ]
        else:
            probes = [
                {
                    "endpoint_role": "artifacts",
                    "method": "head",
                    "path": "/api/formula.jws.json",
                    "expected_status": [200],
                    "expected_content_type": "application/json",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/api/formula/jq.json",
                    "expected_status": [200],
                    "expected_content_type": "application/json",
                    "contains": "{homebrew_bottle_tag}",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "head",
                    "path": "/v2/homebrew/core/jq/blobs/sha256:{homebrew_bottle_sha}",
                    "expected_status": [200, 206],
                    "expected_content_type": "application/octet-stream",
                },
            ]
    elif (
        tool_id == "tlmgr"
        and upstream_key == TLMGR_RUNTIME_UPSTREAM
        and entry["raw_name"] == "CTAN"
        and entry["provider_id"] in TLMGR_ENDPOINTS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["2026"]
        delivery_mode = "mirror"
        metadata_content_type = (
            "text/plain"
            if entry["provider_id"] == "aliyun"
            else "application/octet-stream"
        )
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/tlpkg/texlive.tlpdb.sha512",
                "expected_status": [200],
                "expected_content_type": metadata_content_type,
                "contains": "  texlive.tlpdb",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/archive/texlive.infra.tar.xz",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "sha256": TLMGR_INFRA_SHA256,
            },
        ]
        for platform, sha256 in TLMGR_PLATFORM_SHA256.items():
            probes.append(
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": f"/archive/texlive.infra.{platform}.tar.xz",
                    "expected_status": [200],
                    "expected_content_type": "application/octet-stream",
                    "sha256": sha256,
                }
            )
    elif (
        tool_id == "bioconductor"
        and upstream_key == BIOCONDUCTOR_RUNTIME_UPSTREAM
        and entry["raw_name"] == "bioconductor"
        and entry["provider_id"] in BIOCONDUCTOR_ENDPOINTS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["3.23"]
        delivery_mode = "mirror"
        probes = []
        for index, (repository, package, version, sha256) in enumerate(
            BIOCONDUCTOR_PACKAGES
        ):
            probes.append(
                {
                    "endpoint_role": "index" if index == 0 else "metadata",
                    "method": "get",
                    "path": f"/packages/3.23/{repository}/src/contrib/PACKAGES",
                    "expected_status": [200],
                    "expected_content_type": "application/octet-stream",
                    "contains": f"Package: {package}",
                }
            )
            probes.append(
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": (
                        f"/packages/3.23/{repository}/src/contrib/"
                        f"{package}_{version}.tar.gz"
                    ),
                    "expected_status": [200],
                    "expected_content_type": "application/octet-stream",
                    "sha256": sha256,
                }
            )
    elif (
        tool_id == "sbt"
        and upstream_key in {SBT_MAVEN_UPSTREAM, SBT_IVY_UPSTREAM}
        and entry["provider_id"] in SBT_ACTIONABLE_PROVIDERS
        and entry["raw_name"] in {"maven", "sbt"}
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["sbt-1.x", "sbt-2.x"]
        delivery_mode = "proxy"
        if upstream_key == SBT_MAVEN_UPSTREAM:
            probes = [
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>commons-lang3</artifactId>",
                },
                {
                    "endpoint_role": "index",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/maven-metadata.xml",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>commons-lang3</artifactId>",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "head",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
                    "expected_status": [200, 206],
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.sha1",
                    "expected_status": [200, 206],
                    "contains": "1ed471194b02f2c6cb734a0cd6f6f107c673afae",
                },
            ]
        else:
            prefix = (
                "/com.typesafe.sbt/sbt-native-packager/scala_2.12/"
                "sbt_1.0/1.7.6/"
            )
            probes = [
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": prefix + "ivys/ivy.xml",
                    "expected_status": [200, 206],
                    "contains": 'module="sbt-native-packager"',
                },
                {
                    "endpoint_role": "index",
                    "method": "get",
                    "path": prefix + "ivys/ivy.xml.sha1",
                    "expected_status": [200, 206],
                    "contains": "a391298b496a45d2726b3b196b31d2467136e0c8",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "head",
                    "path": prefix + "jars/sbt-native-packager.jar",
                    "expected_status": [200, 206],
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": prefix + "jars/sbt-native-packager.jar.sha1",
                    "expected_status": [200, 206],
                    "contains": "ee875aa975277e173b15588242b4eb773f9d430c",
                },
            ]
    elif (
        tool_id == "leiningen"
        and entry["raw_name"] in {"maven", "clojars"}
        and (
            entry["provider_id"] in MAVEN_REGISTRY_ENDPOINTS
            if entry["raw_name"] == "maven"
            else entry["provider_id"] in LEININGEN_CLOJARS_ENDPOINTS
        )
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["leiningen-2.x"]
        delivery_mode = "proxy"
        if upstream_key == GRADLE_MAVEN_UPSTREAM:
            probes = [
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>commons-lang3</artifactId>",
                },
                {
                    "endpoint_role": "index",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/maven-metadata.xml",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>commons-lang3</artifactId>",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "head",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
                    "expected_status": [200, 206],
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.sha1",
                    "expected_status": [200, 206],
                    "contains": "1ed471194b02f2c6cb734a0cd6f6f107c673afae",
                },
            ]
        else:
            prefix = "/lein-pprint/lein-pprint/1.3.2/lein-pprint-1.3.2"
            probes = [
                {
                    "endpoint_role": "index",
                    "method": "get",
                    "path": "/lein-pprint/lein-pprint/maven-metadata.xml",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>lein-pprint</artifactId>",
                },
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": prefix + ".pom",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>lein-pprint</artifactId>",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "head",
                    "path": prefix + ".jar",
                    "expected_status": [200, 206],
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": prefix + ".jar.sha1",
                    "expected_status": [200, 206],
                    "contains": "bf88d437e144ea38dfd550d9d50ea1385c8b1bc1",
                },
            ]
    elif (
        tool_id == "flutter"
        and upstream_key == FLUTTER_STORAGE_RUNTIME_UPSTREAM
        and (
            (entry["provider_id"] == "nju" and entry["raw_name"] == "flutter")
            or (
                entry["provider_id"] == "sjtug"
                and entry["raw_name"] == "flutter_infra"
            )
        )
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = [FLUTTER_RELEASE_IDENTITY]
        delivery_mode = "mirror"
        engine_root = (
            "/flutter_infra_release/flutter/"
            f"{FLUTTER_ENGINE_ARTIFACT_VERSION}"
        )
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/flutter_infra_release/releases/releases_linux.json",
                "expected_status": [200],
                "expected_content_type": "application/json",
                "contains": (
                    f'"hash": "{FLUTTER_FRAMEWORK_REVISION}",\n'
                    '      "channel": "stable",\n'
                    f'      "version": "{FLUTTER_FRAMEWORK_VERSION}"'
                ),
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{engine_root}/linux-x64/artifacts.zip.intoto.jsonl",
                "expected_status": [200],
                "sha256": FLUTTER_X64_PROVENANCE_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"{engine_root}/linux-x64/artifacts.zip",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{engine_root}/linux-arm64/artifacts.zip.intoto.jsonl",
                "expected_status": [200],
                "sha256": FLUTTER_ARM64_PROVENANCE_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"{engine_root}/linux-arm64/artifacts.zip",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id in {"dart-pub", "flutter"}
        and upstream_key == DART_PUB_RUNTIME_UPSTREAM
        and entry["raw_name"] == "dart-pub"
        and entry["provider_id"] in DART_PUB_HOSTED_ENDPOINTS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "proxy"
        archive_path = (
            "/retry-3.1.2.tar.gz"
            if entry["provider_id"] == "sjtug"
            else "/retry/versions/3.1.2.tar.gz"
        )
        archive_content_type = (
            "application/octet"
            if entry["provider_id"] == "sjtug"
            else "application/octet-stream"
        )
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/api/packages/retry",
                "expected_status": [200],
                "expected_content_type": "application/json",
                "contains": '"retry"',
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/api/packages/retry",
                "expected_status": [200],
                "expected_content_type": "application/json",
                "contains": DART_PUB_RETRY_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": archive_path,
                "expected_status": [200, 206],
                "expected_content_type": archive_content_type,
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": archive_path,
                "expected_status": [200, 206],
                "expected_content_type": archive_content_type,
                "sha256": DART_PUB_RETRY_SHA256,
            },
        ]
    elif (
        tool_id == "ghcup"
        and upstream_key == GHCUP_RUNTIME_UPSTREAM
        and entry["provider_id"] in GHCUP_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["0.0.9"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/ghcup-0.0.9.yaml",
                "expected_status": [200, 206],
                "contains": "ghcupDownloads:",
                "sha256": GHCUP_METADATA_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/ghcup-0.0.9.yaml.sig",
                "expected_status": [200, 206],
                "sha256": GHCUP_SIGNATURE_SHA256,
            },
            *[
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/ghcup-0.0.9.yaml",
                    "expected_status": [200, 206],
                    "contains": "{" + tool + "_sha}",
                }
                for tool in ("ghc", "cabal", "hls", "stack")
            ],
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/~ghc/9.10.3/{ghc_file}",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/~ghcup/unofficial-bindists/cabal/3.14.2.0/{cabal_file}",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/~ghcup/unofficial-bindists/haskell-language-server/2.13.0.0/{hls_file}",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/~ghcup/unofficial-bindists/stack/3.7.1/{stack_file}",
                "expected_status": [200, 206],
            },
        ]
    elif (
        tool_id == "stack"
        and upstream_key == STACKAGE_RUNTIME_UPSTREAM
        and entry["provider_id"] in STACK_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["lts-22"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/snapshots.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"lts-22"',
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/stackage-snapshots/lts/22/43.yaml",
                "expected_status": [200, 206],
                "sha256": STACK_SNAPSHOT_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/global-hints.yaml",
                "expected_status": [200, 206],
                "contains": "ghc-9.6.6",
                "sha256": STACK_GLOBAL_HINTS_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/stack-setup.yaml",
                "expected_status": [200, 206],
                "contains": "{toolchain_file}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/stack-setup.yaml",
                "expected_status": [200, 206],
                "contains": "{toolchain_sha}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/ghc/{toolchain_file}",
                "expected_status": [200, 206],
            },
        ]
    elif (
        tool_id == "stack"
        and upstream_key == STACK_HACKAGE_UPSTREAM
        and entry["provider_id"] in STACK_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["secure"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/root.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"Root"',
                "sha256": CABAL_ROOT_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/timestamp.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"Timestamp"',
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/snapshot.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "01-index.tar.gz",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/mirrors.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"Mirrorlist"',
            },
            {
                "endpoint_role": "index",
                "method": "head",
                "path": "/01-index.tar.gz",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/package/StateVar-1.2.2.tar.gz",
                "expected_status": [200, 206],
                "sha256": CABAL_TARBALL_SHA256,
            },
        ]
    elif tool_id == "apt" and upstream_key in APT_RUNTIME_UPSTREAMS:
        compatibility["architectures"] = APT_RUNTIME_UPSTREAMS[upstream_key]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/dists/{suite}/InRelease",
                "expected_status": [200],
                "contains": "-----BEGIN PGP SIGNED MESSAGE-----",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/dists/{suite}/{component}/binary-{architecture}/Release",
                "expected_status": [200],
                "contains": "Architecture:",
            },
        ]
    elif (tool_id == "dnf" and upstream_key in DNF_RUNTIME_UPSTREAMS) or (
        tool_id == "yum" and upstream_key in YUM_RUNTIME_UPSTREAMS
    ):
        compatibility["architectures"] = (
            DNF_RUNTIME_UPSTREAMS.get(upstream_key)
            or YUM_RUNTIME_UPSTREAMS[upstream_key]
        )
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/{repository_path}repodata/repomd.xml",
                "expected_status": [200],
                "contains": "<repomd",
            }
        ]
    elif tool_id == "pacman" and upstream_key in PACMAN_RUNTIME_UPSTREAMS:
        compatibility["architectures"] = PACMAN_RUNTIME_UPSTREAMS[upstream_key]
        compatibility["distributions"] = [
            {"id": distribution, "versions": [], "codenames": []}
            for distribution in PACMAN_RUNTIME_DISTRIBUTIONS[upstream_key]
        ]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/{repository_path}",
                "expected_status": [200],
            }
        ]
    elif tool_id == "zypper" and upstream_key in ZYPPER_RUNTIME_UPSTREAMS:
        compatibility["architectures"] = ZYPPER_RUNTIME_UPSTREAMS[upstream_key]
        compatibility["distributions"] = [
            {"id": distribution, "versions": [], "codenames": []}
            for distribution in ZYPPER_RUNTIME_DISTRIBUTIONS[upstream_key]
        ]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/{repository_path}repodata/repomd.xml",
                "expected_status": [200],
                "contains": "<repomd",
            }
        ]
    elif tool_id == "portage" and upstream_key in PORTAGE_RUNTIME_UPSTREAMS:
        has_rsync_endpoint = any(
            endpoint["protocol"] == "rsync"
            for endpoint in entry["public_endpoints"]
        )
        if upstream_key == "gentoo--repository-metadata" or has_rsync_endpoint:
            compatibility["architectures"] = ["x86_64", "arm64"]
            compatibility["distributions"] = [
                {"id": "gentoo", "versions": [], "codenames": []}
            ]
            delivery_mode = "mirror"
            if upstream_key == "gentoo--repository-metadata":
                probes = [
                    {
                        "endpoint_role": "metadata",
                        "method": "head",
                        "path": "/distfiles/",
                        "expected_status": [200],
                    },
                    {
                        "endpoint_role": "metadata",
                        "method": "get",
                        "path": "/releases/{gentoo_arch}/autobuilds/latest-stage3-{stage3_arch}-openrc.txt",
                        "expected_status": [200],
                        "contains": "stage3-",
                    },
                ]
            else:
                probes = [
                    {
                        "endpoint_role": "metadata",
                        "method": "get",
                        "path": "/profiles/repo_name",
                        "expected_status": [200],
                        "contains": "gentoo",
                    },
                    {
                        "endpoint_role": "metadata",
                        "method": "head",
                        "path": "/profiles/arch/{gentoo_arch}/",
                        "expected_status": [200],
                    },
                ]
    elif tool_id == "apk" and upstream_key == APK_RUNTIME_UPSTREAM:
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["distributions"] = [
            {"id": "alpine", "versions": [], "codenames": []}
        ]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/{branch}/{repository}/{architecture}/APKINDEX.tar.gz",
                "expected_status": [200],
            }
        ]
    elif tool_id == "xbps" and upstream_key == XBPS_RUNTIME_UPSTREAM:
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["distributions"] = [
            {"id": "void", "versions": [], "codenames": []}
        ]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/{repository_path}/{xbps_arch}-repodata",
                "expected_status": [200],
            }
        ]
    elif tool_id == "nix" and upstream_key == NIX_RUNTIME_UPSTREAM:
        compatibility["architectures"] = ["x86_64", "arm64"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/nix-cache-info",
                "expected_status": [200],
                "contains": "StoreDir: /nix/store",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/{narinfo_hash}.narinfo",
                "expected_status": [200],
                "contains": "Sig: cache.nixos.org-1:",
            },
        ]
    elif tool_id == "nix-macos" and upstream_key == NIX_RUNTIME_UPSTREAM:
        compatibility["operating_systems"] = []
        compatibility["architectures"] = []
        compatibility["environments"] = []
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "unknown"
        probes = []
        if entry["provider_id"] in NIX_MACOS_ACTIONABLE_PROVIDERS:
            compatibility["operating_systems"] = ["macos"]
            compatibility["architectures"] = ["x86_64", "arm64"]
            compatibility["environments"] = ["host"]
            delivery_mode = "mirror"
            probes = [
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/nix-cache-info",
                    "expected_status": [200],
                    "contains": "StoreDir: /nix/store",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/{darwin_probe_hash}.narinfo",
                    "expected_status": [200],
                    "contains": "StorePath: /nix/store/{darwin_probe_hash}-{darwin_probe_name}",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/{darwin_probe_hash}.narinfo",
                    "expected_status": [200],
                    "contains": "Sig: cache.nixos.org-1:",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/nar/{darwin_nar_file}",
                    "expected_status": [200, 206],
                    "expected_content_type": "application/octet-stream",
                    "sha256": "{darwin_nar_digest}",
                },
            ]
    elif tool_id == "guix" and upstream_key in GUIX_RUNTIME_UPSTREAMS:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/{store_hash}.narinfo",
                "expected_status": [200],
                "contains": GUIX_RUNTIME_UPSTREAMS[upstream_key],
            }
        ]
    elif tool_id == "flatpak" and upstream_key == FLATPAK_RUNTIME_UPSTREAM:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "proxy"
        probes = [
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/config",
                "expected_status": [200],
                "contains": "collection-id=org.flathub.Stable",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/summary.idx",
                "expected_status": [200],
                "contains": "{flatpak_arch}",
            },
        ]
    elif tool_id == "opkg" and upstream_key in OPKG_RUNTIME_UPSTREAMS:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = [
            {
                "id": OPKG_RUNTIME_UPSTREAMS[upstream_key],
                "versions": [],
                "codenames": [],
            }
        ]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/{repository_path}/Packages.gz",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/{repository_path}/Packages.sig",
                "expected_status": [200, 206],
            },
        ]
    elif (
        tool_id == "go"
        and upstream_key == GO_PROXY_UPSTREAM
        and entry["provider_id"] in GO_PROXY_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        delivery_mode = "proxy"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/github.com/pkg/errors/@v/list",
                "expected_status": [200, 206],
                "contains": "v0.9.1",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/github.com/pkg/errors/@v/v0.9.1.info",
                "expected_status": [200, 206],
                "contains": "v0.9.1",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/github.com/pkg/errors/@v/v0.9.1.mod",
                "expected_status": [200, 206],
                "contains": "module github.com/pkg/errors",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/github.com/pkg/errors/@v/v0.9.1.zip",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/sumdb/sum.golang.org/supported",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/sumdb/sum.golang.org/lookup/github.com/pkg/errors@v0.9.1",
                "expected_status": [200, 206],
                "contains": "github.com/pkg/errors v0.9.1 h1:",
            },
        ]
    elif (
        tool_id == "cabal"
        and upstream_key == CABAL_RUNTIME_UPSTREAM
        and entry["provider_id"] in CABAL_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["secure"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/root.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"Root"',
                "sha256": CABAL_ROOT_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/timestamp.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"Timestamp"',
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/snapshot.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "01-index.tar.gz",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/mirrors.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"Mirrorlist"',
            },
            {
                "endpoint_role": "index",
                "method": "head",
                "path": "/01-index.tar.gz",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/package/StateVar-1.2.2.tar.gz",
                "expected_status": [200, 206],
                "sha256": CABAL_TARBALL_SHA256,
            },
        ]
    elif (
        tool_id == "nuget"
        and upstream_key == NUGET_RUNTIME_UPSTREAM
        and entry["provider_id"] in NUGET_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux", "windows"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["v3"]
        delivery_mode = "proxy"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/index.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "PackageBaseAddress/3.0.0",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/index.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": NUGET_REGISTRATION_ENDPOINT,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/nuget.versioning/index.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "registration-semver2/nuget.versioning/page/",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/nuget.versioning/page/6.0.5/7.9.0.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"version":"6.12.1"',
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/nuget.versioning/index.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"6.12.1"',
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/nuget.versioning/6.12.1/nuget.versioning.6.12.1.nupkg",
                "expected_status": [200, 206],
                "sha256": NUGET_NUPKG_SHA256,
            },
        ]
    elif (
        tool_id == "composer"
        and upstream_key == COMPOSER_RUNTIME_UPSTREAM
        and entry["provider_id"] in COMPOSER_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["v1", "v2"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/packages.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "providers-lazy-url",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/p/psr/log.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "psr/log",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/p2/psr/log.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "https://repo.huaweicloud.com/repository/php/psr/log/3.0.2/psr-log-3.0.2.zip",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/p2/psr/log.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": "https://github.com/php-fig/log.git",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/psr/log/3.0.2/psr-log-3.0.2.zip",
                "expected_status": [200, 206],
                "sha256": COMPOSER_DIST_SHA256,
            },
            {
                "endpoint_role": "git",
                "method": "get",
                "path": "/archive/refs/tags/3.0.2.zip",
                "expected_status": [200, 206],
                "sha256": COMPOSER_SOURCE_SHA256,
            },
        ]
    elif (
        tool_id == "bundler"
        and upstream_key == RUBYGEMS_RUNTIME_UPSTREAM
        and entry["provider_id"] in BUNDLER_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        if entry["provider_id"] in BUNDLER_COMPACT_PROVIDERS:
            probes = [
                {
                    "endpoint_role": "index",
                    "method": "head",
                    "path": "/versions",
                    "expected_status": [200, 206],
                },
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/info/net-protocol",
                    "expected_status": [200, 206],
                    "expected_content_type": "text/plain",
                    "contains": "0.3.0 ",
                },
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/info/net-protocol",
                    "expected_status": [200, 206],
                    "expected_content_type": "text/plain",
                    "contains": "timeout:>= 0",
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/gems/net-protocol-0.3.0.gem",
                    "expected_status": [200, 206],
                    "expected_content_type": "application/octet-stream",
                    "sha256": RUBYGEMS_GEM_SHA256,
                },
            ]
        else:
            probes = [
                {
                    "endpoint_role": "index",
                    "method": "head",
                    "path": "/specs.4.8.gz",
                    "expected_status": [200, 206],
                },
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/quick/Marshal.4.8/net-protocol-0.3.0.gemspec.rz",
                    "expected_status": [200, 206],
                    "expected_content_type": "application/octet-stream",
                    "sha256": BUNDLER_CLASSIC_GEMSPEC_SHA256,
                },
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/gems/net-protocol-0.3.0.gem",
                    "expected_status": [200, 206],
                    "expected_content_type": "application/octet-stream",
                    "sha256": RUBYGEMS_GEM_SHA256,
                },
            ]
    elif (
        tool_id == "rubygems"
        and upstream_key == RUBYGEMS_RUNTIME_UPSTREAM
        and entry["provider_id"] in RUBYGEMS_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "head",
                "path": "/specs.4.8.gz",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/quick/Marshal.4.8/net-protocol-0.3.0.gemspec.rz",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/gems/net-protocol-0.3.0.gem",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
                "sha256": RUBYGEMS_GEM_SHA256,
            },
        ]
    elif (
        tool_id == "cargo"
        and upstream_key == CARGO_SPARSE_UPSTREAM
        and entry["provider_id"] in CARGO_SPARSE_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        provider = entry["provider_id"]
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/config.json",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"dl"',
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/it/oa/itoa",
                "expected_status": [200, 206],
                "contains": CARGO_CRATE_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": CARGO_CRATE_PATHS[provider],
                "expected_status": [200, 206],
                "sha256": CARGO_CRATE_SHA256,
            },
        ]
    elif (
        tool_id == "rustup"
        and upstream_key == RUSTUP_RUNTIME_UPSTREAM
        and entry["provider_id"] in RUSTUP_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        manifest_sha256 = RUSTUP_MANIFEST_SHA256[entry["provider_id"]]
        probes = [
            {
                "endpoint_role": "releases",
                "method": "get",
                "path": "/dist/2026-08-20/channel-rust-stable.toml",
                "expected_status": [200, 206],
                "sha256": manifest_sha256,
            },
            {
                "endpoint_role": "releases",
                "method": "get",
                "path": "/dist/2026-08-20/channel-rust-stable.toml.sha256",
                "expected_status": [200, 206],
                "contains": manifest_sha256,
            },
            {
                "endpoint_role": "releases",
                "method": "head",
                "path": "/dist/2026-08-20/rustc-1.98.0-{host}.tar.xz",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "releases",
                "method": "head",
                "path": "/dist/2026-08-20/cargo-1.98.0-{host}.tar.xz",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "releases",
                "method": "head",
                "path": "/dist/2026-08-20/rust-std-1.98.0-{host}.tar.xz",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/release-stable.toml",
                "expected_status": [200, 206],
                "contains": "schema-version = '1'",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/archive/1.29.0/{host}/rustup-init.sha256",
                "expected_status": [200, 206],
                "contains": "{rustup_sha256}",
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/archive/1.29.0/{host}/rustup-init",
                "expected_status": [200, 206],
            },
        ]
    elif (
        tool_id in NODE_DISTRIBUTION_TOOLS
        and upstream_key == NODE_DISTRIBUTION_UPSTREAM
    ) or (tool_id == "nvm" and upstream_key == IOJS_RELEASE_UPSTREAM):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "releases",
                "method": "head",
                "path": "/index.tab",
                "expected_status": [200, 206],
            },
            {
                "endpoint_role": "releases",
                "method": "get",
                "path": "/{version}/SHASUMS256.txt",
                "expected_status": [200, 206],
                "contains": "{artifact_prefix}-{version}-linux-{architecture}.tar.xz",
            },
            {
                "endpoint_role": "releases",
                "method": "head",
                "path": "/{version}/{artifact_prefix}-{version}-linux-{architecture}.tar.xz",
                "expected_status": [200, 206],
            },
        ]
    elif (
        tool_id in {"gradle", "maven"}
        and upstream_key == GRADLE_MAVEN_UPSTREAM
        and entry["raw_name"] == "maven"
        and entry["provider_id"] in MAVEN_REGISTRY_ENDPOINTS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "proxy"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom",
                "expected_status": [200, 206],
                "contains": "<artifactId>commons-lang3</artifactId>",
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
                "expected_status": [200, 206],
            },
        ]
        if tool_id == "maven":
            probes.insert(
                1,
                {
                    "endpoint_role": "index",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/maven-metadata.xml",
                    "expected_status": [200, 206],
                    "contains": "<artifactId>commons-lang3</artifactId>",
                },
            )
            probes.append(
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.sha1",
                    "expected_status": [200, 206],
                    "contains": "1ed471194b02f2c6cb734a0cd6f6f107c673afae",
                }
            )
    elif (
        tool_id == "gradle"
        and upstream_key == GRADLE_DISTRIBUTION_UPSTREAM
        and entry["provider_id"] in GRADLE_DISTRIBUTION_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "releases",
                "method": "get",
                "path": "/{distribution_file}.sha256",
                "expected_status": [200, 206],
                "contains": "{distribution_checksum}",
            },
            {
                "endpoint_role": "releases",
                "method": "head",
                "path": "/{distribution_file}",
                "expected_status": [200, 206],
            },
        ]
    elif tool_id == "cpan" and upstream_key == CPAN_RUNTIME_UPSTREAM:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        try_tiny_root = "/authors/id/E/ET/ETHER"
        probes = [
            {
                "endpoint_role": "index",
                "method": "head",
                "path": "/modules/02packages.details.txt.gz",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{try_tiny_root}/Try-Tiny-0.32.meta",
                "expected_status": [200],
                "contains": '"name" : "Try-Tiny"',
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{try_tiny_root}/CHECKSUMS",
                "expected_status": [200],
                "contains": CPAN_TRY_TINY_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"{try_tiny_root}/Try-Tiny-0.32.tar.gz",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": f"{try_tiny_root}/Try-Tiny-0.32.tar.gz",
                "expected_status": [200],
                "sha256": CPAN_TRY_TINY_SHA256,
            },
        ]
    elif tool_id == "cran" and upstream_key == CRAN_RUNTIME_UPSTREAM:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "head",
                "path": "/src/contrib/PACKAGES.gz",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/web/packages/digest/DESCRIPTION",
                "expected_status": [200],
                "contains": "Version: 0.6.39",
                "sha256": CRAN_DIGEST_DESCRIPTION_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": "/src/contrib/digest_0.6.39.tar.gz",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/src/contrib/digest_0.6.39.tar.gz",
                "expected_status": [200],
                "sha256": CRAN_DIGEST_ARCHIVE_SHA256,
            },
        ]
    elif (
        tool_id == "pyenv"
        and upstream_key == PYENV_RUNTIME_UPSTREAM
        and entry["provider_id"] in PYENV_ENDPOINTS
        and entry["raw_name"] == "python"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = [PYENV_RELEASE_IDENTITY]
        delivery_mode = "mirror"
        release_root = "/3.14.7"
        archive = "Python-3.14.7.tar.xz"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{release_root}/",
                "expected_status": [200],
                "contains": archive,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{release_root}/{archive}.sig",
                "expected_status": [200],
                "sha256": PYENV_SIGNATURE_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"{release_root}/{archive}",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": f"{release_root}/{archive}",
                "expected_status": [200],
                "sha256": PYENV_ARCHIVE_SHA256,
            },
        ]
    elif tool_id == "bazel" and upstream_key == BAZEL_RELEASE_UPSTREAM:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = [BAZEL_VERSION]
        delivery_mode = "mirror"
        release_root = f"/{BAZEL_VERSION}"
        x64 = f"bazel-{BAZEL_VERSION}-linux-x86_64"
        arm64 = f"bazel-{BAZEL_VERSION}-linux-arm64"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{release_root}/",
                "expected_status": [200],
                "contains": x64,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{release_root}/{x64}.sha256",
                "expected_status": [200],
                "contains": BAZEL_X64_SHA256,
                "sha256": BAZEL_X64_CHECKSUM_FILE_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{release_root}/{arm64}.sha256",
                "expected_status": [200],
                "contains": BAZEL_ARM64_SHA256,
                "sha256": BAZEL_ARM64_CHECKSUM_FILE_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"{release_root}/{x64}",
                "expected_status": [200],
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"{release_root}/{arm64}",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "bazel"
        and upstream_key == BAZEL_APT_UPSTREAM
        and entry["provider_id"] in BAZEL_APT_ENDPOINTS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = [
            {"id": "debian", "versions": [], "codenames": []},
            {"id": "ubuntu", "versions": [], "codenames": []},
        ]
        compatibility["repository_versions"] = [BAZEL_VERSION]
        delivery_mode = "mirror"
        deb = f"bazel_{BAZEL_VERSION}_amd64.deb"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/dists/stable/jdk1.8/binary-amd64/Packages",
                "expected_status": [200],
                "contains": BAZEL_DEB_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/dists/stable/InRelease",
                "expected_status": [200],
                "contains": "Origin: Bazel Authors",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/dists/stable/Release",
                "expected_status": [200],
                "contains": "Architectures: amd64",
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": f"/pool/jdk1.8/b/bazel/{deb}",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "opam"
        and upstream_key == OPAM_REPOSITORY_UPSTREAM
        and entry["public_endpoints"][0]["url"].rstrip("/")
        == OPAM_REPOSITORY_ENDPOINT
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = [OPAM_REPOSITORY_REVISION]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/info/refs",
                "expected_status": [200],
                "contains": OPAM_REPOSITORY_REVISION,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/HEAD",
                "expected_status": [200],
                "contains": "ref: refs/heads/master",
            },
            {
                "endpoint_role": "artifacts",
                "method": "get",
                "path": "/objects/info/packs",
                "expected_status": [200],
                "contains": "P pack-",
            },
        ]
    elif tool_id == "opam" and upstream_key == OPAM_CACHE_UPSTREAM:
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "proxy"
        cache_path = f"/sha256/61/{OPAM_CACHE_SHA256}"
        probes = [
            {
                "endpoint_role": "index",
                "method": "head",
                "path": cache_path,
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": cache_path,
                "expected_status": [200],
                "sha256": OPAM_CACHE_SHA256,
            },
            {
                "endpoint_role": "artifacts",
                "method": "head",
                "path": cache_path,
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "julia"
        and upstream_key == JULIA_RUNTIME_UPSTREAM
        and entry["provider_id"] == "nju"
        and entry["raw_name"] == "julia"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "proxy"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/registries",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "contains": f"/registry/{JULIA_GENERAL_REGISTRY_UUID}/",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": (
                    f"/registry/{JULIA_GENERAL_REGISTRY_UUID}/"
                    f"{JULIA_GENERAL_REGISTRY_TREE}"
                ),
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"/package/{JULIA_EXAMPLE_UUID}/{JULIA_EXAMPLE_TREE}",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "sha256": JULIA_EXAMPLE_SOURCE_SHA256,
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"/package/{JULIA_HELLO_UUID}/{JULIA_HELLO_TREE}",
                "expected_status": [200],
                "expected_content_type": "application/octet-stream",
                "sha256": JULIA_HELLO_SOURCE_SHA256,
            },
            *[
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": f"/artifact/{tree}",
                    "expected_status": [200],
                    "expected_content_type": "application/octet-stream",
                    "sha256": digest,
                }
                for tree, digest in JULIA_HELLO_ARTIFACTS.values()
            ],
        ]
    elif (
        tool_id == "kubernetes-images"
        and upstream_key == KUBERNETES_IMAGES_UPSTREAM
        and entry["provider_id"] == "nju"
        and entry["raw_name"] == "k8s"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "proxy"
        manifest_path = "/v2/{repository_path}/manifests/{tag}"
        probes = [
            {
                "endpoint_role": "registry",
                "method": "get",
                "path": manifest_path,
                "expected_status": [200],
                "accept": OCI_MANIFEST_ACCEPT,
                "contains": '"architecture": "{oci_arch}"',
            },
            {
                "endpoint_role": "registry",
                "method": "get",
                "path": manifest_path,
                "expected_status": [200],
                "accept": OCI_MANIFEST_ACCEPT,
                "contains": '"digest": "sha256:',
            },
        ]
    elif (
        tool_id == "containerd"
        and upstream_key == KUBERNETES_IMAGES_UPSTREAM
        and entry["provider_id"] == "nju"
        and entry["raw_name"] == "k8s"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "proxy"
        manifest_path = "/v2/{repository_path}/manifests/{tag}"
        probes = [
            {
                "endpoint_role": "registry",
                "method": "get",
                "path": manifest_path,
                "expected_status": [200],
                "accept": OCI_MANIFEST_ACCEPT,
                "contains": '"architecture": "{oci_arch}"',
            },
            {
                "endpoint_role": "registry",
                "method": "get",
                "path": manifest_path,
                "expected_status": [200],
                "accept": OCI_MANIFEST_ACCEPT,
                "contains": '"digest": "sha256:',
            },
        ]
    elif (
        tool_id == "podman-registry"
        and entry["provider_id"] == "nju"
        and entry["raw_name"] in {"gcr", "ghcr", "quay"}
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "proxy"
        manifest_path = "/v2/{repository_path}/manifests/{tag}"
        probes = [
            {
                "endpoint_role": "registry",
                "method": "get",
                "path": manifest_path,
                "expected_status": [200],
                "accept": OCI_MANIFEST_ACCEPT,
                "contains": '"architecture": "{oci_arch}"',
            },
            {
                "endpoint_role": "registry",
                "method": "get",
                "path": manifest_path,
                "expected_status": [200],
                "accept": OCI_MANIFEST_ACCEPT,
                "contains": '"digest": "sha256:',
            },
        ]
    elif (
        tool_id == "kubernetes-packages"
        and upstream_key == KUBERNETES_PACKAGES_UPSTREAM
        and entry["provider_id"] in KUBERNETES_PACKAGES_ACTIONABLE_PROVIDERS
        and entry["raw_name"] == "kubernetes"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "mirror"
        deb_root = "/core:/stable:/{minor}/deb"
        rpm_root = "/core:/stable:/{minor}/rpm"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{deb_root}/Release",
                "expected_status": [200],
                "contains": "Origin: obs://build.opensuse.org/isv:kubernetes:core:stable:{minor}/deb",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{deb_root}/Packages",
                "expected_status": [200],
                "contains": "Package: kubeadm",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{deb_root}/Packages",
                "expected_status": [200],
                "contains": "Architecture: {deb_arch}",
            },
            *[
                {
                    "endpoint_role": "packages",
                    "method": "head",
                    "path": f"/core:/stable:/v1.35/deb/{path}",
                    "expected_status": [200],
                }
                for path in KUBERNETES_DEB_BASELINE.values()
            ],
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{rpm_root}/repodata/repomd.xml",
                "expected_status": [200],
                "contains": '<data type="primary">',
            },
            *[
                {
                    "endpoint_role": "packages",
                    "method": "head",
                    "path": f"/core:/stable:/v1.35/rpm/{path}",
                    "expected_status": [200],
                }
                for path in KUBERNETES_RPM_BASELINE.values()
            ],
        ]
    elif (
        tool_id == "docker-ce"
        and upstream_key == DOCKER_CE_UPSTREAM
        and entry["provider_id"] in DOCKER_CE_ENDPOINTS
        and entry["raw_name"] == "docker-ce"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "mirror"
        apt_root = "/linux/{apt_distro}/dists/{codename}/stable"
        rpm_root = "/linux/{rpm_distro}/{release}/{rpm_arch}/stable"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/linux/{apt_distro}/dists/{codename}/InRelease",
                "expected_status": [200],
                "contains": "Origin: Docker",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{apt_root}/binary-{{apt_arch}}/Packages",
                "expected_status": [200],
                "contains": "Package: docker-ce",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/linux/debian/dists/bookworm/stable/binary-amd64/Packages",
                "expected_status": [200],
                "contains": "Architecture: amd64",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": "/linux/debian/dists/bookworm/stable/binary-arm64/Packages",
                "expected_status": [200],
                "contains": "Architecture: arm64",
            },
            {
                "endpoint_role": "metadata",
                "method": "get",
                "path": f"{rpm_root}/repodata/repomd.xml",
                "expected_status": [200],
                "contains": '<data type="primary">',
            },
            {
                "endpoint_role": "packages",
                "method": "get",
                "path": "/linux/fedora/42/x86_64/stable/repodata/repomd.xml",
                "expected_status": [200],
                "contains": '<data type="primary">',
            },
            {
                "endpoint_role": "packages",
                "method": "get",
                "path": "/linux/fedora/42/aarch64/stable/repodata/repomd.xml",
                "expected_status": [200],
                "contains": '<data type="primary">',
            },
        ]
    elif tool_id == "elpa" and entry["raw_name"].startswith("elpa/"):
        archive = entry["raw_name"].split("/", 1)[1]
        _, package = ELPA_ARCHIVES[archive]
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = []
        delivery_mode = "mirror"
        marker = {
            "gnu": "(a68-mode",
            "nongnu": "(adoc-mode",
            "melpa": "(dash .",
        }[archive]
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/archive-contents",
                "expected_status": [200],
                "contains": marker,
            },
            {
                "endpoint_role": "packages",
                "method": "head",
                "path": f"/{package}",
                "expected_status": [200],
            },
        ]
        if archive in {"gnu", "nongnu"}:
            probes.extend(
                [
                    {
                        "endpoint_role": "metadata",
                        "method": "head",
                        "path": "/archive-contents.sig",
                        "expected_status": [200],
                    },
                    {
                        "endpoint_role": "packages",
                        "method": "head",
                        "path": f"/{package}.sig",
                        "expected_status": [200],
                    },
                ]
            )
        else:
            probes.append(
                {
                    "endpoint_role": "metadata",
                    "method": "get",
                    "path": "/archive-contents",
                    "expected_status": [200],
                    "contains": "20260221 1346",
                }
            )
    elif (
        tool_id == "ros"
        and upstream_key == ROS1_UPSTREAM
        and entry["provider_id"] in ROS1_ACTIONABLE_PROVIDERS
        and entry["raw_name"] == "ros"
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ["noetic-focal-final"]
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/ubuntu/dists/focal/Release",
                "expected_status": [200],
                "contains": "Origin: ROS",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/ubuntu/dists/focal/Release",
                "expected_status": [200],
                "contains": "Architectures: i386 amd64 arm64 armhf",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/ubuntu/dists/focal/Release.gpg",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/ubuntu/dists/focal/main/binary-amd64/Packages.gz",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": "/ubuntu/dists/focal/main/binary-arm64/Packages.gz",
                "expected_status": [200],
            },
            *[
                {
                    "endpoint_role": "packages",
                    "method": "head",
                    "path": f"/{path}",
                    "expected_status": [200],
                }
                for path in ROS1_BASELINE_PACKAGES.values()
            ],
        ]
    elif (
        tool_id == "mysql"
        and upstream_key == MYSQL_UPSTREAM
        and entry["provider_id"] in MYSQL_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = MYSQL_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/apt/{family}"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{root}/dists/{{release}}/InRelease",
                "expected_status": [200],
                "contains": "Origin: MySQL",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": f"{root}/dists/{{release}}/Release.gpg",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": f"{root}/dists/{{release}}/mysql-8.4-lts/binary-amd64/Packages",
                "expected_status": [200],
            },
            {
                "endpoint_role": "packages",
                "method": "head",
                "path": f"{root}/pool/mysql-8.4-lts/m/mysql-community/{{package_name}}",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "mysql"
        and upstream_key == MYSQL_UPSTREAM
        and entry["provider_id"] in MYSQL_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = MYSQL_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        if entry["provider_id"] == "tuna":
            root = "/yum/mysql-8.4-community-el{release}-{architecture}"
        else:
            root = "/yum/mysql-8.4-community/el/{release}/{architecture}"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{root}/repodata/repomd.xml",
                "expected_status": [200],
                "contains": "<repomd",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": f"{root}/repodata/repomd.xml",
                "expected_status": [200],
            },
            {
                "endpoint_role": "packages",
                "method": "head",
                "path": f"{root}/{{package_name}}",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "mongodb"
        and upstream_key == MONGODB_UPSTREAM
        and entry["provider_id"] in MONGODB_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = list(MONGODB_APT_REPOSITORY_VERSIONS)
        delivery_mode = "mirror"
        root = "/apt/{family}"
        release_root = f"{root}/dists/{{release}}/mongodb-org/8.0"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{release_root}/InRelease",
                "expected_status": [200],
                "contains": "Origin: mongodb",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": f"{release_root}/Release.gpg",
                "expected_status": [200],
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": f"{release_root}/{{component}}/binary-{{architecture}}/Packages",
                "expected_status": [200],
            },
            {
                "endpoint_role": "packages",
                "method": "head",
                "path": f"{release_root}/{{component}}/binary-{{architecture}}/{{package_name}}",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "mongodb"
        and upstream_key == MONGODB_UPSTREAM
        and entry["provider_id"] in MONGODB_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = list(MONGODB_RPM_REPOSITORY_VERSIONS)
        delivery_mode = "mirror"
        root = "/yum/el{release}-8.0"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": f"{root}/repodata/repomd.xml",
                "expected_status": [200],
                "contains": "<repomd",
            },
            {
                "endpoint_role": "metadata",
                "method": "head",
                "path": f"{root}/repodata/repomd.xml",
                "expected_status": [200],
            },
            {
                "endpoint_role": "packages",
                "method": "head",
                "path": f"{root}/RPMS/{{package_name}}",
                "expected_status": [200],
            },
        ]
    elif (
        tool_id == "influxdb"
        and upstream_key == INFLUXDB_UPSTREAM
        and entry["provider_id"] in INFLUXDB_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = list(INFLUXDB_APT_REPOSITORY_VERSIONS)
        if entry["provider_id"] == "ustc":
            compatibility["repository_versions"] = [
                version
                for version in compatibility["repository_versions"]
                if version.startswith("debian-")
            ]
        delivery_mode = "mirror"
        root = "/{family}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/stable/InRelease", "expected_status": [200], "contains": "Origin: InfluxDB"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/stable/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/stable/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/packages/{{package_name}}", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/packages/influxdb2-client_2.7.5-3_{{architecture}}.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "influxdb"
        and upstream_key == INFLUXDB_UPSTREAM
        and entry["provider_id"] in {"nju", "tuna"}
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = INFLUXDB_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/yum/el9-x86_64"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/{{package_name}}", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/influxdb2-client_2.7.5-3.x86_64.rpm", "expected_status": [200]},
        ]
    elif (
        tool_id == "mariadb"
        and upstream_key == MARIADB_UPSTREAM
        and entry["provider_id"] in MARIADB_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = MARIADB_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/repo/11.8/{family}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/{{release}}/InRelease", "expected_status": [200], "contains": "Origin: MariaDB"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/m/mariadb/mariadb-server_11.8.9+maria~{{platform_tag}}_{{architecture}}.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "mariadb"
        and upstream_key == MARIADB_UPSTREAM
        and entry["provider_id"] in MARIADB_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = MARIADB_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/yum/11.8/rhel/9/{architecture}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/rpms/MariaDB-server-11.8.9-1.el9.{{architecture}}.rpm", "expected_status": [200]},
        ]
    elif (
        tool_id == "postgresql"
        and upstream_key == POSTGRESQL_UPSTREAM
        and entry["provider_id"] in {"aliyun", "nju"}
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = POSTGRESQL_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/repos/apt"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/{{release}}-pgdg/InRelease", "expected_status": [200], "contains": "Origin: apt.postgresql.org"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}-pgdg/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}-pgdg/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/p/postgresql-17/postgresql-17_17.11-1.pgdg{{platform_tag}}+2_{{architecture}}.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "postgresql"
        and upstream_key == POSTGRESQL_UPSTREAM
        and entry["provider_id"] in POSTGRESQL_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = POSTGRESQL_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/repos/yum/17/redhat/rhel-9-{architecture}"
        package = "postgresql17-server-17.5-2PGDG.rhel9.{architecture}.rpm" if entry["provider_id"] == "huaweicloud" else "postgresql17-server-17.9-1PGDG.rhel9.7.{architecture}.rpm"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/{package}", "expected_status": [200]},
        ]
    elif (
        tool_id == "elasticstack"
        and upstream_key == ELASTICSTACK_UPSTREAM
        and entry["provider_id"] in ELASTICSTACK_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ELASTICSTACK_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/9.x/apt"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/stable/InRelease", "expected_status": [200], "contains": "Origin: elastic"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/stable/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/stable/main/binary-amd64/Packages.gz", "expected_status": [200]},
            *[
                {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/{product[0]}/{product}/{product}-9.5.2-amd64.deb", "expected_status": [200]}
                for product in ["elasticsearch", "kibana", "logstash", "filebeat"]
            ],
        ]
    elif (
        tool_id == "grafana"
        and upstream_key == GRAFANA_UPSTREAM
        and entry["provider_id"] in GRAFANA_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = GRAFANA_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/apt"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/stable/InRelease", "expected_status": [200], "contains": "Architectures: amd64 arm64"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/stable/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/stable/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/g/grafana/grafana_13.2.0_32077357341_linux_{{architecture}}.deb", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/g/grafana-enterprise/grafana-enterprise_13.2.0_32077357341_linux_{{architecture}}.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "zabbix"
        and upstream_key == ZABBIX_UPSTREAM
        and entry["provider_id"] in ZABBIX_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ZABBIX_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        stable = "/zabbix/7.4/stable/{family}"
        release = "/zabbix/7.4/release/{family}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{stable}/dists/{{release}}/InRelease", "expected_status": [200], "contains": "Origin: Zabbix"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{stable}/dists/{{release}}/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{stable}/dists/{{release}}/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{stable}/pool/main/z/zabbix/zabbix-server-pgsql_7.4.14-1+{{platform_tag}}_{{architecture}}.deb", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{stable}/pool/main/z/zabbix/zabbix-agent2_7.4.14-1+{{platform_tag}}_{{architecture}}.deb", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{release}/pool/main/z/zabbix-release/zabbix-release_7.4-3+{{platform_tag}}_all.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "zabbix"
        and upstream_key == ZABBIX_UPSTREAM
        and entry["provider_id"] in ZABBIX_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ZABBIX_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/zabbix/7.4/stable/rhel/9/{architecture}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/zabbix-server-pgsql-7.4.14-release1.el9.{{architecture}}.rpm", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/zabbix-agent2-7.4.14-release1.el9.{{architecture}}.rpm", "expected_status": [200]},
        ]
    elif (
        tool_id == "gitlab-runner"
        and upstream_key == GITLAB_RUNNER_UPSTREAM
        and entry["provider_id"] in GITLAB_RUNNER_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = GITLAB_RUNNER_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/{family}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/{{release}}/InRelease", "expected_status": [200], "contains": "Origin: packages.gitlab.com/runner/gitlab-runner"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/g/gitlab-runner/gitlab-runner_19.3.1-1_{{architecture}}.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "gitlab-runner"
        and upstream_key == GITLAB_RUNNER_UPSTREAM
        and entry["provider_id"] in GITLAB_RUNNER_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = GITLAB_RUNNER_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/yum/el9-{architecture}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml.asc", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml.key", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/Packages/g/gitlab-runner-19.3.1-1.{{architecture}}.rpm", "expected_status": [200]},
        ]
    elif (
        tool_id == "ceph"
        and upstream_key == CEPH_UPSTREAM
        and entry["provider_id"] in CEPH_ENDPOINTS
        and entry["raw_name"].endswith("-apt-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = CEPH_APT_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/debian-squid"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/{{release}}/InRelease", "expected_status": [200], "contains": "Origin: ceph.com"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/Release.gpg", "expected_status": [200]},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/main/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/main/c/ceph/ceph_19.2.6-1{{release}}_{{architecture}}.deb", "expected_status": [200]},
        ]
    elif (
        tool_id == "ceph"
        and upstream_key == CEPH_UPSTREAM
        and entry["provider_id"] in CEPH_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = CEPH_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/rpm-squid/el9/{architecture}"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            {"endpoint_role": "packages", "method": "head", "path": f"{root}/ceph-19.2.6-0.el9.{{architecture}}.rpm", "expected_status": [200]},
        ]
    elif (
        tool_id == "nginx"
        and upstream_key == NGINX_UPSTREAM
        and entry["provider_id"] in NGINX_ENDPOINTS
        and entry["raw_name"].endswith("-runtime")
    ):
        channel = "mainline" if "-mainline-" in entry["raw_name"] else "stable"
        manager = "rpm" if "-rpm-" in entry["raw_name"] else "apt"
        prefix = "/mainline" if channel == "mainline" else ""
        version = "1.31.4" if channel == "mainline" else "1.30.4"
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        if manager == "apt":
            compatibility["repository_versions"] = [
                f"{family}-{release}-{channel}-{architecture}"
                for family, release in [("debian", "bookworm"), ("ubuntu", "jammy"), ("ubuntu", "noble")]
                for architecture in ["amd64", "arm64"]
            ]
            root = f"{prefix}/{{family}}"
            probes = [
                {"endpoint_role": "index", "method": "get", "path": f"{root}/dists/{{release}}/InRelease", "expected_status": [200], "contains": "Origin: nginx"},
                {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/Release.gpg", "expected_status": [200]},
                {"endpoint_role": "metadata", "method": "head", "path": f"{root}/dists/{{release}}/nginx/binary-{{architecture}}/Packages.gz", "expected_status": [200]},
                {"endpoint_role": "packages", "method": "head", "path": f"{root}/pool/nginx/n/nginx/nginx_{version}-1~{{release}}_{{architecture}}.deb", "expected_status": [200]},
            ]
        else:
            compatibility["repository_versions"] = [
                f"el-9-{channel}-{architecture}" for architecture in ["x86_64", "aarch64"]
            ]
            root = f"{prefix}/rhel/9/{{architecture}}"
            probes = [
                {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
                {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
                {"endpoint_role": "packages", "method": "head", "path": f"{root}/RPMS/nginx-{version}-1.el9.ngx.{{architecture}}.rpm", "expected_status": [200]},
            ]
    elif (
        tool_id == "elasticstack"
        and upstream_key == ELASTICSTACK_UPSTREAM
        and entry["provider_id"] in ELASTICSTACK_ENDPOINTS
        and entry["raw_name"].endswith("-rpm-runtime")
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        compatibility["repository_versions"] = ELASTICSTACK_RPM_REPOSITORY_VERSIONS
        delivery_mode = "mirror"
        root = "/9.x/yum"
        probes = [
            {"endpoint_role": "index", "method": "get", "path": f"{root}/repodata/repomd.xml", "expected_status": [200], "contains": "<repomd"},
            {"endpoint_role": "metadata", "method": "head", "path": f"{root}/repodata/repomd.xml", "expected_status": [200]},
            *[
                {"endpoint_role": "packages", "method": "head", "path": f"{root}/9.5.2/{product}-9.5.2-{{architecture}}.rpm", "expected_status": [200]}
                for product in ["elasticsearch", "kibana", "logstash", "filebeat"]
            ],
        ]
    elif (
        tool_id in {"pip", "pdm", "poetry", "uv"}
        and upstream_key == PIP_RUNTIME_UPSTREAM
        and entry["raw_name"] in PIP_RUNTIME_ENTRY_NAMES
    ):
        compatibility["operating_systems"] = (
            ["linux", "macos", "windows"] if tool_id in {"pip", "uv"} else ["linux"]
        )
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "proxy" if entry["provider_id"] == "ustc" else "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/sampleproject/",
                "expected_status": [200],
                "expected_content_type": "text/html",
                "contains": "sampleproject-",
            }
        ]
        if tool_id in {"pdm", "poetry", "uv"}:
            probes.append(
                {
                    "endpoint_role": "artifacts",
                    "method": "get",
                    "path": "/d7/73/c16e5f3f0d37c60947e70865c255a58dc408780a6474de0523afd0ec553a/sampleproject-4.0.0-py3-none-any.whl",
                    "expected_status": [200, 206],
                    "contains": "PK",
                }
            )
    elif (
        tool_id in NPM_REGISTRY_TOOLS
        and upstream_key == NPM_RUNTIME_UPSTREAM
        and entry["raw_name"] in NPM_RUNTIME_ENTRY_NAMES
        and entry["provider_id"] in NPM_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "proxy"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/is-number/latest",
                "expected_status": [200, 206],
                "expected_content_type": "application/json",
                "contains": '"name":"is-number"',
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/is-number/-/is-number-7.0.0.tgz",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
        ]
    elif (
        tool_id == "conda"
        and upstream_key == CONDA_RUNTIME_UPSTREAM
        and entry["provider_id"] in CONDA_ACTIONABLE_PROVIDERS
    ):
        compatibility["operating_systems"] = ["linux"]
        compatibility["architectures"] = ["x86_64", "arm64"]
        compatibility["environments"] = ["container", "host"]
        compatibility["distributions"] = []
        delivery_mode = "mirror"
        probes = [
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/pkgs/main/noarch/repodata.json.zst",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/pkgs/main/{subdir}/repodata.json.zst",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/cloud/conda-forge/noarch/repodata.json.zst",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/cloud/conda-forge/{subdir}/repodata.json.zst",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
            {
                "endpoint_role": "index",
                "method": "get",
                "path": "/pkgs/main/{subdir}/{representative_package}",
                "expected_status": [200, 206],
                "expected_content_type": "application/octet-stream",
            },
        ]
    return compatibility, delivery_mode, probes


def build(inventory: dict[str, Any], revision: int, generated_at: str) -> dict[str, Any]:
    planned_entries = []
    for source in inventory["entries"]:
        entry = source
        targets = list(source["adapter_targets"])
        packagist_source = any(
            item.get("webUrl", "").rstrip("/") == "https://packagist.org"
            for item in source.get("provider_metadata", {}).get("sources", [])
        )
        if source["raw_name"] == "php" and packagist_source:
            entry = {**source, "adapter_state": "planned"}
            if not any(target["tool_id"] == "composer" for target in targets):
                targets.append(
                    {
                        "tool_id": "composer",
                        "state": "planned",
                        "issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/55",
                    }
                )
            entry["adapter_targets"] = targets
        if source["raw_name"] == "maven" and source["provider_id"] in MAVEN_REGISTRY_ENDPOINTS:
            entry = {**source, "adapter_state": "planned"}
            if not any(target["tool_id"] == "leiningen" for target in targets):
                targets.append(
                    {
                        "tool_id": "leiningen",
                        "state": "planned",
                        "issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/62",
                    }
                )
            entry["adapter_targets"] = targets
        if source["raw_name"] == "dart-pub":
            entry = {**source, "adapter_state": "planned"}
            if not any(target["tool_id"] == "flutter" for target in targets):
                targets.append(
                    {
                        "tool_id": "flutter",
                        "state": "planned",
                        "issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/66",
                    }
                )
            entry["adapter_targets"] = targets
        if source["raw_name"] == "python" and source["provider_id"] in PYENV_ENDPOINTS:
            entry = {**source, "adapter_state": "planned"}
            if not any(target["tool_id"] == "pyenv" for target in targets):
                targets.append(
                    {
                        "tool_id": "pyenv",
                        "state": "planned",
                        "issue": "https://github.com/vibelab-tools/MirrorSwitch/issues/69",
                    }
                )
            entry["adapter_targets"] = targets
        if entry["adapter_state"] == "planned":
            if (
                any(target["tool_id"] == "mysql" for target in targets)
                and entry["provider_id"] in MYSQL_ENDPOINTS
                and entry["raw_name"] in {"mysql", "mysql-repo"}
            ):
                surfaces = ["rpm"]
                if entry["provider_id"] in {"tuna", "ustc"}:
                    surfaces.insert(0, "apt")
                for surface in surfaces:
                    planned_entries.append(
                        {
                            **entry,
                            "raw_name": f"{entry['raw_name']}-{surface}-runtime",
                        }
                    )
            elif (
                any(target["tool_id"] == "mongodb" for target in targets)
                and entry["provider_id"] in MONGODB_ENDPOINTS
                and entry["provider_id"] != "aliyun"
                and entry["raw_name"] == "mongodb"
            ):
                for surface in ["apt", "rpm"]:
                    planned_entries.append(
                        {
                            **entry,
                            "raw_name": f"mongodb-{surface}-runtime",
                        }
                    )
            elif (
                any(target["tool_id"] == "influxdb" for target in targets)
                and entry["provider_id"] in INFLUXDB_ENDPOINTS
                and entry["raw_name"] == "influxdata"
            ):
                surfaces = ["apt", "rpm"] if entry["provider_id"] in {"nju", "tuna"} else ["apt"]
                for surface in surfaces:
                    planned_entries.append(
                        {
                            **entry,
                            "raw_name": f"influxdata-{surface}-runtime",
                        }
                    )
            elif (
                any(target["tool_id"] == "mariadb" for target in targets)
                and entry["provider_id"] in MARIADB_ENDPOINTS
                and entry["raw_name"] == "mariadb"
            ):
                for surface in ["apt", "rpm"]:
                    planned_entries.append({**entry, "raw_name": f"mariadb-{surface}-runtime"})
            elif (
                any(target["tool_id"] == "postgresql" for target in targets)
                and entry["provider_id"] in POSTGRESQL_ENDPOINTS
                and entry["raw_name"] == "postgresql"
            ):
                surfaces = ["rpm"] if entry["provider_id"] == "huaweicloud" else ["apt", "rpm"]
                for surface in surfaces:
                    planned_entries.append({**entry, "raw_name": f"postgresql-{surface}-runtime"})
            elif (
                any(target["tool_id"] == "elasticstack" for target in targets)
                and entry["provider_id"] in ELASTICSTACK_ENDPOINTS
                and entry["raw_name"] == "elasticstack"
            ):
                for surface in ["apt", "rpm"]:
                    planned_entries.append({**entry, "raw_name": f"elasticstack-{surface}-runtime"})
            elif (
                any(target["tool_id"] == "grafana" for target in targets)
                and entry["provider_id"] in GRAFANA_ENDPOINTS
                and entry["raw_name"] == "grafana"
            ):
                planned_entries.append({**entry, "raw_name": "grafana-apt-runtime"})
            elif (
                any(target["tool_id"] == "zabbix" for target in targets)
                and entry["provider_id"] in ZABBIX_ENDPOINTS
                and entry["raw_name"] == "zabbix"
            ):
                for surface in ["apt", "rpm"]:
                    planned_entries.append({**entry, "raw_name": f"zabbix-{surface}-runtime"})
            elif (
                any(target["tool_id"] == "gitlab-runner" for target in targets)
                and entry["provider_id"] in GITLAB_RUNNER_ENDPOINTS
                and entry["raw_name"] == "gitlab-runner"
            ):
                for surface in ["apt", "rpm"]:
                    planned_entries.append({**entry, "raw_name": f"gitlab-runner-{surface}-runtime"})
            elif (
                any(target["tool_id"] == "ceph" for target in targets)
                and entry["provider_id"] in CEPH_ENDPOINTS
                and entry["raw_name"] == "ceph"
            ):
                for surface in ["apt", "rpm"]:
                    planned_entries.append({**entry, "raw_name": f"ceph-{surface}-runtime"})
            elif (
                any(target["tool_id"] == "nginx" for target in targets)
                and entry["provider_id"] in NGINX_ENDPOINTS
                and entry["raw_name"] == "nginx"
            ):
                for channel in ["stable", "mainline"]:
                    for surface in ["apt", "rpm"]:
                        planned_entries.append({**entry, "raw_name": f"nginx-{channel}-{surface}-runtime"})
            elif entry["raw_name"] == "elpa":
                for archive, (family, _) in ELPA_ARCHIVES.items():
                    root = entry["public_endpoints"][0]["url"].rstrip("/")
                    planned_entries.append(
                        {
                            **entry,
                            "raw_name": f"elpa/{archive}",
                            "normalized_upstream": family,
                            "public_endpoints": [
                                {
                                    "url": f"{root}/{archive}/",
                                    "protocol": "https",
                                    "derivation": "reviewed-elpa-archive-subpath",
                                }
                            ],
                        }
                    )
            else:
                planned_entries.append(entry)
    active_providers = {entry["provider_id"] for entry in planned_entries}
    providers = [
        {
            "id": provider["id"],
            "display_name": provider["display_name"],
            "catalog_source": provider["homepage"],
        }
        for provider in inventory["providers"]
        if provider["id"] in active_providers
    ]

    upstream_map: dict[str, dict[str, Any]] = {}
    tool_map: dict[str, dict[str, Any]] = {}
    candidate_map: dict[str, dict[str, Any]] = {}
    for entry in planned_entries:
        for target in entry["adapter_targets"]:
            tool_id = target["tool_id"]
            upstream_family, content_kind = runtime_upstream_identity(entry, tool_id)
            upstream_key = upstream_id(upstream_family, content_kind)
            upstream = upstream_map.setdefault(
                upstream_key,
                {
                    "id": upstream_key,
                    "family": upstream_family,
                    "display_name": upstream_family,
                    "content_kind": content_kind,
                    "aliases": set(),
                },
            )
            upstream["aliases"].add(entry["raw_name"])
            tool = {
                "id": tool_id,
                "adapter_key": tool_id,
                "display_name": tool_id,
                "state": (
                    "supported"
                    if tool_id
                    in {
                        "apk",
                        "apt",
                        "bazel",
                        "bioconductor",
                        "bundler",
                        "cabal",
                        "cargo",
                        "ceph",
                        "composer",
                        "cocoapods",
                        "conda",
                        "containerd",
                        "cpan",
                        "cran",
                        "cygwin",
                        "dnf",
                        "docker-ce",
                        "elasticstack",
                        "elpa",
                        "dart-pub",
                        "flatpak",
                        "fnm",
                        "flutter",
                        "go",
                        "ghcup",
                        "gitlab-runner",
                        "grafana",
                        "homebrew",
                        "rubygems",
                        "rustup",
                        "ros",
                        "sbt",
                        "scoop",
                        "stack",
                        "tlmgr",
                        "gradle",
                        "guix",
                        "influxdb",
                        "julia",
                        "kubernetes-images",
                        "kubernetes-packages",
                        "leiningen",
                        "macports",
                        "mariadb",
                        "maven",
                        "mongodb",
                        "mysql",
                        "msys2",
                        "nginx",
                        "nix",
                        "nix-macos",
                        "npm",
                        "nvm",
                        "nuget",
                        "opkg",
                        "opam",
                        "pdm",
                        "pip",
                        "pnpm",
                        "poetry",
                        "podman-registry",
                        "uv",
                        "winget",
                        "yum",
                        "yarn",
                        "pacman",
                        "portage",
                        "postgresql",
                        "pyenv",
                        "xbps",
                        "zypper",
                        "zabbix",
                    }
                    else target["state"]
                ),
                "implementation_issue": target["issue"],
                "supported_scopes": tool_scopes(tool_id),
                "composition": "single",
            }
            existing_tool = tool_map.setdefault(tool_id, tool)
            if existing_tool["implementation_issue"] != target["issue"]:
                raise ValueError(f"tool {tool_id} maps to multiple implementation issues")

            endpoints = candidate_endpoints(entry, tool_id, upstream_key)
            compatibility, delivery_mode, probes = runtime_properties(
                entry, tool_id, upstream_key
            )
            grouping = json.dumps(
                [
                    entry["provider_id"],
                    upstream_key,
                    tool_id,
                    endpoints,
                    compatibility,
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            candidate_id = hashlib.sha256(grouping.encode()).hexdigest()[:24]
            runtime_content_validated = (
                tool_id == "pyenv"
                and upstream_key == PYENV_RUNTIME_UPSTREAM
                and bool(probes)
            )
            candidate = candidate_map.setdefault(
                candidate_id,
                {
                    "id": candidate_id,
                    "provider_id": entry["provider_id"],
                    "upstream_id": upstream_key,
                    "tool_id": tool_id,
                    "catalog_state": "partial"
                    if not compatibility["operating_systems"]
                    or (
                        not runtime_content_validated
                        and any(
                            endpoint["derivation"].endswith("not-published-in-listing")
                            for endpoint in entry["public_endpoints"]
                        )
                    )
                    else "cataloged",
                    "delivery_mode": delivery_mode,
                    "raw_names": set(),
                    "endpoints": endpoints,
                    "compatibility": compatibility,
                    "probes": [],
                    "source_urls": set(),
                    "observed_at": entry["observed_at"],
                },
            )
            candidate["raw_names"].add(entry["raw_name"])
            candidate["source_urls"].add(entry["source_url"])
            for probe in probes:
                if probe not in candidate["probes"]:
                    candidate["probes"].append(probe)

    upstreams = []
    for upstream in upstream_map.values():
        upstream["aliases"] = sorted(
            upstream["aliases"], key=lambda value: (value.casefold(), value)
        )
        upstreams.append(upstream)
    candidates = []
    for candidate in candidate_map.values():
        candidate["raw_names"] = sorted(
            candidate["raw_names"], key=lambda value: (value.casefold(), value)
        )
        candidate["source_urls"] = sorted(candidate["source_urls"])
        candidates.append(candidate)

    inventory_bytes = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    content_digest = hashlib.sha256(
        inventory_bytes + b"\0runtime-catalog-format-" + CATALOG_FORMAT_REVISION.encode()
    ).hexdigest()[:12]
    observed_day = inventory["observed_at"].split("T", 1)[0].replace("-", ".")
    return {
        "schema_version": 2,
        "content_version": f"{observed_day}+{content_digest}",
        "content_revision": revision,
        "generated_at": generated_at,
        "providers": sorted(providers, key=lambda item: item["id"]),
        "upstreams": sorted(upstreams, key=lambda item: item["id"]),
        "tools": sorted(tool_map.values(), key=lambda item: item["id"]),
        "candidates": sorted(candidates, key=lambda item: item["id"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", default="catalog/provider-inventory.json")
    parser.add_argument("--output", default="catalog/mirrors.json")
    parser.add_argument("--content-revision", type=int)
    parser.add_argument("--generated-at")
    args = parser.parse_args()

    generated_at = args.generated_at or utc_now()
    revision = args.content_revision or int(
        datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    )
    inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    catalog = build(inventory, revision, generated_at)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {len(catalog['candidates'])} candidates for {len(catalog['tools'])} tools to {output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
