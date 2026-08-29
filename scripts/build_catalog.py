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
    "mariadb",
    "mongodb",
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
    "nix-macos",
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

CATALOG_FORMAT_REVISION = "37"

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


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def upstream_id(family: str, content_type: str) -> str:
    return f"{family}--{content_type}"


def runtime_upstream_identity(
    entry: dict[str, Any], tool_id: str
) -> tuple[str, str]:
    if tool_id == "sbt" and entry["raw_name"] == "maven":
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
    return entry["normalized_upstream"], entry["content_type"]


def tool_scopes(tool_id: str) -> list[str]:
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
    if tool_id in {"flatpak", "nix"}:
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
    if tool_id in {"maven", "sbt"}:
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
        if tool_id == "nix" and upstream_key == NIX_RUNTIME_UPSTREAM:
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
    if (
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
        compatibility["operating_systems"] = ["linux"]
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
    elif (
        tool_id in {"pip", "pdm", "poetry", "uv"}
        and upstream_key == PIP_RUNTIME_UPSTREAM
        and entry["raw_name"] in PIP_RUNTIME_ENTRY_NAMES
    ):
        compatibility["operating_systems"] = ["linux"]
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
        if entry["adapter_state"] == "planned":
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
                        "bundler",
                        "cabal",
                        "cargo",
                        "composer",
                        "conda",
                        "dnf",
                        "flatpak",
                        "fnm",
                        "go",
                        "ghcup",
                        "rubygems",
                        "rustup",
                        "sbt",
                        "stack",
                        "gradle",
                        "guix",
                        "maven",
                        "nix",
                        "npm",
                        "nvm",
                        "nuget",
                        "opkg",
                        "pdm",
                        "pip",
                        "pnpm",
                        "poetry",
                        "uv",
                        "yum",
                        "yarn",
                        "pacman",
                        "portage",
                        "xbps",
                        "zypper",
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
            candidate = candidate_map.setdefault(
                candidate_id,
                {
                    "id": candidate_id,
                    "provider_id": entry["provider_id"],
                    "upstream_id": upstream_key,
                    "tool_id": tool_id,
                    "catalog_state": "partial"
                    if not compatibility["operating_systems"]
                    or any(
                        endpoint["derivation"].endswith("not-published-in-listing")
                        for endpoint in entry["public_endpoints"]
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
