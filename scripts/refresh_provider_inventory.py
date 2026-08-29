#!/usr/bin/env python3
"""Refresh the six-provider public mirror inventory from official listings."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen


USER_AGENT = "MirrorSwitch-inventory/0.1 (+https://github.com/vibelab-tools/MirrorSwitch)"

PROVIDERS = {
    "aliyun": {
        "display_name": "Alibaba Cloud",
        "homepage": "https://developer.aliyun.com/mirror/",
        "sources": [
            "https://developer.aliyun.com/mirror/?serviceType=mirror",
            "https://developer.aliyun.com/mirror/?pageNum=2&serviceType=mirror",
        ],
    },
    "huaweicloud": {
        "display_name": "Huawei Cloud",
        "homepage": "https://mirrors.huaweicloud.com/",
        "sources": ["https://mirrors.huaweicloud.com/v1/repositories"],
    },
    "ustc": {
        "display_name": "USTC",
        "homepage": "https://mirrors.ustc.edu.cn/",
        "sources": ["https://mirrors.ustc.edu.cn/help/index.html"],
    },
    "tuna": {
        "display_name": "Tsinghua TUNA",
        "homepage": "https://mirrors.tuna.tsinghua.edu.cn/",
        "sources": [
            "https://raw.githubusercontent.com/tuna/mirror-web/master/_helpz/enabled.yaml"
        ],
    },
    "nju": {
        "display_name": "Nanjing University",
        "homepage": "https://mirrors.nju.edu.cn/",
        "sources": [
            "https://mirrors.nju.edu.cn/configs/tunasync.json",
            "https://mirrors.nju.edu.cn/configs/addition.json",
        ],
    },
    "sjtug": {
        "display_name": "SJTUG",
        "homepage": "https://mirror.sjtu.edu.cn/",
        "sources": ["https://mirror.sjtu.edu.cn/lug/v1/manager/summary"],
    },
}

USTC_NON_REPOSITORY_PAGES = {
    "contributor",
    "index",
    "quickstart",
    "rsync-guide",
}

ALIASES = {
    "brew.git": "homebrew",
    "brew": "homebrew",
    "homebrew.git": "homebrew",
    "homebrew-core.git": "homebrew-core",
    "homebrew-cask.git": "homebrew-cask",
    "homebrew-install.git": "homebrew-install",
    "crates.io-index.git": "crates.io-index",
    "dockerhub": "docker-hub",
    "docker-hub": "docker-hub",
    "node": "nodejs",
    "node.js": "nodejs",
    "ubuntu-old-releases": "oldubuntu-releases",
    "ubuntu-oldrelease": "oldubuntu-releases",
    "opensuse": "opensuse",
    "suse": "opensuse",
    "archlinux-cn": "archlinuxcn",
    "rockylinux": "rocky",
    "voidlinux": "void",
    "pypi-packages": "pypi",
    "python-release": "python-releases",
    "nodejs-release": "nodejs",
    "fedora/linux": "fedora",
}

LANGUAGE_REGISTRIES = {
    "anaconda",
    "bioconductor",
    "clojars",
    "conan",
    "cpan",
    "cran",
    "crates.io-index",
    "ctan",
    "dart-pub",
    "elpa",
    "goproxy",
    "go",
    "hackage",
    "julia",
    "julia-pkg",
    "maven",
    "nuget",
    "npm",
    "opam",
    "packagist",
    "pypi",
    "rubygems",
    "rust",
    "stackage",
}

ALIYUN_PUBLISHED_MIRRORS = {
    "goproxy": {
        "detail_url": "https://developer.aliyun.com/mirror/goproxy",
        "endpoint": "https://mirrors.aliyun.com/goproxy/",
    },
}

SYSTEM_REPOSITORY_MARKERS = {
    "almalinux",
    "alpine",
    "archlinux",
    "archlinuxarm",
    "archlinuxcn",
    "centos",
    "debian",
    "deepin",
    "epel",
    "fedora",
    "gentoo",
    "immortalwrt",
    "kali",
    "manjaro",
    "openeuler",
    "opensuse",
    "openwrt",
    "rocky",
    "ubuntu",
    "void",
}

RELEASE_MARKERS = {
    "adoptium",
    "electron",
    "flutter",
    "ghcup",
    "julia-releases",
    "nodejs",
    "nwjs",
    "openjdk",
    "pyenv",
    "rust-static",
    "rustup",
}

ISSUE_TARGETS: list[tuple[set[str], list[tuple[str, int]]]] = [
    ({"debian", "ubuntu", "debian-security", "ubuntu-ports"}, [("apt", 27)]),
    ({"fedora", "rocky", "almalinux", "openeuler"}, [("dnf", 28)]),
    ({"centos", "centos-stream", "centos-vault", "epel"}, [("yum", 29)]),
    ({"archlinux", "archlinuxarm", "archlinuxcn", "manjaro"}, [("pacman", 30)]),
    ({"opensuse"}, [("zypper", 31)]),
    ({"gentoo", "gentoo-portage"}, [("portage", 32)]),
    ({"alpine"}, [("apk", 33)]),
    ({"void"}, [("xbps", 34)]),
    ({"nix", "nix-channels", "nixos"}, [("nix", 35), ("nix-macos", 97)]),
    ({"guix"}, [("guix", 36)]),
    ({"flatpak", "flathub"}, [("flatpak", 37)]),
    ({"openwrt", "immortalwrt"}, [("opkg", 38)]),
    ({"pypi"}, [("pip", 39), ("pdm", 43), ("poetry", 45), ("uv", 46)]),
    ({"npm"}, [("npm", 40), ("yarn", 41), ("pnpm", 44)]),
    ({"anaconda"}, [("conda", 42)]),
    ({"gradle"}, [("gradle", 47)]),
    ({"maven"}, [("maven", 48), ("gradle", 47), ("sbt", 61)]),
    ({"nodejs"}, [("nvm", 49), ("fnm", 50)]),
    ({"iojs"}, [("nvm", 49)]),
    ({"go", "goproxy"}, [("go", 51)]),
    ({"rubygems"}, [("rubygems", 52), ("bundler", 58)]),
    ({"crates.io-index"}, [("cargo", 53)]),
    ({"rust-static", "rustup"}, [("rustup", 54)]),
    ({"packagist", "composer"}, [("composer", 55)]),
    ({"nuget"}, [("nuget", 56), ("nuget-windows", 107)]),
    ({"hackage"}, [("cabal", 57)]),
    ({"stackage"}, [("stack", 59)]),
    ({"ghcup"}, [("ghcup", 60)]),
    ({"sbt", "ivy"}, [("sbt", 61)]),
    ({"clojars", "leiningen"}, [("leiningen", 62)]),
    ({"dart-pub"}, [("dart-pub", 63)]),
    ({"bioconductor"}, [("bioconductor", 64)]),
    ({"ctan"}, [("tlmgr", 65)]),
    ({"flutter"}, [("flutter", 66)]),
    ({"cpan"}, [("cpan", 67)]),
    ({"cran"}, [("cran", 68)]),
    ({"pyenv", "python-releases"}, [("pyenv", 69)]),
    ({"bazel", "bazel-apt"}, [("bazel", 70)]),
    ({"opam"}, [("opam", 71)]),
    ({"julia", "julia-pkg"}, [("julia", 72)]),
    ({"conan"}, [("conan", 73)]),
    ({"kubernetes-images"}, [("kubernetes-images", 74)]),
    ({"docker-hub", "docker-registry"}, [("docker-registry", 75)]),
    ({"quay", "gcr", "ghcr"}, [("podman-registry", 76)]),
    ({"kubernetes"}, [("kubernetes-packages", 77)]),
    ({"docker-ce"}, [("docker-ce", 78)]),
    ({"containerd"}, [("containerd", 79)]),
    ({"elpa"}, [("elpa", 80)]),
    ({"ros"}, [("ros", 81)]),
    ({"helm"}, [("helm", 82)]),
    ({"jenkins", "jenkins-updates"}, [("jenkins", 83)]),
    ({"ros2"}, [("ros2", 84)]),
    ({"mysql"}, [("mysql", 85)]),
    ({"mongodb"}, [("mongodb", 86)]),
    ({"influxdata"}, [("influxdb", 87)]),
    ({"mariadb"}, [("mariadb", 88)]),
    ({"postgresql", "postgresql-pgdg"}, [("postgresql", 89)]),
    ({"elasticstack"}, [("elasticstack", 90)]),
    ({"grafana"}, [("grafana", 91)]),
    ({"zabbix"}, [("zabbix", 92)]),
    ({"gitlab-runner"}, [("gitlab-runner", 93)]),
    ({"ceph"}, [("ceph", 94)]),
    ({"nginx"}, [("nginx", 95)]),
    (
        {
            "homebrew",
            "homebrew-api",
            "homebrew-bottles",
            "homebrew-cask",
            "homebrew-core",
            "homebrew-install",
        },
        [("homebrew", 96)],
    ),
    ({"cocoapods"}, [("cocoapods", 98)]),
    ({"macports"}, [("macports", 99)]),
    ({"scoop"}, [("scoop", 100)]),
    ({"chocolatey"}, [("chocolatey", 101)]),
    ({"msys2"}, [("msys2", 102)]),
    ({"winget", "winget-source"}, [("winget", 103)]),
    ({"cygwin"}, [("cygwin", 104)]),
    ({"powershell-gallery"}, [("powershell-gallery", 105)]),
]

PROBE_SPECS = [
    (
        "aliyun",
        "ubuntu",
        "https://mirrors.aliyun.com/ubuntu/",
        "https://mirrors.aliyun.com/ubuntu/dists/noble/InRelease",
    ),
    (
        "huaweicloud",
        "ubuntu",
        "https://repo.huaweicloud.com/ubuntu/",
        "https://repo.huaweicloud.com/ubuntu/dists/noble/InRelease",
    ),
    (
        "ustc",
        "debian",
        "https://mirrors.ustc.edu.cn/debian/",
        "https://mirrors.ustc.edu.cn/debian/dists/stable/InRelease",
    ),
    (
        "tuna",
        "debian",
        "https://mirrors.tuna.tsinghua.edu.cn/debian/",
        "https://mirrors.tuna.tsinghua.edu.cn/debian/dists/stable/InRelease",
    ),
    (
        "nju",
        "debian",
        "https://mirrors.nju.edu.cn/debian/",
        "https://mirrors.nju.edu.cn/debian/dists/stable/InRelease",
    ),
    (
        "sjtug",
        "debian",
        "https://mirror.sjtu.edu.cn/debian/",
        "https://mirror.sjtu.edu.cn/debian/dists/stable/InRelease",
    ),
]


@dataclass
class Fetched:
    url: str
    body: bytes
    retrieved_at: str

    def source_snapshot(self, discovered: int, included: int, excluded: list[dict[str, str]]) -> dict[str, Any]:
        return {
            "url": self.url,
            "retrieved_at": self.retrieved_at,
            "sha256": hashlib.sha256(self.body).hexdigest(),
            "discovered_entries": discovered,
            "included_entries": included,
            "excluded_entries": excluded,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch(url: str, attempts: int = 5, timeout: int = 60, headers: dict[str, str] | None = None) -> Fetched:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        request_headers.update(headers)
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = Request(url, headers=request_headers)
            with urlopen(request, timeout=timeout) as response:
                return Fetched(url, response.read(), utc_now())
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(min(2**attempt, 8))
    raise RuntimeError(f"could not fetch {url}: {last_error}")


def normalize_name(raw_name: str) -> str:
    value = raw_name.strip().casefold().replace("_", "-").strip("/")
    value = re.sub(r"\s+", "-", value)
    for prefix in ("git/", "github/"):
        if value.startswith(prefix):
            value = value.removeprefix(prefix)
    if value.endswith(".git"):
        value = value.removesuffix(".git")
    if value.startswith("pypi/") or value == "jetson-pypi":
        value = "pypi"
    if value == "fedora/epel":
        value = "epel"
    if value == "nix-channels/store":
        value = "nix-channels"
    return ALIASES.get(value, value)


def endpoint(url: str, derivation: str) -> dict[str, str]:
    return {
        "url": url,
        "protocol": url.split(":", 1)[0].lower(),
        "derivation": derivation,
    }


def classify_content(normalized: str, raw_name: str, public_endpoints: list[dict[str, str]]) -> str:
    name = normalized.casefold()
    raw = raw_name.casefold()
    if raw.endswith(".git") or any("/git/" in item["url"] for item in public_endpoints):
        return "git-mirror"
    if "github-raw" in name or name.endswith("-raw"):
        return "raw-proxy"
    if "github-release" in name or name.endswith("-release-proxy"):
        return "release-proxy"
    if name == "homebrew-bottles" or name in {"nix", "nix-channels", "nix4loong"}:
        return "binary-cache"
    if name in LANGUAGE_REGISTRIES or any(
        token in name for token in ("maven", "pypi", "opam-cache")
    ):
        return "language-registry"
    if name == "docker-ce" or name == "kubernetes":
        return "repository-metadata"
    if name.startswith(("mysql-repo", "ros2-")) or "yum" in name:
        return "repository-metadata"
    if any(token in name for token in ("dockerhub", "docker-hub", "registry", "quay", "ghcr", "gcr")):
        return "container-registry"
    if name in RELEASE_MARKERS or any(
        token in name
        for token in (
            "cdimage",
            "releases",
            "livecd",
            "iso",
            "cloud-images",
            "gradle/distributions",
            "flutter-infra",
            "flutter-sdk",
        )
    ):
        return "release-artifacts"
    if name in SYSTEM_REPOSITORY_MARKERS or any(
        name.startswith(f"{marker}-") for marker in SYSTEM_REPOSITORY_MARKERS
    ):
        return "repository-metadata"
    return "static-files"


def platforms(normalized: str, content_type: str) -> list[str]:
    name = normalized.casefold()
    if any(token in name for token in ("homebrew", "macports", "cocoapods")):
        return ["macos"]
    if any(token in name for token in ("winget", "scoop", "chocolatey", "cygwin", "msys2", "powershell")):
        return ["windows"]
    if name == "nuget":
        return ["linux", "macos", "windows"]
    if content_type in {"language-registry", "git-mirror", "release-artifacts", "raw-proxy", "release-proxy"}:
        return ["linux", "macos", "windows"]
    if content_type in {"repository-metadata", "container-registry", "binary-cache"}:
        return ["linux"]
    return []


def distributions(normalized: str, content_type: str) -> list[str]:
    if content_type != "repository-metadata":
        return []
    for marker in sorted(SYSTEM_REPOSITORY_MARKERS, key=len, reverse=True):
        if normalized == marker or normalized.startswith(f"{marker}-"):
            return [marker]
    return []


def architectures(normalized: str, provider_metadata: dict[str, Any]) -> list[str]:
    result: set[str] = set()
    catalogs = {str(value).casefold() for value in provider_metadata.get("catalog", [])}
    if "x86" in catalogs:
        result.add("x86_64")
    if "arm" in catalogs:
        result.add("arm64")
    name = normalized.casefold()
    if any(token in name for token in ("arm64", "aarch64", "archlinuxarm", "ubuntu-ports")):
        result.add("arm64")
    return sorted(result)


def adapter_targets(normalized: str, content_type: str) -> list[dict[str, Any]]:
    mappings: set[tuple[str, int]] = set()
    for names, issue_mappings in ISSUE_TARGETS:
        if normalized in names:
            mappings.update(issue_mappings)

    def add(*items: tuple[str, int]) -> None:
        mappings.update(items)

    if content_type == "repository-metadata":
        if normalized.startswith(("debian-", "ubuntu-")):
            add(("apt", 27))
        if normalized.startswith(("fedora-", "rocky-", "almalinux-", "openeuler-")):
            add(("dnf", 28))
        if normalized.startswith("centos-"):
            add(("dnf", 28), ("yum", 29))
        if normalized.startswith(("archlinux", "manjaro-")):
            add(("pacman", 30))
        if normalized.startswith("opensuse-"):
            add(("zypper", 31))
        if normalized.startswith("gentoo-"):
            add(("portage", 32))
        if normalized in {"bioarchlinux", "endeavouros"}:
            add(("pacman", 30))
        if normalized.startswith("mysql"):
            add(("mysql", 85))
        if normalized.startswith("ros2"):
            add(("ros2", 84))
        if "yum" in normalized:
            add(("yum", 29))
    if content_type == "language-registry":
        if "pypi" in normalized:
            add(("pip", 39), ("pdm", 43), ("poetry", 45), ("uv", 46))
        if "maven" in normalized:
            add(("maven", 48), ("gradle", 47), ("sbt", 61))
        if normalized.startswith("opam"):
            add(("opam", 71))
    if content_type == "release-artifacts":
        if normalized.startswith("node"):
            add(("nvm", 49), ("fnm", 50))
        if normalized.startswith("python"):
            add(("pyenv", 69))
        if normalized.startswith("flutter"):
            add(("flutter", 66))
        if normalized.startswith(("rustup", "rust-static")):
            add(("rustup", 54))
        if normalized.startswith("gradle"):
            add(("gradle", 47))
    if normalized.startswith("homebrew"):
        add(("homebrew", 96))
    if normalized.startswith("scoop"):
        add(("scoop", 100))
    if normalized.startswith("opam"):
        add(("opam", 71))
    if normalized.startswith("guix"):
        add(("guix", 36))
    if normalized.startswith("gentoo"):
        add(("portage", 32))
    if normalized.startswith("nix") and content_type in {"binary-cache", "git-mirror"}:
        add(("nix", 35), ("nix-macos", 97))
    if normalized.startswith("flutter-sdk"):
        add(("flutter", 66))
    if normalized in {"crates.io-index", "rust"}:
        add(("cargo", 53))

    return [
        {
            "tool_id": tool,
            "state": "planned",
            "issue": f"https://github.com/vibelab-tools/MirrorSwitch/issues/{issue}",
        }
        for tool, issue in sorted(mappings, key=lambda item: (item[1], item[0]))
    ]


def make_record(
    provider_id: str,
    raw_name: str,
    source_url: str,
    observed_at: str,
    public_endpoints: list[dict[str, str]],
    provider_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider_metadata = provider_metadata or {}
    normalized = normalize_name(raw_name)
    content_type = classify_content(normalized, raw_name, public_endpoints)
    targets = adapter_targets(normalized, content_type)
    identity = "\0".join([provider_id, raw_name, source_url])
    return {
        "id": f"{provider_id}:{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
        "provider_id": provider_id,
        "raw_name": raw_name,
        "normalized_upstream": normalized,
        "source_url": source_url,
        "observed_at": observed_at,
        "public_endpoints": public_endpoints,
        "content_type": content_type,
        "compatibility": {
            "operating_systems": platforms(normalized, content_type),
            "distributions": distributions(normalized, content_type),
            "versions": [],
            "architectures": architectures(normalized, provider_metadata),
            "evidence": "Only dimensions explicit in the listing or name are recorded; empty means unspecified by provider.",
        },
        "inventory_state": "cataloged",
        "adapter_state": "planned" if targets else "not-supported",
        "adapter_targets": targets,
        "validation": {
            "status": "pending-adapter",
            "reason": "A tool-specific metadata/artifact probe is required before this entry can become supported.",
        },
        "provider_metadata": provider_metadata,
    }


def collect_aliyun(observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: dict[str, dict[str, Any]] = {}
    snapshots = []
    pattern = re.compile(rb'href=["\'](/mirror/([^"\'/?#]+))["\']', re.IGNORECASE)
    for url in PROVIDERS["aliyun"]["sources"]:
        fetched = fetch(url)
        names = sorted({html.unescape(match.group(2).decode("utf-8")) for match in pattern.finditer(fetched.body)})
        for raw_name in names:
            records.setdefault(
                raw_name,
                make_record(
                    "aliyun",
                    raw_name,
                    url,
                    observed_at,
                    [
                        endpoint(
                            f"https://mirrors.aliyun.com/{quote(raw_name, safe='._-')}/",
                            "provider-path-convention",
                        )
                    ],
                    {"detail_url": f"https://developer.aliyun.com/mirror/{quote(raw_name, safe='._-')}"},
                ),
            )
        snapshots.append(fetched.source_snapshot(len(names), len(names), []))
    for raw_name, published in ALIYUN_PUBLISHED_MIRRORS.items():
        fetched = fetch(published["detail_url"])
        if published["endpoint"].encode() not in fetched.body:
            raise RuntimeError(
                f"published endpoint missing from {published['detail_url']}: "
                f"{published['endpoint']}"
            )
        records[raw_name] = make_record(
            "aliyun",
            raw_name,
            published["detail_url"],
            observed_at,
            [endpoint(published["endpoint"], "published-instructions")],
            {"detail_url": published["detail_url"]},
        )
        snapshots.append(fetched.source_snapshot(1, 1, []))
    return list(records.values()), snapshots


def collect_huawei(observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    url = PROVIDERS["huaweicloud"]["sources"][0]
    fetched = fetch(url)
    payload = json.loads(fetched.body)
    rows = payload["result"]["repolist"]
    records = []
    for row in rows:
        raw_name = str(row.get("name") or row.get("repoName") or row.get("displayName"))
        endpoints = []
        mirror_path = row.get("mirrorPath")
        if mirror_path:
            endpoints.append(endpoint(urljoin("https://repo.huaweicloud.com/", mirror_path), "published-path"))
        for download in row.get("download", []):
            if download.get("downloadUrl"):
                endpoints.append(
                    endpoint(
                        urljoin("https://repo.huaweicloud.com/", download["downloadUrl"]),
                        "published-download",
                    )
                )
        if row.get("mirrorUrl"):
            endpoints.append(endpoint(row["mirrorUrl"], "published-url"))
        if not endpoints:
            endpoints.append(
                endpoint(
                    f"https://repo.huaweicloud.com/{quote(raw_name, safe='._-')}/",
                    "candidate-name-path-not-published-in-listing",
                )
            )
        metadata = {
            key: row[key]
            for key in (
                "displayName",
                "online",
                "syncState",
                "updateTime",
                "validateTime",
                "catalog",
                "mirrorPath",
                "sources",
            )
            if key in row
        }
        if not mirror_path and not row.get("download") and not row.get("mirrorUrl"):
            metadata["endpoint_status"] = "candidate derived from provider path; content validation required"
        records.append(make_record("huaweicloud", raw_name, url, observed_at, endpoints, metadata))
    return records, [fetched.source_snapshot(len(rows), len(rows), [])]


def collect_ustc(observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    url = PROVIDERS["ustc"]["sources"][0]
    fetched = fetch(url)
    links = sorted(
        {
            html.unescape(value.decode("utf-8"))
            for value in re.findall(rb'href=["\']([^"\']+\.html)["\']', fetched.body, re.IGNORECASE)
        }
    )
    records = []
    excluded = []
    for link in links:
        if link.startswith("http"):
            excluded.append({"name": link, "reason": "canonical/help navigation link"})
            continue
        raw_name = Path(link).name.removesuffix(".html")
        if raw_name in USTC_NON_REPOSITORY_PAGES:
            excluded.append({"name": raw_name, "reason": "help/documentation page, not a repository"})
            continue
        records.append(
            make_record(
                "ustc",
                raw_name,
                urljoin(url, link),
                observed_at,
                [
                    endpoint(
                        f"https://mirrors.ustc.edu.cn/{quote(raw_name, safe='._-')}/",
                        "help-name-path-convention",
                    )
                ],
            )
        )
    return records, [fetched.source_snapshot(len(links), len(records), excluded)]


def collect_tuna(observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    url = PROVIDERS["tuna"]["sources"][0]
    fetched = fetch(url)
    names = []
    for raw_line in fetched.body.decode("utf-8").splitlines():
        match = re.fullmatch(r'\s*-\s*["\'](.+?)["\']\s*', raw_line)
        if match:
            names.append(match.group(1))
    records = [
        make_record(
            "tuna",
            raw_name,
            url,
            observed_at,
            [
                endpoint(
                    f"https://mirrors.tuna.tsinghua.edu.cn/{quote(raw_name, safe='._-')}/",
                    "enabled-name-path-convention",
                )
            ],
            {"help_url": f"https://mirrors.tuna.tsinghua.edu.cn/help/{quote(raw_name, safe='._-')}/"},
        )
        for raw_name in names
    ]
    return records, [fetched.source_snapshot(len(names), len(names), [])]


def collect_nju(observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records = []
    snapshots = []
    for url in PROVIDERS["nju"]["sources"]:
        fetched = fetch(url)
        rows = json.loads(fetched.body)
        for row in rows:
            raw_name = row["name"]
            if "path" in row:
                public_url = urljoin("https://mirrors.nju.edu.cn/", row["path"])
                derivation = "published-addition-path"
            else:
                public_url = f"https://mirrors.nju.edu.cn/{quote(raw_name, safe='._-')}/"
                derivation = "tunasync-name-path-convention"
            metadata = {
                key: row[key]
                for key in ("status", "last_update", "upstream", "size", "inherit", "path")
                if key in row
            }
            records.append(
                make_record(
                    "nju",
                    raw_name,
                    url,
                    observed_at,
                    [endpoint(public_url, derivation)],
                    metadata,
                )
            )
        snapshots.append(fetched.source_snapshot(len(rows), len(rows), []))
    return records, snapshots


def collect_sjtug(observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    url = PROVIDERS["sjtug"]["sources"][0]
    fetched = fetch(url)
    workers = json.loads(fetched.body)["WorkerStatus"]
    records = []
    excluded = []
    for raw_name, status in sorted(workers.items()):
        if raw_name.startswith("."):
            excluded.append({"name": raw_name, "reason": "internal status worker, not a public repository"})
            continue
        metadata = {
            key: status[key]
            for key in ("Result", "LastFinished", "Idle")
            if key in status
        }
        records.append(
            make_record(
                "sjtug",
                raw_name,
                url,
                observed_at,
                [
                    endpoint(
                        f"https://mirror.sjtu.edu.cn/{quote(raw_name, safe='._-')}/",
                        "worker-name-path-convention",
                    )
                ],
                metadata,
            )
        )
    return records, [fetched.source_snapshot(len(workers), len(records), excluded)]


COLLECTORS: dict[str, Callable[[str], tuple[list[dict[str, Any]], list[dict[str, Any]]]]] = {
    "aliyun": collect_aliyun,
    "huaweicloud": collect_huawei,
    "ustc": collect_ustc,
    "tuna": collect_tuna,
    "nju": collect_nju,
    "sjtug": collect_sjtug,
}


def run_probe(provider_id: str, upstream: str, endpoint_url: str, probe_url: str) -> dict[str, Any]:
    fetched = fetch(probe_url, headers={"Range": "bytes=0-1023"})
    prefix = fetched.body[:1024]
    valid = prefix.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----")
    return {
        "provider_id": provider_id,
        "normalized_upstream": upstream,
        "endpoint": endpoint_url,
        "probe_url": probe_url,
        "method": "GET range 0-1023",
        "expected_content": "APT InRelease clear-signed metadata",
        "checked_at": fetched.retrieved_at,
        "result": "passed" if valid else "failed",
        "response_sha256_prefix": hashlib.sha256(prefix).hexdigest(),
    }


def apply_probes(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    probes = []
    for provider_id, upstream, endpoint_url, probe_url in PROBE_SPECS:
        probe = run_probe(provider_id, upstream, endpoint_url, probe_url)
        if probe["result"] != "passed":
            raise RuntimeError(f"content probe failed: {probe_url}")
        probes.append(probe)
        matching = next(
            (
                entry
                for entry in entries
                if entry["provider_id"] == provider_id
                and entry["normalized_upstream"] == upstream
            ),
            None,
        )
        if matching is None:
            raise RuntimeError(f"probe has no inventory entry: {provider_id}/{upstream}")
        matching["validation"] = {
            "status": "passed",
            "probe_url": probe_url,
            "expected_content": probe["expected_content"],
            "checked_at": probe["checked_at"],
            "evidence_sha256": probe["response_sha256_prefix"],
        }
    return probes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="catalog/provider-inventory.json")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--observed-at", help="Override the shared observation timestamp")
    args = parser.parse_args()

    observed_at = args.observed_at or utc_now()
    entries = []
    provider_documents = []
    for provider_id, collector in COLLECTORS.items():
        print(f"collecting {provider_id}", file=sys.stderr)
        provider_entries, sources = collector(observed_at)
        entries.extend(provider_entries)
        provider_sources = list(PROVIDERS[provider_id]["sources"])
        if provider_id == "aliyun":
            provider_sources.extend(
                published["detail_url"]
                for published in ALIYUN_PUBLISHED_MIRRORS.values()
            )
        provider_documents.append(
            {
                "id": provider_id,
                **PROVIDERS[provider_id],
                "sources": provider_sources,
                "source_snapshots": sources,
                "included_entries": len(provider_entries),
            }
        )

    entries.sort(key=lambda entry: (entry["provider_id"], entry["raw_name"].casefold(), entry["source_url"]))
    probes = apply_probes(entries) if args.probe else []
    document = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "observed_at": observed_at,
        "scope": "Entries listed by the six official public provider sources at observation time; listing is not support.",
        "providers": provider_documents,
        "entries": entries,
        "content_probes": probes,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(entries)} entries to {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
