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
    "fnm",
    "go",
    "homebrew",
    "nix-macos",
    "nvm",
    "pyenv",
    "rustup",
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

CATALOG_FORMAT_REVISION = "12"

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


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def upstream_id(family: str, content_type: str) -> str:
    return f"{family}--{content_type}"


def tool_scopes(tool_id: str) -> list[str]:
    if tool_id == "nix":
        return ["system", "user"]
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
    role = ROLE_BY_CONTENT[entry["content_type"]]
    endpoints = []
    for item in entry["public_endpoints"]:
        url = item["url"]
        if tool_id == "nix" and upstream_key == NIX_RUNTIME_UPSTREAM:
            url = url.replace("nix-channels%2Fstore", "nix-channels/store")
            if not url.rstrip("/").endswith("/store"):
                url = url.rstrip("/") + "/store/"
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
    if tool_id == "apt" and upstream_key in APT_RUNTIME_UPSTREAMS:
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
    return compatibility, delivery_mode, probes


def build(inventory: dict[str, Any], revision: int, generated_at: str) -> dict[str, Any]:
    planned_entries = [
        entry for entry in inventory["entries"] if entry["adapter_state"] == "planned"
    ]
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
        upstream_key = upstream_id(entry["normalized_upstream"], entry["content_type"])
        upstream = upstream_map.setdefault(
            upstream_key,
            {
                "id": upstream_key,
                "family": entry["normalized_upstream"],
                "display_name": entry["normalized_upstream"],
                "content_kind": entry["content_type"],
                "aliases": set(),
            },
        )
        upstream["aliases"].add(entry["raw_name"])

        for target in entry["adapter_targets"]:
            tool_id = target["tool_id"]
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
                        "dnf",
                        "guix",
                        "nix",
                        "yum",
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
