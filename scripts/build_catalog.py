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


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def upstream_id(family: str, content_type: str) -> str:
    return f"{family}--{content_type}"


def tool_scopes(tool_id: str) -> list[str]:
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


def candidate_endpoints(entry: dict[str, Any]) -> list[dict[str, str]]:
    role = ROLE_BY_CONTENT[entry["content_type"]]
    return [
        {"role": role, "protocol": item["protocol"], "url": item["url"]}
        for item in entry["public_endpoints"]
    ]


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
    return [
        {
            "method": "get",
            "path": path,
            "expected_status": [200, 206],
            "expected_content_type": "application/octet-stream",
            "contains": "-----BEGIN PGP SIGNED MESSAGE-----",
        }
    ]


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
                "state": target["state"],
                "implementation_issue": target["issue"],
                "supported_scopes": tool_scopes(tool_id),
                "composition": "single",
            }
            existing_tool = tool_map.setdefault(tool_id, tool)
            if existing_tool["implementation_issue"] != target["issue"]:
                raise ValueError(f"tool {tool_id} maps to multiple implementation issues")

            endpoints = candidate_endpoints(entry)
            compatibility = candidate_compatibility(entry)
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
            for probe in candidate_probe(entry):
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
    observed_day = inventory["observed_at"].split("T", 1)[0].replace("-", ".")
    return {
        "schema_version": 1,
        "content_version": f"{observed_day}+{hashlib.sha256(inventory_bytes).hexdigest()[:12]}",
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
