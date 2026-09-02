#!/usr/bin/env python3
"""Require a public-boundary test for every supported catalog adapter."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    catalog = json.loads((ROOT / "catalog/mirrors.json").read_text())
    missing = []
    for tool in catalog["tools"]:
        if tool["state"] != "supported":
            continue
        test = ROOT / "tests" / f"{tool['adapter_key'].replace('-', '_')}_adapter_boundary.rs"
        if not test.is_file():
            missing.append(f"{tool['id']}: {test.relative_to(ROOT)}")
    if missing:
        raise SystemExit("supported adapters without boundary tests:\n" + "\n".join(missing))
    print(f"covered {sum(tool['state'] == 'supported' for tool in catalog['tools'])} supported adapters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
