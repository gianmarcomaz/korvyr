"""
Fetch the top 1000 npm packages by popularity and save to
supplyguard/data/popular_packages.json.

One-time data fetch — run this once before training/evaluation.

Usage:
    python scripts/fetch_popular_packages.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = ROOT / "supplyguard" / "data" / "popular_packages.json"


SEARCH_TERMS = [
    "keywords:javascript", "keywords:nodejs", "keywords:typescript",
    "keywords:utility", "keywords:react", "keywords:cli",
    "keywords:http", "keywords:json", "keywords:test",
    "keywords:server", "keywords:framework", "keywords:css",
    "keywords:webpack", "keywords:babel", "keywords:eslint",
]


def main() -> None:
    packages: list[str] = []
    print("Fetching top npm packages by popularity...")

    for term in SEARCH_TERMS:
        for offset in range(0, 250, 250):
            url = (
                f"https://registry.npmjs.org/-/v1/search"
                f"?text={term}&size=250&from={offset}&popularity=1.0"
            )
            print(f"  Fetching {term} offset={offset}...", end=" ", flush=True)

            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                batch = [obj["package"]["name"] for obj in data.get("objects", [])]
                packages.extend(batch)
                print(f"got {len(batch)} packages")
            except Exception as e:
                print(f"FAILED: {e}")
                continue

            time.sleep(0.5)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for p in packages:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(unique, indent=2), encoding="utf-8")
    print(f"\nSaved {len(unique)} packages to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
