"""Small helpers shared by the scanner, graph builder, and evaluation code.

These live here because several independent components need exactly the same
behaviour: npm manifests are read the same way everywhere (BOM tolerant, never
raising), and two different detectors compare package names with the same
bounded edit distance.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def read_package_json(package_dir: str | Path) -> dict:
    """Return the parsed ``package.json`` of *package_dir*, or ``{}``.

    npm tarballs in the wild contain BOM-prefixed and malformed manifests, so
    every caller in Korvyr treats an unreadable manifest as "no metadata"
    rather than as a scan failure.
    """
    path = Path(package_dir) / "package.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        log.debug("Failed to parse package.json in %s", package_dir)
        return {}
    return data if isinstance(data, dict) else {}


def edit_distance(a: str, b: str, max_distance: int = 2) -> int:
    """Levenshtein distance, short-circuited above *max_distance*.

    Typosquat checks only care about "within 1-2 edits", so strings whose
    lengths already differ by more than *max_distance* return
    ``max_distance + 1`` without doing the full dynamic-programming pass.
    """
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]
