"""
Package metadata risk scorer.

Returns a risk score from 0.0 to 1.0 based purely on package metadata
(name, structure, social signals) — does NOT look at source code.

Used as a third input signal in the hybrid decision function to catch
typosquats and structurally suspicious packages.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from korvyr.utils import edit_distance

log = logging.getLogger(__name__)

# Load popular packages list (top 1000 by weekly downloads)
_POPULAR_PACKAGES: list[str] = []
_POPULAR_SET: set[str] = set()
_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "popular_packages.json"

if _DATA_PATH.exists():
    try:
        _POPULAR_PACKAGES = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
        _POPULAR_SET = set(_POPULAR_PACKAGES)
    except (json.JSONDecodeError, OSError):
        log.warning("Failed to load popular_packages.json — typosquat detection disabled")


def compute_metadata_risk(package_name: str, package_json: dict) -> float:
    """
    Returns a risk score from 0.0 to 1.0 based on package metadata.
    Does NOT look at source code — purely structural/social signals.
    """
    risk = 0.0

    # Typosquat detection stays shallow on purpose: this is a risk nudge, not a verdict.
    if _POPULAR_PACKAGES and package_name and not package_name.startswith("@"):
        if package_name not in _POPULAR_SET:
            min_distance = min(
                (edit_distance(package_name, pop) for pop in _POPULAR_PACKAGES),
                default=99,
            )
            if min_distance <= 2:
                risk += 0.3

    # Sparse package metadata
    if not package_json.get("repository"):
        risk += 0.1
    if not package_json.get("license"):
        risk += 0.05
    desc = package_json.get("description", "")
    if not desc or len(desc) < 20:
        risk += 0.05

    # Install hooks present
    scripts = package_json.get("scripts", {})
    if "preinstall" in scripts or "postinstall" in scripts or "install" in scripts:
        risk += 0.2

    # Zero dependencies + install hooks = extra suspicious
    deps = package_json.get("dependencies", {})
    if len(deps) == 0 and ("preinstall" in scripts or "postinstall" in scripts):
        risk += 0.15

    return min(risk, 1.0)
