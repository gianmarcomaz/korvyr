"""
Assemble train / val / test splits from individual graph .pt files.

Memory-efficient: infers labels from filenames (build_dataset.py saves
malicious packages as 0.pt … N_mal-1.pt, benign as N_mal.pt … end),
shuffles file paths, then copies files into split directories.
Never loads any .pt file — no torch dependency.

Usage:
    python scripts/assemble_splits.py
"""

from __future__ import annotations

import csv
import json
import logging
import os
import random
import shutil
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

print("assemble_splits.py: starting …", flush=True)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT_DIR / "data" / "raw"
PROCESSED_DIR = ROOT_DIR / "data" / "processed"
GRAPHS_DIR = PROCESSED_DIR / "graphs"

MALICIOUS_MANIFEST = RAW_DIR / "malicious_manifest.csv"
BENIGN_MANIFEST = RAW_DIR / "benign_manifest.csv"

SPLIT_DIRS = {
    "train": PROCESSED_DIR / "train",
    "val": PROCESSED_DIR / "val",
    "test": PROCESSED_DIR / "test",
}

MANIFEST_PATH = PROCESSED_DIR / "split_manifest.json"

SEED = 42
TRAIN_FRAC = 0.70
VAL_FRAC = 0.15

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


def _count_manifest_rows(path: Path) -> int:
    """Count rows in a CSV manifest (excluding header)."""
    if not path.exists():
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for _ in csv.reader(f)) - 1  # subtract header


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    log.info("=== Assemble dataset splits ===")

    n_malicious = _count_manifest_rows(MALICIOUS_MANIFEST)
    log.info("Malicious manifest entries: %d (indices 0 … %d)",
             n_malicious, n_malicious - 1)

    pt_files = sorted(GRAPHS_DIR.glob("*.pt"),
                      key=lambda p: int(p.stem))
    log.info("Found %d .pt files in %s", len(pt_files), GRAPHS_DIR)

    if not pt_files:
        log.error("No graph files found — nothing to do")
        return

    entries: list[dict] = []
    for p in pt_files:
        idx = int(p.stem)
        label = 1.0 if idx < n_malicious else 0.0
        entries.append({
            "path": str(p),
            "filename": p.name,
            "label": label,
            "idx": idx,
        })

    log.info("Built index for %d graphs", len(entries))

    # ---- Campaign-aware splitting ----
    # Group malicious packages by name to avoid campaign leakage.
    # Many Datadog malicious samples come from the same attacker campaign
    # with near-identical code — random splitting puts copies in both
    # train and test, inflating metrics via memorization.

    # Build campaign groups from the malicious manifest
    campaign_groups: dict[str, list[dict]] = {}
    benign_entries: list[dict] = []

    for entry in entries:
        if entry["label"] == 1.0:
            # Derive campaign key from the original manifest path
            idx = entry["idx"]
            # Use the package name as campaign key (same name = same campaign)
            campaign_key = f"mal_{idx // 10}"  # group nearby indices
            campaign_groups.setdefault(campaign_key, []).append(entry)
        else:
            benign_entries.append(entry)

    # Read malicious manifest for better grouping if available
    if MALICIOUS_MANIFEST.exists():
        import csv as csv_mod
        campaign_groups = {}
        mal_names: list[str] = []
        with open(MALICIOUS_MANIFEST, encoding="utf-8") as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                mal_names.append(row.get("package_name", ""))

        for entry in entries:
            if entry["label"] == 1.0:
                idx = entry["idx"]
                if idx < len(mal_names):
                    campaign_key = mal_names[idx]
                else:
                    campaign_key = f"mal_unknown_{idx}"
                campaign_groups.setdefault(campaign_key, []).append(entry)

    log.info("Campaign groups: %d unique campaigns, %d benign packages",
             len(campaign_groups), len(benign_entries))

    # Shuffle and split campaign groups
    random.seed(SEED)
    group_keys = list(campaign_groups.keys())
    random.shuffle(group_keys)

    n_groups = len(group_keys)
    n_train_groups = int(n_groups * TRAIN_FRAC)
    n_val_groups = int(n_groups * VAL_FRAC)

    train_mal: list[dict] = []
    val_mal: list[dict] = []
    test_mal: list[dict] = []

    for i, key in enumerate(group_keys):
        if i < n_train_groups:
            train_mal.extend(campaign_groups[key])
        elif i < n_train_groups + n_val_groups:
            val_mal.extend(campaign_groups[key])
        else:
            test_mal.extend(campaign_groups[key])

    # Split benign packages randomly
    random.shuffle(benign_entries)
    n_ben = len(benign_entries)
    n_train_ben = int(n_ben * TRAIN_FRAC)
    n_val_ben = int(n_ben * VAL_FRAC)

    train_ben = benign_entries[:n_train_ben]
    val_ben = benign_entries[n_train_ben:n_train_ben + n_val_ben]
    test_ben = benign_entries[n_train_ben + n_val_ben:]

    # Combine and shuffle within each split
    splits: dict[str, list[dict]] = {
        "train": train_mal + train_ben,
        "val": val_mal + val_ben,
        "test": test_mal + test_ben,
    }
    for split_entries in splits.values():
        random.shuffle(split_entries)

    # ---- Copy files into split directories ----
    for split_name, split_entries in splits.items():
        dest_dir = SPLIT_DIRS[split_name]
        dest_dir.mkdir(parents=True, exist_ok=True)

        copied = 0
        skipped = 0
        for entry in split_entries:
            src = Path(entry["path"])
            dst = dest_dir / entry["filename"]
            if not dst.exists():
                shutil.copy2(src, dst)
                copied += 1
            else:
                skipped += 1
            entry["split"] = split_name

        log.info("  %s: copied %d files, skipped %d (already existed)",
                 split_name, copied, skipped)

    # ---- Save manifest ----
    manifest = {
        "seed": SEED,
        "total": len(entries),
        "n_malicious_manifest": n_malicious,
        "splits": {
            name: [e["filename"] for e in split_entries]
            for name, split_entries in splits.items()
        },
    }
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    log.info("Manifest saved to %s", MANIFEST_PATH)

    # ---- Statistics ----
    log.info("─── Split statistics ───")
    total_mal = 0

    for split_name, split_entries in splits.items():
        mal = sum(1 for e in split_entries if e["label"] == 1.0)
        ben = len(split_entries) - mal
        log.info(
            "  %5s: %5d total  |  %5d malicious, %5d benign",
            split_name, len(split_entries), mal, ben,
        )
        total_mal += mal

    log.info(
        "─── Overall: %d graphs (%d malicious, %d benign) ───",
        len(entries), total_mal, len(entries) - total_mal,
    )


if __name__ == "__main__":
    main()
