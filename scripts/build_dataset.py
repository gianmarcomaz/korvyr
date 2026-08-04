"""
Build the Korvyr PyTorch Geometric dataset.

Reads malicious and benign manifests, runs each package through the CPG
builder in parallel, then splits into train / val / test and saves to disk.

Each worker saves its Data object to an individual .pt file under
data/processed/graphs/ to avoid shared-memory serialisation issues.

Usage:
    python scripts/build_dataset.py
    python scripts/build_dataset.py --test-run
    python scripts/build_dataset.py --resume
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import argparse
import csv
import logging
import multiprocessing as mp
import random
import time
import traceback
from pathlib import Path

# NOTE: torch and korvyr are imported LAZILY — not here — so that
# worker processes spawned on Windows don't pay the import cost twice at
# module level.  They are imported inside _process_one() and main().

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT_DIR / "data" / "raw"
PROCESSED_DIR = ROOT_DIR / "data" / "processed"
GRAPHS_DIR = PROCESSED_DIR / "graphs"

MALICIOUS_MANIFEST = RAW_DIR / "malicious_manifest.csv"
BENIGN_MANIFEST = RAW_DIR / "benign_manifest.csv"

TRAIN_PATH = PROCESSED_DIR / "train_dataset.pt"
VAL_PATH = PROCESSED_DIR / "val_dataset.pt"
TEST_PATH = PROCESSED_DIR / "test_dataset.pt"
FAILED_LOG = PROCESSED_DIR / "failed_packages.log"
CPG_FAILURES_CSV = PROCESSED_DIR / "cpg_failures.csv"

SEED = 42
TRAIN_FRAC = 0.70
VAL_FRAC = 0.15
DEFAULT_WORKERS = 4

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Manifest reading
# ---------------------------------------------------------------------------


def _read_manifest(path: Path, label: int) -> list[tuple[str, int]]:
    """Return list of (package_dir, label) from a CSV manifest."""
    if not path.exists():
        log.warning("Manifest not found: %s", path)
        return []
    rows: list[tuple[str, int]] = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg_path = ROOT_DIR / row["path"]
            if pkg_path.is_dir():
                rows.append((str(pkg_path), label))
            else:
                log.debug("Package dir missing, skipping: %s", row["path"])
    return rows


# ---------------------------------------------------------------------------
# Worker  (heavy imports are deferred to first call)
# ---------------------------------------------------------------------------

_build_cpg = None
_torch = None


def _init_worker() -> None:
    """Called once per worker process to do heavy imports."""
    global _build_cpg, _torch
    import torch as _t
    _torch = _t
    from korvyr.graph.cpg_builder import build_cpg
    _build_cpg = build_cpg


def _classify_error(exc_str: str, package_dir: str) -> str:
    """Classify a CPG build error into a category."""
    exc_lower = exc_str.lower()
    if "no js" in exc_lower or "no javascript" in exc_lower:
        return "no_js_files"
    if "parse" in exc_lower or "syntax" in exc_lower or "tree_sitter" in exc_lower:
        return "parse_error"
    if "empty" in exc_lower or "0 nodes" in exc_lower:
        return "empty_graph"
    return "other"


def _process_one(args: tuple[str, int, str]) -> tuple[str | None, str | None, dict | None]:
    """Build a CPG for one package, save to *out_path*.

    Returns ``(out_path, None, None)`` on success,
    ``(None, error_msg, failure_info)`` on failure, or
    ``(None, None, None)`` if no JS files found.
    """
    package_dir, label, out_path = args
    try:
        data = _build_cpg(package_dir, label=label)
        if data is None:
            return None, None, {
                "package_path": package_dir,
                "label": label,
                "error_type": "no_js_files",
                "error_message": "CPG build returned None (no JS files)",
            }
        _torch.save(data, out_path)
        return out_path, None, None
    except Exception:
        tb = traceback.format_exc()
        error_type = _classify_error(tb, package_dir)
        return None, f"{package_dir}\n{tb}", {
            "package_path": package_dir,
            "label": label,
            "error_type": error_type,
            "error_message": tb.strip().split("\n")[-1][:200],
        }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("Starting build_dataset.py …", flush=True)

    parser = argparse.ArgumentParser(description="Build Korvyr dataset")
    parser.add_argument(
        "--test-run", action="store_true",
        help="Only process 5 malicious + 5 benign packages (quick sanity check)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip packages whose .pt file already exists in data/processed/graphs/",
    )
    args = parser.parse_args()

    log.info("=== Korvyr dataset builder ===")

    # ---- gather tasks ----
    malicious = _read_manifest(MALICIOUS_MANIFEST, label=1)
    benign = _read_manifest(BENIGN_MANIFEST, label=0)

    if args.test_run:
        malicious = malicious[:5]
        benign = benign[:5]
        log.info("--test-run: limited to %d malicious + %d benign",
                 len(malicious), len(benign))

    all_entries = malicious + benign

    log.info(
        "Manifests loaded: %d malicious, %d benign, %d total",
        len(malicious), len(benign), len(all_entries),
    )
    if not all_entries:
        log.error("No packages to process — exiting")
        return

    # ---- prepare output dir & build task tuples (dir, label, out_path) ----
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

    tasks: list[tuple[str, int, str]] = []
    already_done: list[str] = []

    for idx, (pkg_dir, label) in enumerate(all_entries):
        out_path = str(GRAPHS_DIR / f"{idx}.pt")
        if args.resume and Path(out_path).exists():
            already_done.append(out_path)
        else:
            tasks.append((pkg_dir, label, out_path))

    if args.resume and already_done:
        log.info("--resume: %d packages already processed, %d remaining",
                 len(already_done), len(tasks))

    if not tasks and not already_done:
        log.error("No packages to process — exiting")
        return

    # ---- parallel processing ----
    num_workers = min(DEFAULT_WORKERS, max(1, mp.cpu_count() - 1))
    log.info("Processing %d packages with %d workers", len(tasks), num_workers)

    new_paths: list[str] = []
    failures: list[str] = []
    cpg_failure_records: list[dict] = []
    error_counts: dict[str, int] = {"parse_error": 0, "no_js_files": 0, "empty_graph": 0, "other": 0}

    t0 = time.perf_counter()

    if tasks:
        with mp.Pool(num_workers, initializer=_init_worker) as pool:
            from tqdm import tqdm
            for out_path, err, failure_info in tqdm(
                pool.imap_unordered(_process_one, tasks),
                total=len(tasks),
                desc="Building CPGs",
                unit="pkg",
            ):
                if err is not None:
                    failures.append(err)
                if failure_info is not None:
                    cpg_failure_records.append(failure_info)
                    error_counts[failure_info["error_type"]] = (
                        error_counts.get(failure_info["error_type"], 0) + 1
                    )
                elif out_path is not None:
                    new_paths.append(out_path)

    elapsed = time.perf_counter() - t0

    total = len(tasks)
    ok = len(new_paths)
    failed = total - ok
    log.info(
        "Done: %d / %d succeeded, %d failed (%.1f pkg/s)",
        ok, total, failed, total / max(elapsed, 0.001),
    )

    # ---- error breakdown ----
    log.info("─── Error breakdown ───")
    for err_type, count in sorted(error_counts.items(), key=lambda x: -x[1]):
        log.info("  %-15s  %d", err_type, count)

    # ---- save failure log ----
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with open(FAILED_LOG, "w", encoding="utf-8") as f:
        for entry in failures:
            f.write(entry)
            f.write("\n" + "─" * 60 + "\n")
    log.info("Failed-packages log: %s (%d entries)", FAILED_LOG, len(failures))

    # ---- save CPG failures CSV ----
    if cpg_failure_records:
        with open(CPG_FAILURES_CSV, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["package_path", "label", "error_type", "error_message"],
            )
            writer.writeheader()
            writer.writerows(cpg_failure_records)
        log.info("CPG failures CSV: %s (%d entries)", CPG_FAILURES_CSV,
                 len(cpg_failure_records))

    # ---- reload all graph files (new + previously done) ----
    all_paths = already_done + new_paths
    log.info("Loading %d graph files for splitting …", len(all_paths))

    import torch
    from tqdm import tqdm

    results: list[object] = []
    for p in tqdm(all_paths, desc="Loading graphs", unit="file"):
        try:
            results.append(torch.load(p, weights_only=False))
        except Exception as exc:
            log.warning("Failed to load %s: %s", p, exc)

    if not results:
        log.error("No successful CPGs — nothing to save")
        return

    # ---- shuffle & split ----
    random.seed(SEED)
    random.shuffle(results)

    n = len(results)
    n_train = int(n * TRAIN_FRAC)
    n_val = int(n * VAL_FRAC)

    train_data = results[:n_train]
    val_data = results[n_train : n_train + n_val]
    test_data = results[n_train + n_val :]

    # ---- save ----
    torch.save(train_data, TRAIN_PATH)
    torch.save(val_data, VAL_PATH)
    torch.save(test_data, TEST_PATH)
    log.info("Saved: %s (%d), %s (%d), %s (%d)",
             TRAIN_PATH, len(train_data),
             VAL_PATH, len(val_data),
             TEST_PATH, len(test_data))

    # ---- statistics ----
    def _split_stats(name: str, split: list) -> None:
        if not split:
            log.info("  %s: empty", name)
            return
        mal = sum(1 for d in split if d.y.item() == 1.0)
        ben = len(split) - mal
        ratio = f"1:{ben / max(mal, 1):.1f}" if mal > 0 else "N/A"
        avg_nodes = sum(d.num_nodes for d in split) / len(split)
        avg_edges = sum(d.edge_index.size(1) for d in split) / len(split)
        log.info(
            "  %s: %5d total  |  %5d malicious, %5d benign (ratio: %s)"
            "  |  avg nodes %.0f, avg edges %.0f",
            name, len(split), mal, ben, ratio, avg_nodes, avg_edges,
        )
        if mal > 0 and ben / mal > 3.0:
            log.warning(
                "  ⚠ %s: class imbalance ratio %.1f:1 (benign:malicious) — "
                "consider using --balance flag or WeightedRandomSampler during training",
                name, ben / mal,
            )

    log.info("─── Split statistics ───")
    _split_stats("train", train_data)
    _split_stats("val  ", val_data)
    _split_stats("test ", test_data)

    all_data = results
    avg_nodes = sum(d.num_nodes for d in all_data) / len(all_data)
    avg_edges = sum(d.edge_index.size(1) for d in all_data) / len(all_data)
    log.info(
        "─── Overall: %d graphs, avg %.0f nodes, avg %.0f edges, "
        "%.1f sec (%.1f pkg/s) ───",
        len(all_data), avg_nodes, avg_edges, elapsed, total / max(elapsed, 0.001),
    )


if __name__ == "__main__":
    main()
