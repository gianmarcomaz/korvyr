"""
Diagnose CPG construction failures on the real-eval package set.

Loads package paths from data/processed/hybrid_real_evaluation.json, attempts
to build a CPG for each package, and writes detailed success/failure rows to
data/processed/cpg_diagnostic.csv.
"""

from __future__ import annotations

import csv
import argparse
import json
import multiprocessing as mp
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.graph.cpg_builder import build_cpg


ROOT = Path(__file__).resolve().parent.parent
INPUT_PATH = ROOT / "data" / "processed" / "hybrid_real_evaluation.json"
OUTPUT_PATH = ROOT / "data" / "processed" / "cpg_diagnostic.csv"
PACKAGE_TIMEOUT_SECONDS = 8


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Diagnose CPG build failures")
    p.add_argument(
        "--resume",
        action="store_true",
        help="Skip package paths already present in cpg_diagnostic.csv",
    )
    p.add_argument(
        "--max-packages",
        type=int,
        default=None,
        help="Optional cap on packages to process in this run",
    )
    p.add_argument(
        "--worker-timeout",
        type=float,
        default=0.0,
        help=(
            "Use a subprocess timeout per package. 0 runs inline, which is faster "
            "and still streams partial CSV rows."
        ),
    )
    return p.parse_args()


def _count_js_files(package_dir: Path) -> int:
    return sum(
        1
        for p in package_dir.rglob("*")
        if p.suffix in (".js", ".mjs") and p.is_file()
    )


def _count_total_lines(package_dir: Path) -> int:
    total = 0
    for p in package_dir.rglob("*"):
        if p.suffix not in (".js", ".mjs") or not p.is_file():
            continue
        try:
            total += p.read_text(encoding="utf-8", errors="replace").count("\n") + 1
        except OSError:
            continue
    return total


def _load_packages() -> list[dict]:
    data = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    seen: set[str] = set()
    packages: list[dict] = []
    for pkg in data.get("packages", []):
        path = pkg.get("path")
        if not path or path in seen:
            continue
        seen.add(path)
        packages.append(pkg)
    return packages


def _build_worker(package_path: str, label: int, queue: mp.Queue) -> None:
    try:
        data = build_cpg(package_path, label=label)
        if data is None:
            queue.put(
                {
                    "status": "failure",
                    "error_type": "CPG_NONE",
                    "error_message": "build_cpg returned None",
                    "num_nodes": 0,
                    "num_edges": 0,
                }
            )
            return
        queue.put(
            {
                "status": "success",
                "error_type": "",
                "error_message": "",
                "num_nodes": int(data.num_nodes),
                "num_edges": int(data.edge_index.shape[1]),
            }
        )
    except Exception as e:
        queue.put(
            {
                "status": "failure",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "num_nodes": 0,
                "num_edges": 0,
            }
        )


def _build_with_timeout(package_path: Path, label: int) -> dict:
    queue: mp.Queue = mp.Queue()
    proc = mp.Process(
        target=_build_worker,
        args=(str(package_path), label, queue),
    )
    proc.start()
    proc.join(PACKAGE_TIMEOUT_SECONDS)
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        return {
            "status": "failure",
            "error_type": "BUILD_TIMEOUT",
            "error_message": f"build exceeded {PACKAGE_TIMEOUT_SECONDS}s",
            "num_nodes": 0,
            "num_edges": 0,
        }
    if not queue.empty():
        return queue.get()
    if proc.exitcode not in (0, None):
        return {
            "status": "failure",
            "error_type": "WORKER_EXIT",
            "error_message": f"worker exited with code {proc.exitcode}",
            "num_nodes": 0,
            "num_edges": 0,
        }
    return {
        "status": "failure",
        "error_type": "NO_WORKER_RESULT",
        "error_message": "worker finished without returning a result",
        "num_nodes": 0,
        "num_edges": 0,
    }


def _build_inline(package_path: Path, label: int) -> dict:
    try:
        data = build_cpg(str(package_path), label=label)
        if data is None:
            return {
                "status": "failure",
                "error_type": "CPG_NONE",
                "error_message": "build_cpg returned None",
                "num_nodes": 0,
                "num_edges": 0,
            }
        return {
            "status": "success",
            "error_type": "",
            "error_message": "",
            "num_nodes": int(data.num_nodes),
            "num_edges": int(data.edge_index.shape[1]),
        }
    except Exception as e:
        return {
            "status": "failure",
            "error_type": type(e).__name__,
            "error_message": str(e),
            "num_nodes": 0,
            "num_edges": 0,
        }


def _load_existing_rows() -> tuple[set[str], Counter[str], dict[str, dict], int, int]:
    processed: set[str] = set()
    error_counts: Counter[str] = Counter()
    examples: dict[str, dict] = {}
    success = 0
    failure = 0

    if not OUTPUT_PATH.exists():
        return processed, error_counts, examples, success, failure

    with OUTPUT_PATH.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            path = row.get("package_path", "")
            if path:
                processed.add(path)
            if row.get("status") == "failure":
                failure += 1
                etype = row.get("error_type", "") or "UNKNOWN"
                error_counts[etype] += 1
                examples.setdefault(etype, row)
            else:
                success += 1
    return processed, error_counts, examples, success, failure


def main() -> None:
    args = parse_args()
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Missing input JSON: {INPUT_PATH}")

    packages = _load_packages()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    processed_paths: set[str] = set()
    if args.resume:
        processed_paths, error_counts, examples, success, failure = _load_existing_rows()
    else:
        error_counts = Counter()
        examples = {}
        success = 0
        failure = 0

    remaining = [p for p in packages if p["path"] not in processed_paths]
    if args.max_packages is not None:
        remaining = remaining[: args.max_packages]

    t0 = time.perf_counter()
    mode = "a" if args.resume and OUTPUT_PATH.exists() else "w"
    with OUTPUT_PATH.open(mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "package_path",
                "true_label",
                "status",
                "error_type",
                "error_message",
                "num_js_files",
                "total_lines",
                "num_nodes",
                "num_edges",
            ],
        )
        if mode == "w":
            writer.writeheader()

        for pkg in tqdm(remaining, desc="Diagnosing CPG builds", unit="pkg"):
            package_path = Path(pkg["path"])
            label = int(pkg.get("true_label", 0))
            num_js_files = _count_js_files(package_path)
            total_lines = _count_total_lines(package_path)
            build_start = time.perf_counter()
            if args.worker_timeout > 0:
                global PACKAGE_TIMEOUT_SECONDS
                PACKAGE_TIMEOUT_SECONDS = args.worker_timeout
                build_result = _build_with_timeout(package_path, label)
            else:
                build_result = _build_inline(package_path, label)
            build_seconds = time.perf_counter() - build_start

            row = {
                "package_path": str(package_path),
                "true_label": label,
                "status": build_result["status"],
                "error_type": build_result["error_type"],
                "error_message": build_result["error_message"],
                "num_js_files": num_js_files,
                "total_lines": total_lines,
                "num_nodes": build_result["num_nodes"],
                "num_edges": build_result["num_edges"],
            }

            if row["status"] == "failure":
                failure += 1
                etype = row["error_type"]
                error_counts[etype] += 1
                examples.setdefault(etype, row)
            else:
                success += 1

            writer.writerow(row)
            f.flush()

    elapsed = time.perf_counter() - t0
    total = success + failure
    print()
    print("CPG Diagnostic Summary")
    print("======================")
    print(f"Input: {INPUT_PATH}")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Total packages: {total}")
    print(f"Success: {success}")
    print(f"Failure: {failure}")
    print(f"Success rate: {success / max(total, 1):.2%}")
    print(f"Elapsed seconds: {elapsed:.1f}")
    print(f"Processed this run: {len(remaining)}")
    print(f"Previously processed: {len(processed_paths)}")
    print(f"Worker timeout seconds: {args.worker_timeout}")
    print()
    print("Top error types:")
    if error_counts:
        for error_type, count in error_counts.most_common(5):
            print(f"  {error_type}: {count}")
    else:
        print("  none")
    print()
    print("Example package for each error type:")
    if examples:
        for error_type, row in examples.items():
            print(f"  {error_type}")
            print(f"    path: {row['package_path']}")
            print(f"    js_files: {row['num_js_files']}")
            print(f"    total_lines: {row['total_lines']}")
            print(f"    message: {row['error_message']}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
