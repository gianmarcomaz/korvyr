"""
Compare two hybrid evaluation JSON files (baseline vs new).

Prints a side-by-side comparison of metrics, decision bucket shifts,
and identifies specific packages where the verdict changed.

Usage:
    python scripts/compare_evals.py \\
        --baseline data/processed/hybrid_real_evaluation.json \\
        --new data/processed/hybrid_eval_v2.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def load_eval(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        log.error("File not found: %s", path)
        sys.exit(1)
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two hybrid evaluations")
    parser.add_argument("--baseline", required=True, help="Path to baseline eval JSON")
    parser.add_argument("--new", required=True, help="Path to new eval JSON")
    args = parser.parse_args()

    base = load_eval(args.baseline)
    new = load_eval(args.new)

    log.info("═══ SupplyGuard Evaluation Comparison ═══")
    log.info("")

    # ── Summary ──
    log.info("── Dataset ──")
    for label, data in [("Baseline", base), ("New", new)]:
        s = data.get("summary", {})
        log.info("  %s: %d total (%d malicious, %d benign)",
                 label, s.get("n_total", 0),
                 s.get("n_malicious", 0), s.get("n_benign", 0))
    log.info("")

    # ── Metrics comparison ──
    log.info("── Metrics (Hybrid) ──")
    log.info("%-12s  %-10s  %-10s  %-8s", "Metric", "Baseline", "New", "Δ")
    log.info("─" * 48)

    base_m = base.get("metrics", {}).get("hybrid", {})
    new_m = new.get("metrics", {}).get("hybrid", {})

    for metric in ["precision", "recall", "f1", "fp", "fn", "tp", "tn", "flagged"]:
        bv = base_m.get(metric, 0)
        nv = new_m.get(metric, 0)
        delta = nv - bv
        if isinstance(bv, float):
            log.info("  %-10s  %.4f      %.4f      %+.4f", metric, bv, nv, delta)
        else:
            log.info("  %-10s  %6d      %6d      %+d", metric, bv, nv, delta)
    log.info("")

    # ── All three systems ──
    log.info("── All Systems ──")
    log.info("%-12s  %-8s  %-8s  %-8s", "System", "Prec", "Recall", "F1")
    log.info("─" * 44)
    for system in ["gnn_only", "rules_only", "hybrid"]:
        for label, data in [("Baseline", base), ("New", new)]:
            m = data.get("metrics", {}).get(system, {})
            log.info("  %-10s (%s)  %.4f  %.4f  %.4f",
                     system, label[:3], m.get("precision", 0),
                     m.get("recall", 0), m.get("f1", 0))
    log.info("")

    # ── Decision bucket shifts ──
    log.info("── Decision Buckets ──")
    all_buckets = sorted(set(
        list(base.get("buckets", {}).keys()) +
        list(new.get("buckets", {}).keys())
    ))
    log.info("%-30s  %-8s  %-8s  %-8s", "Bucket", "Base", "New", "Δ")
    log.info("─" * 58)
    for bucket in all_buckets:
        bv = base.get("buckets", {}).get(bucket, 0)
        nv = new.get("buckets", {}).get(bucket, 0)
        delta = nv - bv
        marker = " ←" if abs(delta) > 5 else ""
        log.info("  %-28s  %5d     %5d     %+d%s", bucket, bv, nv, delta, marker)
    log.info("")

    # ── Per-package verdict changes ──
    base_pkgs = {p["name"]: p for p in base.get("packages", [])}
    new_pkgs = {p["name"]: p for p in new.get("packages", [])}
    common = set(base_pkgs.keys()) & set(new_pkgs.keys())

    fixed = []     # was wrong in baseline, correct in new
    broken = []    # was correct in baseline, wrong in new
    changed = []   # verdict changed

    for name in sorted(common):
        bp = base_pkgs[name]
        np_ = new_pkgs[name]
        label = bp["true_label"]
        bv = bp["hybrid_verdict"]
        nv = np_["hybrid_verdict"]

        if bv == nv:
            continue

        changed.append((name, label, bv, nv, np_.get("gnn_score", -1),
                        np_.get("rules_score", 0)))

        b_correct = (bv == "malicious" and label == 1) or (bv == "clean" and label == 0)
        n_correct = (nv == "malicious" and label == 1) or (nv == "clean" and label == 0)

        if not b_correct and n_correct:
            fixed.append(name)
        elif b_correct and not n_correct:
            broken.append(name)

    log.info("── Verdict Changes ──")
    log.info("  Total changed: %d", len(changed))
    log.info("  Fixed (wrong→right): %d", len(fixed))
    log.info("  Broken (right→wrong): %d", len(broken))
    log.info("")

    if fixed:
        log.info("  Fixed packages:")
        for name in fixed[:20]:
            p = new_pkgs[name]
            log.info("    %-30s  label=%d  GNN=%.3f  rules=%.0f  %s→%s",
                     name[:30], p["true_label"], p.get("gnn_score", -1),
                     p.get("rules_score", 0),
                     base_pkgs[name]["hybrid_verdict"],
                     p["hybrid_verdict"])

    if broken:
        log.info("")
        log.info("  ⚠ Broken packages (regressions):")
        for name in broken[:20]:
            p = new_pkgs[name]
            log.info("    %-30s  label=%d  GNN=%.3f  rules=%.0f  %s→%s",
                     name[:30], p["true_label"], p.get("gnn_score", -1),
                     p.get("rules_score", 0),
                     base_pkgs[name]["hybrid_verdict"],
                     p["hybrid_verdict"])

    log.info("")
    log.info("═══ Done ═══")


if __name__ == "__main__":
    main()
