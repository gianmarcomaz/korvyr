"""
Standalone evaluation of the rules engine on raw packages.

Runs the rules engine (no GNN) on 300 malicious + 300 benign raw packages
and reports precision, recall, per-rule breakdown, false positives, and
malicious packages that evade detection.
"""

import json
import logging
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.scanner.rules_engine import run_rules

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "processed" / "rules_evaluation.json"

SAMPLE_SIZE = 300
FLAG_THRESHOLD = 15.0  # total_score >= this OR has_critical → flagged


def _collect_packages(base_dir: Path, limit: int) -> list[Path]:
    """Find package dirs containing at least one .js file."""
    found = []
    for pj in sorted(base_dir.rglob("package.json")):
        pkg_dir = pj.parent
        # Skip nested node_modules
        if "node_modules" in pkg_dir.parts:
            continue
        # Must have at least one JS file
        has_js = any(pkg_dir.rglob("*.js"))
        if has_js:
            found.append(pkg_dir)
            if len(found) >= limit:
                break
    return found


def main():
    mal_dir = RAW_DIR / "malicious" / "npm"
    ben_dir = RAW_DIR / "benign"

    log.info("Collecting malicious packages from %s ...", mal_dir)
    mal_pkgs = _collect_packages(mal_dir, SAMPLE_SIZE)
    log.info("  Found %d malicious packages with JS files", len(mal_pkgs))

    log.info("Collecting benign packages from %s ...", ben_dir)
    ben_pkgs = _collect_packages(ben_dir, SAMPLE_SIZE)
    log.info("  Found %d benign packages with JS files", len(ben_pkgs))

    # ── Run rules engine ──
    all_results = []  # (pkg_dir, label, rules_result)
    rule_counts_mal = defaultdict(int)  # rule_id → count on malicious
    rule_counts_ben = defaultdict(int)  # rule_id → count on benign

    log.info("")
    log.info("═══ Running rules engine on %d packages ═══", len(mal_pkgs) + len(ben_pkgs))

    t0 = time.perf_counter()

    for i, (pkg_dir, label) in enumerate(
        [(p, "malicious") for p in mal_pkgs] + [(p, "benign") for p in ben_pkgs]
    ):
        try:
            result = run_rules(str(pkg_dir))
        except Exception as e:
            log.warning("  Error on %s: %s", pkg_dir.name, e)
            continue

        flagged = result.has_critical or result.total_score >= FLAG_THRESHOLD
        all_results.append((pkg_dir, label, result, flagged))

        counts = rule_counts_mal if label == "malicious" else rule_counts_ben
        for rule in result.matched_rules:
            counts[rule.rule_id] += 1

        if (i + 1) % 100 == 0:
            log.info("  Processed %d/%d ...", i + 1, len(mal_pkgs) + len(ben_pkgs))

    elapsed = time.perf_counter() - t0
    log.info("  Done in %.1fs (%.0f pkg/s)", elapsed, len(all_results) / max(elapsed, 0.01))

    # ── Compute metrics ──
    tp = sum(1 for _, l, _, f in all_results if l == "malicious" and f)
    fp = sum(1 for _, l, _, f in all_results if l == "benign" and f)
    fn = sum(1 for _, l, _, f in all_results if l == "malicious" and not f)
    tn = sum(1 for _, l, _, f in all_results if l == "benign" and not f)

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    n_mal = sum(1 for _, l, _, _ in all_results if l == "malicious")
    n_ben = sum(1 for _, l, _, _ in all_results if l == "benign")

    log.info("")
    log.info("═══ Rules-Only Results ═══")
    log.info("  Samples:   %d malicious, %d benign", n_mal, n_ben)
    log.info("  TP=%d  FP=%d  FN=%d  TN=%d", tp, fp, fn, tn)
    log.info("  Precision: %.4f  (%d/%d flagged correctly)", precision, tp, tp + fp)
    log.info("  Recall:    %.4f  (%d/%d malicious caught)", recall, tp, tp + fn)
    log.info("  F1:        %.4f", f1)

    # ── Per-rule breakdown ──
    all_rule_ids = sorted(set(list(rule_counts_mal.keys()) + list(rule_counts_ben.keys())))

    log.info("")
    log.info("═══ Per-Rule Breakdown ═══")
    log.info("%-30s  %-12s  %-12s", "Rule", "Malicious", "Benign")
    log.info("─" * 58)
    for rid in all_rule_ids:
        mc = rule_counts_mal.get(rid, 0)
        bc = rule_counts_ben.get(rid, 0)
        log.info("  %-28s  %4d         %4d", rid, mc, bc)

    # ── Benign packages that triggered rules (false positive analysis) ──
    ben_triggered = [
        (pkg, res) for pkg, label, res, _ in all_results
        if label == "benign" and len(res.matched_rules) > 0
    ]

    log.info("")
    log.info("═══ Benign Packages That Triggered Rules (%d) ═══", len(ben_triggered))
    for pkg, res in ben_triggered[:30]:  # show first 30
        rules = ", ".join(f"{r.rule_id}({r.severity[0]})" for r in res.matched_rules)
        log.info("  %-40s  score=%5.1f  [%s]",
                 pkg.name[:40], res.total_score, rules)

    # ── Malicious packages with zero rules (GNN-only catches) ──
    mal_missed = [
        pkg for pkg, label, res, flagged in all_results
        if label == "malicious" and not flagged
    ]

    log.info("")
    log.info("═══ Malicious Packages With Zero/Low Rules (%d) ═══", len(mal_missed))
    for pkg in mal_missed[:30]:
        log.info("  %s", pkg)

    # ── Save JSON ──
    output = {
        "summary": {
            "n_malicious": n_mal, "n_benign": n_ben,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "flag_threshold": FLAG_THRESHOLD,
        },
        "per_rule": {
            rid: {"malicious": rule_counts_mal.get(rid, 0),
                  "benign": rule_counts_ben.get(rid, 0)}
            for rid in all_rule_ids
        },
        "benign_false_positives": [
            {"package": str(pkg.name),
             "score": res.total_score,
             "rules": [r.rule_id for r in res.matched_rules]}
            for pkg, res in ben_triggered
        ],
        "malicious_missed": [str(pkg) for pkg in mal_missed],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    log.info("")
    log.info("Results saved to %s", OUTPUT_PATH)
    log.info("═══ Done ═══")


if __name__ == "__main__":
    main()
