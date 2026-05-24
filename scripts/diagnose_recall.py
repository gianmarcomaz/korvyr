"""Phase 1 recall diagnostics for the production-path evaluator.

This script intentionally delegates package loading, CPG construction, GNN
inference, rules, metadata, and hybrid decision logic to
``scripts.evaluate_production``. The diagnostics below are reporting-only.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from argparse import Namespace
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluate_production import run_evaluation
from supplyguard.scanner.scan_pipeline import ThresholdConfig

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVAL_SOURCE = ROOT / "data" / "processed" / "hybrid_real_evaluation_phase1_manifest.json"
DEFAULT_MODEL = ROOT / "checkpoints" / "best_model.pt"
DIAGNOSTICS_DIR = ROOT / "data" / "diagnostics"
OUTPUT_JSON = DIAGNOSTICS_DIR / "phase1_diagnostic.json"


def _phase_bucket(record: dict[str, Any]) -> str:
    """Map current production decision text to the phase prompt buckets."""
    verdict = str(record.get("hybrid_verdict", ""))
    path = str(record.get("decision_path", "")).lower()
    gnn = float(record.get("gnn_score", -1.0))
    cfg = ThresholdConfig()

    if verdict == "malicious":
        if "critical behavioral rule" in path:
            return "critical_override"
        if "very high confidence" in path:
            return "auto_block"
        if "confirming rules" in path or "moderate malicious" in path:
            return "uncertain_rules_block"
        return "auto_block"

    if verdict == "clean":
        if gnn >= 0 and gnn < cfg.gnn_auto_pass:
            return "auto_pass"
        return "uncertain_clean"

    if "review-only critical" in path or "critical rule matched" in path:
        return "critical_override_review"
    if gnn >= 0 and gnn < cfg.gnn_auto_pass:
        return "auto_pass_review"
    if gnn >= cfg.gnn_auto_block:
        return "uncertain_suspicious"
    return "uncertain_suspicious"


def _score_bins(records: list[dict[str, Any]]) -> tuple[Counter[str], int]:
    bins = Counter()
    errors = 0
    for record in records:
        score = float(record.get("gnn_score", -1.0))
        if score < 0:
            errors += 1
            continue
        idx = min(int(score * 10), 9)
        label = f"[{idx / 10:.2f}-{(idx + 1) / 10:.2f}{']' if idx == 9 else ')'}"
        bins[label] += 1
    return bins, errors


def _print_score_distribution(title: str, records: list[dict[str, Any]]) -> None:
    bins, errors = _score_bins(records)
    print(f"\n=== GNN Score Distribution ({title}, N={len(records)}) ===")
    for idx in range(10):
        label = f"[{idx / 10:.2f}-{(idx + 1) / 10:.2f}{']' if idx == 9 else ')'}"
        print(f"  {label}: {bins[label]} packages")
    print(f"  GNN error/no score: {errors} packages")


def _print_bucket_breakdown(title: str, records: list[dict[str, Any]]) -> None:
    counts = Counter(str(record["phase_decision_bucket"]) for record in records)
    print(f"\n=== Decision Bucket Breakdown ({title}) ===")
    for bucket, count in sorted(counts.items()):
        print(f"  {bucket:<28} {count}")


def _print_false_negative_analysis(records: list[dict[str, Any]]) -> None:
    false_negatives = [
        r for r in records
        if int(r["true_label"]) == 1 and r["hybrid_verdict"] != "malicious"
    ]
    bands = {
        "rules_score = 0": 0,
        "rules_score 1-5": 0,
        "rules_score 6-10": 0,
        "rules_score 11-14": 0,
        "rules_score >= 15": 0,
    }
    for record in false_negatives:
        score = float(record.get("rules_score", 0.0))
        if score == 0:
            bands["rules_score = 0"] += 1
        elif score <= 5:
            bands["rules_score 1-5"] += 1
        elif score <= 10:
            bands["rules_score 6-10"] += 1
        elif score < 15:
            bands["rules_score 11-14"] += 1
        else:
            bands["rules_score >= 15"] += 1

    print(f"\n=== False Negative Analysis ({len(false_negatives)} missed malicious packages) ===")
    for label, count in bands.items():
        print(f"  Packages with {label:<17} {count}")

    suspicious = [r for r in false_negatives if r["hybrid_verdict"] == "suspicious"]
    rule_counts: Counter[str] = Counter()
    for record in suspicious:
        rule_counts.update(record.get("rules_matched", []))
    gnn_scores = [float(r["gnn_score"]) for r in suspicious if float(r["gnn_score"]) >= 0]
    rule_scores = [float(r.get("rules_score", 0.0)) for r in suspicious]
    print("\n=== Suspicious-but-not-blocked (malicious packages marked suspicious) ===")
    print(f"  Count: {len(suspicious)}")
    print(f"  Mean GNN score: {statistics.mean(gnn_scores):.3f}" if gnn_scores else "  Mean GNN score: n/a")
    print(f"  Mean rules_score: {statistics.mean(rule_scores):.2f}" if rule_scores else "  Mean rules_score: n/a")
    print(f"  Top rules seen: {rule_counts.most_common(5)}")


def _print_summary(records: list[dict[str, Any]]) -> None:
    cfg = ThresholdConfig()
    malicious = [r for r in records if int(r["true_label"]) == 1]
    benign = [r for r in records if int(r["true_label"]) == 0]
    mal_scores = [float(r["gnn_score"]) for r in malicious if float(r["gnn_score"]) >= 0]
    ben_scores = [float(r["gnn_score"]) for r in benign if float(r["gnn_score"]) >= 0]

    mal_mean = statistics.mean(mal_scores) if mal_scores else math.nan
    ben_mean = statistics.mean(ben_scores) if ben_scores else math.nan
    mal_std = statistics.pstdev(mal_scores) if len(mal_scores) > 1 else 0.0
    ben_std = statistics.pstdev(ben_scores) if len(ben_scores) > 1 else 0.0

    print("\n=== Summary Statistics ===")
    print(f"  GNN mean score (malicious):   {mal_mean:.3f} +/- {mal_std:.3f}")
    print(f"  GNN mean score (benign):      {ben_mean:.3f} +/- {ben_std:.3f}")
    print(f"  GNN score separation (means): {mal_mean - ben_mean:.3f}")
    print(f"  Current auto_pass threshold:  {cfg.gnn_auto_pass:.2f}")
    print(f"  Current auto_block threshold: {cfg.gnn_auto_block:.2f}")
    print(
        "  Packages above auto_block (malicious): "
        f"{sum(1 for s in mal_scores if s >= cfg.gnn_auto_block)} / {len(malicious)}"
    )
    print(
        "  Packages above auto_block (benign):    "
        f"{sum(1 for s in ben_scores if s >= cfg.gnn_auto_block)} / {len(benign)}"
    )


def _diagnostic_records(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for record in packages:
        item = {
            "package_name": record["package_name"],
            "package_path": record.get("package_path", ""),
            "true_label": int(record["true_label"]),
            "gnn_score": float(record.get("gnn_score", -1.0)),
            "rules_score": float(record.get("rules_score", 0.0)),
            "rules_matched": list(record.get("rules_matched", [])),
            "rules_details": list(record.get("rules_details", [])),
            "hybrid_verdict": record.get("hybrid_verdict", "unknown"),
            "decision_bucket": record.get("decision_bucket", "unknown"),
            "decision_path": record.get("decision_path", ""),
        }
        item["phase_decision_bucket"] = _phase_bucket(item)
        out.append(item)
    return out


def main() -> None:
    if not DEFAULT_EVAL_SOURCE.exists():
        raise SystemExit(f"Missing eval source: {DEFAULT_EVAL_SOURCE}")
    if not DEFAULT_MODEL.exists():
        raise SystemExit(f"Missing model checkpoint: {DEFAULT_MODEL}")

    DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
    args = Namespace(
        package=[],
        tarball=[],
        from_existing_eval=DEFAULT_EVAL_SOURCE,
        malicious_manifest=ROOT / "data" / "raw" / "malicious_manifest.csv",
        benign_manifest=ROOT / "data" / "raw" / "benign_manifest.csv",
        sample_size=0,
        seed=42,
        model_path=DEFAULT_MODEL,
        output_json=DIAGNOSTICS_DIR / "phase1_production_eval.json",
        output_md=DIAGNOSTICS_DIR / "phase1_production_eval.md",
        device="cpu",
        log_level="INFO",
    )
    print("Running canonical production-path evaluation for Phase 1 diagnostics...")
    output = run_evaluation(args)
    records = _diagnostic_records(output["packages"])
    OUTPUT_JSON.write_text(json.dumps(records, indent=2), encoding="utf-8")

    malicious = [r for r in records if r["true_label"] == 1]
    benign = [r for r in records if r["true_label"] == 0]
    _print_score_distribution("Malicious packages", malicious)
    _print_score_distribution("Benign packages", benign)
    _print_bucket_breakdown("Malicious packages only", malicious)
    _print_bucket_breakdown("Benign packages only", benign)
    _print_false_negative_analysis(records)
    _print_summary(records)
    print(f"\nSaved diagnostic records: {OUTPUT_JSON} ({len(records)} entries)")


if __name__ == "__main__":
    main()
