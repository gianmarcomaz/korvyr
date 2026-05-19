"""Audit package-context signals for residual hybrid v2 errors.

This script replays the best calibrated hybrid v2 configuration over an
existing production-path evaluation JSON, then measures candidate context
signals as hypothetical suppressors or confirmations. It does not rescan
packages and does not change production scanner behavior.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.evaluation.context_signals import (
    default_candidate_signals,
    enrich_record_context,
    evaluate_candidate,
    hard_examples,
    prediction_from_record,
)
from supplyguard.evaluation.hybrid_policy_v2 import HybridV2Config, apply_policy_to_record
from supplyguard.evaluation.reporting import compute_binary_metrics


ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure candidate package-context signals on hybrid v2 errors.",
    )
    parser.add_argument(
        "--production-json",
        type=Path,
        default=ROOT / "results" / "production_eval_gnn_v2_cuda.json",
    )
    parser.add_argument(
        "--calibration-json",
        type=Path,
        default=ROOT / "results" / "hybrid_v2_calibration.json",
    )
    parser.add_argument(
        "--precision-target",
        default="0.96",
        help="Precision target key under best_recall_at_precision, e.g. 0.96.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "results" / "context_signal_audit.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=ROOT / "results" / "context_signal_audit.md",
    )
    return parser.parse_args()


def _load_best_config(calibration: dict[str, Any], precision_target: str) -> HybridV2Config:
    rows = calibration["best_recall_at_precision"].get(precision_target, [])
    if not rows:
        raise ValueError(f"No calibration row found for precision target {precision_target}")
    config_dict = rows[0]["config"]
    allowed = set(HybridV2Config.__dataclass_fields__)
    return HybridV2Config(
        **{key: value for key, value in config_dict.items() if key in allowed}
    )


def _replay(records: list[dict[str, Any]], config: HybridV2Config) -> list[dict[str, Any]]:
    return [
        enrich_record_context(apply_policy_to_record(record, config))
        for record in records
    ]


def _metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [int(record["true_label"]) for record in records]
    preds = [prediction_from_record(record) for record in records]
    return compute_binary_metrics(preds, labels)


def _combined_adjustment(
    records: list[dict[str, Any]],
    candidate_results: list[dict[str, Any]],
) -> dict[str, Any]:
    by_name = {candidate.name: candidate for candidate in default_candidate_signals()}
    chosen_names = [
        result["name"]
        for result in candidate_results
        if (
            result["kind"] == "suppressor"
            and result["matched_cells"]["tp"] == 0
            and result["matched_cells"]["fp"] > 0
        )
        or (
            result["kind"] == "confirmer"
            and result["matched_cells"]["tn"] == 0
            and result["matched_cells"]["fn"] > 0
        )
    ]
    chosen = [by_name[name] for name in chosen_names]

    labels = [int(record["true_label"]) for record in records]
    baseline_preds = [prediction_from_record(record) for record in records]
    adjusted_preds = list(baseline_preds)
    touched: list[dict[str, Any]] = []

    for idx, record in enumerate(records):
        fired = [candidate for candidate in chosen if candidate.predicate(record)]
        if not fired:
            continue
        before = adjusted_preds[idx]
        after = before
        for candidate in fired:
            if candidate.kind == "suppressor" and before == 1:
                after = 0
            elif candidate.kind == "confirmer" and before == 0:
                after = 1
        adjusted_preds[idx] = after
        if after != before:
            touched.append(
                {
                    "package_name": record.get("package_name", ""),
                    "true_label": int(record["true_label"]),
                    "before": before,
                    "after": after,
                    "signals": [candidate.name for candidate in fired],
                }
            )

    return {
        "chosen_signal_names": chosen_names,
        "baseline_metrics": compute_binary_metrics(baseline_preds, labels),
        "adjusted_metrics": compute_binary_metrics(adjusted_preds, labels),
        "changed_packages": touched,
    }


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Context Signal Audit",
        "",
        "This report measures candidate context signals against the replayed hybrid "
        "v2 error set. It is analysis only and does not change production scanner "
        "behavior.",
        "",
        f"- Production input: `{result['inputs']['production_json']}`",
        f"- Calibration input: `{result['inputs']['calibration_json']}`",
        f"- Precision target replayed: {result['precision_target']}",
        f"- Packages: {result['counts']['total']}",
        f"- Malicious: {result['counts']['malicious']}",
        f"- Benign: {result['counts']['benign']}",
        f"- Replay config: `{result['config']}`",
        "",
        "## Baseline Replay",
        "",
        "| Precision | Recall | F1 | TP | FP | FN | TN |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    metrics = result["baseline_metrics"]
    lines.append(
        f"| {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
        f"{metrics['f1']:.4f} | {metrics['tp']} | {metrics['fp']} | "
        f"{metrics['fn']} | {metrics['tn']} |"
    )

    lines.extend(
        [
            "",
            "## Candidate Signal Impact",
            "",
            "| Signal | Kind | Matched | FP Saved | TP Hurt | FN Saved | TN Hurt | Precision After | Recall After | F1 After |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in result["candidate_results"]:
        cells = item["matched_cells"]
        metrics_after = item["adjusted_metrics"]
        if item["kind"] == "suppressor":
            fp_saved = max(0, -item["deltas"]["fp"])
            tp_hurt = max(0, -item["deltas"]["tp"])
            fn_saved = 0
            tn_hurt = 0
        else:
            fp_saved = 0
            tp_hurt = 0
            fn_saved = max(0, -item["deltas"]["fn"])
            tn_hurt = max(0, -item["deltas"]["tn"])
        lines.append(
            f"| {item['name']} | {item['kind']} | {item['matched']} | "
            f"{fp_saved} | {tp_hurt} | {fn_saved} | {tn_hurt} | "
            f"{metrics_after['precision']:.4f} | {metrics_after['recall']:.4f} | "
            f"{metrics_after['f1']:.4f} |"
        )
        if item["matched"] and (cells["fp"] or cells["fn"]):
            examples = ", ".join(
                package["package_name"] for package in item["matched_packages"][:8]
            )
            lines.append(f"| Examples |  |  |  |  |  |  |  |  | `{examples}` |")

    combined = result["combined_zero_hurt_signals"]
    combined_metrics = combined["adjusted_metrics"]
    lines.extend(
        [
            "",
            "## Zero-Hurt Combination",
            "",
            "This combines only individual signals that saved at least one current "
            "error and caused zero measured opposite-class harm on this 600-package "
            "replay set.",
            "",
            f"- Signals: `{combined['chosen_signal_names']}`",
            "",
            "| Precision | Recall | F1 | TP | FP | FN | TN |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            (
                f"| {combined_metrics['precision']:.4f} | "
                f"{combined_metrics['recall']:.4f} | {combined_metrics['f1']:.4f} | "
                f"{combined_metrics['tp']} | {combined_metrics['fp']} | "
                f"{combined_metrics['fn']} | {combined_metrics['tn']} |"
            ),
            "",
            "## Hard Examples",
            "",
            f"- False positives for hard-negative retraining: "
            f"{len(result['hard_examples']['false_positives'])}",
            f"- False negatives for hard-positive retraining: "
            f"{len(result['hard_examples']['false_negatives'])}",
            "",
            "## Interpretation",
            "",
            result["interpretation"],
            "",
        ]
    )
    return "\n".join(lines)


def _interpret(result: dict[str, Any]) -> str:
    baseline = result["baseline_metrics"]
    combined = result["combined_zero_hurt_signals"]["adjusted_metrics"]
    if combined["precision"] >= 0.96 and combined["recall"] >= 0.88:
        return (
            "The measured zero-hurt context signals reach the requested operating "
            "region on this replay set. The next step is to implement the winning "
            "signals in scanner code and validate on a separate holdout set."
        )
    if combined["recall"] > baseline["recall"] and combined["precision"] >= baseline["precision"]:
        return (
            "The measured context signals improve both precision and recall on this "
            "replay set, but do not yet reach the requested operating region. The "
            "remaining gap likely needs hard-example retraining and more separating "
            "features for mid-GNN/no-rule malicious packages."
        )
    return (
        "The tested context signals do not yet improve both metrics enough to justify "
        "a production policy change by themselves. Use the hard-example lists for the "
        "next retraining pass and add narrower package-context features before "
        "lowering block thresholds."
    )


def main() -> None:
    args = parse_args()
    production = json.loads(args.production_json.read_text(encoding="utf-8"))
    calibration = json.loads(args.calibration_json.read_text(encoding="utf-8"))
    config = _load_best_config(calibration, args.precision_target)
    replayed = _replay(production["packages"], config)
    candidates = default_candidate_signals()
    candidate_results = [evaluate_candidate(replayed, candidate) for candidate in candidates]
    combined = _combined_adjustment(replayed, candidate_results)

    labels = [int(record["true_label"]) for record in replayed]
    result = {
        "inputs": {
            "production_json": str(args.production_json),
            "calibration_json": str(args.calibration_json),
        },
        "precision_target": args.precision_target,
        "config": config.to_dict(),
        "counts": {
            "total": len(replayed),
            "malicious": sum(labels),
            "benign": len(labels) - sum(labels),
        },
        "baseline_metrics": _metrics(replayed),
        "candidate_results": candidate_results,
        "combined_zero_hurt_signals": combined,
        "hard_examples": hard_examples(replayed),
    }
    result["interpretation"] = _interpret(result)

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    args.output_md.write_text(_render_markdown(result), encoding="utf-8")

    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")
    print(
        "Baseline: "
        f"P={result['baseline_metrics']['precision']:.4f} "
        f"R={result['baseline_metrics']['recall']:.4f} "
        f"FP={result['baseline_metrics']['fp']} "
        f"FN={result['baseline_metrics']['fn']}"
    )
    print(
        "Zero-hurt combo: "
        f"P={combined['adjusted_metrics']['precision']:.4f} "
        f"R={combined['adjusted_metrics']['recall']:.4f} "
        f"FP={combined['adjusted_metrics']['fp']} "
        f"FN={combined['adjusted_metrics']['fn']}"
    )


if __name__ == "__main__":
    main()
