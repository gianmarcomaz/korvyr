"""Replay and sweep the experimental precision-aware hybrid v2 policy.

This script consumes JSON emitted by ``scripts/evaluate_production.py``.  It
does not rescan packages and does not change production defaults; it replays the
recorded GNN/rules/metadata signals through a candidate policy to estimate which
precision/recall bands are reachable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from korvyr.evaluation.hybrid_policy_v2 import (
    HybridV2Config,
    apply_policy_to_record,
)
from korvyr.evaluation.reporting import compute_binary_metrics, summarize_records

ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Calibrate the experimental hybrid v2 policy from eval JSON.",
    )
    parser.add_argument(
        "--input-json",
        type=Path,
        default=ROOT / "results" / "production_eval_gnn_v2_cuda.json",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "results" / "hybrid_v2_calibration.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=ROOT / "results" / "hybrid_v2_calibration.md",
    )
    return parser.parse_args()


def _metric_row(config: HybridV2Config, records: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [int(record["true_label"]) for record in records]
    replayed = [apply_policy_to_record(record, config) for record in records]
    preds = [1 if record["hybrid_verdict"] == "malicious" else 0 for record in replayed]
    return {
        "config": config.to_dict(),
        "metrics": compute_binary_metrics(preds, labels),
        "summary": summarize_records(replayed),
    }


def _sweep_configs() -> list[HybridV2Config]:
    configs: list[HybridV2Config] = []
    for gnn_direct in [0.78, 0.80, 0.82, 0.85, 0.88, 0.90, 0.92, 0.94, 0.96, 0.98, 1.01]:
        for confirm_floor in [0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75]:
            for confirm_threshold in [1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 10.0, 12.0]:
                for hard_min_gnn in [0.0, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75]:
                    for hard_threshold in [2.0, 5.0, 8.0, 10.0, 12.0, 15.0]:
                        configs.append(
                            HybridV2Config(
                                gnn_direct_block_threshold=gnn_direct,
                                gnn_confirm_floor=confirm_floor,
                                weighted_confirm_threshold=confirm_threshold,
                                hard_rule_min_gnn=hard_min_gnn,
                                hard_rule_score_threshold=hard_threshold,
                            )
                        )
    return configs


def _sort_for_recall(row: dict[str, Any]) -> tuple[float, float, float, int]:
    metrics = row["metrics"]
    return (
        float(metrics["recall"]),
        float(metrics["f1"]),
        float(metrics["precision"]),
        -int(metrics["fp"]),
    )


def _compact_row(row: dict[str, Any]) -> dict[str, Any]:
    metrics = row["metrics"]
    return {
        "config": row["config"],
        "metrics": {
            key: metrics[key]
            for key in ["precision", "recall", "f1", "tp", "fp", "fn", "tn", "flagged"]
        },
        "decision_buckets": row["summary"]["decision_buckets"],
        "false_positives": [
            {
                "package_name": r["package_name"],
                "gnn_score": r["gnn_score"],
                "rules_matched": r.get("rules_matched", []),
                "decision_path": r["decision_path"],
            }
            for r in row["summary"]["false_positives"][:25]
        ],
        "false_negatives": [
            {
                "package_name": r["package_name"],
                "gnn_score": r["gnn_score"],
                "rules_matched": r.get("rules_matched", []),
                "decision_path": r["decision_path"],
            }
            for r in row["summary"]["false_negatives"][:25]
        ],
    }


def _top_for_precision(rows: list[dict[str, Any]], target: float) -> list[dict[str, Any]]:
    candidates = [
        row for row in rows
        if float(row["metrics"]["precision"]) >= target
    ]
    return [
        _compact_row(row)
        for row in sorted(candidates, key=_sort_for_recall, reverse=True)[:10]
    ]


def _top_for_recall(rows: list[dict[str, Any]], target: float) -> list[dict[str, Any]]:
    candidates = [
        row for row in rows
        if float(row["metrics"]["recall"]) >= target
    ]
    return [
        _compact_row(row)
        for row in sorted(
            candidates,
            key=lambda row: (
                float(row["metrics"]["precision"]),
                float(row["metrics"]["f1"]),
                -int(row["metrics"]["fp"]),
            ),
            reverse=True,
        )[:10]
    ]


def _best_overall(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _compact_row(row)
        for row in sorted(
            rows,
            key=lambda row: (
                float(row["metrics"]["f1"]),
                float(row["metrics"]["precision"]),
                float(row["metrics"]["recall"]),
            ),
            reverse=True,
        )[:10]
    ]


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Hybrid V2 Calibration",
        "",
        "This is a replay experiment over recorded production-path signals. It does "
        "not change production scanner behavior.",
        "",
        f"- Input: `{result['input_json']}`",
        f"- Packages: {result['counts']['total_packages']}",
        f"- Malicious: {result['counts']['malicious_packages']}",
        f"- Benign: {result['counts']['benign_packages']}",
        f"- Configs swept: {result['configs_swept']}",
        "",
        "## Current Production Hybrid",
        "",
        "| Precision | Recall | F1 | TP | FP | FN | TN |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    current = result["current_hybrid_metrics"]
    lines.append(
        f"| {current['precision']:.4f} | {current['recall']:.4f} | "
        f"{current['f1']:.4f} | {current['tp']} | {current['fp']} | "
        f"{current['fn']} | {current['tn']} |"
    )

    lines.extend(["", "## Best Recall At Precision Targets", ""])
    for target, rows in result["best_recall_at_precision"].items():
        lines.extend([f"### Precision >= {target}", ""])
        if not rows:
            lines.append("- No configuration reached this precision target.")
            lines.append("")
            continue
        lines.extend([
            "| Rank | Precision | Recall | F1 | TP | FP | FN | GNN Direct | Confirm Floor | Rule Confirm |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for idx, row in enumerate(rows[:5], 1):
            metrics = row["metrics"]
            cfg = row["config"]
            lines.append(
                f"| {idx} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
                f"{metrics['f1']:.4f} | {metrics['tp']} | {metrics['fp']} | "
                f"{metrics['fn']} | {cfg['gnn_direct_block_threshold']:.2f} | "
                f"{cfg['gnn_confirm_floor']:.2f} | {cfg['weighted_confirm_threshold']:.1f} |"
            )
        lines.append("")

    lines.extend(["## Best Precision At Recall Targets", ""])
    for target, rows in result["best_precision_at_recall"].items():
        lines.extend([f"### Recall >= {target}", ""])
        if not rows:
            lines.append("- No configuration reached this recall target.")
            lines.append("")
            continue
        metrics = rows[0]["metrics"]
        cfg = rows[0]["config"]
        lines.append(
            f"- Best: precision {metrics['precision']:.4f}, recall "
            f"{metrics['recall']:.4f}, FP {metrics['fp']}, FN {metrics['fn']} "
            f"with config `{cfg}`"
        )
        lines.append("")

    reach = result["target_reachability"]
    lines.extend([
        "## Target Reachability",
        "",
        f"- Precision >= 0.96 and recall >= 0.88: {reach['p96_r88']}",
        f"- Precision >= 0.97 and recall >= 0.88: {reach['p97_r88']}",
        f"- Precision >= 0.98 and recall >= 0.88: {reach['p98_r88']}",
        f"- Precision >= 0.99 and recall >= 0.88: {reach['p99_r88']}",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    data = json.loads(args.input_json.read_text(encoding="utf-8"))
    records = data["packages"]
    current_metrics = data["summary"]["metrics"]["hybrid"]
    rows = [_metric_row(config, records) for config in _sweep_configs()]

    best_recall_at_precision = {
        f"{target:.2f}": _top_for_precision(rows, target)
        for target in [0.96, 0.97, 0.98, 0.99]
    }
    best_precision_at_recall = {
        f"{target:.2f}": _top_for_recall(rows, target)
        for target in [0.88, 0.89, 0.90, 0.92]
    }
    labels = [int(record["true_label"]) for record in records]
    result = {
        "input_json": str(args.input_json),
        "counts": {
            "total_packages": len(records),
            "malicious_packages": sum(labels),
            "benign_packages": len(records) - sum(labels),
        },
        "configs_swept": len(rows),
        "policy": "hybrid_v2_replay",
        "current_hybrid_metrics": current_metrics,
        "best_recall_at_precision": best_recall_at_precision,
        "best_precision_at_recall": best_precision_at_recall,
        "best_overall_f1": _best_overall(rows),
        "target_reachability": {
            "p96_r88": bool([
                row for row in rows
                if row["metrics"]["precision"] >= 0.96 and row["metrics"]["recall"] >= 0.88
            ]),
            "p97_r88": bool([
                row for row in rows
                if row["metrics"]["precision"] >= 0.97 and row["metrics"]["recall"] >= 0.88
            ]),
            "p98_r88": bool([
                row for row in rows
                if row["metrics"]["precision"] >= 0.98 and row["metrics"]["recall"] >= 0.88
            ]),
            "p99_r88": bool([
                row for row in rows
                if row["metrics"]["precision"] >= 0.99 and row["metrics"]["recall"] >= 0.88
            ]),
        },
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    args.output_md.write_text(_render_markdown(result), encoding="utf-8")

    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")
    for target, rows_for_target in best_recall_at_precision.items():
        if not rows_for_target:
            print(f"precision >= {target}: no config")
            continue
        best = rows_for_target[0]["metrics"]
        print(
            f"precision >= {target}: recall={best['recall']:.4f} "
            f"precision={best['precision']:.4f} fp={best['fp']} fn={best['fn']}"
        )


if __name__ == "__main__":
    main()
