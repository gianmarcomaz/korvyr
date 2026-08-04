"""Audit lifecycle/install-hook separating signals for hybrid v2 errors."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from korvyr.evaluation.context_signals import evaluate_candidate, prediction_from_record
from korvyr.evaluation.hybrid_policy_v2 import HybridV2Config, apply_policy_to_record
from korvyr.evaluation.lifecycle_signals import (
    enrich_lifecycle_context,
    lifecycle_candidate_signals,
)
from korvyr.evaluation.reporting import compute_binary_metrics

ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure lifecycle separating signals on hybrid v2 replay errors.",
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
    parser.add_argument("--precision-target", default="0.96")
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "results" / "lifecycle_signal_audit.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=ROOT / "results" / "lifecycle_signal_audit.md",
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
        enrich_lifecycle_context(apply_policy_to_record(record, config))
        for record in records
    ]


def _metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [int(record["true_label"]) for record in records]
    preds = [prediction_from_record(record) for record in records]
    return compute_binary_metrics(preds, labels)


def _hook_error_slice(records: list[dict[str, Any]]) -> dict[str, Any]:
    slice_records = [
        record for record in records
        if record["context"]["has_lifecycle_hook"]
        and 0.35 <= record["context"]["gnn_score"] < 0.80
    ]
    labels = [int(record["true_label"]) for record in slice_records]
    preds = [prediction_from_record(record) for record in slice_records]
    false_negatives = [
        record for record in slice_records
        if int(record["true_label"]) == 1 and prediction_from_record(record) == 0
    ]
    true_negatives = [
        record for record in slice_records
        if int(record["true_label"]) == 0 and prediction_from_record(record) == 0
    ]
    return {
        "count": len(slice_records),
        "metrics": compute_binary_metrics(preds, labels),
        "false_negatives": [
            _compact_record(record) for record in false_negatives[:50]
        ],
        "true_negatives": [
            _compact_record(record) for record in true_negatives[:50]
        ],
    }


def _compact_record(record: dict[str, Any]) -> dict[str, Any]:
    lifecycle = record["lifecycle_context"]
    return {
        "package_name": record.get("package_name", ""),
        "true_label": int(record["true_label"]),
        "current_pred": prediction_from_record(record),
        "gnn_score": float(record["gnn_score"]),
        "metadata_risk": float(record.get("metadata_risk", 0.0) or 0.0),
        "rules_matched": list(record.get("rules_matched", [])),
        "lifecycle_hooks": record["context"]["lifecycle_hooks"],
        "hook_commands": lifecycle["hook_commands"],
        "hook_target_files_found": lifecycle["hook_target_files_found"],
        "hook_risk_score": lifecycle["hook_risk_score"],
        "hook_has_network": lifecycle["hook_has_network"],
        "hook_has_shell_exec": lifecycle["hook_has_shell_exec"],
        "hook_has_secret_terms": lifecycle["hook_has_secret_terms"],
        "hook_has_obfuscation": lifecycle["hook_has_obfuscation"],
        "hook_has_benign_build_terms": lifecycle["hook_has_benign_build_terms"],
    }


def _combined_confirmers(
    records: list[dict[str, Any]],
    candidate_results: list[dict[str, Any]],
) -> dict[str, Any]:
    by_name = {candidate.name: candidate for candidate in lifecycle_candidate_signals()}
    chosen_names = [
        result["name"]
        for result in candidate_results
        if result["kind"] == "confirmer"
        and result["matched_cells"]["fn"] > 0
        and result["matched_cells"]["tn"] == 0
    ]
    chosen = [by_name[name] for name in chosen_names]
    labels = [int(record["true_label"]) for record in records]
    baseline_preds = [prediction_from_record(record) for record in records]
    adjusted_preds = list(baseline_preds)
    changed: list[dict[str, Any]] = []

    for idx, record in enumerate(records):
        if baseline_preds[idx] == 1:
            continue
        fired = [candidate for candidate in chosen if candidate.predicate(record)]
        if not fired:
            continue
        adjusted_preds[idx] = 1
        changed.append(
            {
                "package_name": record.get("package_name", ""),
                "true_label": int(record["true_label"]),
                "signals": [candidate.name for candidate in fired],
            }
        )

    return {
        "chosen_signal_names": chosen_names,
        "baseline_metrics": compute_binary_metrics(baseline_preds, labels),
        "adjusted_metrics": compute_binary_metrics(adjusted_preds, labels),
        "changed_packages": changed,
    }


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Lifecycle Signal Audit",
        "",
        "This report measures install-hook command and target-file traits as "
        "candidate separating signals. It is replay-only and does not change "
        "production scanner behavior.",
        "",
        f"- Production input: `{result['inputs']['production_json']}`",
        f"- Calibration input: `{result['inputs']['calibration_json']}`",
        f"- Precision target replayed: {result['precision_target']}",
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

    hook_slice = result["mid_gnn_hook_slice"]
    lines.extend(
        [
            "",
            "## Mid-GNN Lifecycle-Hook Slice",
            "",
            f"- Records: {hook_slice['count']}",
            f"- Slice metrics: `{hook_slice['metrics']}`",
            f"- False negatives in slice: {len(hook_slice['false_negatives'])}",
            f"- True negatives in slice: {len(hook_slice['true_negatives'])}",
            "",
            "## Candidate Signal Impact",
            "",
            "| Signal | Kind | Matched | FP Saved | TP Hurt | FN Saved | TN Hurt | Precision After | Recall After | F1 After |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in result["candidate_results"]:
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
        after = item["adjusted_metrics"]
        lines.append(
            f"| {item['name']} | {item['kind']} | {item['matched']} | "
            f"{fp_saved} | {tp_hurt} | {fn_saved} | {tn_hurt} | "
            f"{after['precision']:.4f} | {after['recall']:.4f} | "
            f"{after['f1']:.4f} |"
        )
        if item["matched_cells"]["fn"] or item["matched_cells"]["tn"]:
            examples = ", ".join(
                package["package_name"] for package in item["matched_packages"][:8]
            )
            lines.append(f"| Examples |  |  |  |  |  |  |  |  | `{examples}` |")

    combined = result["zero_tn_hurt_confirmer_combo"]
    combo = combined["adjusted_metrics"]
    lines.extend(
        [
            "",
            "## Zero-TN-Hurt Confirmer Combination",
            "",
            f"- Signals: `{combined['chosen_signal_names']}`",
            "",
            "| Precision | Recall | F1 | TP | FP | FN | TN |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            (
                f"| {combo['precision']:.4f} | {combo['recall']:.4f} | "
                f"{combo['f1']:.4f} | {combo['tp']} | {combo['fp']} | "
                f"{combo['fn']} | {combo['tn']} |"
            ),
            "",
            "## Interpretation",
            "",
            result["interpretation"],
            "",
        ]
    )
    return "\n".join(lines)


def _interpret(result: dict[str, Any]) -> str:
    combo = result["zero_tn_hurt_confirmer_combo"]["adjusted_metrics"]
    baseline = result["baseline_metrics"]
    if combo["recall"] > baseline["recall"] and combo["precision"] >= baseline["precision"]:
        return (
            "Lifecycle command/target-file traits found a narrower confirmer that "
            "improves recall without adding measured false positives on this replay "
            "set. This is a candidate for a guarded production experiment, followed "
            "by holdout evaluation."
        )
    return (
        "Lifecycle traits did not find a no-false-positive recall lift. The install "
        "hook region still needs either deeper script semantics or retraining on the "
        "hard examples before production policy changes are justified."
    )


def main() -> None:
    args = parse_args()
    production = json.loads(args.production_json.read_text(encoding="utf-8"))
    calibration = json.loads(args.calibration_json.read_text(encoding="utf-8"))
    config = _load_best_config(calibration, args.precision_target)
    replayed = _replay(production["packages"], config)
    candidates = lifecycle_candidate_signals()
    candidate_results = [evaluate_candidate(replayed, candidate) for candidate in candidates]
    combined = _combined_confirmers(replayed, candidate_results)
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
        "mid_gnn_hook_slice": _hook_error_slice(replayed),
        "candidate_results": candidate_results,
        "zero_tn_hurt_confirmer_combo": combined,
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
        "Zero-TN-hurt confirmer combo: "
        f"P={combined['adjusted_metrics']['precision']:.4f} "
        f"R={combined['adjusted_metrics']['recall']:.4f} "
        f"FP={combined['adjusted_metrics']['fp']} "
        f"FN={combined['adjusted_metrics']['fn']}"
    )


if __name__ == "__main__":
    main()
