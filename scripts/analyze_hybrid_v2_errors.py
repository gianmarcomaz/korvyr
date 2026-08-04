"""Root-cause analysis for the best hybrid v2 replay configuration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from korvyr.evaluation.error_analysis import (
    improvement_candidates,
    summarize_error_records,
)
from korvyr.evaluation.hybrid_policy_v2 import HybridV2Config, apply_policy_to_record

ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze FP/FN root causes for the best hybrid v2 config.",
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
        help="Key under best_recall_at_precision to analyze, e.g. 0.96.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "results" / "hybrid_v2_error_analysis.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=ROOT / "results" / "hybrid_v2_error_analysis.md",
    )
    return parser.parse_args()


def _load_best_config(calibration: dict[str, Any], precision_target: str) -> dict[str, Any]:
    rows = calibration["best_recall_at_precision"].get(precision_target, [])
    if not rows:
        raise ValueError(f"No calibration row found for precision target {precision_target}")
    return rows[0]


def _config_from_dict(config: dict[str, Any]) -> HybridV2Config:
    allowed = set(HybridV2Config.__dataclass_fields__)
    return HybridV2Config(**{key: value for key, value in config.items() if key in allowed})


def _replay_records(records: list[dict[str, Any]], config: HybridV2Config) -> list[dict[str, Any]]:
    return [apply_policy_to_record(record, config) for record in records]


def _false_positives(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        record for record in records
        if int(record["true_label"]) == 0 and record["hybrid_verdict"] == "malicious"
    ]


def _false_negatives(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        record for record in records
        if int(record["true_label"]) == 1 and record["hybrid_verdict"] != "malicious"
    ]


def _render_section(title: str, summary: dict[str, Any]) -> list[str]:
    lines = [f"## {title}", ""]
    lines.append(f"- Count: {summary['count']}")
    lines.append(f"- Categories: `{summary['categories']}`")
    lines.append(f"- Score bands: `{summary['score_bands']}`")
    lines.append(f"- Rule profile buckets: `{summary['rule_profile_buckets']}`")
    lines.append(f"- Top rules: `{summary['top_rules']}`")
    lines.extend(["", "| Package | Category | GNN | Rules | Manifest Hooks | Decision |"])
    lines.append("|---|---|---:|---|---|---|")
    for record in summary["records"][:30]:
        hooks = ",".join(record["manifest"].get("script_hooks", []))
        rules = ",".join(record["rules_matched"][:5])
        lines.append(
            f"| {record['package_name']} | {record['category']} | "
            f"{record['gnn_score']:.4f} | {rules} | {hooks} | "
            f"{record['decision_bucket']} |"
        )
    lines.append("")
    return lines


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Hybrid V2 Error Analysis",
        "",
        "This report explains the residual false positives and false negatives for "
        "the best replayed hybrid v2 config. It is analysis only; it does not "
        "change production scanner behavior.",
        "",
        f"- Production input: `{result['inputs']['production_json']}`",
        f"- Calibration input: `{result['inputs']['calibration_json']}`",
        f"- Precision target analyzed: {result['precision_target']}",
        f"- Metrics: `{result['metrics']}`",
        f"- Config: `{result['config']}`",
        "",
    ]
    lines.extend(_render_section("False Positives", result["false_positives"]))
    lines.extend(_render_section("False Negatives", result["false_negatives"]))
    lines.extend(["## Improvement Candidates", ""])
    for item in result["improvement_candidates"]:
        lines.append(f"### {item['candidate']}")
        lines.append(f"- Area: {item['area']}")
        lines.append(f"- Why: {item['why']}")
        lines.append(f"- Risk: {item['risk']}")
        lines.append("")
    lines.extend([
        "## Reachability Note",
        "",
        "The current replayed signals do not reach precision >= 0.96 with recall "
        ">= 0.88. Improvements that move both metrics require new separating "
        "signal, not only threshold movement.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    production = json.loads(args.production_json.read_text(encoding="utf-8"))
    calibration = json.loads(args.calibration_json.read_text(encoding="utf-8"))
    best = _load_best_config(calibration, args.precision_target)
    config = _config_from_dict(best["config"])
    replayed = _replay_records(production["packages"], config)
    fps = _false_positives(replayed)
    fns = _false_negatives(replayed)
    fp_summary = summarize_error_records(fps, "fp")
    fn_summary = summarize_error_records(fns, "fn")
    result = {
        "inputs": {
            "production_json": str(args.production_json),
            "calibration_json": str(args.calibration_json),
        },
        "precision_target": args.precision_target,
        "config": config.to_dict(),
        "metrics": best["metrics"],
        "false_positives": fp_summary,
        "false_negatives": fn_summary,
        "improvement_candidates": improvement_candidates(fp_summary, fn_summary),
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    args.output_md.write_text(_render_markdown(result), encoding="utf-8")
    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")
    print(f"FP categories: {fp_summary['categories']}")
    print(f"FN categories: {fn_summary['categories']}")


if __name__ == "__main__":
    main()
