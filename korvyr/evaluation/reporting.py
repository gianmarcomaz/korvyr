"""Pure helpers for production-path evaluation reports."""

from __future__ import annotations

from collections import Counter
from typing import Any


def compute_binary_metrics(
    predictions: list[int],
    labels: list[int],
) -> dict[str, float | int]:
    """Return standard binary-classification metrics for 0/1 predictions."""
    tp = sum(1 for pred, label in zip(predictions, labels) if pred == 1 and label == 1)
    fp = sum(1 for pred, label in zip(predictions, labels) if pred == 1 and label == 0)
    fn = sum(1 for pred, label in zip(predictions, labels) if pred == 0 and label == 1)
    tn = sum(1 for pred, label in zip(predictions, labels) if pred == 0 and label == 0)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "flagged": tp + fp,
    }


def malicious_prediction(verdict: str) -> int:
    """Treat only hard-block malicious verdicts as positive predictions."""
    return 1 if verdict == "malicious" else 0


def decision_bucket(verdict: str, decision_path: str) -> str:
    """Map production decision text to stable reporting buckets."""
    path = decision_path.lower()
    if verdict == "clean":
        if "unavailable" in path:
            return "gnn_unavailable_clean"
        if "confident clean" in path:
            return "gnn_confident_clean"
        return "clean_pass"
    if verdict == "malicious":
        if "v2 install-hook recall block" in path:
            return "v2_install_hook_recall_block"
        if "v2 direct gnn block" in path:
            return "v2_gnn_direct_block"
        if "v2 gnn + weighted rules block" in path:
            return "v2_gnn_weighted_rules_block"
        if "v2 high-reliability rules block" in path:
            return "v2_hard_rules_block"
        if "critical behavioral rule" in path:
            return "critical_rule_block"
        if "very high confidence" in path:
            return "gnn_very_high_block"
        if "confirming rules" in path:
            return "gnn_rules_confirmed_block"
        if "gnn unavailable" in path:
            return "rules_only_block"
        return "malicious_block"
    if "without strong static confirmation" in path:
        return "gnn_unconfirmed_review"
    if "v2 review: low gnn" in path:
        return "v2_low_gnn_review"
    if "v2 review: evidence below block thresholds" in path:
        return "v2_static_review"
    if "v2 review: gnn-only uncertainty" in path:
        return "v2_gnn_review"
    if "review-only critical" in path:
        return "review_only_critical"
    if "gnn unavailable" in path:
        return "gnn_unavailable_review"
    if "static evidence" in path or "rule" in path:
        return "static_evidence_review"
    return "uncertain_review"


def per_rule_saved_hurt(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Count when each matched rule improved or hurt GNN-only correctness."""
    saved: Counter[str] = Counter()
    hurt: Counter[str] = Counter()

    for record in records:
        label = int(record["true_label"])
        gnn_pred = int(record["gnn_score"] >= 0.5) if record["gnn_score"] >= 0 else 0
        hybrid_pred = malicious_prediction(str(record["hybrid_verdict"]))
        gnn_correct = gnn_pred == label
        hybrid_correct = hybrid_pred == label
        for rule_id in record.get("rules_matched", []):
            if not gnn_correct and hybrid_correct:
                saved[str(rule_id)] += 1
            elif gnn_correct and not hybrid_correct:
                hurt[str(rule_id)] += 1

    all_rules = sorted(set(saved) | set(hurt))
    return {rule: {"saved": saved[rule], "hurt": hurt[rule]} for rule in all_rules}


def gnn_score_bucket_calibration(records: list[dict[str, Any]]) -> dict[str, dict[str, float | int]]:
    """Summarize observed malicious rate by GNN score bucket.

    This is not probability calibration in the statistical sense; it is a
    compact reliability table for comparing checkpoints on the same corpus.
    """
    buckets = [
        ("[0.00,0.10)", 0.0, 0.1),
        ("[0.10,0.20)", 0.1, 0.2),
        ("[0.20,0.30)", 0.2, 0.3),
        ("[0.30,0.40)", 0.3, 0.4),
        ("[0.40,0.50)", 0.4, 0.5),
        ("[0.50,0.60)", 0.5, 0.6),
        ("[0.60,0.70)", 0.6, 0.7),
        ("[0.70,0.80)", 0.7, 0.8),
        ("[0.80,0.90)", 0.8, 0.9),
        ("[0.90,1.00]", 0.9, 1.0000001),
    ]
    out: dict[str, dict[str, float | int]] = {}
    for name, low, high in buckets:
        bucket_records = [
            record for record in records
            if low <= float(record.get("gnn_score", -1.0)) < high
        ]
        total = len(bucket_records)
        malicious = sum(int(record["true_label"]) for record in bucket_records)
        avg_score = (
            sum(float(record.get("gnn_score", 0.0)) for record in bucket_records)
            / max(total, 1)
        )
        out[name] = {
            "total": total,
            "malicious": malicious,
            "benign": total - malicious,
            "observed_malicious_rate": malicious / max(total, 1),
            "avg_gnn_score": avg_score,
        }
    return out


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the canonical aggregate JSON summary from package records."""
    labels = [int(record["true_label"]) for record in records]
    gnn_preds = [
        1 if float(record.get("gnn_score", -1.0)) >= 0.5 else 0
        for record in records
    ]
    rules_preds = [
        malicious_prediction(str(record.get("rules_verdict", "clean")))
        for record in records
    ]
    hybrid_preds = [
        malicious_prediction(str(record.get("hybrid_verdict", "clean")))
        for record in records
    ]

    gnn_available = [
        record for record in records
        if float(record.get("gnn_score", -1.0)) >= 0.0
    ]
    gnn_errors = [
        str(record.get("gnn_error_type") or "UNKNOWN")
        for record in records
        if float(record.get("gnn_score", -1.0)) < 0.0
    ]
    cpg_status_counts = Counter(str(record.get("cpg_status", "unknown")) for record in records)
    bucket_counts = Counter(str(record.get("decision_bucket", "unknown")) for record in records)

    false_positives = [
        record for record, pred in zip(records, hybrid_preds)
        if pred == 1 and int(record["true_label"]) == 0
    ]
    false_negatives = [
        record for record, pred in zip(records, hybrid_preds)
        if pred == 0 and int(record["true_label"]) == 1
    ]

    total = len(records)
    return {
        "counts": {
            "total_packages": total,
            "malicious_packages": sum(labels),
            "benign_packages": total - sum(labels),
        },
        "metrics": {
            "gnn_only": compute_binary_metrics(gnn_preds, labels),
            "rules_only": compute_binary_metrics(rules_preds, labels),
            "hybrid": compute_binary_metrics(hybrid_preds, labels),
        },
        "coverage": {
            "gnn_coverage_rate": len(gnn_available) / max(total, 1),
            "gnn_failure_count": len(gnn_errors),
            "gnn_error_buckets": dict(Counter(gnn_errors)),
            "cpg_none_count": cpg_status_counts.get("cpg_none", 0),
            "cpg_failure_count": cpg_status_counts.get("failure", 0),
            "cpg_status_counts": dict(cpg_status_counts),
        },
        "decision_buckets": dict(bucket_counts),
        "per_rule_contribution": per_rule_saved_hurt(records),
        "gnn_score_buckets": gnn_score_bucket_calibration(records),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def _metric_line(name: str, metrics: dict[str, Any]) -> str:
    return (
        f"| {name} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
        f"{metrics['f1']:.4f} | {metrics['tp']} | {metrics['fp']} | "
        f"{metrics['fn']} | {metrics['tn']} |"
    )


def render_markdown_report(summary: dict[str, Any], records: list[dict[str, Any]]) -> str:
    """Render a compact human-readable Markdown report."""
    counts = summary["counts"]
    coverage = summary["coverage"]
    metrics = summary["metrics"]
    lines = [
        "# Korvyr Production-Path Evaluation",
        "",
        "This report is measured output from the canonical evaluator. It does not "
        "claim target accuracy unless the metrics below show it.",
        "",
        "## Dataset",
        "",
        f"- Total packages: {counts['total_packages']}",
        f"- Malicious packages: {counts['malicious_packages']}",
        f"- Benign packages: {counts['benign_packages']}",
        "",
        "## Metrics",
        "",
        "| System | Precision | Recall | F1 | TP | FP | FN | TN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        _metric_line("GNN-only", metrics["gnn_only"]),
        _metric_line("Rules-only", metrics["rules_only"]),
        _metric_line("Hybrid", metrics["hybrid"]),
        "",
        "## Coverage",
        "",
        f"- GNN coverage rate: {coverage['gnn_coverage_rate']:.2%}",
        f"- GNN failure count: {coverage['gnn_failure_count']}",
        f"- CPG none count: {coverage['cpg_none_count']}",
        f"- CPG failure count: {coverage['cpg_failure_count']}",
        f"- GNN error buckets: `{coverage['gnn_error_buckets']}`",
        f"- CPG status counts: `{coverage['cpg_status_counts']}`",
        "",
        "## Decision Buckets",
        "",
    ]
    for bucket, count in sorted(summary["decision_buckets"].items()):
        lines.append(f"- {bucket}: {count}")

    lines.extend(["", "## Per-Rule Saved/Hurt", ""])
    if summary["per_rule_contribution"]:
        lines.extend(["| Rule | Saved | Hurt |", "|---|---:|---:|"])
        for rule, values in summary["per_rule_contribution"].items():
            lines.append(f"| {rule} | {values['saved']} | {values['hurt']} |")
    else:
        lines.append("- No matched rules affected hybrid correctness.")

    lines.extend(["", "## GNN Score Buckets", ""])
    lines.extend([
        "| Score Bucket | Total | Malicious | Benign | Observed Malicious Rate | Avg GNN |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for bucket, values in summary["gnn_score_buckets"].items():
        lines.append(
            f"| {bucket} | {values['total']} | {values['malicious']} | "
            f"{values['benign']} | {values['observed_malicious_rate']:.4f} | "
            f"{values['avg_gnn_score']:.4f} |"
        )

    lines.extend(["", "## False Positives", ""])
    if summary["false_positives"]:
        for record in summary["false_positives"][:50]:
            lines.append(
                f"- {record['package_name']} | GNN={record['gnn_score']:.4f} | "
                f"rules={record['rules_matched']} | {record['decision_path']}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## False Negatives", ""])
    if summary["false_negatives"]:
        for record in summary["false_negatives"][:50]:
            lines.append(
                f"- {record['package_name']} | GNN={record['gnn_score']:.4f} | "
                f"rules={record['rules_matched']} | {record['decision_path']}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Records", "", f"- Package records included: {len(records)}"])
    return "\n".join(lines) + "\n"
