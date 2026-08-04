"""Package-context signal audit helpers for hybrid v2 errors.

These helpers are intentionally replay-only. They measure candidate context
signals against recorded production-path evaluation rows before any scanner
behavior is changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from korvyr.evaluation.error_analysis import HIGH_NOISE_RULES, HIGH_RELIABILITY_RULES
from korvyr.evaluation.reporting import compute_binary_metrics, malicious_prediction
from korvyr.utils import read_package_json as load_package_json

INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare"}


@dataclass(frozen=True)
class CandidateSignal:
    name: str
    kind: str
    description: str
    predicate: Callable[[dict[str, Any]], bool]


def _dict_len(value: Any) -> int:
    return len(value) if isinstance(value, dict) else 0


def manifest_context(record: dict[str, Any]) -> dict[str, Any]:
    """Extract manifest and package-shape traits from one evaluation record."""
    package_path = record.get("package_path") or record.get("source_path") or ""
    manifest = load_package_json(str(package_path))
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        scripts = {}

    lifecycle_hooks = sorted(hook for hook in INSTALL_HOOKS if hook in scripts)
    description = str(manifest.get("description") or "")
    dependencies = manifest.get("dependencies", {})
    dev_dependencies = manifest.get("devDependencies", {})
    name = str(manifest.get("name") or record.get("package_name") or "")

    rule_ids = [str(rule_id) for rule_id in record.get("rules_matched", [])]
    noisy_rule_count = sum(1 for rule_id in rule_ids if rule_id in HIGH_NOISE_RULES)
    high_reliability_rule_count = sum(
        1 for rule_id in rule_ids if rule_id in HIGH_RELIABILITY_RULES
    )

    return {
        "package_name": name,
        "has_package_json": bool(manifest),
        "scoped": name.startswith("@"),
        "has_repository": bool(manifest.get("repository")),
        "has_license": bool(manifest.get("license")),
        "has_description": bool(description.strip()),
        "description_length": len(description),
        "scripts_count": len(scripts),
        "lifecycle_hooks": lifecycle_hooks,
        "has_lifecycle_hook": bool(lifecycle_hooks),
        "dependency_count": _dict_len(dependencies),
        "dev_dependency_count": _dict_len(dev_dependencies),
        "gnn_score": float(record.get("gnn_score", -1.0)),
        "metadata_risk": float(record.get("metadata_risk", 0.0) or 0.0),
        "num_js_files": int(record.get("num_js_files", 0) or 0),
        "num_nodes": int(record.get("num_nodes", 0) or 0),
        "num_edges": int(record.get("num_edges", 0) or 0),
        "rule_ids": rule_ids,
        "rules_count": len(rule_ids),
        "has_rules": bool(rule_ids),
        "noisy_rule_count": noisy_rule_count,
        "high_reliability_rule_count": high_reliability_rule_count,
        "rules_noisy_only": bool(rule_ids)
        and noisy_rule_count == len(rule_ids)
        and high_reliability_rule_count == 0,
        "rules_none": not rule_ids,
        "has_med_install_hook_rule": "MED_INSTALL_HOOK_EXISTS" in rule_ids,
        "has_structural_rule": "MED_SUSPICIOUS_PACKAGE_STRUCTURE" in rule_ids,
        "has_manifest_hook_only_rule": "MED_MANIFEST_INSTALL_HOOK_ONLY" in rule_ids,
        "has_critical_rule": any(rule_id.startswith("CRIT_") for rule_id in rule_ids),
    }


def enrich_record_context(record: dict[str, Any]) -> dict[str, Any]:
    """Attach context traits under ``context`` without mutating the input."""
    out = dict(record)
    out["context"] = manifest_context(record)
    return out


def _ctx(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("context") or manifest_context(record)


def default_candidate_signals() -> list[CandidateSignal]:
    """Return candidate signals to measure against residual v2 errors."""
    return [
        CandidateSignal(
            "suppress_no_rules_benign_context_high_gnn",
            "suppressor",
            "High GNN/no-rule block with low metadata risk and benign manifest context.",
            lambda record: (
                _ctx(record)["gnn_score"] >= 0.80
                and _ctx(record)["rules_none"]
                and not _ctx(record)["has_lifecycle_hook"]
                and _ctx(record)["metadata_risk"] <= 0.15
                and _ctx(record)["has_license"]
                and _ctx(record)["description_length"] >= 20
            ),
        ),
        CandidateSignal(
            "suppress_no_hooks_noisy_rules_benign_context",
            "suppressor",
            "No lifecycle hooks, noisy-only rules, low metadata risk, and benign manifest context.",
            lambda record: (
                _ctx(record)["rules_noisy_only"]
                and not _ctx(record)["has_lifecycle_hook"]
                and _ctx(record)["metadata_risk"] <= 0.15
                and (_ctx(record)["has_license"] or _ctx(record)["has_repository"])
                and _ctx(record)["description_length"] >= 20
            ),
        ),
        CandidateSignal(
            "suppress_dummy_graph_no_hooks_low_metadata",
            "suppressor",
            "One-node graph artifact with no lifecycle hooks and low metadata risk.",
            lambda record: (
                _ctx(record)["num_nodes"] <= 1
                and not _ctx(record)["has_lifecycle_hook"]
                and _ctx(record)["metadata_risk"] <= 0.15
            ),
        ),
        CandidateSignal(
            "suppress_large_bundle_no_hooks_noisy_rules",
            "suppressor",
            "Large bundled package with no lifecycle hooks and only noisy rules.",
            lambda record: (
                (_ctx(record)["num_js_files"] >= 20 or _ctx(record)["num_nodes"] >= 30000)
                and not _ctx(record)["has_lifecycle_hook"]
                and _ctx(record)["rules_noisy_only"]
                and _ctx(record)["metadata_risk"] <= 0.15
            ),
        ),
        CandidateSignal(
            "confirm_metadata_risk_high",
            "confirmer",
            "High metadata risk as an additional hard-block confirmation.",
            lambda record: _ctx(record)["metadata_risk"] >= 0.40,
        ),
        CandidateSignal(
            "confirm_structural_or_manifest_hook_rule",
            "confirmer",
            "High-precision structural package rule or manifest hook-only rule.",
            lambda record: (
                _ctx(record)["has_structural_rule"]
                or _ctx(record)["has_manifest_hook_only_rule"]
            ),
        ),
        CandidateSignal(
            "confirm_mid_gnn_install_hook_rule",
            "confirmer",
            "Mid-GNN package with lifecycle hook and MED_INSTALL_HOOK_EXISTS.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and _ctx(record)["has_med_install_hook_rule"]
            ),
        ),
        CandidateSignal(
            "confirm_mid_gnn_install_hook_metadata",
            "confirmer",
            "Mid-GNN package with lifecycle hook and non-trivial metadata risk.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and _ctx(record)["metadata_risk"] >= 0.20
            ),
        ),
        CandidateSignal(
            "confirm_sparse_mid_gnn_no_rules",
            "confirmer",
            "Mid/high GNN package with no rules and sparse or missing benign context.",
            lambda record: (
                0.55 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["rules_none"]
                and not _ctx(record)["has_repository"]
                and not _ctx(record)["has_license"]
                and _ctx(record)["description_length"] < 20
            ),
        ),
    ]


def prediction_from_record(record: dict[str, Any]) -> int:
    return malicious_prediction(str(record.get("hybrid_verdict", "clean")))


def evaluate_candidate(
    records: list[dict[str, Any]],
    candidate: CandidateSignal,
) -> dict[str, Any]:
    """Measure one candidate as a suppressor or confirmer intervention."""
    labels = [int(record["true_label"]) for record in records]
    baseline_preds = [prediction_from_record(record) for record in records]
    adjusted_preds = list(baseline_preds)
    matched_records: list[dict[str, Any]] = []

    for idx, record in enumerate(records):
        if not candidate.predicate(record):
            continue
        matched_records.append(record)
        if candidate.kind == "suppressor" and baseline_preds[idx] == 1:
            adjusted_preds[idx] = 0
        elif candidate.kind == "confirmer" and baseline_preds[idx] == 0:
            adjusted_preds[idx] = 1

    baseline_metrics = compute_binary_metrics(baseline_preds, labels)
    adjusted_metrics = compute_binary_metrics(adjusted_preds, labels)
    matched_by_cell = {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
    }
    for record in matched_records:
        label = int(record["true_label"])
        pred = prediction_from_record(record)
        if pred == 1 and label == 1:
            matched_by_cell["tp"] += 1
        elif pred == 1 and label == 0:
            matched_by_cell["fp"] += 1
        elif pred == 0 and label == 1:
            matched_by_cell["fn"] += 1
        else:
            matched_by_cell["tn"] += 1

    return {
        "name": candidate.name,
        "kind": candidate.kind,
        "description": candidate.description,
        "matched": len(matched_records),
        "matched_cells": matched_by_cell,
        "baseline_metrics": baseline_metrics,
        "adjusted_metrics": adjusted_metrics,
        "deltas": {
            "precision": adjusted_metrics["precision"] - baseline_metrics["precision"],
            "recall": adjusted_metrics["recall"] - baseline_metrics["recall"],
            "f1": adjusted_metrics["f1"] - baseline_metrics["f1"],
            "tp": adjusted_metrics["tp"] - baseline_metrics["tp"],
            "fp": adjusted_metrics["fp"] - baseline_metrics["fp"],
            "fn": adjusted_metrics["fn"] - baseline_metrics["fn"],
            "tn": adjusted_metrics["tn"] - baseline_metrics["tn"],
        },
        "matched_packages": [
            {
                "package_name": record.get("package_name", ""),
                "true_label": int(record.get("true_label", 0)),
                "current_pred": prediction_from_record(record),
                "gnn_score": float(record.get("gnn_score", -1.0)),
                "rules_matched": list(record.get("rules_matched", [])),
                "context": _ctx(record),
            }
            for record in matched_records
        ],
    }


def hard_examples(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Return compact FP/FN hard-example manifests for future retraining."""
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    for record in records:
        pred = prediction_from_record(record)
        label = int(record["true_label"])
        if pred == label:
            continue
        item = {
            "package_name": record.get("package_name", ""),
            "package_path": record.get("package_path") or record.get("source_path") or "",
            "true_label": label,
            "current_pred": pred,
            "gnn_score": float(record.get("gnn_score", -1.0)),
            "rules_matched": list(record.get("rules_matched", [])),
            "metadata_risk": float(record.get("metadata_risk", 0.0) or 0.0),
            "context": _ctx(record),
        }
        if pred == 1:
            false_positives.append(item)
        else:
            false_negatives.append(item)
    return {"false_positives": false_positives, "false_negatives": false_negatives}
