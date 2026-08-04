"""Helpers for explaining hybrid policy false positives and negatives."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

HIGH_NOISE_RULES = {
    "CRIT_DYNAMIC_REQUIRE_EXEC",
    "CRIT_REVERSE_SHELL",
    "HIGH_WEBHOOK_EXFIL",
    "HIGH_ENCODED_PAYLOAD_CHAIN",
    "HIGH_RUNTIME_PROTOTYPE_POLLUTION",
    "HIGH_STEGANOGRAPHIC_PAYLOAD",
    "MED_NETWORK_PLUS_FS",
    "MED_MINIFIED_SINGLE_FILE",
    "HIGH_TYPOSQUAT_SIGNAL",
}

HIGH_RELIABILITY_RULES = {
    "CRIT_INSTALL_HOOK_EXEC",
    "CRIT_EXFIL_CREDENTIALS",
    "CRIT_MANIFEST_NODE_EVAL",
    "HIGH_OBFUSCATED_INSTALL",
    "HIGH_DNS_EXFIL",
    "HIGH_SELF_DELETE",
    "HIGH_MANIFEST_SUSPICIOUS_URL",
    "MED_SUSPICIOUS_PACKAGE_STRUCTURE",
    "MED_MANIFEST_INSTALL_HOOK_ONLY",
    "CRIT_INSTALL_HOOK_NETWORK",
}


def score_band(score: float) -> str:
    """Return a compact score band label."""
    if score < 0:
        return "gnn_unavailable"
    if score < 0.35:
        return "low_<0.35"
    if score < 0.50:
        return "low_mid_0.35_0.50"
    if score < 0.75:
        return "mid_0.50_0.75"
    if score < 0.80:
        return "near_block_0.75_0.80"
    if score < 0.90:
        return "high_0.80_0.90"
    return "very_high_>=0.90"


def rule_profile_bucket(rule_ids: list[str]) -> str:
    """Classify the reliability mix of matched rules."""
    if not rule_ids:
        return "no_rules"
    high_rel = sum(1 for rule_id in rule_ids if rule_id in HIGH_RELIABILITY_RULES)
    noisy = sum(1 for rule_id in rule_ids if rule_id in HIGH_NOISE_RULES)
    if high_rel and not noisy:
        return "high_reliability_rules_only"
    if high_rel and noisy:
        return "mixed_reliability_rules"
    if noisy:
        return "noisy_rules_only"
    return "unknown_rules"


def package_metadata_shape(package_path: str) -> dict[str, Any]:
    """Read simple manifest traits useful for FP/FN root-cause analysis."""
    path = Path(package_path) / "package.json"
    if not path.exists():
        return {
            "has_package_json": False,
            "script_hooks": [],
            "dependency_count": 0,
            "has_repository": False,
            "has_license": False,
            "description_length": 0,
        }
    try:
        package_json = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return {
            "has_package_json": True,
            "package_json_error": True,
            "script_hooks": [],
            "dependency_count": 0,
            "has_repository": False,
            "has_license": False,
            "description_length": 0,
        }

    scripts = package_json.get("scripts", {})
    if not isinstance(scripts, dict):
        scripts = {}
    deps = package_json.get("dependencies", {})
    if not isinstance(deps, dict):
        deps = {}
    hook_names = [
        hook for hook in ["preinstall", "install", "postinstall", "prepare"]
        if hook in scripts
    ]
    return {
        "has_package_json": True,
        "name": package_json.get("name", ""),
        "version": package_json.get("version", ""),
        "script_hooks": hook_names,
        "dependency_count": len(deps),
        "has_repository": bool(package_json.get("repository")),
        "has_license": bool(package_json.get("license")),
        "description_length": len(str(package_json.get("description", ""))),
    }


def categorize_error(record: dict[str, Any], error_type: str) -> str:
    """Return a root-cause category for a false positive or false negative."""
    score = float(record.get("gnn_score", -1.0))
    rules = [str(rule) for rule in record.get("rules_matched", [])]
    rule_bucket = rule_profile_bucket(rules)
    bucket = str(record.get("decision_bucket", ""))

    if error_type == "fp":
        if score >= 0.90 and rule_bucket == "no_rules":
            return "fp_gnn_very_high_without_rules"
        if score >= 0.80 and rule_bucket == "no_rules":
            return "fp_gnn_high_without_rules"
        if rule_bucket == "noisy_rules_only":
            return "fp_noisy_rule_confirmation"
        if rule_bucket == "mixed_reliability_rules":
            return "fp_mixed_rule_confirmation"
        if rule_bucket == "high_reliability_rules_only":
            return "fp_high_reliability_rule_collision"
        return "fp_other"

    if score < 0.35 and rule_bucket == "no_rules":
        return "fn_low_gnn_no_rules"
    if score < 0.35:
        return "fn_low_gnn_weak_rules"
    if score < 0.75 and rule_bucket == "no_rules":
        return "fn_mid_gnn_no_rules"
    if score < 0.75:
        return "fn_mid_gnn_weak_rules"
    if score >= 0.80 and rule_bucket == "no_rules":
        return "fn_high_gnn_no_rules"
    if score >= 0.80 and "review" in bucket:
        return "fn_high_gnn_review_policy"
    if rule_bucket in {"noisy_rules_only", "mixed_reliability_rules"}:
        return "fn_rule_signal_too_noisy"
    return "fn_other"


def summarize_error_records(records: list[dict[str, Any]], error_type: str) -> dict[str, Any]:
    """Summarize categorized FP or FN records."""
    categorized = []
    for record in records:
        metadata = package_metadata_shape(str(record.get("package_path", "")))
        category = categorize_error(record, error_type)
        categorized.append(
            {
                "package_name": record.get("package_name", ""),
                "category": category,
                "gnn_score": float(record.get("gnn_score", -1.0)),
                "score_band": score_band(float(record.get("gnn_score", -1.0))),
                "rules_matched": list(record.get("rules_matched", [])),
                "rule_profile_bucket": rule_profile_bucket(
                    [str(rule) for rule in record.get("rules_matched", [])]
                ),
                "metadata_risk": float(record.get("metadata_risk", 0.0)),
                "decision_bucket": record.get("decision_bucket", ""),
                "decision_path": record.get("decision_path", ""),
                "num_js_files": record.get("num_js_files", 0),
                "num_nodes": record.get("num_nodes", 0),
                "num_edges": record.get("num_edges", 0),
                "manifest": metadata,
            }
        )

    rule_counts = Counter()
    for record in categorized:
        rule_counts.update(str(rule) for rule in record["rules_matched"])
    return {
        "count": len(categorized),
        "categories": dict(Counter(record["category"] for record in categorized)),
        "score_bands": dict(Counter(record["score_band"] for record in categorized)),
        "rule_profile_buckets": dict(
            Counter(record["rule_profile_bucket"] for record in categorized)
        ),
        "top_rules": dict(rule_counts.most_common(20)),
        "records": categorized,
    }


def improvement_candidates(fp_summary: dict[str, Any], fn_summary: dict[str, Any]) -> list[dict[str, str]]:
    """Return measured, non-speculative improvement candidates."""
    candidates: list[dict[str, str]] = []
    fp_cats = fp_summary["categories"]
    fn_cats = fn_summary["categories"]

    if fp_cats.get("fp_gnn_very_high_without_rules", 0):
        candidates.append(
            {
                "area": "precision",
                "candidate": "Add context gates for very-high GNN/no-rule blocks",
                "why": (
                    "Some benign packages are blocked only because the GNN score is "
                    "very high. Requiring package-context safety checks or stronger "
                    "calibration could reduce false positives."
                ),
                "risk": (
                    "This can lower recall unless high-score malicious packages are "
                    "recovered by better metadata or rule evidence."
                ),
            }
        )
    if fp_cats.get("fp_noisy_rule_confirmation", 0) or fp_cats.get("fp_mixed_rule_confirmation", 0):
        candidates.append(
            {
                "area": "precision",
                "candidate": "Split noisy rules into benign-context and malicious-context variants",
                "why": (
                    "Noisy rules still participate in false-positive blocks. Context "
                    "checks for bundled builds, legitimate webhook-like code, and "
                    "framework dynamic execution are likely to improve precision."
                ),
                "risk": "Requires targeted fixtures; broad suppressors can hide real malware.",
            }
        )
    if fn_cats.get("fn_high_gnn_no_rules", 0) or fn_cats.get("fn_high_gnn_review_policy", 0):
        candidates.append(
            {
                "area": "recall",
                "candidate": "Create high-precision confirmation signals for high-GNN review cases",
                "why": (
                    "Many false negatives already have high GNN scores but lack "
                    "safe confirmation. Metadata and manifest-derived evidence could "
                    "convert these from review to hard block."
                ),
                "risk": "Without a new separating signal, this recreates the GNN false positives.",
            }
        )
    if fn_cats.get("fn_mid_gnn_no_rules", 0) or fn_cats.get("fn_mid_gnn_weak_rules", 0):
        candidates.append(
            {
                "area": "recall",
                "candidate": "Add manifest/metadata confirmation for mid-GNN packages",
                "why": (
                    "Most residual false negatives sit in the mid GNN range with "
                    "no rules or weak install-hook style rules. Policy alone cannot "
                    "safely block them without extra evidence."
                ),
                "risk": (
                    "The same mid-score region contains benign packages, so this "
                    "needs targeted context features rather than a lower GNN threshold."
                ),
            }
        )
    if fn_cats.get("fn_low_gnn_no_rules", 0) or fn_cats.get("fn_low_gnn_weak_rules", 0):
        candidates.append(
            {
                "area": "model/data",
                "candidate": "Hard-positive retraining set for low-GNN false negatives",
                "why": (
                    "Low-score malicious packages are not recoverable by policy alone. "
                    "They need new graph/model signal or labels in training."
                ),
                "risk": "Requires verified labels and another train/eval cycle.",
            }
        )
    return candidates
