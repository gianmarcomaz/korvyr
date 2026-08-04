"""Replayable precision-aware hybrid policy experiments.

This module is intentionally pure and side-effect free.  It operates on the
records emitted by ``scripts/evaluate_production.py`` so candidate hybrid
policies can be swept quickly before any production scanner behavior changes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RuleProfile:
    """How much a rule should contribute to hard-block confirmation."""

    weight: float
    hard_block_capable: bool = False
    review_only: bool = False


@dataclass(frozen=True)
class HybridV2Config:
    """Config for the experimental tiered hybrid policy."""

    gnn_direct_block_threshold: float = 0.80
    gnn_confirm_floor: float = 0.45
    weighted_confirm_threshold: float = 1.0
    hard_rule_score_threshold: float = 8.0
    hard_rule_min_gnn: float = 0.45
    clean_threshold: float = 0.35
    unknown_rule_weight: float = 0.5

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True)
class HybridV2Decision:
    verdict: str
    confidence: float
    decision_path: str
    decision_bucket: str
    weighted_rule_score: float
    hard_rule_score: float


DEFAULT_RULE_PROFILES: dict[str, RuleProfile] = {
    # High-reliability rules on the current production evaluation set.
    "CRIT_INSTALL_HOOK_EXEC": RuleProfile(1.0, hard_block_capable=True),
    "CRIT_EXFIL_CREDENTIALS": RuleProfile(1.0, hard_block_capable=True),
    "CRIT_MANIFEST_NODE_EVAL": RuleProfile(1.0, hard_block_capable=True),
    "HIGH_OBFUSCATED_INSTALL": RuleProfile(1.0, hard_block_capable=True),
    "HIGH_DNS_EXFIL": RuleProfile(1.0, hard_block_capable=True),
    "HIGH_SELF_DELETE": RuleProfile(1.0, hard_block_capable=True),
    "HIGH_MANIFEST_SUSPICIOUS_URL": RuleProfile(1.0, hard_block_capable=True),
    "MED_SUSPICIOUS_PACKAGE_STRUCTURE": RuleProfile(0.7, hard_block_capable=True),
    "MED_MANIFEST_INSTALL_HOOK_ONLY": RuleProfile(0.7, hard_block_capable=True),
    "MED_EVAL_USAGE": RuleProfile(0.7, hard_block_capable=True),
    "MED_INSTALL_HOOK_EXISTS": RuleProfile(0.2),
    "CRIT_INSTALL_HOOK_NETWORK": RuleProfile(0.9, hard_block_capable=True),
    "CRIT_EXFIL_FILES": RuleProfile(0.7, hard_block_capable=True),
    # Noisy or review-only evidence. These can still contribute, but weakly.
    "CRIT_DYNAMIC_REQUIRE_EXEC": RuleProfile(0.1, review_only=True),
    "CRIT_REVERSE_SHELL": RuleProfile(0.3, review_only=True),
    "HIGH_WEBHOOK_EXFIL": RuleProfile(0.2),
    "HIGH_ENCODED_PAYLOAD_CHAIN": RuleProfile(0.6),
    "MED_NETWORK_PLUS_FS": RuleProfile(0.1),
    "MED_MINIFIED_SINGLE_FILE": RuleProfile(0.0, review_only=True),
    "HIGH_PROCESS_ENV_BULK": RuleProfile(0.2),
    "HIGH_STEGANOGRAPHIC_PAYLOAD": RuleProfile(0.1),
    "HIGH_EVAL_DECODED": RuleProfile(0.5),
    "HIGH_RUNTIME_PROTOTYPE_POLLUTION": RuleProfile(0.2),
    "HIGH_TYPOSQUAT_SIGNAL": RuleProfile(0.0, review_only=True),
}


def _severity_fallback_score(severity: str) -> float:
    return {"critical": 10.0, "high": 5.0, "medium": 2.0}.get(severity, 0.0)


def _rule_raw_score(rule: dict[str, Any]) -> float:
    score = float(rule.get("score") or 0.0)
    if score:
        return score
    return _severity_fallback_score(str(rule.get("severity", "")))


def weighted_rule_scores(
    rules_details: list[dict[str, Any]],
    *,
    profiles: dict[str, RuleProfile] | None = None,
    unknown_rule_weight: float = 0.5,
) -> tuple[float, float]:
    """Return ``(weighted_score, hard_block_score)`` for matched rule details."""
    profiles = profiles or DEFAULT_RULE_PROFILES
    weighted = 0.0
    hard = 0.0
    for rule in rules_details:
        rule_id = str(rule.get("rule_id", ""))
        raw = _rule_raw_score(rule)
        profile = profiles.get(rule_id, RuleProfile(unknown_rule_weight))
        contribution = raw * profile.weight
        weighted += contribution
        if profile.hard_block_capable and not profile.review_only:
            hard += contribution
    return weighted, hard


def decide_record_v2(
    record: dict[str, Any],
    config: HybridV2Config,
    *,
    profiles: dict[str, RuleProfile] | None = None,
) -> HybridV2Decision:
    """Apply the experimental tiered policy to one production eval record."""
    gnn_score = float(record.get("gnn_score", -1.0))
    gnn_available = gnn_score >= 0.0
    rules_details = list(record.get("rules_details", []))
    weighted_score, hard_score = weighted_rule_scores(
        rules_details,
        profiles=profiles,
        unknown_rule_weight=config.unknown_rule_weight,
    )

    if gnn_available and gnn_score >= config.gnn_direct_block_threshold:
        return HybridV2Decision(
            "malicious",
            min(0.97, max(0.90, gnn_score)),
            f"v2 direct GNN block: score={gnn_score:.3f}",
            "v2_gnn_direct_block",
            weighted_score,
            hard_score,
        )

    if (
        gnn_available
        and gnn_score >= config.gnn_confirm_floor
        and weighted_score >= config.weighted_confirm_threshold
    ):
        return HybridV2Decision(
            "malicious",
            min(0.95, max(0.80, gnn_score + 0.10)),
            "v2 GNN + weighted rules block: "
            f"score={gnn_score:.3f}, weighted_rules={weighted_score:.1f}",
            "v2_gnn_weighted_rules_block",
            weighted_score,
            hard_score,
        )

    if (
        gnn_available
        and gnn_score >= config.hard_rule_min_gnn
        and hard_score >= config.hard_rule_score_threshold
    ):
        return HybridV2Decision(
            "malicious",
            min(0.95, max(0.82, gnn_score + 0.08)),
            "v2 high-reliability rules block: "
            f"score={gnn_score:.3f}, hard_rules={hard_score:.1f}",
            "v2_hard_rules_block",
            weighted_score,
            hard_score,
        )

    if gnn_available and gnn_score < config.clean_threshold and weighted_score <= 0:
        return HybridV2Decision(
            "clean",
            min(0.95, 1.0 - gnn_score),
            f"v2 clean: low GNN score={gnn_score:.3f}, no weighted rules",
            "v2_clean_pass",
            weighted_score,
            hard_score,
        )

    if gnn_available and gnn_score < config.clean_threshold:
        return HybridV2Decision(
            "suspicious",
            0.65,
            "v2 review: low GNN with static evidence "
            f"score={gnn_score:.3f}, weighted_rules={weighted_score:.1f}",
            "v2_low_gnn_review",
            weighted_score,
            hard_score,
        )

    if weighted_score > 0 or hard_score > 0:
        return HybridV2Decision(
            "suspicious",
            min(0.75, max(0.50, gnn_score if gnn_available else 0.5)),
            "v2 review: evidence below block thresholds "
            f"score={gnn_score:.3f}, weighted_rules={weighted_score:.1f}",
            "v2_static_review",
            weighted_score,
            hard_score,
        )

    return HybridV2Decision(
        "suspicious",
        min(0.75, max(0.50, gnn_score if gnn_available else 0.5)),
        f"v2 review: GNN-only uncertainty score={gnn_score:.3f}",
        "v2_gnn_review",
        weighted_score,
        hard_score,
    )


def apply_policy_to_record(
    record: dict[str, Any],
    config: HybridV2Config,
    *,
    profiles: dict[str, RuleProfile] | None = None,
) -> dict[str, Any]:
    """Return a copy of a production record with v2 decision fields applied."""
    decision = decide_record_v2(record, config, profiles=profiles)
    out = dict(record)
    out["hybrid_verdict"] = decision.verdict
    out["confidence"] = decision.confidence
    out["decision_path"] = decision.decision_path
    out["decision_bucket"] = decision.decision_bucket
    out["v2_weighted_rule_score"] = decision.weighted_rule_score
    out["v2_hard_rule_score"] = decision.hard_rule_score
    return out
