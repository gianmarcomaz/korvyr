"""
Hybrid GNN + Rules scan pipeline.

Combines the KorvyrGIN model (structural analysis) with the behavioral rules
engine (source-code analysis) into one verdict.

Pipeline flow:
    1. Build CPG → run GNN inference → gnn_score
    2. Run rules engine on raw source → rules_result
    3. Decision logic combines both signals → verdict

The thresholds in ``ThresholdConfig`` are the calibrated high-recall operating
point measured on a 600-package balanced development benchmark
(precision 0.9635, recall 0.8800). That benchmark was also used to develop the
policy, so those figures are not production estimates - see
docs/evaluation.md.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import torch

from korvyr.graph.cpg_builder import build_cpg
from korvyr.metadata.risk_scorer import compute_metadata_risk
from korvyr.scanner.manifest_scanner import merge_manifest_rules
from korvyr.scanner.rules_engine import RulesResult, run_rules
from korvyr.utils import read_package_json

log = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────

@dataclass
class ThresholdConfig:
    """Thresholds for the hybrid classification pipeline."""
    gnn_auto_pass: float = 0.35
    gnn_auto_block: float = 0.80
    gnn_uncertain_low: float = 0.35
    gnn_uncertain_high: float = 0.80
    rules_block_on_critical: bool = True
    rules_block_threshold: float = 15.0
    rules_auto_block_threshold: float = 1.0
    rules_moderate_block_threshold: float = 10.0
    gnn_confirm_floor: float = 0.45
    hard_rule_score_threshold: float = 8.0
    hard_rule_min_gnn: float = 0.0
    install_hook_confirm_enabled: bool = True
    install_hook_confirm_low: float = 0.35
    install_hook_confirm_high: float = 0.80
    clean_threshold: float = 0.35
    unknown_rule_weight: float = 0.5


# ── Result ────────────────────────────────────────────────────────────────

NON_CONFIRMING_RULES: set[str] = {
    "HIGH_WEBHOOK_EXFIL",
    "HIGH_STEGANOGRAPHIC_PAYLOAD",
    "HIGH_RUNTIME_PROTOTYPE_POLLUTION",
    "MED_NETWORK_PLUS_FS",
    "HIGH_TYPOSQUAT_SIGNAL",
    "MED_MINIFIED_SINGLE_FILE",
}

RULE_PRECISION_WEIGHTS: dict[str, float] = {
    "CRIT_INSTALL_HOOK_EXEC": 1.0,
    "CRIT_EXFIL_CREDENTIALS": 1.0,
    "CRIT_MANIFEST_CURL_PIPE": 1.0,
    "CRIT_MANIFEST_NODE_EVAL": 1.0,
    "HIGH_DNS_EXFIL": 1.0,
    "HIGH_SELF_DELETE": 1.0,
    "HIGH_MANIFEST_SUSPICIOUS_URL": 1.0,
    "HIGH_OBFUSCATED_INSTALL": 1.0,
    "MED_SUSPICIOUS_PACKAGE_STRUCTURE": 0.7,
    "MED_MANIFEST_INSTALL_HOOK_ONLY": 0.7,
    "MED_EVAL_USAGE": 0.7,
    "MED_INSTALL_HOOK_EXISTS": 0.2,
    "CRIT_INSTALL_HOOK_NETWORK": 0.95,
    "CRIT_EXFIL_FILES": 0.70,
    "CRIT_REVERSE_SHELL": 0.30,
    "HIGH_EVAL_DECODED": 0.60,
    "HIGH_ENCODED_PAYLOAD_CHAIN": 0.60,
    "HIGH_WEBHOOK_EXFIL": 0.20,
    "HIGH_PROCESS_ENV_BULK": 0.20,
    "HIGH_RUNTIME_PROTOTYPE_POLLUTION": 0.20,
    "HIGH_STEGANOGRAPHIC_PAYLOAD": 0.10,
    "MED_NETWORK_PLUS_FS": 0.10,
    "MED_MINIFIED_SINGLE_FILE": 0.0,
    "HIGH_TYPOSQUAT_SIGNAL": 0.0,
    "CRIT_DYNAMIC_REQUIRE_EXEC": 0.10,
}

HARD_BLOCK_CAPABLE_RULES: set[str] = {
    "CRIT_INSTALL_HOOK_EXEC",
    "CRIT_EXFIL_CREDENTIALS",
    "CRIT_MANIFEST_CURL_PIPE",
    "CRIT_MANIFEST_NODE_EVAL",
    "HIGH_OBFUSCATED_INSTALL",
    "HIGH_DNS_EXFIL",
    "HIGH_SELF_DELETE",
    "HIGH_MANIFEST_SUSPICIOUS_URL",
    "MED_SUSPICIOUS_PACKAGE_STRUCTURE",
    "MED_MANIFEST_INSTALL_HOOK_ONLY",
    "MED_EVAL_USAGE",
    "CRIT_INSTALL_HOOK_NETWORK",
    "CRIT_EXFIL_FILES",
}

REVIEW_ONLY_CRITICAL_RULES: set[str] = {
    "CRIT_DYNAMIC_REQUIRE_EXEC",
    "CRIT_EXFIL_FILES",
    "CRIT_INSTALL_HOOK_NETWORK",
    "CRIT_REVERSE_SHELL",
}


def _confirming_rule_score(rules_result: RulesResult) -> float:
    """Weighted score from rules reliable enough to confirm GNN hits."""
    total = 0.0
    for rule in rules_result.matched_rules:
        # Some rules are useful signals but too noisy to confirm a model hit alone.
        if rule.rule_id in NON_CONFIRMING_RULES:
            continue
        explicit_score = getattr(rule, "score", 0.0)
        if explicit_score:
            contribution = explicit_score
        elif rule.severity == "critical":
            contribution = 10
        elif rule.severity == "high":
            contribution = 5
        elif rule.severity == "medium":
            contribution = 2
        else:
            contribution = 0
        total += contribution * RULE_PRECISION_WEIGHTS.get(rule.rule_id, 1.0)
    return total


def _rule_raw_score(rule) -> float:
    explicit_score = getattr(rule, "score", 0.0)
    if explicit_score:
        return float(explicit_score)
    if rule.severity == "critical":
        return 10.0
    if rule.severity == "high":
        return 5.0
    if rule.severity == "medium":
        return 2.0
    return 0.0


def _weighted_rule_scores(
    rules_result: RulesResult,
    cfg: ThresholdConfig,
) -> tuple[float, float]:
    """Return replay-calibrated weighted and hard-block-capable rule scores."""
    weighted = 0.0
    hard = 0.0
    for rule in rules_result.matched_rules:
        raw = _rule_raw_score(rule)
        contribution = raw * RULE_PRECISION_WEIGHTS.get(
            rule.rule_id,
            cfg.unknown_rule_weight,
        )
        weighted += contribution
        if rule.rule_id in HARD_BLOCK_CAPABLE_RULES:
            hard += contribution
    return weighted, hard


def _has_install_hook_signal(rules_result: RulesResult) -> bool:
    return any(rule.rule_id == "MED_INSTALL_HOOK_EXISTS" for rule in rules_result.matched_rules)


@dataclass
class ScanResult:
    """Full result from the hybrid scan pipeline."""
    package_name: str = ""
    verdict: str = "clean"            # "clean", "malicious", "suspicious"
    confidence: float = 0.0           # 0.0–1.0
    gnn_score: float = 0.0           # raw GNN probability
    metadata_risk: float = 0.0       # 0.0–1.0 structural/social risk
    rules_result: Optional[RulesResult] = None
    decision_path: str = ""          # human-readable explanation
    evidence: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def summary(self) -> str:
        rs = self.rules_result.total_score if self.rules_result else 0
        return (f"[{self.verdict.upper():10s}] "
                f"GNN={self.gnn_score:.3f}  "
                f"rules_score={rs:.0f}  "
                f"meta_risk={self.metadata_risk:.2f}  "
                f"confidence={self.confidence:.2f}  "
                f"path={self.decision_path}")


# ── GNN inference ─────────────────────────────────────────────────────────

def _run_gnn(
    package_dir: str,
    model: Optional[torch.nn.Module],
    device: str,
) -> Optional[float]:
    """Build CPG and run GNN inference. Returns probability or None on failure."""
    if model is None:
        log.info("GNN model is unavailable for %s", package_dir)
        return None

    try:
        # Parser failures degrade to rules-only scanning instead of failing the request.
        data = build_cpg(package_dir, label=0)
        if data is None:
            log.debug("CPG build returned None for %s", package_dir)
            return None
        data = data.to(device)
        with torch.no_grad():
            logit = model(
                x=data.x,
                edge_index=data.edge_index,
                edge_type=data.edge_type,
                metadata=data.metadata.unsqueeze(0),
                batch=torch.zeros(data.num_nodes, dtype=torch.long, device=device),
            )
            prob = torch.sigmoid(logit).item()
        return prob
    except Exception as e:
        log.warning("GNN inference failed for %s: %s", package_dir, e)
        return None


# ── Decision logic ────────────────────────────────────────────────────────

def _decide(
    gnn_score: Optional[float],
    rules_result: RulesResult,
    cfg: ThresholdConfig,
    metadata_risk: float = 0.0,
) -> tuple[str, float, str, list[str]]:
    """Apply decision logic and return (verdict, confidence, decision_path, evidence)."""
    evidence: list[str] = []
    # Calibrated high-recall profile measured on the 600-package production eval.
    # Ambiguous evidence still becomes review unless it matches a measured
    # confirmer such as the mid-GNN install-hook signal.

    # Collect evidence from rules
    for rule in rules_result.matched_rules:
        evidence.append(
            f"[{rule.severity.upper()}] {rule.rule_id}: {rule.description}"
        )

    if gnn_score is not None:
        evidence.insert(0, f"GNN score: {gnn_score:.3f}")
    if metadata_risk > 0:
        evidence.append(f"Metadata risk: {metadata_risk:.2f}")

    gnn_available = gnn_score is not None
    gnn = gnn_score if gnn_available else 0.5  # neutral if unavailable
    weighted_score, hard_score = _weighted_rule_scores(rules_result, cfg)
    has_install_hook = _has_install_hook_signal(rules_result)

    if gnn_available and gnn >= cfg.gnn_auto_block:
        return (
            "malicious",
            min(0.97, max(0.90, gnn)),
            f"v2 direct GNN block: score={gnn:.3f}",
            evidence,
        )

    if (
        cfg.install_hook_confirm_enabled
        and gnn_available
        and cfg.install_hook_confirm_low <= gnn < cfg.install_hook_confirm_high
        and has_install_hook
    ):
        return (
            "malicious",
            min(0.95, max(0.82, gnn + 0.10)),
            "v2 install-hook recall block: "
            f"score={gnn:.3f}, rule=MED_INSTALL_HOOK_EXISTS",
            evidence,
        )

    if (
        gnn_available
        and gnn >= cfg.gnn_confirm_floor
        and weighted_score >= cfg.rules_auto_block_threshold
    ):
        return (
            "malicious",
            min(0.95, max(0.80, gnn + 0.10)),
            "v2 GNN + weighted rules block: "
            f"score={gnn:.3f}, weighted_rules={weighted_score:.1f}",
            evidence,
        )

    if (
        gnn_available
        and gnn >= cfg.hard_rule_min_gnn
        and hard_score >= cfg.hard_rule_score_threshold
    ):
        return (
            "malicious",
            min(0.95, max(0.82, gnn + 0.08)),
            "v2 high-reliability rules block: "
            f"score={gnn:.3f}, hard_rules={hard_score:.1f}",
            evidence,
        )

    if not gnn_available:
        if hard_score >= cfg.hard_rule_score_threshold:
            return (
                "malicious",
                0.85,
                f"GNN unavailable + high-reliability rules "
                f"(hard_rules={hard_score:.1f})",
                evidence,
            )
        if weighted_score > 0 or rules_result.total_score > 0 or metadata_risk > 0.5:
            return (
                "suspicious",
                0.65,
                f"GNN unavailable + static signals "
                f"(weighted_rules={weighted_score:.1f}, metadata={metadata_risk:.2f})",
                evidence,
            )
        return (
            "clean",
            0.50,
            "GNN unavailable + no static signals",
            evidence,
        )

    if gnn < cfg.clean_threshold and weighted_score <= 0:
        return (
            "clean",
            min(0.95, 1.0 - gnn),
            f"v2 clean: low GNN score={gnn:.3f}, no weighted rules",
            evidence,
        )

    if gnn < cfg.clean_threshold:
        return (
            "suspicious",
            0.65,
            "v2 review: low GNN with static evidence "
            f"score={gnn:.3f}, weighted_rules={weighted_score:.1f}",
            evidence,
        )

    if weighted_score > 0 or hard_score > 0:
        return (
            "suspicious",
            min(0.75, max(0.50, gnn)),
            "v2 review: evidence below block thresholds "
            f"score={gnn:.3f}, weighted_rules={weighted_score:.1f}",
            evidence,
        )

    return (
        "suspicious",
        min(0.75, max(0.50, gnn)),
        f"v2 review: GNN-only uncertainty score={gnn:.3f}",
        evidence,
    )

# ── Public API ────────────────────────────────────────────────────────────

def scan_package(
    package_dir: str,
    model: torch.nn.Module,
    device: str,
    threshold_config: Optional[ThresholdConfig] = None,
) -> ScanResult:
    """Run the full hybrid scan pipeline on a package.

    Parameters
    ----------
    package_dir : str
        Path to the extracted npm package directory.
    model : torch.nn.Module
        Loaded KorvyrGIN model (in eval mode).
    device : str
        "cpu" or "cuda".
    threshold_config : ThresholdConfig, optional
        Thresholds for the decision logic. Uses defaults if None.

    Returns
    -------
    ScanResult with verdict, confidence, and detailed evidence.
    """
    t0 = time.perf_counter()
    cfg = threshold_config or ThresholdConfig()
    pkg_dir = Path(package_dir)

    result = ScanResult(
        package_name=pkg_dir.name,
    )

    # Step 1: GNN inference
    gnn_score = _run_gnn(package_dir, model, device)
    result.gnn_score = gnn_score if gnn_score is not None else -1.0

    if gnn_score is None:
        log.info("GNN failed for %s — falling back to rules-only", pkg_dir.name)

    # Step 2: Rules engine
    try:
        rules_result = run_rules(package_dir)
        rules_result = merge_manifest_rules(rules_result, package_dir)
    except Exception as e:
        log.warning("Rules engine failed for %s: %s — falling back to GNN-only",
                    pkg_dir.name, e)
        rules_result = RulesResult()

    result.rules_result = rules_result

    # Step 3: Metadata risk
    pkg_json = read_package_json(pkg_dir)
    metadata_risk = compute_metadata_risk(pkg_dir.name, pkg_json)
    result.metadata_risk = metadata_risk

    # Step 4: Decision logic
    verdict, confidence, decision_path, evidence = _decide(
        gnn_score, rules_result, cfg, metadata_risk,
    )
    result.verdict = verdict
    result.confidence = confidence
    result.decision_path = decision_path
    result.evidence = evidence
    result.elapsed_ms = (time.perf_counter() - t0) * 1000

    log.info("Scan %s: %s (%.0fms)", pkg_dir.name, result.summary(),
             result.elapsed_ms)
    return result
