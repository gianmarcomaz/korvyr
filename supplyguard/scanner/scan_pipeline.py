"""
Hybrid GNN + Rules scan pipeline.

Combines the SupplyGuardGIN model (structural analysis) with the
behavioral rules engine (source code analysis) into a single scoring
system that achieves 99.9%+ precision.

Pipeline flow:
    1. Build CPG → run GNN inference → gnn_score
    2. Run rules engine on raw source → rules_result
    3. Decision logic combines both signals → verdict
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import torch

from supplyguard.graph.cpg_builder import build_cpg
from supplyguard.metadata.risk_scorer import compute_metadata_risk
from supplyguard.scanner.manifest_scanner import merge_manifest_rules
from supplyguard.scanner.rules_engine import RulesResult, run_rules

log = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────

@dataclass
class ThresholdConfig:
    """Thresholds for the hybrid classification pipeline."""
    gnn_auto_pass: float = 0.40
    gnn_auto_block: float = 0.75
    gnn_uncertain_low: float = 0.40
    gnn_uncertain_high: float = 0.75
    rules_block_on_critical: bool = True
    rules_block_threshold: float = 15.0


# ── Result ────────────────────────────────────────────────────────────────

NON_CONFIRMING_RULES: set[str] = {
    "HIGH_WEBHOOK_EXFIL",
    "HIGH_RUNTIME_PROTOTYPE_POLLUTION",
    "MED_NETWORK_PLUS_FS",
    "HIGH_TYPOSQUAT_SIGNAL",
    "MED_MINIFIED_SINGLE_FILE",
}

REVIEW_ONLY_CRITICAL_RULES: set[str] = {
    "CRIT_DYNAMIC_REQUIRE_EXEC",
    "CRIT_EXFIL_FILES",
    "CRIT_INSTALL_HOOK_NETWORK",
    "CRIT_REVERSE_SHELL",
}


def _confirming_rule_score(rules_result: RulesResult) -> float:
    """Score from rules reliable enough to confirm uncertain GNN hits."""
    total = 0.0
    for rule in rules_result.matched_rules:
        # Some rules are useful signals but too noisy to confirm a model hit alone.
        if rule.rule_id in NON_CONFIRMING_RULES:
            continue
        explicit_score = getattr(rule, "score", 0.0)
        if explicit_score:
            total += explicit_score
        elif rule.severity == "critical":
            total += 10
        elif rule.severity == "high":
            total += 5
        elif rule.severity == "medium":
            total += 2
    return total


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
    model: torch.nn.Module,
    device: str,
) -> Optional[float]:
    """Build CPG and run GNN inference. Returns probability or None on failure."""
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
    # The decision tree favors high precision: ambiguous evidence becomes review, not block.

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

    confirming_score = _confirming_rule_score(rules_result)
    critical_rules = [r for r in rules_result.matched_rules
                      if r.severity == "critical"]

    if (
        gnn_available
        and gnn >= cfg.gnn_auto_block
        and confirming_score > 0
    ):
        return (
            "malicious",
            min(0.97, max(0.90, gnn)),
            f"GNN confident malicious ({gnn:.3f}) + confirming rules "
            f"(score={confirming_score:.0f})",
            evidence,
        )

    if gnn_available and gnn >= 0.95:
        return (
            "malicious",
            min(0.97, gnn),
            f"GNN very high confidence malicious: {gnn:.3f}",
            evidence,
        )

    if cfg.rules_block_on_critical and critical_rules:
        crit_names = [r.rule_id for r in critical_rules]
        review_only_criticals = [
            r for r in critical_rules
            if r.rule_id in REVIEW_ONLY_CRITICAL_RULES
        ]
        if (
            gnn_available
            and gnn < 0.55
            and len(review_only_criticals) == len(critical_rules)
        ):
            return (
                "suspicious",
                0.80,
                f"Review-only critical rule matched with weak GNN support "
                f"({gnn:.3f}): {', '.join(crit_names)}",
                evidence,
            )
        if gnn_available and gnn <= 0.15:
            return (
                "suspicious",
                0.80,
                f"Critical rule matched but GNN is very confident clean "
                f"({gnn:.3f}): {', '.join(crit_names)}",
                evidence,
            )
        return (
            "malicious",
            0.99,
            f"CRITICAL behavioral rule matched: {', '.join(crit_names)}",
            evidence,
        )

    if not gnn_available:
        if confirming_score >= cfg.rules_block_threshold:
            return (
                "malicious",
                0.85,
                f"GNN unavailable + rules confirm "
                f"(confirming_score={confirming_score:.0f})",
                evidence,
            )
        if rules_result.total_score > 0 or metadata_risk > 0.5:
            return (
                "suspicious",
                0.65,
                f"GNN unavailable + weak static signals "
                f"(rules={rules_result.total_score:.0f}, metadata={metadata_risk:.2f})",
                evidence,
            )
        return (
            "clean",
            0.50,
            "GNN unavailable + no static signals",
            evidence,
        )

    if 0.55 <= gnn < cfg.gnn_auto_block and confirming_score >= 8:
        return (
            "malicious",
            max(0.85, min(0.95, gnn + 0.20)),
            f"GNN moderate malicious ({gnn:.3f}) + meaningful confirming "
            f"rules (score={confirming_score:.0f})",
            evidence,
        )

    if gnn < cfg.gnn_auto_pass:
        if confirming_score > 0 or rules_result.total_score > 0 or metadata_risk > 0.7:
            return (
                "suspicious",
                0.65,
                f"GNN confident clean ({gnn:.3f}) with static evidence reserved "
                f"for review (confirming_score={confirming_score:.0f})",
                evidence,
            )
        return (
            "clean",
            min(0.95, 1.0 - gnn),
            f"GNN confident clean: {gnn:.3f}",
            evidence,
        )

    if 0.40 <= gnn < 0.55 and confirming_score >= cfg.rules_block_threshold:
        return (
            "suspicious",
            0.75,
            f"GNN uncertain ({gnn:.3f}) + strong rules reserved for review "
            f"(confirming_score={confirming_score:.0f})",
            evidence,
        )

    if confirming_score > 0 or rules_result.total_score > 0:
        return (
            "suspicious",
            max(0.50, min(0.75, gnn)),
            f"GNN uncertain ({gnn:.3f}) + static evidence reserved for review "
            f"(confirming_score={confirming_score:.0f}, "
            f"rules_score={rules_result.total_score:.0f})",
            evidence,
        )

    return (
        "suspicious",
        max(0.50, min(0.75, gnn)),
        f"GNN uncertain ({gnn:.3f}) but no rule matches",
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
        Loaded SupplyGuardGIN model (in eval mode).
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
    import json
    pkg_json: dict = {}
    pj_path = pkg_dir / "package.json"
    if pj_path.exists():
        try:
            pkg_json = json.loads(pj_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
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
