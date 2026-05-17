"""
Real hybrid evaluation: GNN inference + real rules engine on raw packages.

Runs the FULL pipeline (CPG build → GNN → rules engine → hybrid decision)
on sampled raw packages and compares GNN-only, rules-only, and hybrid.
"""

import csv
import argparse
import json
import logging
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, field

import torch
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.graph.cpg_builder import build_cpg
from supplyguard.metadata.risk_scorer import compute_metadata_risk
from supplyguard.model.gin_classifier import SupplyGuardGIN
from supplyguard.scanner.manifest_scanner import merge_manifest_rules
from supplyguard.scanner.rules_engine import MatchedRule, RulesResult, run_rules
from supplyguard.scanner.scan_pipeline import (
    REVIEW_ONLY_CRITICAL_RULES,
    ThresholdConfig,
    _confirming_rule_score,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
CHECKPOINT_DIR = ROOT / "checkpoints"
OUTPUT_PATH = ROOT / "data" / "processed" / "hybrid_real_evaluation.json"

SAMPLE_SIZE = 300
SEED = 42


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Evaluate the real GNN + rules hybrid pipeline on raw packages",
    )
    p.add_argument(
        "--sample-size",
        type=int,
        default=SAMPLE_SIZE,
        help="Number of malicious and benign packages to sample",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="Path to write the JSON evaluation output",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=SEED,
        help="Random seed for sampling and shuffling",
    )
    return p.parse_args()


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class PackageResult:
    package_name: str = ""
    package_path: str = ""
    true_label: int = 0          # 0=benign, 1=malicious
    gnn_score: float = -1.0      # -1 if GNN failed
    gnn_verdict: str = "unknown"
    rules_verdict: str = "unknown"
    rules_score: float = 0.0
    rules_critical: bool = False
    rules_matched: list[str] = field(default_factory=list)
    rules_details: list[dict] = field(default_factory=list)
    metadata_risk: float = 0.0
    hybrid_verdict: str = "unknown"
    decision_path: str = ""
    decision_bucket: str = ""
    skipped: bool = False
    skip_reason: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────

def _collect_from_manifest(
    manifest_path: Path,
    label: int,
    limit: int,
    seed: int = SEED,
) -> list[tuple[Path, int]]:
    """Read manifest CSV and sample packages with at least 1 JS file."""
    if not manifest_path.exists():
        log.warning("Manifest not found: %s", manifest_path)
        return []

    candidates = []
    with open(manifest_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rel_path = row.get("path", "")
            if not rel_path:
                continue
            pkg_dir = ROOT / rel_path
            # Find the actual package directory (may have nested structure)
            if not pkg_dir.exists():
                continue
            # Check for package.json somewhere under pkg_dir
            pj_files = list(pkg_dir.rglob("package.json"))
            if not pj_files:
                continue
            # Use the first package.json directory
            actual_dir = pj_files[0].parent
            # Must have at least one JS file
            has_js = any(actual_dir.rglob("*.js"))
            if has_js:
                candidates.append((actual_dir, label))

    random.seed(seed)
    if len(candidates) > limit:
        candidates = random.sample(candidates, limit)
    return candidates


def _hybrid_decide(gnn_score: float, rules_result: RulesResult,
                   cfg: ThresholdConfig,
                   metadata_risk: float = 0.0) -> tuple[str, str, str]:
    """Apply hybrid decision logic. Returns (verdict, decision_path, bucket)."""
    gnn_available = gnn_score >= 0.0
    gnn = gnn_score if gnn_available else 0.5
    confirming_score = _confirming_rule_score(rules_result)
    critical_rules = [r for r in rules_result.matched_rules
                      if r.severity == "critical"]

    if gnn_available and gnn >= cfg.gnn_auto_block and confirming_score > 0:
        return (
            "malicious",
            f"GNN confident malicious ({gnn:.3f}) + confirming rules "
            f"(score={confirming_score:.0f})",
            "auto_block_confirmed",
        )

    if gnn_available and gnn >= 0.95:
        return (
            "malicious",
            f"GNN very high confidence malicious ({gnn:.3f})",
            "gnn_very_high",
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
                f"Review-only critical rule with weak GNN support "
                f"({gnn:.3f}): {', '.join(crit_names)}",
                "review_only_critical",
            )
        if gnn_available and gnn <= 0.15:
            return (
                "suspicious",
                f"Critical rule matched but GNN very confidently clean "
                f"({gnn:.3f}): {', '.join(crit_names)}",
                "critical_gnn_clean_review",
            )
        return (
            "malicious",
            f"CRITICAL rule: {', '.join(crit_names)}",
            "critical_override",
        )

    if not gnn_available:
        if confirming_score >= cfg.rules_block_threshold:
            return ("malicious",
                    f"GNN unavailable + rules confirm (score={confirming_score:.0f})",
                    "rules_only_block")
        if rules_result.total_score > 0 or metadata_risk > 0.5:
            return ("suspicious",
                    f"GNN unavailable + weak static signals "
                    f"(rules={rules_result.total_score:.0f}, metadata={metadata_risk:.2f})",
                    "rules_only_suspicious")
        return "clean", "GNN unavailable + no static signals", "rules_only_clean"

    if 0.55 <= gnn < cfg.gnn_auto_block and confirming_score >= 8:
        return (
            "malicious",
            f"GNN moderate malicious ({gnn:.3f}) + meaningful confirming "
            f"rules (score={confirming_score:.0f})",
            "moderate_gnn_rules_block",
        )

    if gnn < cfg.gnn_auto_pass:
        if confirming_score > 0 or rules_result.total_score > 0 or metadata_risk > 0.7:
            return (
                "suspicious",
                f"GNN auto-pass ({gnn:.3f}) + static evidence for review "
                f"(score={confirming_score:.0f})",
                "auto_pass_review",
            )
        return "clean", f"GNN auto-pass ({gnn:.3f})", "auto_pass"

    if 0.40 <= gnn < 0.55 and confirming_score >= cfg.rules_block_threshold:
        return (
            "suspicious",
            f"GNN uncertain ({gnn:.3f}) + strong rules reserved for review "
            f"(score={confirming_score:.0f})",
            "uncertain_strong_rules_review",
        )

    if confirming_score > 0:
        return (
            "suspicious",
            f"GNN uncertain ({gnn:.3f}) + confirming rules reserved for review "
            f"(score={confirming_score:.0f})",
            "uncertain_rules_review",
        )

    if rules_result.total_score > 0:
        return ("suspicious",
                f"GNN uncertain ({gnn:.3f}) + non-confirming rules "
                f"(score={rules_result.total_score:.0f})",
                "uncertain_nonconfirming_rules")

    return "suspicious", f"GNN uncertain ({gnn:.3f}), no rules", "uncertain_suspicious"

    # Rule 1: Critical rules override
    if cfg.rules_block_on_critical and rules_result.has_critical:
        crit_names = [r.rule_id for r in rules_result.matched_rules
                      if r.severity == "critical"]
        return (
            "malicious",
            f"CRITICAL rule: {', '.join(crit_names)}",
            "critical_override",
        )

    if not gnn_available:
        if confirming_score >= cfg.rules_block_threshold:
            return ("malicious",
                    f"GNN unavailable + rules confirm (score={confirming_score:.0f})",
                    "rules_only_block")
        if rules_result.total_score > 0 or metadata_risk > 0.5:
            return ("suspicious",
                    f"GNN unavailable + weak static signals "
                    f"(rules={rules_result.total_score:.0f}, metadata={metadata_risk:.2f})",
                    "rules_only_suspicious")
        return "clean", "GNN unavailable + no static signals", "rules_only_clean"

    # Rule 2: GNN auto-block
    if gnn_available and gnn >= cfg.gnn_auto_block:
        return "malicious", f"GNN auto-block ({gnn:.3f})", "auto_block"

    # Rule 3: GNN auto-pass
    if gnn_available and gnn < cfg.gnn_auto_pass:
        if confirming_score >= 15.0:
            return ("malicious",
                    f"GNN clean ({gnn:.3f}) but confirming rules score={confirming_score:.0f}",
                    "auto_pass_rules_override")
        if metadata_risk > 0.7 and confirming_score > 0:
            return ("suspicious",
                    f"GNN clean ({gnn:.3f}) but high metadata risk ({metadata_risk:.2f})",
                    "auto_pass_meta_override")
        return "clean", f"GNN auto-pass ({gnn:.3f})", "auto_pass"

    # Rule 4: Uncertain zone
    if confirming_score >= 15.0:
        return ("malicious",
                f"GNN uncertain ({gnn:.3f}) + rules confirm "
                f"(score={confirming_score:.0f})",
                "uncertain_rules_block")

    if metadata_risk > 0.5 and confirming_score > 0:
        return ("malicious",
                f"GNN uncertain ({gnn:.3f}) + metadata risk ({metadata_risk:.2f}) "
                f"+ confirming rules (score={confirming_score:.0f})",
                "uncertain_meta_escalation")

    if confirming_score > 0:
        return ("malicious",
                f"GNN uncertain ({gnn:.3f}) + confirming rules "
                f"(score={confirming_score:.0f})",
                "uncertain_rules_confirm")

    if rules_result.total_score > 0:
        return ("suspicious",
                f"GNN uncertain ({gnn:.3f}) + non-confirming rules "
                f"(score={rules_result.total_score:.0f})",
                "uncertain_nonconfirming_rules")

    return "suspicious", f"GNN uncertain ({gnn:.3f}), no rules", "uncertain_suspicious"


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info("Device: %s", device)

    # Load model
    model = SupplyGuardGIN(
        node_feat_dim=35, metadata_dim=8, hidden_dim=128,
        num_gin_layers=4, num_edge_types=4, dropout=0.3,
    )
    best_path = CHECKPOINT_DIR / "best_model.pt"
    state = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(state["model_state_dict"])
    model.to(device)
    model.eval()
    log.info("Loaded checkpoint from epoch %s", state.get("epoch", "?"))

    # Collect packages
    mal_manifest = ROOT / "data" / "raw" / "malicious_manifest.csv"
    ben_manifest = ROOT / "data" / "raw" / "benign_manifest.csv"

    log.info("Collecting packages from manifests...")
    mal_pkgs = _collect_from_manifest(
        mal_manifest, label=1, limit=args.sample_size, seed=args.seed,
    )
    ben_pkgs = _collect_from_manifest(
        ben_manifest, label=0, limit=args.sample_size, seed=args.seed,
    )
    log.info("  Malicious: %d  Benign: %d", len(mal_pkgs), len(ben_pkgs))

    all_pkgs = mal_pkgs + ben_pkgs
    random.seed(args.seed)
    random.shuffle(all_pkgs)

    cfg = ThresholdConfig(gnn_auto_pass=0.40, gnn_auto_block=0.75,
                          gnn_uncertain_low=0.40, gnn_uncertain_high=0.75)

    # Process packages
    results: list[PackageResult] = []
    skip_counts = defaultdict(int)

    t0 = time.perf_counter()
    for pkg_dir, label in tqdm(all_pkgs, desc="Processing packages"):
        pr = PackageResult(
            package_name=pkg_dir.name,
            package_path=str(pkg_dir),
            true_label=label,
        )

        # Step 1: Build CPG + GNN inference
        try:
            data = build_cpg(str(pkg_dir), label=label)
            if data is None:
                pr.gnn_score = -1.0
                skip_counts["cpg_none"] += 1
            else:
                data = data.to(device)
                with torch.no_grad():
                    logit = model.forward_from_data(data)
                    pr.gnn_score = torch.sigmoid(logit).item()
        except Exception as e:
            pr.gnn_score = -1.0
            skip_counts["gnn_error"] += 1
            log.debug("GNN failed for %s: %s", pkg_dir.name, e)

        # Step 2: Rules engine
        try:
            rules_result = run_rules(str(pkg_dir))
            rules_result = merge_manifest_rules(rules_result, str(pkg_dir))
        except Exception as e:
            rules_result = RulesResult()
            skip_counts["rules_error"] += 1
            log.debug("Rules failed for %s: %s", pkg_dir.name, e)

        pr.rules_score = rules_result.total_score
        pr.rules_critical = rules_result.has_critical
        pr.rules_matched = [r.rule_id for r in rules_result.matched_rules]
        pr.rules_details = [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity,
                "score": getattr(r, "score", 0.0),
            }
            for r in rules_result.matched_rules
        ]

        # Individual verdicts
        pr.gnn_verdict = (
            "malicious" if pr.gnn_score >= 0.5
            else "clean" if pr.gnn_score >= 0.0
            else "unknown"
        )
        pr.rules_verdict = (
            "malicious" if rules_result.has_critical or rules_result.total_score >= 15.0
            else "clean"
        )

        # Step 3: Metadata risk
        pkg_json_data: dict = {}
        pj_path = pkg_dir / "package.json"
        if pj_path.exists():
            try:
                pkg_json_data = json.loads(pj_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        pr.metadata_risk = compute_metadata_risk(pkg_dir.name, pkg_json_data)

        # Step 4: Hybrid decision
        verdict, decision_path, bucket = _hybrid_decide(
            pr.gnn_score, rules_result, cfg, pr.metadata_risk
        )
        pr.hybrid_verdict = verdict
        pr.decision_path = decision_path
        pr.decision_bucket = bucket

        results.append(pr)

    elapsed = time.perf_counter() - t0
    log.info("Processed %d packages in %.1fs (%.1f pkg/s)",
             len(results), elapsed, len(results) / max(elapsed, 0.01))

    # ── Compute metrics ──────────────────────────────────────────────────
    def _metrics(preds: list[int], labels: list[int]) -> dict:
        tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
        fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
        fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
        tn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 0)
        prec = tp / max(tp + fp, 1)
        rec = tp / max(tp + fn, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-9)
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": prec, "recall": rec, "f1": f1,
                "flagged": tp + fp}

    labels = [r.true_label for r in results]

    # GNN-only (threshold=0.5)
    gnn_preds = [1 if r.gnn_score >= 0.5 else 0 for r in results]
    # Rules-only
    rules_preds = [1 if r.rules_verdict == "malicious" else 0 for r in results]
    # Hybrid (suspicious does NOT count as malicious for flagging)
    hybrid_preds = [1 if r.hybrid_verdict == "malicious" else 0
                    for r in results]

    gnn_m = _metrics(gnn_preds, labels)
    rules_m = _metrics(rules_preds, labels)
    hybrid_m = _metrics(hybrid_preds, labels)

    log.info("")
    log.info("═══ Three-Way Comparison ═══")
    log.info("%-12s  %-8s  %-8s  %-8s  %-6s  %-6s  %-8s",
             "System", "Prec", "Recall", "F1", "FP", "FN", "Flagged")
    log.info("─" * 68)
    for name, m in [("GNN-only", gnn_m), ("Rules-only", rules_m), ("Hybrid", hybrid_m)]:
        log.info("  %-10s  %.4f    %.4f    %.4f    %4d    %4d    %4d",
                 name, m["precision"], m["recall"], m["f1"],
                 m["fp"], m["fn"], m["flagged"])

    # ── Decision buckets ─────────────────────────────────────────────────
    bucket_counts = defaultdict(int)
    for r in results:
        bucket_counts[r.decision_bucket] += 1

    log.info("")
    log.info("═══ Decision Buckets ═══")
    for bucket in ["auto_pass", "auto_pass_review", "auto_block",
                    "auto_block_confirmed", "gnn_very_high", "critical_override",
                    "review_only_critical",
                    "critical_gnn_clean_review", "moderate_gnn_rules_block",
                    "auto_pass_rules_override", "uncertain_rules_block",
                    "uncertain_strong_rules_review", "uncertain_rules_review",
                    "uncertain_rules_confirm", "uncertain_nonconfirming_rules",
                    "uncertain_suspicious",
                    "uncertain_clean", "rules_only_block", "rules_only_suspicious",
                    "rules_only_clean"]:
        log.info("  %-30s  %d", bucket, bucket_counts.get(bucket, 0))

    uncertain_total = (bucket_counts.get("uncertain_rules_block", 0) +
                       bucket_counts.get("uncertain_suspicious", 0) +
                       bucket_counts.get("uncertain_clean", 0))
    log.info("  %-30s  %d", "TOTAL uncertain zone", uncertain_total)

    # ── Disagreement analysis ────────────────────────────────────────────
    log.info("")
    log.info("═══ Disagreement Analysis ═══")
    gnn_clean_rules_mal = [(r, i) for i, r in enumerate(results)
                           if r.gnn_verdict == "clean" and r.rules_verdict == "malicious"]
    gnn_mal_rules_clean = [(r, i) for i, r in enumerate(results)
                           if r.gnn_verdict == "malicious" and r.rules_verdict == "clean"]
    both_agree = [(r, i) for i, r in enumerate(results)
                  if r.gnn_verdict == r.rules_verdict]

    log.info("  GNN=clean + Rules=malicious: %d packages", len(gnn_clean_rules_mal))
    for r, _ in gnn_clean_rules_mal[:10]:
        log.info("    %-30s  label=%d  GNN=%.3f  rules=%s",
                 r.package_name[:30], r.true_label, r.gnn_score,
                 r.rules_matched)

    log.info("  GNN=malicious + Rules=clean: %d packages", len(gnn_mal_rules_clean))
    for r, _ in gnn_mal_rules_clean[:10]:
        log.info("    %-30s  label=%d  GNN=%.3f  rules=%s",
                 r.package_name[:30], r.true_label, r.gnn_score,
                 r.rules_matched)

    both_right = sum(1 for r, _ in both_agree
                     if (r.gnn_verdict == "malicious") == (r.true_label == 1))
    log.info("  Both agree: %d  (correct: %d, wrong: %d)",
             len(both_agree), both_right, len(both_agree) - both_right)

    # ── Error analysis: False Positives ──────────────────────────────────
    fps = [r for r in results
           if hybrid_preds[results.index(r)] == 1 and r.true_label == 0]
    log.info("")
    log.info("═══ False Positives (Hybrid) — %d packages ═══", len(fps))
    for r in fps[:20]:
        log.info("  %-35s  GNN=%.3f  rules_score=%.0f  rules=%s",
                 r.package_name[:35], r.gnn_score, r.rules_score,
                 r.rules_matched)
        log.info("    → path: %s", r.decision_path)

    # ── Error analysis: False Negatives ──────────────────────────────────
    fns = [r for r in results
           if hybrid_preds[results.index(r)] == 0 and r.true_label == 1]
    log.info("")
    log.info("═══ False Negatives (Hybrid) — %d packages ═══", len(fns))

    fn_gnn_missed_rules_missed = [r for r in fns if r.gnn_score < 0.5 and r.rules_score < 15.0 and not r.rules_critical]
    fn_gnn_low_rules_missed = [r for r in fns if 0.25 <= r.gnn_score < 0.65 and r.rules_score < 15.0 and not r.rules_critical]
    fn_both_missed = [r for r in fns if r.gnn_score < 0.25 and r.rules_score < 15.0 and not r.rules_critical]

    log.info("  Breakdown:")
    log.info("    GNN missed + Rules missed (both blind): %d", len(fn_gnn_missed_rules_missed))
    log.info("    GNN in uncertain zone + Rules missed:   %d", len(fn_gnn_low_rules_missed))
    log.info("    GNN < auto_pass + Rules missed:         %d", len(fn_both_missed))

    for r in fns[:15]:
        log.info("  %-35s  GNN=%.3f  rules_score=%.0f  rules=%s  bucket=%s",
                 r.package_name[:35], r.gnn_score, r.rules_score,
                 r.rules_matched, r.decision_bucket)

    # ── Per-rule contribution ────────────────────────────────────────────
    log.info("")
    log.info("═══ Per-Rule Contribution in Hybrid ═══")
    log.info("%-30s  %-8s  %-8s", "Rule", "Saved", "Hurt")
    log.info("─" * 50)

    rule_saved = defaultdict(int)
    rule_hurt = defaultdict(int)
    for i, r in enumerate(results):
        for rule_id in r.rules_matched:
            # Would GNN-only have gotten this right?
            gnn_correct = (gnn_preds[i] == r.true_label)
            hyb_correct = (hybrid_preds[i] == r.true_label)
            if not gnn_correct and hyb_correct:
                rule_saved[rule_id] += 1
            elif gnn_correct and not hyb_correct:
                rule_hurt[rule_id] += 1

    all_rule_ids = sorted(set(list(rule_saved.keys()) + list(rule_hurt.keys())))
    for rid in all_rule_ids:
        log.info("  %-28s  %4d      %4d", rid, rule_saved.get(rid, 0), rule_hurt.get(rid, 0))

    # ── Skip summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("═══ Skip Summary ═══")
    for reason, count in skip_counts.items():
        log.info("  %-20s  %d", reason, count)

    # ── Threshold sweep ──────────────────────────────────────────────────
    log.info("")
    log.info("═══ Threshold Sweep (real data) ═══")
    log.info("%-8s  %-8s  %-8s  %-8s  %-8s  %-6s  %-6s",
             "AP", "AB", "Prec", "Recall", "F1", "FP", "FN")
    log.info("─" * 62)

    sweep_results = []
    for ap in [0.20, 0.25, 0.30, 0.35, 0.40]:
        for ab in [0.55, 0.65, 0.75, 0.85, 0.90, 0.95]:
            tc = ThresholdConfig(
                gnn_auto_pass=ap, gnn_auto_block=ab,
                gnn_uncertain_low=ap, gnn_uncertain_high=ab,
            )
            preds = []
            for r in results:
                rr = RulesResult(
                    matched_rules=[
                        MatchedRule(
                            rule_id=str(d.get("rule_id", "")),
                            rule_name=str(d.get("rule_name", d.get("rule_id", ""))),
                            severity=str(d.get("severity", "")),
                            description="",
                            score=float(d.get("score", 0.0)),
                        )
                        for d in r.rules_details
                    ],
                    total_score=r.rules_score,
                    has_critical=r.rules_critical,
                )
                v, _, _ = _hybrid_decide(r.gnn_score, rr, tc)
                preds.append(1 if v == "malicious" else 0)

            m = _metrics(preds, labels)
            sweep_results.append((ap, ab, m))
            log.info("  %.2f    %.2f    %.4f    %.4f    %.4f    %4d    %4d",
                     ap, ab, m["precision"], m["recall"], m["f1"],
                     m["fp"], m["fn"])

    # Best at P >= 97%
    log.info("")
    log.info("═══ Best Combo (P ≥ 97%%) ═══")
    filtered = [(ap, ab, m) for ap, ab, m in sweep_results if m["precision"] >= 0.97]
    filtered.sort(key=lambda x: x[2]["f1"], reverse=True)
    for ap, ab, m in filtered[:3]:
        log.info("  AP=%.2f  AB=%.2f  →  P=%.4f  R=%.4f  F1=%.4f  FP=%d  FN=%d",
                 ap, ab, m["precision"], m["recall"], m["f1"],
                 m["fp"], m["fn"])

    # ── Save JSON ────────────────────────────────────────────────────────
    output = {
        "summary": {
            "n_total": len(results),
            "n_malicious": sum(1 for r in results if r.true_label == 1),
            "n_benign": sum(1 for r in results if r.true_label == 0),
            "elapsed_seconds": round(elapsed, 1),
            "thresholds": {"auto_pass": 0.40, "auto_block": 0.75},
        },
        "metrics": {
            "gnn_only": gnn_m,
            "rules_only": rules_m,
            "hybrid": hybrid_m,
        },
        "buckets": dict(bucket_counts),
        "skip_counts": dict(skip_counts),
        "packages": [
            {
                "name": r.package_name,
                "path": r.package_path,
                "true_label": r.true_label,
                "gnn_score": round(r.gnn_score, 4),
                "gnn_verdict": r.gnn_verdict,
                "rules_verdict": r.rules_verdict,
                "rules_score": r.rules_score,
                "rules_critical": r.rules_critical,
                "rules_matched": r.rules_matched,
                "rules_details": r.rules_details,
                "metadata_risk": round(r.metadata_risk, 3),
                "hybrid_verdict": r.hybrid_verdict,
                "decision_path": r.decision_path,
                "decision_bucket": r.decision_bucket,
            }
            for r in results
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    log.info("")
    log.info("Full results saved to %s", args.output)
    log.info("═══ Done ═══")


if __name__ == "__main__":
    main()
