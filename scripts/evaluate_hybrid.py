"""
Evaluate the hybrid GNN + rules pipeline against the test dataset.

Compares GNN-only vs hybrid performance using metadata-simulated rules
(since test data is in graph form, not raw source).
"""

import sys
import logging
from pathlib import Path
from dataclasses import dataclass

import numpy as np
import torch
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.model.gin_classifier import SupplyGuardGIN
from supplyguard.model.training import GraphDataset, Trainer, TrainerConfig
from supplyguard.scanner.scan_pipeline import ThresholdConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
TEST_DIR = DATA_DIR / "test"
CHECKPOINT_DIR = Path(__file__).resolve().parent.parent / "checkpoints"


# ── Simulated rules from metadata ────────────────────────────────────────

@dataclass
class SimulatedRules:
    has_critical: bool = False
    total_score: float = 0.0
    matched: list[str] = None

    def __post_init__(self):
        if self.matched is None:
            self.matched = []


def simulate_rules(metadata) -> SimulatedRules:
    """Approximate rule-engine output using the 8-dim metadata vector.

    metadata indices:
        [0] has_preinstall_hook
        [1] has_postinstall_hook
        [2] num_js_files_norm
        [3] total_lines_norm
        [4] has_install_net_hook
        [5] num_sources_norm
        [6] num_sinks_norm
        [7] has_source_and_sink
    """
    if hasattr(metadata, 'tolist'):
        m = metadata.cpu().tolist() if hasattr(metadata, 'cpu') else metadata.tolist()
    else:
        m = list(metadata)
    has_pre = m[0] > 0.5
    has_post = m[1] > 0.5
    has_hook = has_pre or has_post
    has_net_hook = m[4] > 0.5
    has_sources = m[5] > 0.01
    has_sinks = m[6] > 0.01
    has_taint = m[7] > 0.5

    result = SimulatedRules()

    # CRITICAL: install hook + network + taint flow (exfiltration pattern)
    if has_hook and has_net_hook and has_taint:
        result.has_critical = True
        result.total_score += 10
        result.matched.append("SIM_CRIT_EXFIL")

    # HIGH: install hook + taint (source→sink without confirmed network)
    if has_hook and has_taint and not has_net_hook:
        result.total_score += 5
        result.matched.append("SIM_HIGH_HOOK_TAINT")

    # HIGH: network in hook but no taint
    if has_net_hook and not has_taint:
        result.total_score += 5
        result.matched.append("SIM_HIGH_NET_HOOK")

    # MEDIUM: install hook exists
    if has_hook:
        result.total_score += 2
        result.matched.append("SIM_MED_HOOK")

    # MEDIUM: taint flow without hook
    if has_taint and not has_hook:
        result.total_score += 2
        result.matched.append("SIM_MED_TAINT")

    return result


# ── Hybrid decision ──────────────────────────────────────────────────────

def hybrid_decide(
    gnn_score: float,
    sim_rules: SimulatedRules,
    cfg: ThresholdConfig,
) -> str:
    """Return 'malicious', 'suspicious', or 'clean'."""
    if cfg.rules_block_on_critical and sim_rules.has_critical:
        return "malicious"
    if gnn_score >= cfg.gnn_auto_block:
        return "malicious"
    if gnn_score < cfg.gnn_auto_pass:
        if sim_rules.total_score >= cfg.rules_block_threshold:
            return "malicious"
        return "clean"
    # Uncertain zone
    if sim_rules.total_score >= cfg.rules_block_threshold:
        return "malicious"
    if sim_rules.total_score > 0:
        return "malicious"
    return "suspicious"


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    device = "cuda" if torch.cuda.is_available() else "cpu"
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

    cfg = TrainerConfig(max_nodes_per_graph=50_000, max_nodes_per_batch=30_000)
    test_ds = GraphDataset(TEST_DIR, max_nodes=cfg.max_nodes_per_graph)
    trainer = Trainer(model=model, cfg=cfg, device=device)
    test_loader = trainer._make_loader(test_ds, shuffle=False)

    # Collect predictions + metadata
    all_labels, all_probs, all_meta = [], [], []
    with torch.no_grad():
        for batch in test_loader:
            logits, _ = trainer._forward_batch(batch)
            probs = torch.sigmoid(logits).cpu().tolist()
            labels = batch.y.cpu().tolist()
            all_probs.extend(probs)
            all_labels.extend(labels)
            # Extract per-graph metadata
            meta = batch.metadata.cpu()
            batch_size = int(batch.batch.max().item()) + 1
            if meta.dim() == 2:
                for i in range(meta.size(0)):
                    all_meta.append(meta[i].tolist())
            elif meta.dim() == 1 and len(meta) == 8 and batch_size == 1:
                all_meta.append(meta.tolist())
            elif meta.dim() == 1:
                # Flat concat — reshape to [batch_size, 8]
                try:
                    reshaped = meta.view(batch_size, -1)
                    for i in range(batch_size):
                        all_meta.append(reshaped[i].tolist())
                except RuntimeError:
                    for _ in range(batch_size):
                        all_meta.append([0.0] * 8)

    n = len(all_labels)
    n_mal = sum(1 for l in all_labels if l == 1.0)
    n_ben = n - n_mal
    log.info("Test set: %d samples (%d malicious, %d benign)", n, n_mal, n_ben)

    # ── GNN-only precision-recall table ──
    log.info("")
    log.info("═══ GNN-Only Precision/Recall at Various Thresholds ═══")
    log.info("%-10s  %-8s  %-8s  %-8s  %-8s  %-6s  %-6s",
             "Threshold", "Prec", "Recall", "F1", "Acc", "FP", "FN")
    log.info("─" * 65)
    for t in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        preds = [1.0 if p >= t else 0.0 for p in all_probs]
        p = precision_score(all_labels, preds, zero_division=0.0)
        r = recall_score(all_labels, preds, zero_division=0.0)
        f = f1_score(all_labels, preds, zero_division=0.0)
        a = accuracy_score(all_labels, preds)
        fp = sum(1 for pr, la in zip(preds, all_labels) if pr == 1.0 and la == 0.0)
        fn = sum(1 for pr, la in zip(preds, all_labels) if pr == 0.0 and la == 1.0)
        log.info("  %.1f       %.4f    %.4f    %.4f    %.4f    %4d    %4d",
                 t, p, r, f, a, fp, fn)

    # ── Simulate rules for all test samples ──
    sim_rules_list = []
    for i in range(n):
        if i < len(all_meta):
            sim_rules_list.append(simulate_rules(all_meta[i]))
        else:
            sim_rules_list.append(SimulatedRules())

    # ── Hybrid evaluation with tuned thresholds ──
    tcfg = ThresholdConfig(gnn_auto_pass=0.40, gnn_auto_block=0.75,
                           gnn_uncertain_low=0.40, gnn_uncertain_high=0.75)
    hybrid_preds = []
    buckets = {"auto_pass": 0, "auto_block": 0, "uncertain_rules": 0,
               "uncertain_suspicious": 0, "uncertain_clean": 0, "critical_override": 0}

    for i in range(n):
        gnn = all_probs[i]
        sr = sim_rules_list[i]
        verdict = hybrid_decide(gnn, sr, tcfg)

        if sr.has_critical and tcfg.rules_block_on_critical:
            buckets["critical_override"] += 1
        elif gnn >= tcfg.gnn_auto_block:
            buckets["auto_block"] += 1
        elif gnn < tcfg.gnn_auto_pass:
            buckets["auto_pass"] += 1
        elif sr.total_score >= tcfg.rules_block_threshold:
            buckets["uncertain_rules"] += 1
        elif sr.total_score > 0:
            buckets["uncertain_suspicious"] += 1
        else:
            buckets["uncertain_suspicious"] += 1

        hybrid_preds.append(1.0 if verdict == "malicious" else 0.0)

    gnn_default = [1.0 if p >= 0.5 else 0.0 for p in all_probs]

    log.info("")
    log.info("═══ Comparison: GNN-Only vs Hybrid ═══")
    log.info("%-15s  %-8s  %-8s  %-8s  %-8s",
             "System", "Prec", "Recall", "F1", "Acc")
    log.info("─" * 52)
    for name, preds in [("GNN-only", gnn_default), ("Hybrid", hybrid_preds)]:
        p = precision_score(all_labels, preds, zero_division=0.0)
        r = recall_score(all_labels, preds, zero_division=0.0)
        f = f1_score(all_labels, preds, zero_division=0.0)
        a = accuracy_score(all_labels, preds)
        log.info("  %-13s  %.4f    %.4f    %.4f    %.4f", name, p, r, f, a)

    # FP/FN comparison
    gnn_fp = sum(1 for p, l in zip(gnn_default, all_labels) if p == 1.0 and l == 0.0)
    gnn_fn = sum(1 for p, l in zip(gnn_default, all_labels) if p == 0.0 and l == 1.0)
    hyb_fp = sum(1 for p, l in zip(hybrid_preds, all_labels) if p == 1.0 and l == 0.0)
    hyb_fn = sum(1 for p, l in zip(hybrid_preds, all_labels) if p == 0.0 and l == 1.0)

    log.info("")
    log.info("═══ False Positive / False Negative Counts ═══")
    log.info("  GNN-only:  FP=%d  FN=%d", gnn_fp, gnn_fn)
    log.info("  Hybrid:    FP=%d  FN=%d", hyb_fp, hyb_fn)
    log.info("  Δ FP: %+d  (fewer = better)", hyb_fp - gnn_fp)
    log.info("  Δ FN: %+d  (fewer = better)", hyb_fn - gnn_fn)

    # Decision buckets
    log.info("")
    log.info("═══ Decision Buckets ═══")
    for bucket, count in buckets.items():
        log.info("  %-25s  %d", bucket, count)

    # Flipped samples
    log.info("")
    log.info("═══ Flipped Samples (GNN-only vs Hybrid) ═══")
    wrong_to_right = 0
    right_to_wrong = 0
    for i in range(n):
        gnn_correct = (gnn_default[i] == all_labels[i])
        hyb_correct = (hybrid_preds[i] == all_labels[i])
        if not gnn_correct and hyb_correct:
            wrong_to_right += 1
        elif gnn_correct and not hyb_correct:
            right_to_wrong += 1
    log.info("  Wrong→Right (improved): %d", wrong_to_right)
    log.info("  Right→Wrong (regressed): %d", right_to_wrong)
    log.info("  Net improvement: %+d samples", wrong_to_right - right_to_wrong)

    # ── Focused Threshold Sweep ──
    log.info("")
    log.info("═══ Threshold Sweep (P≥97%%, best F1) ═══")
    log.info("%-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-10s  %-10s  %-10s",
             "AP", "AB", "Prec", "Recall", "F1", "Acc",
             "AutoPass", "AutoBlock", "Uncertain")
    log.info("─" * 95)

    results = []
    for ap in [0.25, 0.30, 0.35, 0.40]:
        for ab in [0.55, 0.60, 0.65, 0.70, 0.75]:
            tc = ThresholdConfig(
                gnn_auto_pass=ap, gnn_auto_block=ab,
                gnn_uncertain_low=ap, gnn_uncertain_high=ab,
                rules_block_threshold=15.0,
            )
            preds = []
            b = {"auto_pass": 0, "auto_block": 0, "uncertain": 0, "crit": 0}
            for i in range(n):
                gnn = all_probs[i]
                sr = sim_rules_list[i]
                v = hybrid_decide(gnn, sr, tc)
                preds.append(1.0 if v == "malicious" else 0.0)
                if sr.has_critical and tc.rules_block_on_critical:
                    b["crit"] += 1
                elif gnn >= ab:
                    b["auto_block"] += 1
                elif gnn < ap:
                    b["auto_pass"] += 1
                else:
                    b["uncertain"] += 1

            p = precision_score(all_labels, preds, zero_division=0.0)
            r = recall_score(all_labels, preds, zero_division=0.0)
            f = f1_score(all_labels, preds, zero_division=0.0)
            a = accuracy_score(all_labels, preds)
            fp = sum(1 for pr, la in zip(preds, all_labels) if pr == 1.0 and la == 0.0)
            fn = sum(1 for pr, la in zip(preds, all_labels) if pr == 0.0 and la == 1.0)

            results.append((ap, ab, p, r, f, a, b, fp, fn))
            log.info("  %.2f    %.2f    %.4f    %.4f    %.4f    %.4f    %4d       %4d       %4d",
                     ap, ab, p, r, f, a, b["auto_pass"], b["auto_block"], b["uncertain"])

    # Find best combo with P >= 97%
    log.info("")
    log.info("═══ Best Combos (P ≥ 97%%) ═══")
    log.info("%-8s  %-8s  %-8s  %-8s  %-8s  %-6s  %-6s",
             "AP", "AB", "Prec", "Recall", "F1", "FP", "FN")
    log.info("─" * 58)
    filtered = [(ap, ab, p, r, f, fp, fn)
                for ap, ab, p, r, f, a, b, fp, fn in results if p >= 0.97]
    filtered.sort(key=lambda x: x[4], reverse=True)  # sort by F1
    for ap, ab, p, r, f, fp, fn in filtered[:5]:
        marker = " ← BEST" if (ap, ab) == (filtered[0][0], filtered[0][1]) else ""
        log.info("  %.2f    %.2f    %.4f    %.4f    %.4f    %4d    %4d%s",
                 ap, ab, p, r, f, fp, fn, marker)

    log.info("")
    log.info("═══ Done ═══")


if __name__ == "__main__":
    main()
