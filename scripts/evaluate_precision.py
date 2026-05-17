"""
Evaluate the best checkpoint with precision-targeted threshold tuning.

No retraining needed — just loads the model and finds the optimal
threshold for 99.9% precision on the validation set, then evaluates
on the test set at that threshold.
"""

import sys
import logging
import time
from pathlib import Path

import numpy as np
import torch

# allow imports from parent directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.model.gin_classifier import SupplyGuardGIN
from supplyguard.model.training import (
    GraphDataset,
    Trainer,
    TrainerConfig,
    _compute_metrics,
    find_optimal_threshold,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
VAL_DIR = DATA_DIR / "val"
TEST_DIR = DATA_DIR / "test"
CHECKPOINT_DIR = Path(__file__).resolve().parent.parent / "checkpoints"


def main():
    device = "cuda" if torch.cuda.is_available() else "cpu"
    log.info("Device: %s", device)

    # Load model
    model = SupplyGuardGIN(
        node_feat_dim=35,
        metadata_dim=8,
        hidden_dim=128,
        num_gin_layers=4,
        num_edge_types=4,
        dropout=0.3,
    )

    best_path = CHECKPOINT_DIR / "best_model.pt"
    if not best_path.exists():
        log.error("No checkpoint found at %s", best_path)
        return

    state = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(state["model_state_dict"])
    model.to(device)
    model.eval()
    log.info("Loaded checkpoint from epoch %d", state.get("epoch", "?"))

    cfg = TrainerConfig(
        max_nodes_per_graph=50_000,
        max_nodes_per_batch=30_000,
    )

    # --- Collect val predictions ---
    log.info("═══ Collecting validation predictions ═══")
    val_ds = GraphDataset(VAL_DIR, max_nodes=cfg.max_nodes_per_graph)
    trainer = Trainer(model=model, cfg=cfg, device=device)
    val_loader = trainer._make_loader(val_ds, shuffle=False)

    val_labels = []
    val_probs = []
    with torch.no_grad():
        for batch in val_loader:
            logits, _ = trainer._forward_batch(batch)
            val_probs.extend(torch.sigmoid(logits).cpu().tolist())
            val_labels.extend(batch.y.cpu().tolist())

    log.info("Val samples: %d", len(val_labels))

    # --- Compute metrics at default threshold ---
    m_default = _compute_metrics(val_labels, val_probs, 0.0, 1, threshold=0.5)
    log.info("Val @ threshold=0.500: %s", m_default.summary())

    # --- Find thresholds for different strategies ---
    for strategy in ["f1", "precision99", "precision999"]:
        t = find_optimal_threshold(val_labels, val_probs, strategy=strategy)
        m = _compute_metrics(val_labels, val_probs, 0.0, 1, threshold=t)
        log.info("Val @ %s (t=%.4f): P=%.4f  R=%.4f  F1=%.4f  R@99P=%.4f  R@99.9P=%.4f",
                 strategy, t, m.precision, m.recall, m.f1,
                 m.recall_at_99p, m.recall_at_999p)

    # --- Best threshold for 99.9% precision ---
    best_t = find_optimal_threshold(val_labels, val_probs, strategy="precision999")
    log.info("")
    log.info("╔══════════════════════════════════════════════════════╗")
    log.info("║  OPTIMAL THRESHOLD FOR 99.9%% PRECISION: %.4f     ║", best_t)
    log.info("╚══════════════════════════════════════════════════════╝")
    log.info("")

    # --- Evaluate on test set ---
    log.info("═══ Test set evaluation ═══")
    test_ds = GraphDataset(TEST_DIR, max_nodes=cfg.max_nodes_per_graph)
    test_loader = trainer._make_loader(test_ds, shuffle=False)

    test_labels = []
    test_probs = []
    with torch.no_grad():
        for batch in test_loader:
            logits, _ = trainer._forward_batch(batch)
            test_probs.extend(torch.sigmoid(logits).cpu().tolist())
            test_labels.extend(batch.y.cpu().tolist())

    log.info("Test samples: %d", len(test_labels))

    # Show results at multiple operating points
    log.info("")
    log.info("═══ Test Results at Multiple Operating Points ═══")
    log.info("%-18s  %-8s  %-8s  %-8s  %-8s  %-8s",
             "Strategy", "Thresh", "Prec", "Recall", "F1", "Acc")
    log.info("─" * 70)

    for label, t in [
        ("Default (0.5)", 0.5),
        ("Max F1", find_optimal_threshold(val_labels, val_probs, "f1")),
        ("Precision≥99%", find_optimal_threshold(val_labels, val_probs, "precision99")),
        ("Precision≥99.9%", find_optimal_threshold(val_labels, val_probs, "precision999")),
    ]:
        m = _compute_metrics(test_labels, test_probs, 0.0, 1, threshold=t)
        log.info("%-18s  %.4f    %.4f    %.4f    %.4f    %.4f",
                 label, t, m.precision, m.recall, m.f1, m.accuracy)

    # Full metrics at 99.9% precision threshold
    m_999 = _compute_metrics(test_labels, test_probs, 0.0, 1, threshold=best_t)
    log.info("")
    log.info("═══ Full Metrics @ 99.9%% Precision Threshold (%.4f) ═══", best_t)
    log.info(m_999.summary())

    # Save threshold to checkpoint
    state["best_threshold"] = best_t
    state["threshold_strategy"] = "precision999"
    torch.save(state, best_path)
    log.info("Updated checkpoint with threshold=%.4f", best_t)


if __name__ == "__main__":
    main()
