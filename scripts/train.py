"""
Train the SupplyGuard GIN malicious-package classifier.

Usage:
    python scripts/train.py
    python scripts/train.py --epochs 30 --lr 5e-4 --batch-size 128
    python scripts/train.py --hidden-dim 256 --num-layers 5
    python scripts/train.py --checkpoint-dir checkpoints/experiments/run1
    python scripts/train.py --resume
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

print("train.py: starting (importing torch — may take a minute) …", flush=True)

import argparse
import json
import logging
import time
from pathlib import Path

import torch

print("train.py: torch imported, setting up …", flush=True)

from supplyguard.model.gin_classifier import SupplyGuardGIN
from supplyguard.model.training import Trainer, TrainerConfig

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data" / "processed"
TRAIN_DIR = DATA_DIR / "train"
VAL_DIR = DATA_DIR / "val"
TEST_DIR = DATA_DIR / "test"
CHECKPOINT_DIR = ROOT_DIR / "checkpoints"
RESULTS_PATH = ROOT_DIR / "results" / "training_results.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train SupplyGuard GIN classifier")

    # model
    p.add_argument("--hidden-dim", type=int, default=128)
    p.add_argument("--num-layers", type=int, default=4)
    p.add_argument("--dropout", type=float, default=0.3)

    # training
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--weight-decay", type=float, default=1e-4)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--patience", type=int, default=10)
    p.add_argument("--monitor",
                   choices=["f1", "auc_roc", "loss", "recall_at_99p", "recall_at_999p"],
                   default="f1",
                   help="Early-stopping metric")
    p.add_argument("--scheduler", choices=["plateau", "cosine", "none"],
                   default="plateau")
    p.add_argument("--max-nodes-per-batch", type=int, default=30_000,
                   help="Max total nodes per batch (dynamic batching budget)")
    p.add_argument("--max-nodes-per-graph", type=int, default=50_000,
                   help="Drop graphs above this size (noise from bundled code)")
    p.add_argument("--accum-steps", type=int, default=4,
                   help="Gradient accumulation steps")
    p.add_argument("--threshold-strategy",
                   choices=["f1", "precision999", "precision99", "recall95"],
                   default="f1",
                   help="Threshold tuning strategy (default: f1 for balanced precision/recall)")
    p.add_argument("--loss", choices=["focal", "bce"], default="focal",
                   help="Loss function. focal is the default for imbalanced security data.")
    p.add_argument("--focal-alpha", type=float, default=0.75,
                   help="Focal-loss alpha for positive/malicious examples")
    p.add_argument("--focal-gamma", type=float, default=2.0,
                   help="Focal-loss focusing parameter")
    p.add_argument("--label-smoothing", type=float, default=0.05,
                   help="Binary-label smoothing applied during training")
    p.add_argument("--no-auto-pos-weight", action="store_true",
                   help="Disable automatic positive-class weighting")

    # system
    p.add_argument("--device", type=str, default=None,
                   help="cpu or cuda (auto-detected if omitted)")
    p.add_argument("--workers", type=int, default=0,
                   help="DataLoader workers (0 = main process)")
    p.add_argument("--skip-test", action="store_true",
                   help="Skip final test-set evaluation")
    p.add_argument("--resume", action="store_true",
                   help="Resume training from last checkpoint")
    p.add_argument("--checkpoint-dir", type=Path, default=CHECKPOINT_DIR,
                   help="Directory for best/periodic checkpoints")
    p.add_argument("--results-path", type=Path, default=RESULTS_PATH,
                   help="Where to write the training JSON summary")
    p.add_argument("--sweep-path", type=Path, default=ROOT_DIR / "results" / "threshold_sweep.json",
                   help="Where to write the validation threshold sweep")
    p.add_argument("--model-copy-path", type=Path, default=None,
                   help="Optional extra copy of the best checkpoint")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    device = args.device
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    log.info("Device: %s", device)

    # ---- verify splits exist ----
    for d, name in [(TRAIN_DIR, "train"), (VAL_DIR, "val"), (TEST_DIR, "test")]:
        n = len(list(d.glob("*.pt"))) if d.exists() else 0
        log.info("  %s: %d graphs", name, n)
        if n == 0 and name != "test":
            log.error("No graphs in %s — run assemble_splits.py first", d)
            return

    # ---- model ----
    model = SupplyGuardGIN(
        node_feat_dim=35,
        metadata_dim=8,
        hidden_dim=args.hidden_dim,
        num_gin_layers=args.num_layers,
        dropout=args.dropout,
    )

    total_params = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    log.info("Model: %s", model.__class__.__name__)
    log.info("  Parameters: %s total, %s trainable",
             f"{total_params:,}", f"{trainable:,}")

    # ---- trainer ----
    cfg = TrainerConfig(
        lr=args.lr,
        weight_decay=args.weight_decay,
        epochs=args.epochs,
        batch_size=args.batch_size,
        patience=args.patience,
        num_workers=args.workers,
        checkpoint_dir=str(args.checkpoint_dir),
        monitor=args.monitor,
        scheduler=args.scheduler,
        max_nodes_per_batch=args.max_nodes_per_batch,
        max_nodes_per_graph=args.max_nodes_per_graph,
        accum_steps=args.accum_steps,
        use_focal_loss=args.loss == "focal",
        focal_alpha=args.focal_alpha,
        focal_gamma=args.focal_gamma,
        label_smoothing=args.label_smoothing,
        auto_pos_weight=not args.no_auto_pos_weight,
        threshold_strategy=args.threshold_strategy,
    )

    trainer = Trainer(model=model, cfg=cfg, device=device)

    # ---- resume from checkpoint ----
    start_epoch = 1
    if args.resume:
        start_epoch = trainer.load_checkpoint()

    # ---- train ----
    log.info("═══ Training started ═══")
    t0 = time.perf_counter()
    history = trainer.fit(train_dir=TRAIN_DIR, val_dir=VAL_DIR,
                          start_epoch=start_epoch)
    train_time = time.perf_counter() - t0
    log.info("Training completed in %.1f seconds", train_time)

    # ---- threshold sweep on validation set ----
    log.info("═══ Threshold sweep ═══")
    sweep_path = args.sweep_path
    sweep_path.parent.mkdir(parents=True, exist_ok=True)

    if trainer._val_labels and trainer._val_probs:
        import numpy as np

        sweep_results = []
        for t in np.arange(0.30, 0.96, 0.05):
            t = round(float(t), 2)
            from supplyguard.model.training import _binary_counts, _compute_metrics
            m = _compute_metrics(
                trainer._val_labels, trainer._val_probs, 0.0, 1, threshold=t,
            )
            preds = [1.0 if p >= t else 0.0 for p in trainer._val_probs]
            _, fp, fn, _ = _binary_counts(trainer._val_labels, preds)
            sweep_results.append({
                "threshold": t, "precision": round(m.precision, 4),
                "recall": round(m.recall, 4), "f1": round(m.f1, 4),
                "fp": fp, "fn": fn,
            })
            log.info("  t=%.2f  P=%.4f  R=%.4f  F1=%.4f  FP=%d  FN=%d",
                     t, m.precision, m.recall, m.f1, fp, fn)

        best_f1 = max(sweep_results, key=lambda x: x["f1"])
        best_p99 = max(
            [s for s in sweep_results if s["precision"] >= 0.99],
            key=lambda x: x["recall"], default=None,
        )
        best_p999 = max(
            [s for s in sweep_results if s["precision"] >= 0.999],
            key=lambda x: x["recall"], default=None,
        )

        sweep_output = {
            "sweep": sweep_results,
            "best_f1": best_f1,
            "best_precision_99": best_p99,
            "best_precision_999": best_p999,
        }
        with open(sweep_path, "w", encoding="utf-8") as f:
            json.dump(sweep_output, f, indent=2)
        log.info("Threshold sweep saved to %s", sweep_path)
        log.info("  Best F1:       t=%.2f → P=%.4f R=%.4f F1=%.4f",
                 best_f1["threshold"], best_f1["precision"],
                 best_f1["recall"], best_f1["f1"])
        if best_p99:
            log.info("  Best P≥99%%:    t=%.2f → P=%.4f R=%.4f",
                     best_p99["threshold"], best_p99["precision"],
                     best_p99["recall"])
        if best_p999:
            log.info("  Best P≥99.9%%:  t=%.2f → P=%.4f R=%.4f",
                     best_p999["threshold"], best_p999["precision"],
                     best_p999["recall"])

    # ---- test ----
    test_metrics = None
    if not args.skip_test:
        log.info("═══ Test evaluation ═══")
        test_metrics = trainer.evaluate(test_dir=TEST_DIR)

    # ---- save results ----
    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    results = {
        "model": {
            "class": model.__class__.__name__,
            "node_feat_dim": 35,
            "metadata_dim": 8,
            "hidden_dim": args.hidden_dim,
            "num_layers": args.num_layers,
            "dropout": args.dropout,
            "total_params": total_params,
        },
        "training": {
            "epochs_run": len(history),
            "best_epoch": trainer.best_epoch,
            "lr": args.lr,
            "batch_size": args.batch_size,
            "train_time_seconds": round(train_time, 1),
            "best_threshold": trainer.best_threshold,
            "monitor": args.monitor,
            "threshold_strategy": args.threshold_strategy,
            "checkpoint_dir": str(args.checkpoint_dir),
            "loss": args.loss,
            "focal_alpha": args.focal_alpha,
            "focal_gamma": args.focal_gamma,
            "label_smoothing": args.label_smoothing,
            "auto_pos_weight": not args.no_auto_pos_weight,
        },
        "checkpoint_metadata": trainer._checkpoint_metadata(),
        "history": history,
    }
    if test_metrics:
        results["test"] = test_metrics.__dict__

    with open(args.results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log.info("Results saved to %s", args.results_path)

    # ---- copy best model to models/ directory ----
    best_ckpt = Path(args.checkpoint_dir) / "best_model.pt"
    if best_ckpt.exists() and args.model_copy_path:
        import shutil
        args.model_copy_path.parent.mkdir(parents=True, exist_ok=True)
        dest = args.model_copy_path
        shutil.copy2(best_ckpt, dest)
        log.info("Best model copied to %s", dest)

    log.info("═══ Done ═══")


if __name__ == "__main__":
    main()
