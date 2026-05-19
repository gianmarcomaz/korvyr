"""
Training engine for SupplyGuard GIN classifier.

Provides:
- ``GraphDataset``         — lazy-loading PyG dataset (one ``.pt`` file per graph)
- ``NodeBudgetSampler``    — dynamic batch sampler that caps total nodes per batch
- ``Trainer``              — full training loop with gradient accumulation,
                             OOM recovery, validation, early stopping,
                             checkpointing, LR scheduling, and rich metrics
"""

from __future__ import annotations

import logging
import math
import random
import hashlib
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset as TorchDataset, Sampler
from torch_geometric.loader import DataLoader
from tqdm import tqdm
try:
    from sklearn.metrics import (
        average_precision_score,
        precision_recall_curve,
        roc_auc_score,
        roc_curve,
    )
except ModuleNotFoundError:  # pragma: no cover - depends on local ML env
    average_precision_score = None
    precision_recall_curve = None
    roc_auc_score = None
    roc_curve = None

log = logging.getLogger(__name__)

METADATA_DIM = 8

# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


class GraphDataset(TorchDataset):
    """Lazy-loading dataset that pre-scans node counts for budget batching.

    Graphs with more than *max_nodes* are excluded — these are typically
    minified bundles or vendored code that add noise, not signal.
    """

    def __init__(self, split_dir: str | Path, max_nodes: int = 50_000) -> None:
        self.split_dir = Path(split_dir)
        all_files = sorted(
            self.split_dir.glob("*.pt"),
            key=lambda p: int(p.stem),
        )
        if not all_files:
            raise FileNotFoundError(f"No .pt files found in {split_dir}")

        self.files: list[Path] = []
        self.node_counts: list[int] = []
        self.labels: list[int] = []
        self.feature_dims: set[int] = set()
        self.metadata_dims: set[int] = set()
        self.total_files = len(all_files)
        self.skipped = 0

        for f in tqdm(all_files, desc=f"Scanning {Path(split_dir).name}",
                      unit="graph"):
            data = torch.load(f, map_location="cpu", weights_only=False)
            n = data.num_nodes
            if n < 2 or (max_nodes is not None and n > max_nodes):
                self.skipped += 1
                continue
            self.files.append(f)
            self.node_counts.append(n)
            self.labels.append(int(float(data.y.item())))
            self.feature_dims.add(int(data.x.shape[1]))
            meta = data.metadata
            self.metadata_dims.add(int(meta.shape[-1] if meta.dim() else 1))

        max_n = max(self.node_counts) if self.node_counts else 0
        avg_n = sum(self.node_counts) / len(self.node_counts) if self.node_counts else 0
        log.info("Dataset %s: %d graphs kept (avg %.0f nodes, max %d), "
                 "%d skipped (>%d nodes)",
                 split_dir, len(self.files), avg_n, max_n, self.skipped, max_nodes)
        if self.feature_dims and self.feature_dims != {35}:
            log.warning("Unexpected node feature dims in %s: %s",
                        split_dir, sorted(self.feature_dims))
        if self.metadata_dims and self.metadata_dims != {METADATA_DIM}:
            log.warning("Unexpected metadata dims in %s: %s",
                        split_dir, sorted(self.metadata_dims))

    def __len__(self) -> int:
        return len(self.files)

    def __getitem__(self, idx: int):
        return torch.load(self.files[idx], map_location="cpu", weights_only=False)

    def summary(self) -> dict[str, Any]:
        """Return a compact, checkpoint-safe summary of the loaded split."""
        total = len(self.files)
        malicious = sum(self.labels)
        benign = total - malicious
        node_hash = hashlib.sha256()
        for path, node_count, label in zip(self.files, self.node_counts, self.labels):
            stat = path.stat()
            node_hash.update(str(path.name).encode("utf-8"))
            node_hash.update(str(stat.st_size).encode("ascii"))
            node_hash.update(str(int(stat.st_mtime_ns)).encode("ascii"))
            node_hash.update(str(node_count).encode("ascii"))
            node_hash.update(str(label).encode("ascii"))
        return {
            "total": total,
            "malicious": malicious,
            "benign": benign,
            "raw_files": self.total_files,
            "skipped": self.skipped,
            "avg_nodes": sum(self.node_counts) / max(total, 1),
            "max_nodes": max(self.node_counts) if self.node_counts else 0,
            "feature_dims": sorted(self.feature_dims),
            "metadata_dims": sorted(self.metadata_dims),
            "fingerprint": node_hash.hexdigest(),
        }


# ---------------------------------------------------------------------------
# Focal Loss — handles class imbalance much better than plain BCE
# ---------------------------------------------------------------------------


class FocalLoss(nn.Module):
    """Focal loss for class-imbalanced binary classification.

    Reduces the contribution of easy-to-classify examples so the model
    focuses on hard negatives (benign packages that look suspicious) and
    hard positives (subtle malware).
    """

    def __init__(
        self,
        alpha: float = 0.25,
        gamma: float = 2.0,
        pos_weight: torch.Tensor | None = None,
        label_smoothing: float = 0.0,
    ) -> None:
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.pos_weight = pos_weight
        self.label_smoothing = label_smoothing

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        # Apply label smoothing: hard 0/1 → soft targets
        if self.label_smoothing > 0:
            targets = targets * (1 - self.label_smoothing) + 0.5 * self.label_smoothing

        bce = F.binary_cross_entropy_with_logits(
            logits, targets, reduction="none",
            pos_weight=self.pos_weight,
        )
        probs = torch.sigmoid(logits)
        pt = targets * probs + (1 - targets) * (1 - probs)
        focal_weight = (1 - pt) ** self.gamma
        alpha_t = targets * self.alpha + (1 - targets) * (1 - self.alpha)
        return (alpha_t * focal_weight * bce).mean()


# ---------------------------------------------------------------------------
# Dynamic batch sampler — caps total nodes per batch, not graph count
# ---------------------------------------------------------------------------


class NodeBudgetSampler(Sampler[list[int]]):
    """Yields mini-batch index lists whose total node count stays within
    *max_nodes*.  Guarantees every graph is seen exactly once per epoch.

    Large graphs that alone exceed the budget are yielded as single-element
    batches so no data is ever dropped.
    """

    def __init__(
        self,
        node_counts: list[int],
        max_nodes: int = 30_000,
        shuffle: bool = True,
    ) -> None:
        self.node_counts = node_counts
        self.max_nodes = max_nodes
        self.shuffle = shuffle

    def __iter__(self):
        indices = list(range(len(self.node_counts)))
        if self.shuffle:
            random.shuffle(indices)

        batch: list[int] = []
        budget = 0

        for idx in indices:
            n = self.node_counts[idx]
            if batch and budget + n > self.max_nodes:
                yield batch
                batch = []
                budget = 0
            batch.append(idx)
            budget += n

        if batch:
            yield batch

    def __len__(self) -> int:
        total = 0
        budget = 0
        batches = 1
        for n in self.node_counts:
            if total > 0 and budget + n > self.max_nodes:
                batches += 1
                budget = 0
            budget += n
            total += 1
        return batches


# ---------------------------------------------------------------------------
# Metrics helper
# ---------------------------------------------------------------------------


def _binary_counts(
    labels: list[float],
    preds: list[float],
) -> tuple[int, int, int, int]:
    tp = sum(1 for y, p in zip(labels, preds) if y == 1.0 and p == 1.0)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0.0 and p == 1.0)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1.0 and p == 0.0)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0.0 and p == 0.0)
    return tp, fp, fn, tn


def _binary_metric_values(
    labels: list[float],
    preds: list[float],
) -> tuple[float, float, float, float]:
    tp, fp, fn, tn = _binary_counts(labels, preds)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy = (tp + tn) / max(tp + fp + fn + tn, 1)
    return accuracy, precision, recall, f1


@dataclass
class Metrics:
    loss: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    auc_roc: float = 0.0
    pr_auc: float = 0.0
    fpr_at_95r: float = 0.0
    recall_at_1fpr: float = 0.0
    recall_at_99p: float = 0.0     # recall when precision >= 99%
    recall_at_999p: float = 0.0    # recall when precision >= 99.9%
    threshold_at_999p: float = 1.0 # threshold needed for 99.9% precision
    optimal_threshold: float = 0.5

    def summary(self) -> str:
        return (
            f"loss={self.loss:.4f}  acc={self.accuracy:.4f}  "
            f"P={self.precision:.4f}  R={self.recall:.4f}  "
            f"F1={self.f1:.4f}  AUC={self.auc_roc:.4f}  "
            f"PR-AUC={self.pr_auc:.4f}  FPR@95R={self.fpr_at_95r:.4f}  "
            f"R@99P={self.recall_at_99p:.4f}  R@99.9P={self.recall_at_999p:.4f}"
        )


def _compute_metrics(
    all_labels: list[float],
    all_probs: list[float],
    total_loss: float,
    n_batches: int,
    threshold: float = 0.5,
) -> Metrics:
    preds = [1.0 if p >= threshold else 0.0 for p in all_probs]
    m = Metrics(loss=total_loss / max(n_batches, 1))
    m.accuracy, m.precision, m.recall, m.f1 = _binary_metric_values(
        all_labels, preds,
    )
    m.optimal_threshold = threshold
    try:
        if roc_auc_score is None:
            raise ValueError("sklearn unavailable")
        m.auc_roc = roc_auc_score(all_labels, all_probs)
    except ValueError:
        m.auc_roc = 0.0

    # PR-AUC — more informative than ROC-AUC for imbalanced data
    try:
        if average_precision_score is None:
            raise ValueError("sklearn unavailable")
        m.pr_auc = average_precision_score(all_labels, all_probs)
    except ValueError:
        m.pr_auc = 0.0

    # Operational metrics
    try:
        if roc_curve is None:
            raise ValueError("sklearn unavailable")
        labels_arr = np.array(all_labels)
        probs_arr = np.array(all_probs)
        fpr, tpr, _ = roc_curve(labels_arr, probs_arr)
        # FPR when recall >= 95%
        idx_95 = np.searchsorted(tpr, 0.95)
        m.fpr_at_95r = float(fpr[min(idx_95, len(fpr) - 1)])
        # Recall when FPR <= 1%
        idx_1fpr = np.searchsorted(fpr, 0.01)
        m.recall_at_1fpr = float(tpr[min(idx_1fpr, len(tpr) - 1)])
    except (ValueError, IndexError):
        m.fpr_at_95r = 1.0
        m.recall_at_1fpr = 0.0

    # Recall at precision targets (critical for cybersecurity)
    try:
        if precision_recall_curve is None:
            raise ValueError("sklearn unavailable")
        prec_arr, rec_arr, thresh_arr = precision_recall_curve(
            labels_arr, probs_arr,
        )
        # Recall @ 99% precision
        mask_99 = prec_arr >= 0.99
        if mask_99.any():
            m.recall_at_99p = float(rec_arr[mask_99].max())
        # Recall @ 99.9% precision
        mask_999 = prec_arr >= 0.999
        if mask_999.any():
            m.recall_at_999p = float(rec_arr[mask_999].max())
            # Find the threshold that achieves 99.9% precision
            best_idx = np.where(mask_999)[0][np.argmax(rec_arr[mask_999])]
            if best_idx < len(thresh_arr):
                m.threshold_at_999p = float(thresh_arr[best_idx])
    except (ValueError, IndexError):
        pass

    return m


def find_optimal_threshold(
    labels: list[float],
    probs: list[float],
    strategy: str = "f1",
    precision_target: float = 0.999,
) -> float:
    """Find the threshold that maximizes the chosen metric.

    Strategies:
        'f1'           — maximize F1 score
        'recall95'     — highest precision while recall >= 0.95
        'precision999' — maximize recall while precision >= 99.9%
        'precision99'  — maximize recall while precision >= 99%
    """
    best_t, best_score = 0.5, -1.0

    # Use finer granularity and wider range for precision-target strategies
    if strategy.startswith("precision"):
        thresholds = np.arange(0.1, 0.9999, 0.001)
    else:
        thresholds = np.arange(0.1, 0.95, 0.01)

    for t in thresholds:
        preds = [1.0 if p >= t else 0.0 for p in probs]
        _, p, r, f1 = _binary_metric_values(labels, preds)

        if strategy == "f1":
            score = f1
        elif strategy == "recall95":
            if r < 0.95:
                continue
            score = p
        elif strategy == "precision999":
            if p < 0.999:
                continue
            score = r  # maximize recall at this precision
        elif strategy == "precision99":
            if p < 0.99:
                continue
            score = r
        else:
            score = f1

        if score > best_score:
            best_score = score
            best_t = t

    return float(best_t)


def calibrate_temperature(
    labels: list[float],
    logits: list[float],
    lr: float = 0.01,
    max_iter: int = 100,
) -> float:
    """Learn a temperature parameter for Platt scaling.

    Dividing logits by temperature before sigmoid makes the model's
    confidence scores more reliable — critical for high-precision
    operating points.
    """
    labels_t = torch.tensor(labels, dtype=torch.float32)
    logits_t = torch.tensor(logits, dtype=torch.float32)
    temperature = torch.nn.Parameter(torch.ones(1))
    optimizer = torch.optim.LBFGS([temperature], lr=lr, max_iter=max_iter)

    def closure():
        optimizer.zero_grad()
        scaled = logits_t / temperature
        loss = F.binary_cross_entropy_with_logits(scaled, labels_t)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(temperature.item())


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


@dataclass
class TrainerConfig:
    """All hyper-parameters in one place."""
    lr: float = 1e-3
    weight_decay: float = 1e-4
    epochs: int = 50
    batch_size: int = 64
    patience: int = 10
    num_workers: int = 0
    checkpoint_dir: str = "checkpoints"
    monitor: str = "f1"            # early-stopping metric (f1 | auc_roc | loss)
    scheduler: str = "plateau"     # plateau | cosine | none
    max_nodes_per_batch: int = 30_000
    max_nodes_per_graph: int = 50_000
    accum_steps: int = 4           # gradient accumulation steps
    use_focal_loss: bool = True    # focal loss instead of BCE
    focal_alpha: float = 0.75      # focal loss alpha (upweight malicious class)
    focal_gamma: float = 2.0       # focal loss gamma (focusing parameter)
    label_smoothing: float = 0.05  # smooth labels to handle noisy data
    auto_pos_weight: bool = True   # auto-compute pos_weight from data
    threshold_strategy: str = "f1" # threshold tuning: f1 | recall95


class Trainer:
    """Encapsulates the full training lifecycle."""

    def __init__(
        self,
        model: nn.Module,
        cfg: TrainerConfig | None = None,
        device: torch.device | str = "cpu",
    ) -> None:
        self.cfg = cfg or TrainerConfig()
        self.device = torch.device(device)
        self.model = model.to(self.device)

        # Loss function — set up after seeing data (pos_weight computed in fit)
        self._pos_weight: torch.Tensor | None = None
        self.criterion = self._build_criterion()

        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.cfg.lr,
            weight_decay=self.cfg.weight_decay,
        )

        self.best_threshold = 0.5  # updated by threshold tuning

        if self.cfg.scheduler == "plateau":
            self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer, mode="max", factor=0.5, patience=3,
            )
        elif self.cfg.scheduler == "cosine":
            self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
                self.optimizer, T_max=self.cfg.epochs,
            )
        else:
            self.scheduler = None

        self.ckpt_dir = Path(self.cfg.checkpoint_dir)
        self.ckpt_dir.mkdir(parents=True, exist_ok=True)

        self.best_metric = -float("inf") if self.cfg.monitor != "loss" else float("inf")
        self.wait = 0
        self.best_epoch = 0
        self._val_labels: list[float] = []
        self._val_probs: list[float] = []
        self.history: list[dict] = []
        self.dataset_summary: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Loss function builder
    # ------------------------------------------------------------------

    def _build_criterion(self) -> nn.Module:
        if self.cfg.use_focal_loss:
            return FocalLoss(
                alpha=self.cfg.focal_alpha,
                gamma=self.cfg.focal_gamma,
                pos_weight=self._pos_weight,
                label_smoothing=self.cfg.label_smoothing,
            )
        else:
            return nn.BCEWithLogitsLoss(
                pos_weight=self._pos_weight,
            )

    def _compute_pos_weight(self, ds: GraphDataset) -> None:
        """Compute pos_weight from dataset label distribution."""
        if not self.cfg.auto_pos_weight:
            return
        n_pos = 0
        n_neg = 0
        for i in range(min(len(ds), 2000)):  # sample to avoid full scan
            data = ds[i]
            if data.y.item() == 1.0:
                n_pos += 1
            else:
                n_neg += 1
        if n_pos > 0 and n_neg > 0:
            weight = n_neg / n_pos
            self._pos_weight = torch.tensor([weight], device=self.device)
            log.info("Auto pos_weight: %.3f (from %d pos, %d neg samples)",
                     weight, n_pos, n_neg)
            self.criterion = self._build_criterion()

    # ------------------------------------------------------------------
    # Build a DataLoader with node-budget batching
    # ------------------------------------------------------------------

    def _make_loader(self, ds: GraphDataset, shuffle: bool) -> DataLoader:
        sampler = NodeBudgetSampler(
            ds.node_counts,
            max_nodes=self.cfg.max_nodes_per_batch,
            shuffle=shuffle,
        )
        return DataLoader(
            ds,
            batch_sampler=sampler,
            num_workers=self.cfg.num_workers,
        )

    # ------------------------------------------------------------------
    # Forward pass helper (with OOM recovery)
    # ------------------------------------------------------------------

    def _forward_batch(self, batch):
        """Run forward pass on *batch*. Returns ``(logits, loss)``."""
        batch = batch.to(self.device)

        meta = batch.metadata
        if meta.dim() == 1:
            meta = meta.view(-1, METADATA_DIM)

        logits = self.model(
            x=batch.x,
            edge_index=batch.edge_index,
            edge_type=batch.edge_type,
            metadata=meta,
            batch=batch.batch,
        )
        loss = self.criterion(logits, batch.y)
        return logits, loss

    # ------------------------------------------------------------------
    # Single epoch
    # ------------------------------------------------------------------

    def _run_epoch(self, loader: DataLoader, train: bool) -> tuple[Metrics, list[float], list[float]]:
        if train:
            self.model.train()
        else:
            self.model.eval()

        total_loss = 0.0
        n_batches = 0
        all_labels: list[float] = []
        all_probs: list[float] = []
        oom_skips = 0

        accum = self.cfg.accum_steps if train else 1
        if train:
            self.optimizer.zero_grad()

        ctx = torch.no_grad() if not train else _nullctx()
        phase = "Train" if train else "Val"

        with ctx:
            pbar = tqdm(loader, desc=phase, unit="batch", leave=False)
            for step, batch in enumerate(pbar):
                try:
                    logits, loss = self._forward_batch(batch)

                    if train:
                        (loss / accum).backward()
                        if (step + 1) % accum == 0 or (step + 1) == len(loader):
                            torch.nn.utils.clip_grad_norm_(
                                self.model.parameters(), 1.0)
                            self.optimizer.step()
                            self.optimizer.zero_grad()

                except torch.cuda.OutOfMemoryError:
                    oom_skips += 1
                    if train:
                        self.optimizer.zero_grad()
                    torch.cuda.empty_cache()
                    pbar.set_postfix(OOM=oom_skips)
                    continue

                total_loss += loss.item()
                n_batches += 1

                probs = torch.sigmoid(logits).detach().cpu().tolist()
                labels = batch.y.cpu().tolist()
                if isinstance(probs, float):
                    probs = [probs]
                    labels = [labels]
                all_probs.extend(probs)
                all_labels.extend(labels)

                if n_batches % 50 == 0:
                    avg_loss = total_loss / n_batches
                    pbar.set_postfix(loss=f"{avg_loss:.4f}")

        if oom_skips:
            log.warning("Epoch had %d OOM-skipped batches", oom_skips)

        metrics = _compute_metrics(all_labels, all_probs, total_loss, n_batches)
        return metrics, all_labels, all_probs

    # ------------------------------------------------------------------
    # Full training loop
    # ------------------------------------------------------------------

    def fit(
        self,
        train_dir: str | Path,
        val_dir: str | Path,
        start_epoch: int = 1,
    ) -> list[dict]:
        """Train the model and return per-epoch history."""

        train_ds = GraphDataset(train_dir, max_nodes=self.cfg.max_nodes_per_graph)
        val_ds = GraphDataset(val_dir, max_nodes=self.cfg.max_nodes_per_graph)
        self.dataset_summary = {
            "train": train_ds.summary(),
            "val": val_ds.summary(),
        }

        # Compute class weight from training data
        self._compute_pos_weight(train_ds)

        train_loader = self._make_loader(train_ds, shuffle=True)
        val_loader = self._make_loader(val_ds, shuffle=False)

        log.info("Train: %d graphs, Val: %d graphs", len(train_ds), len(val_ds))
        log.info("Batches/epoch: ~%d train, ~%d val",
                 len(train_loader), len(val_loader))
        log.info("Config: %s", self.cfg)

        for epoch in range(start_epoch, self.cfg.epochs + 1):
            t0 = time.perf_counter()

            train_m, _, _ = self._run_epoch(train_loader, train=True)
            val_m, val_labels, val_probs = self._run_epoch(val_loader, train=False)

            elapsed = time.perf_counter() - t0
            lr = self.optimizer.param_groups[0]["lr"]

            log.info(
                "Epoch %3d/%d  (%.1fs, lr=%.1e)  "
                "train: %s  |  val: %s",
                epoch, self.cfg.epochs, elapsed, lr,
                train_m.summary(), val_m.summary(),
            )

            # LR scheduling
            if isinstance(self.scheduler, torch.optim.lr_scheduler.ReduceLROnPlateau):
                self.scheduler.step(val_m.f1)
            elif self.scheduler is not None:
                self.scheduler.step()

            # Early stopping + checkpointing
            current = self._get_monitored(val_m)
            improved = self._is_better(current)

            if improved:
                self.best_metric = current
                self.best_epoch = epoch
                self.wait = 0
                self._val_labels = val_labels
                self._val_probs = val_probs
                self._save_checkpoint(epoch, val_m)
                log.info("  ↑ new best %s=%.4f — saved checkpoint",
                         self.cfg.monitor, current)
            else:
                self.wait += 1
                if self.wait >= self.cfg.patience:
                    log.info("Early stopping at epoch %d (patience=%d)",
                             epoch, self.cfg.patience)
                    break

            # Periodic checkpoint every 5 epochs
            if epoch % 5 == 0:
                periodic_path = self.ckpt_dir / f"checkpoint_epoch_{epoch}.pt"
                state = {
                    "epoch": epoch,
                    "model_state_dict": self.model.state_dict(),
                    "optimizer_state_dict": self.optimizer.state_dict(),
                    "val_metrics": val_m.__dict__,
                    "threshold_strategy": self.cfg.threshold_strategy,
                    "checkpoint_metadata": self._checkpoint_metadata(),
                }
                torch.save(state, periodic_path)
                log.info("  Periodic checkpoint saved: %s", periodic_path)

            self.history.append({
                "epoch": epoch,
                "lr": lr,
                "train": train_m.__dict__,
                "val": val_m.__dict__,
            })

        # Tune threshold on best validation predictions
        if self._val_labels:
            self.best_threshold = find_optimal_threshold(
                self._val_labels, self._val_probs,
                strategy=self.cfg.threshold_strategy,
            )
            log.info("Optimal threshold (strategy=%s): %.3f",
                     self.cfg.threshold_strategy, self.best_threshold)

            # Re-save checkpoint with tuned threshold
            best_path = self.ckpt_dir / "best_model.pt"
            if best_path.exists():
                state = torch.load(best_path, map_location=self.device, weights_only=False)
                state["best_threshold"] = self.best_threshold
                state["threshold_strategy"] = self.cfg.threshold_strategy
                state["checkpoint_metadata"] = self._checkpoint_metadata()
                torch.save(state, best_path)

        log.info("Best epoch: %d  best %s: %.4f",
                 self.best_epoch, self.cfg.monitor, self.best_metric)
        return self.history

    # ------------------------------------------------------------------
    # Test evaluation
    # ------------------------------------------------------------------

    def evaluate(self, test_dir: str | Path) -> Metrics:
        """Load best checkpoint and evaluate on the test set."""
        best_path = self.ckpt_dir / "best_model.pt"
        if best_path.exists():
            state = torch.load(best_path, map_location=self.device, weights_only=False)
            self.model.load_state_dict(state["model_state_dict"])
            self.best_threshold = state.get("best_threshold", 0.5)
            if "checkpoint_metadata" in state:
                log.info("Checkpoint metadata: %s", state["checkpoint_metadata"])
            log.info("Loaded best checkpoint from epoch %d (threshold=%.3f)",
                     state.get("epoch", "?"), self.best_threshold)

        test_ds = GraphDataset(test_dir, max_nodes=self.cfg.max_nodes_per_graph)
        test_loader = self._make_loader(test_ds, shuffle=False)

        metrics, _, _ = self._run_epoch(test_loader, train=False)
        log.info("Test results (threshold=%.3f): %s",
                 self.best_threshold, metrics.summary())

        # Also show results at tuned threshold
        if self.best_threshold != 0.5:
            test_labels: list[float] = []
            test_probs: list[float] = []
            self.model.eval()
            with torch.no_grad():
                for batch in test_loader:
                    logits, _ = self._forward_batch(batch)
                    test_probs.extend(torch.sigmoid(logits).cpu().tolist())
                    test_labels.extend(batch.y.cpu().tolist())
            tuned_m = _compute_metrics(
                test_labels, test_probs, metrics.loss, 1,
                threshold=self.best_threshold,
            )
            log.info("Test @ tuned threshold=%.3f: %s",
                     self.best_threshold, tuned_m.summary())

        return metrics

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_monitored(self, m: Metrics) -> float:
        return getattr(m, self.cfg.monitor)

    def _is_better(self, current: float) -> bool:
        if self.cfg.monitor == "loss":
            return current < self.best_metric
        return current > self.best_metric

    def _save_checkpoint(self, epoch: int, val_metrics: Metrics) -> None:
        state = {
            "epoch": epoch,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "val_metrics": val_metrics.__dict__,
            "best_metric": self.best_metric,
            "best_threshold": self.best_threshold,
            "threshold_strategy": self.cfg.threshold_strategy,
            "wait": self.wait,
            "history": self.history,
            "checkpoint_metadata": self._checkpoint_metadata(),
        }
        if self.scheduler is not None:
            state["scheduler_state_dict"] = self.scheduler.state_dict()
        torch.save(state, self.ckpt_dir / "best_model.pt")

    def _checkpoint_metadata(self) -> dict[str, Any]:
        """Metadata needed to audit checkpoint compatibility and provenance."""
        model = self.model
        split_fingerprints = {
            name: summary.get("fingerprint", "")
            for name, summary in self.dataset_summary.items()
        }
        dataset_hash = hashlib.sha256(
            repr(sorted(split_fingerprints.items())).encode("utf-8")
        ).hexdigest()
        return {
            "model": {
                "class": model.__class__.__name__,
                "node_feat_dim": int(getattr(model, "node_feat_dim", 35)),
                "metadata_dim": int(getattr(model, "metadata_dim", METADATA_DIM)),
                "hidden_dim": int(getattr(model, "hidden_dim", 128)),
                "num_gin_layers": int(getattr(model, "num_gin_layers", 4)),
                "num_edge_types": int(getattr(model, "num_edge_types", 4)),
                "dropout": float(getattr(model, "dropout", 0.0)),
            },
            "training_config": asdict(self.cfg),
            "dataset": {
                "splits": self.dataset_summary,
                "fingerprint": dataset_hash,
            },
            "threshold": {
                "strategy": self.cfg.threshold_strategy,
                "chosen": self.best_threshold,
            },
        }

    def load_checkpoint(self) -> int:
        """Restore from checkpoint. Returns the epoch to resume from (next epoch)."""
        ckpt_path = self.ckpt_dir / "best_model.pt"
        if not ckpt_path.exists():
            log.warning("No checkpoint found at %s — starting from scratch", ckpt_path)
            return 1

        state = torch.load(ckpt_path, map_location=self.device, weights_only=False)
        self.model.load_state_dict(state["model_state_dict"])
        self.optimizer.load_state_dict(state["optimizer_state_dict"])
        if self.scheduler is not None and "scheduler_state_dict" in state:
            self.scheduler.load_state_dict(state["scheduler_state_dict"])

        self.best_metric = state.get("best_metric", self.best_metric)
        self.best_epoch = state.get("epoch", 0)
        self.wait = state.get("wait", 0)
        self.history = state.get("history", [])

        resume_epoch = state["epoch"] + 1
        log.info("Resumed from checkpoint — epoch %d, best %s=%.4f",
                 state["epoch"], self.cfg.monitor, self.best_metric)
        return resume_epoch


class _nullctx:
    """No-op context manager for the training branch."""
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
