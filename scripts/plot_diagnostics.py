"""Plot GNN diagnostics produced by ``scripts/diagnose_recall.py``.

Requires the ``research`` extra (matplotlib):

    pip install -e ".[research]"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from korvyr.evaluation.reporting import compute_binary_metrics
from korvyr.scanner.scan_pipeline import ThresholdConfig

ROOT = Path(__file__).resolve().parent.parent
DIAGNOSTICS_DIR = ROOT / "data" / "diagnostics"
INPUT_JSON = DIAGNOSTICS_DIR / "phase1_diagnostic.json"


def _load_records() -> list[dict]:
    if not INPUT_JSON.exists():
        raise SystemExit(f"Missing {INPUT_JSON}. Run `python scripts/diagnose_recall.py` first.")
    return json.loads(INPUT_JSON.read_text(encoding="utf-8"))


def _metrics_at_threshold(records: list[dict], threshold: float) -> tuple[float, float]:
    """GNN-only precision/recall at *threshold*, counting errors as negatives."""
    labels = [int(record["true_label"]) for record in records]
    predictions = [
        1 if float(record["gnn_score"]) >= threshold and float(record["gnn_score"]) >= 0 else 0
        for record in records
    ]
    metrics = compute_binary_metrics(predictions, labels)
    return float(metrics["precision"]), float(metrics["recall"])


def main() -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "matplotlib is required for diagnostics plots. "
            'Install it with: pip install -e ".[research]"'
        ) from exc

    records = _load_records()
    cfg = ThresholdConfig()
    DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
    malicious = [
        float(r["gnn_score"])
        for r in records
        if int(r["true_label"]) == 1 and float(r["gnn_score"]) >= 0
    ]
    benign = [
        float(r["gnn_score"])
        for r in records
        if int(r["true_label"]) == 0 and float(r["gnn_score"]) >= 0
    ]
    error_count = sum(1 for r in records if float(r["gnn_score"]) < 0)

    plt.figure(figsize=(10, 6))
    plt.hist(benign, bins=50, range=(0.0, 1.0), alpha=0.55, color="blue", label="Benign")
    plt.hist(malicious, bins=50, range=(0.0, 1.0), alpha=0.55, color="red", label="Malicious")
    plt.axvline(
        cfg.gnn_auto_pass,
        color="black",
        linestyle="--",
        label=f"auto_pass={cfg.gnn_auto_pass:.2f}",
    )
    plt.axvline(
        cfg.gnn_auto_block,
        color="green",
        linestyle="--",
        label=f"auto_block={cfg.gnn_auto_block:.2f}",
    )
    title = "GNN Score Distribution"
    if error_count:
        title += f" ({error_count} GNN errors excluded)"
    plt.title(title)
    plt.xlabel("GNN score")
    plt.ylabel("Package count")
    plt.legend()
    plt.tight_layout()
    hist_path = DIAGNOSTICS_DIR / "gnn_score_histogram.png"
    plt.savefig(hist_path, dpi=150)
    plt.close()

    thresholds = [round(0.10 + i * 0.01, 2) for i in range(86)]
    precision = []
    recall = []
    for threshold in thresholds:
        p, r = _metrics_at_threshold(records, threshold)
        precision.append(p)
        recall.append(r)

    plt.figure(figsize=(10, 6))
    plt.plot(thresholds, precision, label="Precision", color="blue")
    plt.plot(thresholds, recall, label="Recall", color="red")
    plt.title("GNN-Only Precision-Recall vs Threshold")
    plt.xlabel("GNN block threshold")
    plt.ylabel("Metric")
    plt.ylim(0.0, 1.05)
    plt.legend()
    plt.tight_layout()
    pr_path = DIAGNOSTICS_DIR / "precision_recall_curve.png"
    plt.savefig(pr_path, dpi=150)
    plt.close()

    print(f"Saved {hist_path}")
    print(f"Saved {pr_path}")


if __name__ == "__main__":
    main()
