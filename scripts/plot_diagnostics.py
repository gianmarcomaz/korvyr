"""Plot Phase 1 GNN diagnostics from data/diagnostics/phase1_diagnostic.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.scanner.scan_pipeline import ThresholdConfig

ROOT = Path(__file__).resolve().parent.parent
DIAGNOSTICS_DIR = ROOT / "data" / "diagnostics"
INPUT_JSON = DIAGNOSTICS_DIR / "phase1_diagnostic.json"


def _load_records() -> list[dict]:
    if not INPUT_JSON.exists():
        raise SystemExit(
            f"Missing {INPUT_JSON}. Run `python scripts/diagnose_recall.py` first."
        )
    return json.loads(INPUT_JSON.read_text(encoding="utf-8"))


def _metrics_at_threshold(records: list[dict], threshold: float) -> tuple[float, float]:
    tp = fp = fn = 0
    for record in records:
        label = int(record["true_label"])
        score = float(record["gnn_score"])
        pred = score >= threshold if score >= 0 else False
        if pred and label == 1:
            tp += 1
        elif pred and label == 0:
            fp += 1
        elif not pred and label == 1:
            fn += 1
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return precision, recall


def main() -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ModuleNotFoundError as exc:
        print(
            "matplotlib is not installed; using Pillow fallback to create PNG "
            "diagnostic artifacts."
        )
        _plot_with_pillow(_load_records())
        return

    records = _load_records()
    cfg = ThresholdConfig()
    DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
    malicious = [
        float(r["gnn_score"]) for r in records
        if int(r["true_label"]) == 1 and float(r["gnn_score"]) >= 0
    ]
    benign = [
        float(r["gnn_score"]) for r in records
        if int(r["true_label"]) == 0 and float(r["gnn_score"]) >= 0
    ]
    error_count = sum(1 for r in records if float(r["gnn_score"]) < 0)

    plt.figure(figsize=(10, 6))
    plt.hist(benign, bins=50, range=(0.0, 1.0), alpha=0.55, color="blue", label="Benign")
    plt.hist(malicious, bins=50, range=(0.0, 1.0), alpha=0.55, color="red", label="Malicious")
    plt.axvline(cfg.gnn_auto_pass, color="black", linestyle="--", label=f"auto_pass={cfg.gnn_auto_pass:.2f}")
    plt.axvline(cfg.gnn_auto_block, color="green", linestyle="--", label=f"auto_block={cfg.gnn_auto_block:.2f}")
    title = "GNN Score Distribution - Current Model"
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
    plt.axhline(0.89, color="red", linestyle="--", label="recall=0.89")
    plt.axhline(0.999, color="blue", linestyle="--", label="precision=0.999")
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


def _plot_with_pillow(records: list[dict]) -> None:
    """Fallback PNG generation when matplotlib is unavailable locally."""
    from PIL import Image, ImageDraw, ImageFont

    cfg = ThresholdConfig()
    DIAGNOSTICS_DIR.mkdir(parents=True, exist_ok=True)
    width, height = 1000, 640
    margin = 80
    plot_w = width - 2 * margin
    plot_h = height - 2 * margin
    font = ImageFont.load_default()

    def canvas(title: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
        img = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(img)
        draw.text((margin, 25), title, fill="black", font=font)
        draw.line((margin, height - margin, width - margin, height - margin), fill="black")
        draw.line((margin, margin, margin, height - margin), fill="black")
        return img, draw

    malicious = [
        float(r["gnn_score"]) for r in records
        if int(r["true_label"]) == 1 and float(r["gnn_score"]) >= 0
    ]
    benign = [
        float(r["gnn_score"]) for r in records
        if int(r["true_label"]) == 0 and float(r["gnn_score"]) >= 0
    ]
    errors = sum(1 for r in records if float(r["gnn_score"]) < 0)

    img, draw = canvas(
        f"GNN Score Distribution - Current Model ({errors} GNN errors excluded)"
    )
    bins = 50
    mal_counts = [0] * bins
    ben_counts = [0] * bins
    for score in malicious:
        mal_counts[min(int(score * bins), bins - 1)] += 1
    for score in benign:
        ben_counts[min(int(score * bins), bins - 1)] += 1
    max_count = max(mal_counts + ben_counts + [1])
    bar_w = plot_w / bins
    for i in range(bins):
        x0 = margin + i * bar_w
        x1 = margin + (i + 1) * bar_w - 1
        ben_h = ben_counts[i] / max_count * plot_h
        mal_h = mal_counts[i] / max_count * plot_h
        draw.rectangle((x0, height - margin - ben_h, x1, height - margin), fill=(80, 140, 220))
        draw.rectangle((x0, height - margin - mal_h, x1, height - margin), outline=(220, 70, 70), width=2)
    for value, color, label in (
        (cfg.gnn_auto_pass, "black", f"auto_pass={cfg.gnn_auto_pass:.2f}"),
        (cfg.gnn_auto_block, "green", f"auto_block={cfg.gnn_auto_block:.2f}"),
    ):
        x = margin + value * plot_w
        draw.line((x, margin, x, height - margin), fill=color, width=2)
        draw.text((x + 4, margin + 10), label, fill=color, font=font)
    draw.text((margin, height - 45), "GNN score", fill="black", font=font)
    draw.text((width - margin - 170, 50), "Blue=benign, red outline=malicious", fill="black", font=font)
    hist_path = DIAGNOSTICS_DIR / "gnn_score_histogram.png"
    img.save(hist_path)

    thresholds = [round(0.10 + i * 0.01, 2) for i in range(86)]
    precision = []
    recall = []
    for threshold in thresholds:
        p, r = _metrics_at_threshold(records, threshold)
        precision.append(p)
        recall.append(r)

    img, draw = canvas("GNN-Only Precision-Recall vs Threshold")

    def to_xy(idx: int, value: float) -> tuple[float, float]:
        x = margin + (thresholds[idx] - thresholds[0]) / (thresholds[-1] - thresholds[0]) * plot_w
        y = height - margin - value * plot_h
        return x, y

    for series, color in ((precision, (80, 140, 220)), (recall, (220, 70, 70))):
        points = [to_xy(i, value) for i, value in enumerate(series)]
        draw.line(points, fill=color, width=3)
    for value, color, label in (
        (0.89, (220, 70, 70), "recall=0.89"),
        (0.999, (80, 140, 220), "precision=0.999"),
    ):
        y = height - margin - value * plot_h
        draw.line((margin, y, width - margin, y), fill=color, width=1)
        draw.text((width - margin - 120, y - 14), label, fill=color, font=font)
    draw.text((width - margin - 160, 50), "Blue=precision, red=recall", fill="black", font=font)
    draw.text((margin, height - 45), "GNN block threshold", fill="black", font=font)
    pr_path = DIAGNOSTICS_DIR / "precision_recall_curve.png"
    img.save(pr_path)

    print(f"Saved {hist_path}")
    print(f"Saved {pr_path}")


if __name__ == "__main__":
    main()
