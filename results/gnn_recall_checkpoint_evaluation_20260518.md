# GNN Recall Experiment Evaluation - 2026-05-18

## Decision

- Promotion decision: not promoted.
- Reason: the experiment checkpoint preserved hybrid precision on the 600-package production-path baseline, but hybrid recall regressed from 0.4800 to 0.4500 and hybrid false negatives increased from 156 to 165.
- Default checkpoint left unchanged: `checkpoints/best_model.pt`.
- Experiment checkpoint location: `checkpoints/experiments/gnn_recall_20260518/best_model.pt`.
- Generated checkpoint and model copy are intentionally not committed because checkpoints are generated artifacts excluded by repo policy.

## Commands

Training command used:

```powershell
$env:PYTHONPATH="C:\Users\gianm\Desktop\Everything\Projects\SupplyGuard\.venv\Lib\site-packages;C:\Users\gianm\Desktop\Everything\Projects\SupplyGuard"; C:\Users\gianm\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe scripts\train.py --epochs 1 --patience 1 --checkpoint-dir checkpoints\experiments\gnn_recall_20260518 --results-path results\gnn_recall_training_20260518.json --model-copy-path models\gnn_recall_20260518.pt --threshold-strategy precision999 --monitor recall_at_999p --device cpu --skip-test
```

Canonical production-path evaluation command used:

```powershell
$env:PYTHONPATH="C:\Users\gianm\Desktop\Everything\Projects\SupplyGuard\.venv\Lib\site-packages;C:\Users\gianm\Desktop\Everything\Projects\SupplyGuard"; C:\Users\gianm\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe scripts\evaluate_production.py --from-existing-eval data\processed\hybrid_real_evaluation_phase1_manifest.json --model-path checkpoints\experiments\gnn_recall_20260518\best_model.pt --output-json results\gnn_recall_eval_20260518.json --output-md results\gnn_recall_eval_20260518.md --device cpu --log-level INFO
```

## Training Run

- Epochs completed: 1
- Training time seconds: 5215.8
- Monitor: `recall_at_999p`
- Threshold strategy: `precision999`
- Chosen validation threshold saved in checkpoint metadata: `0.8780000000000007`
- Loss: `focal` alpha `0.75`, gamma `2.0`, label smoothing `0.05`
- Feature dimensions: node `35`, metadata `8`
- Dataset fingerprint: `a37e735d023a523ea0a25d0bc34b79672fc7c7424b9e191d1f459a08a446c00d`
- Train kept/skipped: 21584 kept, 2457 skipped over node cap
- Val kept/skipped: 4475 kept, 473 skipped over node cap

## Production-Path Comparison

| System | Old Precision | New Precision | Delta P | Old Recall | New Recall | Delta R | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---|---|---|---|
| GNN-only | 0.9065 | 0.7888 | -0.1177 | 0.8400 | 0.8467 | +0.0067 | 252->254 | 26->68 | 48->46 | 274->232 |
| Rules-only | 0.8882 | 0.8882 | +0.0000 | 0.5033 | 0.5033 | +0.0000 | 151->151 | 19->19 | 149->149 | 281->281 |
| Hybrid | 1.0000 | 1.0000 | +0.0000 | 0.4800 | 0.4500 | -0.0300 | 144->135 | 0->0 | 156->165 | 300->300 |

## Coverage

- Old GNN coverage: 100.00%; new GNN coverage: 100.00%
- Old GNN failures: 0; new GNN failures: 0
- Old CPG failure/none count: 0; new CPG failure/none count: 0

## GNN Calibration By Score Bucket

| Score Bucket | Old Total | Old Malicious Rate | New Total | New Malicious Rate | New Avg GNN |
|---|---:|---:|---:|---:|---:|
| [0.00,0.10) | 0 | 0.0000 | 0 | 0.0000 | 0.0000 |
| [0.10,0.20) | 0 | 0.0000 | 0 | 0.0000 | 0.0000 |
| [0.20,0.30) | 0 | 0.0000 | 0 | 0.0000 | 0.0000 |
| [0.30,0.40) | 249 | 0.1165 | 174 | 0.1437 | 0.3779 |
| [0.40,0.50) | 73 | 0.2603 | 104 | 0.2019 | 0.4337 |
| [0.50,0.60) | 35 | 0.6286 | 46 | 0.3043 | 0.5384 |
| [0.60,0.70) | 16 | 0.8125 | 20 | 0.6000 | 0.6504 |
| [0.70,0.80) | 36 | 0.8333 | 38 | 0.8158 | 0.7561 |
| [0.80,0.90) | 57 | 0.9474 | 218 | 0.9037 | 0.8592 |
| [0.90,1.00] | 134 | 0.9925 | 0 | 0.0000 | 0.0000 |

## False Positive / False Negative Deltas

- Hybrid false positives: 0 -> 0 (delta +0)
- Hybrid false negatives: 156 -> 165 (delta +9)
- GNN-only false positives: 26 -> 68 (delta +42)
- GNN-only false negatives: 48 -> 46 (delta -2)

## Notes

- The new GNN learned a slightly higher GNN-only recall on this sample, but it also produced many more GNN-only false positives. Production hybrid logic then withheld more unconfirmed high-GNN packages for review, reducing hard-block recall.
- The experiment is useful evidence that a single CPU epoch with the current loss/config is not sufficient to improve precision-constrained recall.
- Future GNN work should use a longer controlled run, preferably GPU-backed, and compare validation precision-target thresholds before spending another full production-path evaluation pass.
