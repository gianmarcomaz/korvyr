GNN-npm-Vulnerabilities
=======================

SupplyGuard
===========

SupplyGuard is a local supply-chain security scanner for npm packages. It combines static JavaScript analysis, metadata risk scoring, graph-based package features, and a behavioral rules engine to flag packages that look suspicious or malicious before they are installed.

The project is organized as a Python scanner with a FastAPI service, a Click-based CLI, a Node.js npm proxy, and a small React dashboard for local scan visibility.

What It Does
------------

- Parses npm packages into AST, CFG, DFG, and CPG-style graph features.
- Scores package metadata for typosquatting and suspicious package structure.
- Runs behavioral rules for install hooks, credential exfiltration, obfuscation, DNS exfiltration, dynamic execution, and prototype pollution.
- Combines GNN and rules signals into clean, suspicious, or malicious verdicts.
- Exposes scans through a FastAPI backend, CLI commands, and an npm registry proxy.

Repository Layout
-----------------

- `supplyguard/` - core Python package, scanner, API, model, parsing, graph, and metadata code.
- `tests/` - pytest suite for parser, graph, rules, API, and CLI behavior.
- `scripts/` - dataset, training, evaluation, and diagnostic utilities.
- `proxy/` - npm registry proxy that scans package tarballs before forwarding them.
- `dashboard/` - React dashboard for viewing proxy scan logs.
- `Dockerfile` - backend API container for the scanner service.
- `docker-compose.yml` - local scanner, Redis, and proxy stack.

Quick Start
-----------

Create and activate a virtual environment, then install the server/test dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[server,test]"
```

Run the Python test suite:

```bash
pytest
```

Start the scanner API:

```bash
uvicorn supplyguard.api.server:app --host 0.0.0.0 --port 8000
```

Scan one package through the CLI:

```bash
supplyguard scan is-number@7.0.0
```

Run the Docker stack:

```bash
docker compose up --build
```

Model Artifacts
---------------

The trained checkpoint is expected at `models/gnn_v2_cuda.pt` by default, or at the path specified by `MODEL_PATH`. Checkpoints and generated graph tensors are intentionally excluded from Git because they are large generated artifacts. The rules engine and tests are designed to remain inspectable without committing the full training corpus.

GNN Training And Evaluation
---------------------------

The production-path baseline is measured with:

```bash
python scripts/evaluate_production.py --from-existing-eval data/processed/hybrid_real_evaluation_phase1_manifest.json --model-path models/gnn_v2_cuda.pt --output-json results/baseline_accuracy.json --output-md results/baseline_accuracy.md --device cuda
```

Run GNN retraining as a separate experiment directory so the default checkpoint is not overwritten until the production-path harness proves a precision-constrained recall improvement:

```bash
python scripts/train.py --checkpoint-dir checkpoints/experiments/gnn_recall_run --results-path results/gnn_recall_training.json --sweep-path results/gnn_recall_threshold_sweep.json --model-copy-path models/gnn_recall_run.pt --threshold-strategy precision999 --monitor recall_at_999p --device cpu
python scripts/evaluate_production.py --from-existing-eval data/processed/hybrid_real_evaluation_phase1_manifest.json --model-path checkpoints/experiments/gnn_recall_run/best_model.pt --output-json results/gnn_recall_eval.json --output-md results/gnn_recall_eval.md --device cpu
```

Training checkpoints include node feature dimension, metadata dimension, training configuration, dataset counts/fingerprint, and the selected threshold strategy. Promote a checkpoint to `models/gnn_v2_cuda.pt` only after comparing it with the baseline report and confirming that false positives do not increase beyond the selected product accuracy profile.

Submission Notes
----------------

This repository is intended to be packaged as a private, project-local Git repository with `.git/`, `tests/`, `Dockerfile`, and source code at the top level. Generated folders such as `venv/`, `node_modules/`, `data/raw/`, `data/processed/`, `checkpoints/`, and caches should stay out of the submitted Git history unless there is a clear review reason to include them.
