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

The trained checkpoint is expected at `checkpoints/best_model.pt` by default, or at the path specified by `MODEL_PATH`. Checkpoints and generated graph tensors are intentionally excluded from Git because they are large generated artifacts. The rules engine and tests are designed to remain inspectable without committing the full training corpus.

Submission Notes
----------------

This repository is intended to be packaged as a private, project-local Git repository with `.git/`, `tests/`, `Dockerfile`, and source code at the top level. Generated folders such as `venv/`, `node_modules/`, `data/raw/`, `data/processed/`, `checkpoints/`, and caches should stay out of the submitted Git history unless there is a clear review reason to include them.
