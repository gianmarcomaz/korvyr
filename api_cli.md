# Prompt: Build the FastAPI Scanning Server + CLI

We're done tuning model accuracy for now. The hybrid pipeline works (98.88% precision, 58.7% recall at AB=0.65). Time to build the product surface — the API server and CLI that let people actually use this thing.

Two pieces to build, in order.

---

## Piece 1: FastAPI Scanning Server — `supplyguard/api/server.py`

This is the backend that everything else calls. It accepts a package tarball (or a package name + version), runs the full hybrid scanning pipeline, and returns the verdict with evidence.

### Setup

- Use FastAPI with uvicorn
- Load the trained model checkpoint once at startup into memory (not per-request)
- Auto-detect device: CUDA if available, otherwise CPU
- Store the ThresholdConfig as server-side defaults that can be overridden per-request

### Endpoints

**1. `POST /scan/tarball`**

Accepts a multipart file upload of a `.tgz` package tarball. This is the primary scanning endpoint.

Flow:
```
1. Receive uploaded tarball
2. Extract to a temp directory
3. Run the full hybrid pipeline:
   a. Build CPG from extracted source (cpg_builder.build_cpg)
   b. Run GNN inference on the CPG graph
   c. Run rules_engine.run_rules on the raw source
   d. Apply hybrid decision logic (scan_pipeline.scan_package)
4. Clean up temp directory
5. Return ScanResult as JSON
```

Request: multipart form with file field `tarball`
Response:
```json
{
  "package_name": "evil-pkg",
  "version": "1.0.0",
  "verdict": "malicious",
  "confidence": 0.94,
  "gnn_score": 0.87,
  "decision_path": "GNN high confidence (0.87) + CRITICAL rule match: CRIT_INSTALL_HOOK_NETWORK",
  "rules_matched": [
    {
      "rule_id": "CRIT_INSTALL_HOOK_NETWORK",
      "severity": "critical",
      "description": "Postinstall hook makes network request to non-registry domain",
      "file_path": "install.js",
      "line_number": 47,
      "matched_snippet": "https.get('https://webhook.site/abc123'..."
    }
  ],
  "evidence": [
    "postinstall hook decodes base64 payload (install.js:47)",
    "decoded content passed to eval() (install.js:49)",
    "outbound HTTP request to non-registry domain (install.js:52)"
  ],
  "scan_time_ms": 2340
}
```

**2. `POST /scan/package`**

Accepts a JSON body with `name` and `version`. The server downloads the tarball from the npm registry itself, then runs the same pipeline as `/scan/tarball`.

Request:
```json
{
  "name": "axios",
  "version": "1.14.1"
}
```

Flow:
```
1. Download tarball from https://registry.npmjs.org/{name}/-/{name}-{version}.tgz
2. Save to temp directory
3. Run the same pipeline as /scan/tarball
4. Clean up and return ScanResult
```

Handle scoped packages: `@scope/package` downloads from `https://registry.npmjs.org/@scope%2fpackage/-/package-{version}.tgz`

**3. `POST /scan/lockfile`**

Accepts a `package-lock.json` file upload. Extracts all dependencies with their versions and scans each one. This is what the CLI will call.

Request: multipart form with file field `lockfile`
Response:
```json
{
  "total_packages": 847,
  "scan_time_seconds": 42.3,
  "results": {
    "clean": 844,
    "suspicious": 2,
    "malicious": 1
  },
  "flagged_packages": [
    {
      "package_name": "plain-crypto-js",
      "version": "4.2.1",
      "verdict": "malicious",
      "confidence": 0.94,
      "gnn_score": 0.87,
      "decision_path": "...",
      "rules_matched": [...],
      "evidence": [...]
    },
    {
      "package_name": "fast-utils",
      "version": "1.0.3",
      "verdict": "suspicious",
      "confidence": 0.62,
      "gnn_score": 0.55,
      "decision_path": "...",
      "rules_matched": [...],
      "evidence": [...]
    }
  ]
}
```

Important: Don't scan all 847 packages sequentially — that would take forever. Instead:
- Use a thread pool (concurrent.futures.ThreadPoolExecutor) with max_workers=4 (limited by CPU for GNN inference)
- Add a simple in-memory cache (dictionary keyed by `name@version`) so if the same package appears in multiple lockfiles, it's only scanned once per server session
- For the MVP, download + scan packages sequentially within the thread pool. We'll add Redis caching later.

**4. `GET /health`**

Returns server status, model loaded status, and device info.
```json
{
  "status": "healthy",
  "model_loaded": true,
  "device": "cpu",
  "model_checkpoint": "best_model.pt",
  "threshold_config": {
    "gnn_auto_pass": 0.25,
    "gnn_auto_block": 0.65
  }
}
```

### Error Handling

- If the tarball can't be extracted: return 400 with `{"error": "Invalid tarball format"}`
- If the package doesn't exist on npm: return 404 with `{"error": "Package not found on npm registry"}`
- If CPG building fails for a package: fall back to rules-only mode for that package and include `"fallback": "rules_only"` in the response
- If rules engine fails: fall back to GNN-only mode and include `"fallback": "gnn_only"` in the response
- If both fail: return the package as `"verdict": "error"` with the error message. Never crash the server.
- All errors should be logged but should never crash the server process

### Server Configuration

```python
# Environment variables
PORT = int(os.getenv("PORT", 8000))
MODEL_PATH = os.getenv("MODEL_PATH", "checkpoints/best_model.pt")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 4))
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB max tarball size

# CORS — allow all origins for MVP
# Rate limiting — skip for MVP, add later
```

### Startup

```python
@app.on_event("startup")
async def load_model():
    # Load model checkpoint into memory
    # Log device, model size, threshold config
    # Verify model can do inference on a dummy tensor (sanity check)
```

Run with: `uvicorn supplyguard.api.server:app --host 0.0.0.0 --port 8000`

---

## Piece 2: CLI Tool — `supplyguard/cli/main.py`

A command-line tool that developers run in their terminal. It talks to the FastAPI server. Keep it simple.

### Installation

The CLI should be installable via pip. Set up the entry point in `setup.py` or `pyproject.toml` so that after `pip install supplyguard`, the user can just type `supplyguard` in their terminal.

Entry point: `supplyguard.cli.main:cli`

### Commands

**1. `supplyguard audit`**

Scans all dependencies in the current project by reading `package-lock.json` from the current directory.

```bash
$ supplyguard audit

  SupplyGuard — Scanning dependencies...

  Reading package-lock.json... 847 packages found.
  Scanning ━━━━━━━━━━━━━━━━━━━━ 100% 847/847 [00:42]

  Results:
  ✓ 844 packages clean
  ⚠ 2 packages suspicious
  ✗ 1 package malicious

  ✗ plain-crypto-js@4.2.1  [MALICIOUS — confidence: 0.94]
    Evidence:
    → postinstall hook decodes base64 payload (install.js:47)
    → decoded content passed to eval() (install.js:49)
    → outbound HTTP request to non-registry domain (install.js:52)
    Decision: GNN high confidence (0.87) + CRITICAL rule: CRIT_INSTALL_HOOK_NETWORK

  ⚠ fast-utils@1.0.3  [SUSPICIOUS — confidence: 0.62]
    Evidence:
    → new maintainer pattern detected
    → name similar to popular package "fastify-utils"

  ⚠ node-helpers@2.1.0  [SUSPICIOUS — confidence: 0.55]
    Evidence:
    → postinstall hook present, no clear purpose

  Scan complete in 42.3s
```

Flags:
- `--api-url` — URL of the scanning server (default: `http://localhost:8000`)
- `--json` — output results as JSON (for CI/CD piping)
- `--fail-on [high|medium|any]` — exit with code 1 if packages above this severity are found. `high` = only fail on malicious verdicts. `medium` = fail on suspicious + malicious. `any` = fail on anything flagged.
- `--lockfile PATH` — path to a specific lockfile (default: `./package-lock.json`)
- `--timeout SECONDS` — request timeout (default: 120)

**2. `supplyguard scan <package>@<version>`**

Scans a single package.

```bash
$ supplyguard scan axios@1.14.1

  SupplyGuard — Scanning axios@1.14.1...

  ✓ axios@1.14.1 is clean [confidence: 0.12]
  Scan complete in 2.3s
```

```bash
$ supplyguard scan plain-crypto-js@4.2.1

  SupplyGuard — Scanning plain-crypto-js@4.2.1...

  ✗ plain-crypto-js@4.2.1 is MALICIOUS [confidence: 0.94]
    Evidence:
    → postinstall hook decodes base64 payload (install.js:47)
    → decoded content passed to eval() (install.js:49)
    → outbound HTTP request to non-registry domain (install.js:52)
    Decision: GNN high confidence (0.87) + CRITICAL rule: CRIT_INSTALL_HOOK_NETWORK

  Scan complete in 2.3s
```

Flags: same as `audit` where applicable (`--api-url`, `--json`, `--timeout`)

**3. `supplyguard version`**

Prints the version number.

### CLI Implementation Details

- Use `click` for the CLI framework (pip install click)
- Use `rich` for colored terminal output, progress bars, and the checkmark/warning/X symbols (pip install rich)
- Use `httpx` for HTTP requests to the API server (pip install httpx)
- The CLI is a thin client — it sends the lockfile or package name to the API and displays the results. No ML code, no PyTorch, no tree-sitter. Just HTTP and pretty printing.
- If the API server is unreachable, print a clear error: "Could not connect to SupplyGuard server at {url}. Is the server running? Start it with: uvicorn supplyguard.api.server:app"

### pyproject.toml / setup.py

Set up the package so it's pip-installable:

```toml
[project]
name = "supplyguard"
version = "0.1.0"
description = "Detect malicious npm packages using Graph Neural Networks"
requires-python = ">=3.9"
dependencies = [
    "click>=8.0",
    "rich>=13.0",
    "httpx>=0.24",
]

[project.optional-dependencies]
server = [
    "fastapi>=0.100",
    "uvicorn>=0.20",
    "torch>=2.0",
    "torch-geometric>=2.3",
    "tree-sitter>=0.20",
    "python-multipart>=0.0.6",
]

[project.scripts]
supplyguard = "supplyguard.cli.main:cli"
```

This way, users who just want the CLI install `pip install supplyguard` (lightweight, no PyTorch). Users who want to run the server install `pip install supplyguard[server]` (includes PyTorch and all ML dependencies).

---

## Piece 3: Tests — `tests/test_api.py` and `tests/test_cli.py`

### test_api.py

**Test 1 — Health endpoint**: Start the server, hit `GET /health`, assert model_loaded is True.

**Test 2 — Scan clean package by name**: POST to `/scan/package` with `{"name": "is-number", "version": "7.0.0"}` (a tiny, well-known, clean package). Assert verdict is "clean".

**Test 3 — Scan malicious tarball**: Create a temp tarball with the same malicious package from the rules engine tests (postinstall hook + credential exfiltration). POST it to `/scan/tarball`. Assert verdict is "malicious" and at least one CRITICAL rule is in rules_matched.

**Test 4 — Scan lockfile**: Create a minimal package-lock.json with 3 dependencies (e.g., is-number, is-odd, and one malicious package). POST it to `/scan/lockfile`. Assert total_packages is 3, results.malicious >= 1.

**Test 5 — Invalid tarball**: POST a non-tarball file to `/scan/tarball`. Assert 400 response.

**Test 6 — Package not found**: POST to `/scan/package` with `{"name": "this-package-definitely-does-not-exist-abc123", "version": "1.0.0"}`. Assert 404 response.

### test_cli.py

**Test 1 — Version command**: Run `supplyguard version` via subprocess, assert it prints a version string.

**Test 2 — Audit with no lockfile**: Run `supplyguard audit` in a temp directory with no package-lock.json. Assert it prints an error message about missing lockfile.

**Test 3 — JSON output**: Run `supplyguard scan is-number@7.0.0 --json --api-url http://localhost:8000`. Parse stdout as JSON. Assert it has the expected fields.

Use pytest with the FastAPI TestClient for API tests (no need to actually start the server). For CLI tests, use click's CliRunner.

---

## Important Constraints

- The server must never crash. Every exception should be caught, logged, and returned as a structured error response.
- The CLI has ZERO ML dependencies. It's a thin HTTP client. This is critical — a developer installing the CLI should not have to install PyTorch.
- Don't build authentication, rate limiting, or Redis caching yet. Those come later.
- Don't build a web dashboard or any frontend. The CLI terminal output IS the interface.
- The server should work on both macOS and Linux.
- Keep the tarball download timeout at 30 seconds. If npm registry is slow, fail gracefully.

## File Structure After This Build

```
supplyguard/
├── supplyguard/
│   ├── api/
│   │   └── server.py          ← NEW: FastAPI scanning server
│   ├── cli/
│   │   └── main.py            ← NEW: CLI tool
│   ├── scanner/
│   │   ├── scan_pipeline.py   ← EXISTS: hybrid pipeline
│   │   └── rules_engine.py    ← EXISTS: behavioral rules
│   ├── model/
│   │   └── gin_classifier.py  ← EXISTS: GNN model
│   ├── parsing/               ← EXISTS: AST/CFG/DFG extractors
│   └── graph/                 ← EXISTS: CPG builder
├── tests/
│   ├── test_api.py            ← NEW
│   └── test_cli.py            ← NEW
├── checkpoints/
│   └── best_model.pt          ← EXISTS: trained model
└── pyproject.toml             ← NEW: package config
```

## Run Order

1. Write all files. Don't run anything yet.
2. I'll review the code.
3. Install dependencies: `pip install fastapi uvicorn python-multipart httpx click rich --break-system-packages`
4. Start the server: `uvicorn supplyguard.api.server:app --host 0.0.0.0 --port 8000`
5. In another terminal, test the CLI: `python -m supplyguard.cli.main scan is-number@7.0.0`
6. Run tests: `python -m pytest tests/test_api.py tests/test_cli.py -v -s`
