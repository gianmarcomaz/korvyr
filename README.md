# Korvyr

**Hybrid GNN and static-analysis prototype for pre-install npm package screening.**

[![CI](https://github.com/gianmarcomaz/Korvyr/actions/workflows/ci.yml/badge.svg)](https://github.com/gianmarcomaz/Korvyr/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

Korvyr inspects an npm package *before* it is installed. It parses the package's
JavaScript into a code property graph, scores that graph with a graph
isomorphism network, runs a behavioural rules engine over the raw source and
`package.json`, and combines the two signals into a `clean` / `suspicious` /
`malicious` verdict together with the evidence that produced it.

> [!WARNING]
> **Research prototype.** Korvyr is a research artifact, not a security product.
> It has been measured on a single balanced 600-package development benchmark
> that was also used while tuning its decision policy. It has not been validated
> on a temporal or malware-family holdout, it has no independent evaluation, and
> it will both miss malicious packages and flag benign ones. Do not use it as
> the only control protecting a real installation path. See
> [Known limitations](#known-limitations).

---

## Contents

- [Threat model](#threat-model)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Docker](#docker)
- [Tests and linting](#tests-and-linting)
- [Evaluation and reproducibility](#evaluation-and-reproducibility)
- [Known limitations](#known-limitations)
- [Technical report](#technical-report)
- [Citation](#citation)
- [Security reporting](#security-reporting)
- [License](#license)

---

## Threat model

**What Korvyr is trying to catch.** A developer or CI job is about to run
`npm install`. Some package in the resolved dependency tree is malicious:
either a package published specifically to attack installers (typosquat,
dependency confusion, throwaway credential stealer) or a legitimate package
whose maintainer account was compromised and which now ships a malicious
version. The payload typically runs at install time via a `preinstall` /
`install` / `postinstall` lifecycle hook, or at first `require()`, and tries to
read credentials or system information and send them to an attacker-controlled
endpoint.

**Position in the pipeline.** Korvyr screens the tarball between the registry
and the developer's machine. Nothing from the package is executed: the analysis
is entirely static.

**Attacker capabilities assumed.** The attacker can publish arbitrary packages
to the public registry, choose names close to popular packages, obfuscate their
payload, and hide behaviour behind dynamic constructs (`eval`, computed
`require`, base64/hex-encoded strings).

**Explicitly out of scope.**

| Not covered | Why |
|---|---|
| Runtime / behavioural detection | Korvyr never executes package code. |
| Non-JavaScript payloads | Only `.js`/`.mjs` sources are parsed; native addons, WASM, and prebuilt binaries are not analysed. |
| Compromise of the registry itself, or of Korvyr's own supply chain | Out of scope. |
| A determined adversary tuning a payload against Korvyr | The rules and thresholds are public; evasion is expected to be practical. |
| Vulnerability detection (CVEs) | Korvyr looks for *malicious intent*, not known-vulnerable versions. Use `npm audit` or a dedicated SCA tool for that. |
| Guaranteed blocking | The proxy fails open by default (see [Known limitations](#known-limitations)). |

---

## Architecture

```
npm client
    |
    v
[ proxy/ ]  npm registry proxy (Node.js, :4873)
    |  intercepts tarball downloads, caches verdicts in Redis or memory
    v
[ korvyr.api ]  scanner API (FastAPI, :8000)
    |
    +-- korvyr.parsing    tree-sitter AST  ->  approximate CFG  ->  lexical DFG
    +-- korvyr.graph      merge into one code property graph (35-dim nodes,
    |                     4 edge types, 8 package-level metadata features)
    +-- korvyr.model      GIN classifier -> gnn_score in [0, 1]
    +-- korvyr.scanner    rules engine (raw source) + manifest scanner (package.json)
    +-- korvyr.metadata   typosquat / structural risk score
    |
    v
korvyr.scanner.scan_pipeline._decide  ->  verdict + confidence + evidence
```

| Path | What lives there |
|---|---|
| `korvyr/` | Scanner package: parsing, graph, model, rules, API, CLI |
| `proxy/` | npm registry proxy (Node.js) |
| `dashboard/` | Read-only React viewer for the proxy log |
| `scripts/` | Dataset, training, evaluation, and diagnostics tooling |
| `tests/` | Offline pytest suite and synthetic fixtures |
| `docs/` | Architecture, API, proxy, and evaluation documentation |

### The GNN component

`korvyr/graph/cpg_builder.py` builds one graph per package:

- **Nodes** are AST nodes from `tree-sitter-javascript`, each encoded as a
  35-dimensional feature vector (node-type one-hot plus binary behavioural flags
  such as *is env access*, *is network call*, *is dynamic require*).
- **Edges** carry one of four types: `ast_child`, `cfg_next`, `cfg_branch`,
  `dfg_def_use`.
- **Graph-level metadata** contributes 8 features (install hooks present, file
  and line counts, source/sink counts).

`korvyr/model/gin_classifier.py` implements `KorvyrGIN`: a 4-layer GINEConv
stack with residual connections, jumping-knowledge concatenation, triple global
pooling (mean ∥ sum ∥ max), an edge-type histogram, and the metadata vector,
followed by an MLP head producing a single logit.

The control-flow and data-flow edges are **approximations** built from AST
structure and lexical name matching, not a sound interprocedural analysis. See
[Known limitations](#known-limitations).

### The static-analysis component

Two independent detectors, kept separate on purpose:

- `korvyr/scanner/rules_engine.py` — 22 behavioural rules over raw JavaScript
  (credential exfiltration, sensitive-file exfiltration, install-hook shell
  execution, install-hook network access, DNS exfiltration, reverse shell,
  dynamic-require execution, decode-then-execute chains, obfuscated install
  scripts, bulk `process.env` harvesting, typosquat naming, known exfiltration
  endpoints, high-entropy payloads, self-deleting scripts, prototype pollution,
  and structural signals).
- `korvyr/scanner/manifest_scanner.py` — manifest-only rules that fire even when
  no JavaScript file survives parsing (curl-pipe-to-shell hooks, `node -e`
  loaders, encoded payloads in hook commands, non-registry URLs in hooks,
  minimal-scaffold-plus-install-hook).

Several rules overlap by design: a package that pipes `curl` into `bash` from a
`postinstall` hook is caught by both the manifest scanner and the source rules,
and each reports its own evidence. That redundancy is deliberate — a detection
that survives parser failure is worth keeping even when another rule covers the
same behaviour.

### The decision layer

`_decide` in `korvyr/scanner/scan_pipeline.py` combines the signals. Rules do
not count equally: `RULE_PRECISION_WEIGHTS` reweights each rule by how reliably
it confirmed true positives during calibration, and `NON_CONFIRMING_RULES` lists
rules considered too noisy to confirm a model hit on their own. In declaration
order, a package is blocked when:

1. `gnn_score >= 0.80` (direct model block), or
2. `0.35 <= gnn_score < 0.80` **and** an install hook is present
   (`MED_INSTALL_HOOK_EXISTS`), or
3. `gnn_score >= 0.45` **and** weighted rule score `>= 1.0`, or
4. the high-reliability rule score `>= 8.0`.

Everything else with evidence becomes `suspicious` (review), and low-score
packages with no weighted rule evidence become `clean`. When no GNN score is
available, only rules can block, and anything with weaker static evidence is
reported as `suspicious` rather than clean.

---

## Installation

Requires **Python 3.10+**. Node.js 20+ is needed for the proxy and dashboard.

```bash
git clone https://github.com/gianmarcomaz/Korvyr.git
cd Korvyr

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Scanner + API + tests
pip install -e ".[test]"
```

Extras:

| Extra | Contents |
|---|---|
| `server` | FastAPI, uvicorn, torch, torch-geometric, tree-sitter |
| `test` | `server` + pytest |
| `dev` | `test` + ruff |
| `research` | `server` + numpy, scikit-learn, matplotlib, tqdm (dataset/training/evaluation scripts) |

`requirements.txt` pins the exact CUDA build used for the reported training run.
It is **not** needed to run the scanner; use it only to reproduce GPU training:

```bash
pip install -r requirements.txt
```

The proxy and dashboard install from their committed lockfiles:

```bash
cd proxy && npm ci
cd ../dashboard && npm ci
```

### GNN checkpoint

**No trained checkpoint is distributed with this repository.** The checkpoint is
a large binary derived from a corpus of real malicious packages that cannot be
redistributed here.

Out of the box, Korvyr therefore runs in **static-only mode**: the rules engine
and manifest scanner produce the verdict, `gnn_score` is reported as `-1.0`, and
`/health` reports `"scan_mode": "static-only"`. The CLI prints a `static-only
verdict` note. Nothing in the running system claims a GNN score it did not
compute.

To run in hybrid mode you must supply your own checkpoint:

```bash
# Train one. This needs a labelled corpus you assemble yourself, which means
# downloading real malware samples - read docs/evaluation.md first.
python scripts/train.py --checkpoint-dir checkpoints/my-run \
    --model-copy-path models/gnn_v2_cuda.pt

# Or point Korvyr at an existing checkpoint
export KORVYR_MODEL_PATH=/path/to/checkpoint.pt
```

The checkpoint must be a Korvyr training checkpoint (a dict containing
`model_state_dict`) matching `node_feat_dim=35`, `metadata_dim=8`,
`hidden_dim=128`, 4 GIN layers, 4 edge types — the constants in
`korvyr/model/checkpoint.py`.

To make a missing checkpoint a hard failure instead of a silent downgrade:

```bash
export KORVYR_REQUIRE_GNN=true    # the API then refuses to start without one
```

---

## Configuration

All runtime configuration is environment-driven with a `KORVYR_` prefix. Copy
[`.env.example`](.env.example) to `.env` and edit; every documented value is also
the built-in default.

Most-used settings:

| Variable | Default | Meaning |
|---|---|---|
| `KORVYR_MODEL_PATH` | `models/gnn_v2_cuda.pt` | GNN checkpoint location |
| `KORVYR_REQUIRE_GNN` | `false` | Fail startup instead of degrading to static-only |
| `KORVYR_API_PORT` | `8000` | Scanner API port |
| `KORVYR_API_URL` | `http://localhost:8000` | Where the CLI looks for the API |
| `KORVYR_MAX_WORKERS` | `4` | Lockfile scan concurrency |
| `KORVYR_REGISTRY_URL` | `https://registry.npmjs.org` | Upstream registry |
| `KORVYR_PROXY_PORT` | `4873` | Proxy port |
| `KORVYR_SCAN_API_URL` | `http://localhost:8000` | Where the proxy sends tarballs |
| `KORVYR_FAIL_MODE` | `open` | `open` forwards unscannable packages, `closed` refuses them |
| `KORVYR_REDIS_URL` | *(empty)* | Shared verdict cache; empty = in-memory |

---

## Usage

All examples below are safe: they scan local synthetic fixtures or small,
well-known real packages. Korvyr never executes package code.

### Run the scanner API

```bash
uvicorn korvyr.api.server:app --host 0.0.0.0 --port 8000
curl http://localhost:8000/health
```

`/health` tells you which mode you are in:

```json
{
  "status": "healthy",
  "scan_mode": "static-only",
  "model_loaded": false,
  "device": "cpu",
  "model_checkpoint": "models/gnn_v2_cuda.pt"
}
```

### Scan with the CLI

```bash
korvyr status                        # API reachable? hybrid or static-only?
korvyr scan is-number@7.0.0          # scan one package
korvyr scan is-number@7.0.0 --json   # machine-readable
korvyr audit --lockfile package-lock.json --fail-on high
```

`korvyr audit` exits `1` when packages at or above `--fail-on` are found, so it
can gate a CI job.

### Scan a local package directory (no network)

```bash
python -c "
from korvyr.scanner.rules_engine import run_rules
from korvyr.scanner.manifest_scanner import merge_manifest_rules
d = 'tests/fixtures/malicious-install-hook'
print(merge_manifest_rules(run_rules(d), d).summary())
"
```

The fixtures under `tests/fixtures/` are **synthetic**. They contain no real
malware: the "malicious" fixture reads two environment variables and references
a non-resolving `*.example` URL so that Korvyr's rules fire, and nothing ever
executes it.

### Run the npm registry proxy

```bash
cd proxy
npm ci
KORVYR_SCAN_API_URL=http://localhost:8000 npm start   # listens on :4873
```

Point npm at it **for a single command** rather than changing your global
config:

```bash
npm install --registry http://localhost:4873 is-number@7.0.0
```

Verdicts are appended to `proxy/logs.jsonl` and served at
`http://localhost:4873/api/logs`. The optional dashboard
([`dashboard/`](dashboard/README.md)) renders that log.

### End-to-end demonstration

```bash
./proxy/demo.sh
```

Checks the API, scans both local fixtures, then installs `is-number@7.0.0`
through the proxy into a temporary directory.

---

## Docker

```bash
docker compose config      # validate the stack definition
docker compose up --build  # korvyr-scanner :8000, korvyr-proxy :4873, korvyr-redis
```

The compose stack mounts `./models` read-only into the scanner container. If it
does not contain the checkpoint named by `KORVYR_MODEL_PATH`, the scanner starts
in static-only mode and reports that on `/health`. No checkpoint is baked into
the image.

The scanner image is CPU-only. GPU inference would additionally require the
NVIDIA container runtime and a CUDA-enabled torch build.

---

## Tests and linting

```bash
pytest                                  # Python suite
ruff check korvyr scripts tests         # lint, including import ordering

cd proxy && npm test                    # proxy suite (jest)
cd dashboard && npm run lint            # dashboard lint
```

`ruff format` has not been applied across the whole tree yet, so formatting is
not gated in CI. New and rewritten modules are formatted; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

The Python suite runs entirely offline — no registry access, no checkpoint and
no corpus required — and exercises the parsers, graph builder, rules, decision
policy, tarball extraction, API, and CLI. CI runs the same commands
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

---

## Evaluation and reproducibility

The canonical evaluator replays the exact production scan path — package load,
CPG, GNN, rules, metadata, `_decide` — so evaluation cannot drift from runtime
behaviour:

```bash
python scripts/evaluate_production.py \
    --package path/to/package:1 \
    --package path/to/other:0 \
    --model-path models/gnn_v2_cuda.pt \
    --output-json results/eval.json \
    --output-md results/eval.md
```

**What you can reproduce from this repository:** the full scan path, the
decision policy, and the report format, on any packages you supply yourself.

**What you cannot reproduce from this repository:** the published numbers. The
600-package corpus, the trained checkpoint, and the machine-readable evaluation
outputs are not distributed here. The aggregate metrics of the run matching the
shipped default policy are recorded in
[`docs/results/production-eval-2026-05-22.md`](docs/results/production-eval-2026-05-22.md);
the evaluation history and caveats are in
[`docs/evaluation.md`](docs/evaluation.md).

Headline figures from that run, on the 600-package balanced development
benchmark, using the checkpoint that is not distributed here:

| System | Precision | Recall | F1 |
|---|---:|---:|---:|
| GNN-only | 0.9085 | 0.8600 | 0.8836 |
| Rules-only | 0.8882 | 0.5033 | 0.6426 |
| Hybrid | 0.9635 | 0.8800 | 0.9199 |

These are **development-benchmark numbers, not production estimates**. The same
600 packages were used while developing and calibrating the decision policy, so
they are optimistic by construction. See [Known limitations](#known-limitations).

---

## Known limitations

**Evaluation**

- The 600-package dataset (300 malicious / 300 benign) is a *balanced
  development benchmark*. Real registry traffic is overwhelmingly benign, so the
  reported precision does not transfer to a production base rate.
- The same dataset was reused during policy development and threshold
  calibration. The reported results are therefore optimistic, and are not
  production estimates.
- **No temporal holdout and no malware-family holdout were evaluated.** Nothing
  here measures generalisation to malware families or time periods the model did
  not see.
- No independent or third-party validation has been performed.
- The corpus, the trained checkpoint, and the machine-readable evaluation
  outputs are not part of this public repository, so the numbers above cannot be
  re-derived from what is published here.

**Analysis**

- The "control-flow" and "data-flow" edges are approximate: CFG edges are
  derived from AST statement structure, and DFG edges from lexical
  definition/use name matching. There is no interprocedural analysis, no alias
  analysis, and no path sensitivity.
- Only `.js` and `.mjs` sources are parsed. Native addons, WASM, and
  non-JavaScript payloads are effectively invisible.
- Large packages hit an AST node cap during graph construction, so their
  representation is truncated.
- The rules and thresholds are public and pattern-based; an adversary who reads
  this repository can construct payloads that avoid them.

**Deployment**

- **The proxy fails open.** When the scanner is unreachable, times out, or
  cannot produce a verdict, the default configuration forwards the package
  *unscanned* and logs a warning. A proxy outage silently removes the control.
  `KORVYR_FAIL_MODE=closed` refuses unscanned packages instead; that mode has
  not been evaluated at scale and will break installs whenever the scanner is
  down.
- `suspicious` packages are forwarded, not blocked. Only `malicious` verdicts
  block.
- Verdicts are cached per `name@version` for `KORVYR_CACHE_TTL` seconds; a
  republished version within that window is served from cache.
- Without a checkpoint the system is a static analyser only. Recall in that mode
  is substantially lower than the hybrid figures above (rules-only recall was
  0.5033 on the development benchmark).

---

## Technical report

The Korvyr technical report documents the dataset construction, model
architecture, calibration procedure, and the full set of caveats summarised
above. It is not stored in this repository; see
[`docs/evaluation.md`](docs/evaluation.md) for the measurement history the
report is based on, and the
[repository releases](https://github.com/gianmarcomaz/Korvyr/releases) for the
report artifact when it is published.

Further documentation:

- [`docs/architecture.md`](docs/architecture.md) — module-by-module walkthrough
- [`docs/api.md`](docs/api.md) — HTTP API reference
- [`docs/proxy.md`](docs/proxy.md) — proxy behaviour and deployment notes
- [`docs/evaluation.md`](docs/evaluation.md) — evaluation history, decisions, caveats

---

## Citation

If you reference Korvyr, please cite it via [`CITATION.cff`](CITATION.cff):

```bibtex
@software{mazzella_korvyr_2026,
  author  = {Mazzella, Gianmarco},
  title   = {Korvyr: Hybrid GNN and Static-Analysis Prototype for
             Pre-Install npm Package Screening},
  year    = {2026},
  url     = {https://github.com/gianmarcomaz/Korvyr},
  version = {0.1.0}
}
```

---

## Security reporting

Please **do not** open a public issue for a security problem in Korvyr itself.
Reporting instructions and scope are in [`SECURITY.md`](SECURITY.md).

Korvyr's verdicts are not vulnerability reports: do not use a `malicious`
verdict as the sole basis for a public accusation against a package or its
maintainer. False positives are expected.

---

## License

[MIT](LICENSE) © Gianmarco Mazzella.

Third-party dependencies retain their own licenses. No third-party package
source, malware sample, or dataset is redistributed in this repository.
