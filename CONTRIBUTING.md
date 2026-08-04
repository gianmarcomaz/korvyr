# Contributing to Korvyr

Korvyr is a research prototype maintained by one person. Contributions are
welcome, especially detection-quality work backed by measurements.

## Setup

```bash
git clone https://github.com/gianmarcomaz/Korvyr.git
cd Korvyr
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

cd proxy && npm ci && cd ..
```

You do **not** need a GNN checkpoint or a package corpus to develop: the whole
test suite runs offline in static-only mode.

## Before opening a pull request

```bash
pytest
ruff check korvyr scripts tests
cd proxy && npm test && cd ..
```

CI runs exactly these commands.

`ruff format` is configured but has **not** been applied across the whole tree,
so CI does not gate on it — a repository-wide reformat would bury real changes
in whitespace churn. Please run `ruff format` on files you touch, and keep the
reformat out of feature pull requests.

## What is most useful

1. **Rules backed by residual false negatives.** The measured error profile
   (see [`docs/evaluation.md`](docs/evaluation.md)) is dominated by malicious
   packages that matched *no* rule at all. A new rule derived from inspecting
   real misses is worth far more than a plausible-looking pattern.
2. **Analysis fidelity.** The CFG and DFG edges are approximations. Making them
   less approximate — real def-use chains, interprocedural edges — is the
   highest-leverage change to the graph pipeline.
3. **Evaluation honesty.** A temporal or malware-family holdout is the single
   biggest gap in the current evidence base.

## Rules: house style

Each rule lives in `korvyr/scanner/rules_engine.py` (source-level) or
`korvyr/scanner/manifest_scanner.py` (manifest-level) and follows the existing
shape:

- One function returning at most one `MatchedRule`, or `None`.
- A docstring stating **what it detects and why benign packages do not trigger
  it**. Every existing rule has an explicit false-positive analysis; new ones
  should too.
- An ID of the form `CRIT_*`, `HIGH_*`, or `MED_*`.
- A test in `tests/test_rules.py` covering both a triggering case and a
  near-miss benign case.

**Do not merge rules just because they detect related behaviour.** Overlapping
detections that produce distinct evidence, or that survive different failure
modes (for example, a manifest rule that still fires when parsing fails), are
kept separate on purpose.

If a new rule should be able to block, add it to `HARD_BLOCK_CAPABLE_RULES` and
give it a weight in `RULE_PRECISION_WEIGHTS` in
`korvyr/scanner/scan_pipeline.py` — and say what measurement justifies that
weight. Rules default to `unknown_rule_weight` if unweighted.

## Changing the decision policy

`_decide` is the policy. Changing thresholds or adding a decision path requires:

- An evaluation run before and after on the same package set, using
  `scripts/evaluate_production.py`.
- Both precision and recall reported, not just the one that improved.
- A new decision-path string mapped in
  `korvyr/evaluation/reporting.py::decision_bucket`, so reports keep grouping
  outcomes correctly.

Policy changes without a measurement will not be merged. This project has a
history of proposals that looked good and made things worse — that history is in
[`docs/evaluation.md`](docs/evaluation.md).

## Changing the feature space

`FEATURE_DIM` in `korvyr/parsing/ast_extractor.py` is the contract between the
parser and every trained checkpoint. Changing the node-type list or the flag set
silently invalidates existing checkpoints. If you change it, say so explicitly in
the PR and in `CHANGELOG.md`.

## Test data

Use **synthetic fixtures**, never real malware. See
[`tests/fixtures/README.md`](tests/fixtures/README.md) for the conventions.
Never commit downloaded packages, graph tensors, checkpoints, or evaluation
output — `data/`, `checkpoints/`, `models/`, and `results/` are git-ignored for
that reason.

## Research integrity

This repository documents what was measured, including the experiments that did
not work. Please keep it that way:

- Do not present development-benchmark numbers as production estimates.
- Do not describe Korvyr as production-ready, state of the art, independently
  validated, or robust to unseen attacks.
- If a change improves one metric at the cost of another, report both.

## Reporting bugs

Open an issue with the Korvyr version or commit, the command you ran, and what
happened. For a scanning bug, a **synthetic** package that reproduces it is
ideal.

Security issues follow a different path — see [`SECURITY.md`](SECURITY.md).

## License

Contributions are accepted under the [MIT license](LICENSE).
