# Evaluation history and caveats

This document records what was actually measured while building Korvyr, in the
order it was measured, including the experiments that failed. It exists so the
headline numbers in the README can be read in context rather than taken at face
value.

Nothing in this file is an estimate. Every figure is copied from a recorded run.

## The benchmark

All figures below come from the same **600-package balanced development
benchmark**: 300 malicious and 300 benign npm packages.

Four properties of that benchmark limit everything downstream:

1. **It is balanced.** Real registry traffic is overwhelmingly benign. A
   precision measured at a 50/50 base rate does not transfer to production.
2. **It was reused.** The same 600 packages were used to develop, calibrate, and
   report the decision policy. The reported results are optimistic by
   construction and are not production estimates.
3. **There is no holdout.** No temporal split and no malware-family split were
   evaluated. Generalisation to unseen families or later time periods is
   unmeasured.
4. **It is not published.** The corpus contains real malicious packages and is
   not redistributed in this repository, so these numbers cannot be re-derived
   from what is public here.

Positive predictions are hard `malicious` verdicts only. `suspicious` (review)
outcomes count as negatives throughout, which is why recall figures here are
lower than a "flagged anything" metric would be.

## Timeline

### Baseline (2026-05-18)

The first production-path baseline used the original checkpoint and the
high-precision policy of the time. It ran on the same 600-package target list.
All 600 packages produced a CPG successfully with zero GNN failures, though
several hit the AST node cap during construction — those packages are scored on
a truncated representation.

Result: hybrid precision 1.0000, recall 0.4800, with 156 false negatives. High
precision, but less than half of the malicious packages were blocked.

### GNN recall experiment (2026-05-18) — not promoted

A retrained checkpoint aimed at higher recall was evaluated against the same
baseline. GNN-only recall improved marginally (0.8400 to 0.8467) but GNN-only
false positives rose from 26 to 68, and **hybrid recall fell** from 0.4800 to
0.4500 because the decision layer diverted more high-score, weakly-confirmed
packages to review. The checkpoint was not promoted.

One CPU epoch took roughly 5,200 seconds, which is why later training used a
GPU environment.

### Phase 1 diagnostics (2026-05-18)

Diagnostics over the same 600 packages established that CPG/GNN coverage was not
the bottleneck: coverage was 600/600, but 147 malicious packages landed in
`suspicious` rather than `malicious`. Those false negatives were concentrated in
weak or absent rule evidence — 74 had a rules score of 0.

This is the finding that shaped the rest of the work: the limiting factor was
*confirming* evidence, not model coverage.

### CUDA retrain and v2 calibration (2026-05-19)

A GPU retrain (early stopping at epoch 48, best checkpoint from epoch 28)
produced `models/gnn_v2_cuda.pt`. On the 600-package evaluation it raised hybrid
recall from 0.4800 to 0.5300 but dropped precision from 1.0000 to 0.9695 under
the then-current policy — not promotable as-is.

A replay-only calibration then swept 33,264 policy configurations over the
recorded signals from that run:

| Precision floor | Best achievable recall |
|---|---|
| >= 0.96 | 0.8200 (precision 0.9647) |
| >= 0.97 | 0.7967 |
| >= 0.98 | substantially lower |
| >= 0.99 | substantially lower |

**No configuration reached recall >= 0.88 at precision >= 0.96 on this
dataset.** The recorded signals simply did not support the simultaneous
high-precision/high-recall target that had been hoped for.

Root-cause analysis at the best operating point (precision 0.9647, recall
0.8200) found 9 false positives — 5 from noisy rule confirmation, 3 from high
model score with no rules, 1 rule collision — and 54 false negatives dominated
by mid- and low-score packages with weak or no rules.

### Signal audits (2026-05-19)

Two replay-only audits looked for signals that could separate those errors
without rescanning or changing scanner behaviour.

**Package-context audit.** One zero-harm suppressor was found (a
dummy-graph/no-hook/low-metadata-risk gate: 2 false positives saved, 0 true
positives lost) and one zero-harm confirmer (sparse mid-score/no-rule context: 1
false negative recovered). Broader confirmers reached recall 0.8800 but each
introduced false positives. The measured zero-harm combination reached precision
0.9724 / recall 0.8233 — better on both axes, still short of the target region.

**Lifecycle-hook audit.** The mid-score lifecycle-hook slice contained 51
packages: 14 TP, 1 FP, 20 FN, 16 TN. **Install-hook presence alone is not a safe
blocker** — that slice is roughly a coin flip. Narrower confirmers (hook plus
secret terms, hook plus obfuscation terms, hook plus multi-family risk) each
recovered 1-2 false negatives with zero true negatives lost. Generic
network-term and low-risk-score confirmers each cost a true negative.

### Promoted policy (2026-05-22)

The calibrated v2 operating point plus the measured install-hook confirmer was
implemented in `_decide` and evaluated end to end on the same 600 packages with
`models/gnn_v2_cuda.pt`:

**Precision 0.9635, recall 0.8800, F1 0.9199** — 264 TP, 10 FP, 36 FN, 290 TN.

Full report: [`results/production-eval-2026-05-22.md`](results/production-eval-2026-05-22.md).

This hit the 0.88 recall goal on this benchmark. It did **not** reach the
98-99% precision that earlier iterations aimed for. The shipped default is
therefore a deliberately high-recall operating point, and its 10 false positives
have never been validated against a holdout.

## Decisions deliberately not taken

- **Lowering the model block threshold further.** Recorded evaluations show it
  increases false positives on benign packages faster than it recovers true
  positives.
- **Blocking on generic install-hook presence.** The lifecycle audit measured
  that slice as close to balanced; blocking it outright would flag many benign
  packages with legitimate build hooks.
- **Adding rules speculatively.** New rules should come from inspecting residual
  false negatives, not from adding plausible-looking patterns.
- **An LLM triage layer.** Proposed but never evaluated; there is no measurement
  supporting its false-positive behaviour, so it was not built.

## Reproducing anything here

The canonical evaluator is `scripts/evaluate_production.py`. It calls the same
`_decide` the runtime uses, so evaluation cannot drift from production
behaviour:

```bash
python scripts/evaluate_production.py \
    --package /path/to/malicious-sample:1 \
    --package /path/to/benign-sample:0 \
    --model-path models/gnn_v2_cuda.pt \
    --output-json results/eval.json \
    --output-md results/eval.md
```

Add `--require-gnn` to fail instead of silently reporting static-only results
when the checkpoint is missing.

To rebuild the pipeline from scratch you must assemble a labelled corpus:

```bash
python scripts/download_benign.py        # popular packages from the npm registry
python scripts/download_malicious.py     # Datadog malicious-software-packages-dataset
python scripts/build_dataset.py          # packages  -> per-package CPG tensors
python scripts/assemble_splits.py        # train/val/test split directories
python scripts/train.py --checkpoint-dir checkpoints/my-run
```

The malicious side comes from the public
[DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset),
whose samples ship as password-protected archives. **Downloading it puts real
malware on your disk.** Handle it in an isolated environment, never install or
execute a sample, and respect that dataset's own terms. Korvyr itself never
executes package code.

The resulting corpus must not be committed here: `data/`, `checkpoints/`,
`models/`, and `results/` are git-ignored, and `tests/test_repo_hygiene.py`
fails if any of them becomes tracked.

**This does not reproduce the published numbers.** Re-running the pipeline gives
you *a* corpus and *a* checkpoint, not the specific 600-package split or the
specific checkpoint the figures above were measured on. Neither the split
manifest nor the checkpoint is published, and both upstream sources change over
time. Treat any numbers you obtain this way as your own measurement, not as a
replication.

Diagnostics and calibration tooling, all replay-only over recorded evaluation
JSON:

| Script | Purpose |
|---|---|
| `scripts/diagnose_recall.py` | Bucket false negatives by score and rule evidence |
| `scripts/calibrate_hybrid_v2.py` | Sweep decision-policy configurations over recorded signals |
| `scripts/analyze_hybrid_v2_errors.py` | Root-cause FP/FN grouping |
| `scripts/audit_context_signals.py` | Test candidate package-context signals |
| `scripts/audit_lifecycle_signals.py` | Test candidate lifecycle-hook signals |
| `scripts/compare_evals.py` | Diff two evaluation runs |
| `scripts/plot_diagnostics.py` | Score histogram and PR curve (needs the `research` extra) |
