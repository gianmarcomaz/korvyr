# Production-path evaluation, 2026-05-22

Measured output of `scripts/evaluate_production.py` for the decision policy that
ships as the default in `korvyr/scanner/scan_pipeline.py`. The numbers below are
copied verbatim from that run; nothing here is estimated or extrapolated.

## Provenance and what is missing

| | |
|---|---|
| Evaluator | `scripts/evaluate_production.py` (canonical production scan path) |
| Corpus | 600 packages: 300 malicious, 300 benign |
| Checkpoint | `models/gnn_v2_cuda.pt` (**not distributed** — see the README) |
| Device | CUDA |
| Policy | `ThresholdConfig` defaults as shipped |

The corpus, the checkpoint, and the machine-readable JSON of this run are **not
part of this repository**. The corpus contains real malicious npm packages that
cannot be redistributed, and the checkpoint is derived from it. This document is
therefore a record of a measurement, not something a reader can re-run here.

## Read this before quoting the numbers

- This is a **balanced development benchmark**, not a sample of registry
  traffic. Real installs are overwhelmingly benign, so precision measured on a
  50/50 split does not carry over to a production base rate.
- **The same 600 packages were used while developing and calibrating the
  decision policy.** These results are optimistic by construction and are not
  production estimates.
- **No temporal holdout and no malware-family holdout were evaluated.** This run
  says nothing about generalisation to unseen malware families or later time
  periods.
- Only hard `malicious` verdicts count as positive predictions. `suspicious`
  (review) outcomes count as negatives for precision and recall.
- Per-package records, including the names of the individual false positives and
  false negatives, are deliberately omitted from the public repository.

## Metrics

| System | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---:|
| GNN-only | 0.9085 | 0.8600 | 0.8836 | 258 | 26 | 42 | 274 |
| Rules-only | 0.8882 | 0.5033 | 0.6426 | 151 | 19 | 149 | 281 |
| Hybrid | 0.9635 | 0.8800 | 0.9199 | 264 | 10 | 36 | 290 |

The hybrid layer traded a small amount of GNN-only precision headroom for recall
and cut false positives from 26 to 10 relative to the model alone, at the cost of
36 remaining false negatives.

## Coverage

- GNN coverage rate: 100.00% (600/600)
- GNN failure count: 0
- CPG none count: 0
- CPG failure count: 0
- CPG status counts: `{'success': 600}`

Full coverage here means every package produced a graph the model could score;
it does not mean every package was *well* represented. Large packages hit the
AST node cap during graph construction.

## Decision buckets

| Bucket | Count |
|---|---:|
| `clean_pass` | 150 |
| `v2_gnn_direct_block` | 223 |
| `v2_gnn_review` | 104 |
| `v2_gnn_weighted_rules_block` | 14 |
| `v2_hard_rules_block` | 3 |
| `v2_install_hook_recall_block` | 34 |
| `v2_low_gnn_review` | 49 |
| `v2_static_review` | 23 |

223 of the 274 blocks came from the model score alone; the install-hook
confirmer accounted for 34 and the rule-confirmed paths for 17.

## Per-rule contribution

How often each matched rule flipped a package from a wrong GNN-only prediction to
a correct hybrid one (`saved`), or the reverse (`hurt`).

| Rule | Saved | Hurt |
|---|---:|---:|
| CRIT_DYNAMIC_REQUIRE_EXEC | 0 | 1 |
| CRIT_EXFIL_CREDENTIALS | 1 | 0 |
| CRIT_INSTALL_HOOK_EXEC | 1 | 0 |
| CRIT_INSTALL_HOOK_NETWORK | 1 | 1 |
| CRIT_MANIFEST_NODE_EVAL | 1 | 0 |
| HIGH_ENCODED_PAYLOAD_CHAIN | 2 | 0 |
| HIGH_EVAL_DECODED | 1 | 0 |
| HIGH_PROCESS_ENV_BULK | 1 | 0 |
| HIGH_RUNTIME_PROTOTYPE_POLLUTION | 3 | 1 |
| HIGH_SELF_DELETE | 1 | 0 |
| HIGH_TYPOSQUAT_SIGNAL | 1 | 0 |
| HIGH_WEBHOOK_EXFIL | 2 | 1 |
| MED_INSTALL_HOOK_EXISTS | 13 | 2 |
| MED_NETWORK_PLUS_FS | 6 | 3 |

`MED_INSTALL_HOOK_EXISTS` is the single largest recall contributor and also a
source of false positives — it is exactly the signal the mid-GNN install-hook
block depends on.

## Observed malicious rate by GNN score bucket

Not statistical calibration; a reliability table for comparing checkpoints on the
same corpus.

| Score bucket | Total | Malicious | Benign | Observed malicious rate | Avg GNN |
|---|---:|---:|---:|---:|---:|
| [0.00,0.10) | 0 | 0 | 0 | 0.0000 | 0.0000 |
| [0.10,0.20) | 0 | 0 | 0 | 0.0000 | 0.0000 |
| [0.20,0.30) | 70 | 7 | 63 | 0.1000 | 0.2885 |
| [0.30,0.40) | 206 | 21 | 185 | 0.1019 | 0.3401 |
| [0.40,0.50) | 40 | 14 | 26 | 0.3500 | 0.4347 |
| [0.50,0.60) | 25 | 15 | 10 | 0.6000 | 0.5413 |
| [0.60,0.70) | 16 | 12 | 4 | 0.7500 | 0.6518 |
| [0.70,0.80) | 20 | 14 | 6 | 0.7000 | 0.7582 |
| [0.80,0.90) | 52 | 50 | 2 | 0.9615 | 0.8612 |
| [0.90,1.00] | 171 | 167 | 4 | 0.9766 | 0.9443 |

The model never produced a score below 0.20 on this corpus, and the 0.30-0.40
bucket holds a third of all packages — the score distribution is compressed,
which is why the decision thresholds sit where they do.

## Error shape

The 10 false positives, by the path that blocked them:

| Path | Count |
|---|---:|
| `v2_gnn_direct_block` (score >= 0.80) | 6 |
| `v2_gnn_weighted_rules_block` | 2 |
| `v2_install_hook_recall_block` | 2 |

Three of the ten matched no rule at all: the model alone blocked them.

The 36 false negatives, by the path that let them through:

| Path | Count |
|---|---:|
| `v2_gnn_review` | 19 |
| `v2_low_gnn_review` | 12 |
| `clean_pass` | 3 |
| `v2_static_review` | 2 |

22 of the 36 matched no rule at all, and 15 scored below the 0.35 clean
threshold. Only 3 were passed outright as clean; the rest were surfaced for
review but not blocked. That profile points at missing rule coverage and a
compressed score distribution rather than at thresholds set too high.
