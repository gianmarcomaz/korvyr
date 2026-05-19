# SupplyGuard Accuracy Decisions

These items were not implemented because the local files do not provide enough
evidence to claim they would improve precision and recall safely.

## Deferred

- Retraining the GNN for 89-90% recall.
  The repo has checkpoints and graph artifacts, but no verified training run in
  this pass that proves a new model beats the current checkpoint. A retrain
  should be run as a separate controlled experiment with saved validation/test
  metrics before replacing `checkpoints/best_model.pt`.

- Lowering GNN block thresholds.
  The saved `data/processed/hybrid_real_evaluation.json` shows that looser GNN
  blocking increases false positives on benign packages. The production default
  was tightened toward high-precision blocking instead.

- Adding an LLM triage layer.
  The prompt proposes this as a later phase, but there are no benign-set
  validation results or API/runtime configuration in the repo to prove it meets
  the false-positive bar.

- Expanding rule coverage beyond existing rules.
  DNS exfiltration, dynamic require, encoded payload, prototype pollution,
  suspicious manifest, and install-hook rules already exist. Additional rules
  should be driven by residual false-negative inspection, not by speculative
  pattern additions.

## Local Measurement Notes

- Python tests pass when run with the bundled Codex Python plus the repo venv
  site-packages and a workspace pytest temp directory.
- The saved 600-package eval indicates GNN coverage is no longer the main local
  failure mode; the larger current risk is precision loss from hard-blocking
  weak or noisy confirmations.
- The precision/recall target is not proven by the current artifacts. Do not
  present 99.9% precision or 89-90% recall as achieved until a fresh full eval
  records those metrics.

## Baseline Evaluation Caveats - 2026-05-18

- The production-path baseline in
  `results/baseline_accuracy_report_20260518_0400.md` is partial, not full
  corpus. Recursive raw-corpus counting and full manifest target collection
  timed out locally before evaluation, so the run used the existing balanced
  600-package target list from
  `data/processed/hybrid_real_evaluation_phase1_manifest.json`.
- The baseline measured 300 benign and 300 malicious packages at commit
  `800712e4998c89b58550a5de73a7595cb0caf2b8` with
  `checkpoints/best_model.pt` and the default production thresholds.
- All 600 packages produced CPG status `success`, with zero GNN failures, but
  several packages reached the AST node cap during CPG construction. Treat those
  cap events as a future coverage/representativeness review item.
- The baseline counts only hard `malicious` verdicts as positive predictions.
  `suspicious` review outcomes are treated as negative for precision/recall,
  matching the canonical evaluator's current reporting semantics.

## GNN Recall Experiment - 2026-05-18

- Experiment checkpoint `checkpoints/experiments/gnn_recall_20260518/best_model.pt`
  was not promoted. On the same 600-package production-path baseline, hybrid
  precision stayed at 1.0000 but recall fell from 0.4800 to 0.4500, with false
  negatives increasing from 156 to 165.
- GNN-only recall improved slightly from 0.8400 to 0.8467, but GNN-only false
  positives increased from 26 to 68. The hybrid decision layer reserved more
  high-GNN, weakly-confirmed cases for review instead of hard-blocking them.
- One CPU epoch completed and produced checkpoint metadata, but it took about
  5216 seconds. Future controlled GNN experiments should use a GPU or a more
  deliberate smaller ablation before running another full production-path
  evaluation.
- The default checkpoint `checkpoints/best_model.pt` remains unchanged.

## Full Retraining Execution Gate - 2026-05-18

- Phase 1 diagnostics completed and wrote
  `data/diagnostics/phase1_diagnostic.json` with 600 records. The current
  source contract is 35 node features, 8 metadata features, and hidden dim 128;
  the 25-dim/64-hidden values in the external prompt are stale for this repo.
- The main recall loss is not CPG/GNN coverage. GNN coverage was 600/600, but
  147 malicious packages landed in `suspicious` rather than hard `malicious`.
  False negatives were concentrated in weak/absent rules: 74 had rules score 0,
  42 had rules score 1-5, 24 had rules score 6-10, 3 had rules score 11-14,
  and 13 had rules score >= 15.
- `matplotlib` is not installed in the active environment. Sandboxed `pip
  install matplotlib` was blocked by network permissions and escalation review
  timed out twice, so `scripts/plot_diagnostics.py` generated the required PNG
  artifacts via a Pillow fallback. Re-run with matplotlib installed if exact
  matplotlib rendering is required.
- `data/processed/train_dataset.pt`, `val_dataset.pt`, and `test_dataset.pt`
  are stale 10-graph/25-dim aggregate artifacts. The real usable full dataset is
  the lazy-loading split directories: `data/processed/train` (24041 graphs),
  `data/processed/val` (4948 graphs), and `data/processed/test` (5321 graphs),
  sampled as 35-dim node features with 8-dim metadata.
- Do not aggregate the full split directories into monolithic `.pt` files in
  this local run. The split directories total roughly 178 GB of graph files, and
  the current trainer is intentionally built to lazy-load per-graph `.pt` files.
- At the initial Phase 2 check, CUDA was unavailable in the active CPU
  environment (`torch.cuda.is_available() == False`). A one-epoch CPU
  experiment took about 5216 seconds, which is why the GPU environment below was
  created before the long retraining job.

## CUDA Retrain And Hybrid V2 Calibration - 2026-05-19

- A project-local GPU environment `.venv-gpu` was created and verified with
  `torch==2.6.0+cu124`, `torch-geometric==2.7.0`, and CUDA available on the
  RTX 4070. `.venv-gpu/` and `.pytest-tmp/` are ignored in git.
- The CUDA retrain completed with early stopping at epoch 48. The best
  checkpoint came from epoch 28 and was copied to `models/gnn_v2_cuda.pt`.
  Training summary is in `results/gnn_v2_cuda_training.json`.
- The 600-package production-path evaluation of `models/gnn_v2_cuda.pt`
  improved hybrid recall from 0.4800 to 0.5300, but precision dropped from
  1.0000 to 0.9695 with five false positives. Do not promote this checkpoint
  under the current production hybrid policy.
- A replay-only v2 hybrid calibration swept 33,264 policy configs from the
  recorded production signals. Best recall at precision >= 0.96 was 0.8200
  with precision 0.9647 (246 TP, 9 FP, 54 FN). Best recall at precision >= 0.97
  was 0.7967. Precision >= 0.98 and >= 0.99 required much lower recall.
- No replayed v2 policy config reached recall >= 0.88 at precision >= 0.96,
  >= 0.97, >= 0.98, or >= 0.99 on the current 600-package dataset. The current
  recorded signals do not support the requested simultaneous 96-99% precision
  and 88-92% recall target.
- Next accuracy work should focus on separating the remaining 54-61 false
  negatives from the 7-9 false positives in the best 96-97% precision configs,
  not on promoting the new checkpoint or simply lowering thresholds.
- Root-cause analysis of the best v2 replay point (precision 0.9647, recall
  0.8200) found 9 false positives: 5 from noisy rule confirmation, 3 from
  high/very-high GNN without rules, and 1 high-reliability rule collision. The
  54 false negatives were mostly mid/low GNN packages with no or weak rules:
  20 mid-GNN weak-rule cases, 18 mid-GNN no-rule cases, 12 low-GNN weak-rule
  cases, and 3 low-GNN no-rule cases.
- The next efficient work is not another threshold sweep. It is adding new
  separating signal: benign-context gates for high-GNN/no-rule and noisy-rule
  false positives, manifest/metadata confirmations for mid-GNN false negatives,
  and hard-positive retraining examples for low-GNN malicious packages.

## Context Signal Audit - 2026-05-19

- A replay-only package-context audit was added and run against the best hybrid
  v2 96% precision operating point. It uses the recorded production-path
  signals from `results/production_eval_gnn_v2_cuda.json` and does not rescan
  packages or change scanner behavior.
- Baseline replay remained precision 0.9647, recall 0.8200, F1 0.8865 with
  246 TP, 9 FP, 54 FN, and 291 TN.
- The only individually zero-harm suppressor found was a dummy-graph/no-hook
  low-metadata-risk gate. It saved 2 false positives and hurt 0 true positives.
  This is promising as a targeted precision fix, but it is too narrow to solve
  recall.
- The only individually zero-harm confirmer found was sparse mid-GNN/no-rule
  package context. It recovered 1 false negative and hurt 0 true negatives.
  This is useful evidence but not enough to justify a broad hard-block policy.
- Broader recall confirmers can reach recall 0.8800, but they introduce false
  positives. `confirm_mid_gnn_install_hook_rule` recovered 18 false negatives
  but hurt 1 true negative, producing precision 0.9635 and recall 0.8800.
  `confirm_mid_gnn_install_hook_metadata` recovered 18 false negatives but hurt
  3 true negatives, producing precision 0.9565 and recall 0.8800.
- Broad benign-context suppressors improve precision but erase too much recall.
  For example, suppressing high-GNN/no-rule packages with benign context saved
  3 false positives but hurt 12 true positives.
- The measured zero-harm combination reached precision 0.9724, recall 0.8233,
  F1 0.8917 with 247 TP, 7 FP, 53 FN, and 293 TN. This improves both metrics
  but does not reach the desired 96-99% precision and 88-92% recall region.
- Based on current local evidence, the next attempt should not be a production
  policy change alone. It should combine hard-example retraining using the 9 FP
  and 54 FN package lists with narrower install-hook context features that can
  separate the one benign install-hook collision from the 18 malicious
  mid-GNN/install-hook false negatives.
