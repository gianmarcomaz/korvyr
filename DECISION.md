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
