# Submission Readiness Notes

These are the remaining owner decisions and the correctness items already handled for submission readiness.

## Resolved In The Latest Readiness Pass

1. API serialization now uses `matched_code_snippet`.
   - `_run_pipeline` now serializes rule snippets from the field defined by `MatchedRule`.
   - `tests/test_api.py` includes a regression test for the response payload.

2. The unreachable decision block was removed from `supplyguard/scanner/scan_pipeline.py`.
   - The current high-precision decision path is now the only path inside `_decide`.
   - `tests/test_rules.py` includes coverage for high-confidence GNN confirmation, rules-only blocking, and fixture-backed credential exfiltration.

3. Minimal inspectable fixtures were added under `tests/fixtures/`.
   - `clean-package/`
   - `malicious-install-hook/`
   - `manifest-curl-pipe/`

## Remaining Owner Decisions

1. Decide whether model checkpoints should ship with the submitted repository.
   - `checkpoints/` and `.pt` files are currently treated as generated artifacts.
   - The API can start without a checkpoint, but GNN-backed scan quality depends on a trained model being available at `MODEL_PATH`.
   - A safe path is to keep checkpoints out of Git and document how to mount or download them for local runs.

2. Decide whether the downloaded package corpus belongs in the submission.
   - `data/raw/` contains third-party package source and malicious sample archives.
   - `data/processed/` contains generated graph tensors.
   - For Project Silver, these are risky to submit because they add licensing/provenance noise and make the repo look less clean.

3. Consider splitting heavyweight training workflows from serving workflows.
   - The backend Dockerfile installs server dependencies only.
   - Training and evaluation scripts need the full ML stack and local datasets.
   - A second `Dockerfile.train` may be useful if tasks will target model training behavior.

4. Normalize non-ASCII console glyphs and section-rule comments across the codebase only if you want a broader style cleanup commit.
   - Several files contain arrows, check marks, and line-drawing comments.
   - They are harmless, but a plain ASCII style may read more like a maintained engineering repo.

5. Confirm repository ownership and provenance.
   - This repo should only be submitted if all included code/assets are yours or have acceptable licenses.
   - The raw package corpus should stay excluded unless each source is clearly allowed.
