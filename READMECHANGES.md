# Changes To Review Before Submission

These are changes I did not make because they could alter product behavior, repository scope, or submission strategy.

1. Decide whether model checkpoints should ship with the submitted repository.
   - `checkpoints/` and `.pt` files are currently treated as generated artifacts.
   - The API can start without a checkpoint, but GNN-backed scan quality depends on a trained model being available at `MODEL_PATH`.
   - A safe path is to keep checkpoints out of Git and document how to mount or download them for local runs.

2. Review the API serialization path in `supplyguard/api/server.py`.
   - `_run_pipeline` reads `r.matched_snippet`, while `MatchedRule` defines `matched_code_snippet`.
   - Fixing that is likely correct, but it is a product logic/API compatibility change, so I left it for review.

3. Review the decision path in `supplyguard/scanner/scan_pipeline.py`.
   - `_decide` appears to return before an older critical/GNN decision block, making that later block unreachable.
   - Removing or reconciling that path would be a real behavior change, so I documented it instead of editing it.

4. Decide whether the downloaded package corpus belongs in the submission.
   - `data/raw/` contains third-party package source and malicious sample archives.
   - `data/processed/` contains generated graph tensors.
   - For Project Silver, these are risky to submit because they add licensing/provenance noise and make the repo look less clean.

5. Consider splitting heavyweight training workflows from serving workflows.
   - The backend Dockerfile installs server dependencies only.
   - Training and evaluation scripts need the full ML stack and local datasets.
   - A second `Dockerfile.train` may be useful if tasks will target model training behavior.

6. Normalize non-ASCII console glyphs and section-rule comments across the codebase.
   - Several files contain arrows, check marks, and line-drawing comments.
   - They are harmless, but a plain ASCII style may read more like a maintained engineering repo.

7. Add a minimal public fixture dataset.
   - Current tests create temporary packages and mock external calls, which is good.
   - A tiny `tests/fixtures/` package set could make parser/rules behavior easier for reviewers to inspect.

8. Confirm repository ownership and provenance.
   - This repo should only be submitted if all included code/assets are yours or have acceptable licenses.
   - The raw package corpus should stay excluded unless each source is clearly allowed.
