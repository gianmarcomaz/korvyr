# SupplyGuard Submission Readiness Summary

Prepared on: 2026-05-17

## What Changed

- Created a project-local Git repository in `SupplyGuard/.git` and moved it to the `main` branch.
- Added `.gitignore` rules for generated and heavy folders: `venv/`, `node_modules/`, caches, `data/raw/`, `data/processed/`, `checkpoints/`, and model checkpoint binaries.
- Added `.dockerignore` while deliberately keeping `.git` visible for Project Silver packaging expectations.
- Added a root `Dockerfile` for the FastAPI scanner service.
- Added `pytest.ini` so tests discover from `tests/` and import the local package from the repo root.
- Expanded `README.md` from empty to a submission-ready project overview, layout, quick start, Docker, model artifact, and packaging notes.
- Added `READMECHANGES.md` for product-affecting items that need owner review before being changed.
- Added focused tests:
  - `tests/test_metadata_manifest.py`
  - `tests/test_submission_readiness.py`
- Added fixture-backed tests and sample packages in `tests/fixtures/`.
- Fixed API rule snippet serialization to use `matched_code_snippet`.
- Removed an unreachable legacy decision block from `_decide`.
- Added concise comments in core scanner/API/CLI files to clarify boundaries and behavior without changing logic.
- Replaced the empty `setup.py` with a minimal setuptools shim for legacy install workflows.
- Added explicit setuptools package discovery so editable installs only package `supplyguard`.
- Added `test` optional dependencies and the JavaScript parser dependency to `pyproject.toml`.
- Updated AST/CPG tests to use the parser-owned `FEATURE_DIM` constant instead of stale hard-coded dimensions.
- Made the manifest curl-pipe scanner test build a focused temporary package, keeping fixture tests for fixture coverage.

## Git History Created

- `initial local project import`
- `add submission packaging notes`
- `summarize submission readiness work`
- `tidy submission summary`
- `resolve submission readiness issues`
- `update readiness summary`
- `fix setuptools package discovery`
- `add javascript parser dependency`

This is an honest local history created from the current project state. It does not fabricate or backdate prior development history.

## Verification

- Confirmed owned source/test/script surface is substantial:
  - `supplyguard/`: 25 files, about 7,519 lines.
  - `tests/`: 7 existing files plus 2 added files.
  - Full owned source/test/scripts/proxy/dashboard surface: about 12,912 lines before the added tests/docs.
- Confirmed `.dockerignore` does not exclude `.git`.
- Confirmed generated/heavy folders are ignored by Git:
  - `venv/`
  - `data/raw/`
  - `data/processed/`
  - `checkpoints/`
  - `proxy/node_modules/`
  - `dashboard/node_modules/`
- Ran a scoped secret scan over owned code paths. The matches found were test fixture strings and detector vocabulary, not live credentials.
- User-local pytest run after dependency install reached collection and executed 60 tests:
  - 56 passed.
  - 4 stale expectation/fixture tests failed and were addressed in the latest working tree changes.
- Could not rerun pytest in the Codex shell because `python`/`py` are not on PATH here and `.venv/Scripts/python.exe` cannot launch from this sandbox.

## Items To Review Before Submission

- `READMECHANGES.md` lists remaining owner decisions and resolved correctness items.
- Most important review items:
  - Decide whether model checkpoints should stay excluded or be provided as a separate local artifact.
  - Keep third-party raw package corpora out of the submitted Git history unless provenance/licensing is fully confirmed.

## Suggested Submission Packaging

Zip the repository folder itself after confirming the local Git repo is present:

```text
SupplyGuard.zip
`-- SupplyGuard/
    |-- .git/
    |-- supplyguard/
    |-- tests/
    |-- Dockerfile
    |-- README.md
    `-- ...
```

Do not include ignored generated folders, virtual environments, node modules, raw downloaded package corpora, processed graph tensors, or model checkpoint binaries unless you intentionally decide otherwise.
