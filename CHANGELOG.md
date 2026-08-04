# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); while the version is
`0.x`, breaking changes may land in a minor release.

## [0.1.0] - 2026-08-04

First public release. The project was previously developed privately under the
name *SupplyGuard* in a repository named `GNN-npm-Vulnerabilities`; this release
renames it to **Korvyr** and prepares the codebase for public use.

### Breaking changes

Anyone with a working copy of the pre-release code must update the following.

- **Python package renamed** `supplyguard` → `korvyr`. Update every import:
  `from supplyguard.scanner...` → `from korvyr.scanner...`.
- **Distribution renamed** `supplyguard` → `korvyr`. Uninstall the old package
  before installing the new one:
  `pip uninstall supplyguard && pip install -e ".[test]"`.
- **CLI renamed** `supplyguard` → `korvyr`. The `supplyguard version` subcommand
  is replaced by `korvyr --version`.
- **Model class renamed** `SupplyGuardGIN` → `KorvyrGIN`. Existing checkpoints
  still load: they store a `model_state_dict`, not a pickled class.
- **All environment variables now use a `KORVYR_` prefix**, and the old names are
  no longer read:

  | Old | New |
  |---|---|
  | `MODEL_PATH` | `KORVYR_MODEL_PATH` |
  | `PORT` (API) | `KORVYR_API_PORT` |
  | `MAX_WORKERS` | `KORVYR_MAX_WORKERS` |
  | `PORT` (proxy) | `KORVYR_PROXY_PORT` |
  | `SCAN_API_URL` | `KORVYR_SCAN_API_URL` |
  | `UPSTREAM_REGISTRY` | `KORVYR_REGISTRY_URL` |
  | `SCAN_TIMEOUT` | `KORVYR_SCAN_TIMEOUT` |
  | `REDIS_URL` | `KORVYR_REDIS_URL` |
  | `FAIL_MODE` | `KORVYR_FAIL_MODE` |
  | `CACHE_TTL` | `KORVYR_CACHE_TTL` |
  | `MAX_TARBALL_SIZE` | `KORVYR_MAX_TARBALL_SIZE` |
  | `LOG_LEVEL` | `KORVYR_LOG_LEVEL` |

- **Docker Compose services renamed** `scanner`/`proxy`/`redis` →
  `korvyr-scanner`/`korvyr-proxy`/`korvyr-redis`, on a named `korvyr` network.
  The scanner now mounts `./models` read-only instead of `./checkpoints`.
- **`Dockerfile.backend` removed.** It duplicated `Dockerfile`; Compose now
  builds from `Dockerfile`.
- **Minimum Python is now 3.10** (was 3.9).
- **`pytest.ini` and `setup.py` removed.** Both are now expressed in
  `pyproject.toml`.
- **The CPG failure CSV is no longer written by default.** Set
  `KORVYR_CPG_FAILURE_LOG` to a path to re-enable it. Previously the scanner
  wrote `data/processed/cpg_build_failures.csv` into the working tree as a side
  effect of scanning.

### Added

- **Static-only mode is now explicit.** With no GNN checkpoint the service runs
  on rules and manifest analysis alone and reports `"scan_mode": "static-only"`
  on `/health` and in every scan response; the CLI labels such verdicts. Setting
  `KORVYR_REQUIRE_GNN=true` makes a missing or unloadable checkpoint a startup
  failure with an actionable message instead of a silent downgrade.
- `korvyr status` command showing API reachability, scan mode, device, and
  checkpoint path.
- `korvyr/config.py` — one place where all `KORVYR_*` runtime configuration is
  read.
- `korvyr/model/checkpoint.py` — one place where the model architecture is
  declared and checkpoints are loaded, with `CheckpointError` for required loads.
- `korvyr/scanner/tarball.py` — safe extraction of untrusted tarballs. Archive
  members that would escape the destination are rejected and links are skipped;
  previously extraction used `shutil.unpack_archive` with no member validation.
- Upload size limits are now enforced: `KORVYR_MAX_UPLOAD_BYTES` on the API
  (previously declared but unused) and `KORVYR_MAX_TARBALL_SIZE` on the proxy.
- `KORVYR_FAIL_MODE=closed` on the proxy now works. It refuses unscannable
  packages with `503`; previously the setting existed in config but was never
  read, and the proxy always failed open.
- Proxy log level filtering and a configurable log file path; a read-only log
  destination no longer crashes the proxy.
- `.env.example`, `CONTRIBUTING.md`, `SECURITY.md`, `CITATION.cff`, this
  changelog, and a GitHub Actions CI workflow.
- `docs/`: architecture walkthrough, API reference, proxy deployment notes,
  evaluation history, and the aggregate metrics of the run matching the shipped
  default policy.
- Tests for safe tarball extraction, static-only reporting, and proxy
  fail-closed mode.

### Changed

- The API now uses a FastAPI lifespan handler instead of the deprecated
  `on_event` hooks.
- Download, extraction, and pipeline invocation are shared between
  `/scan/tarball`, `/scan/package`, and the lockfile fan-out instead of being
  written out three times.
- The proxy's tarball handler no longer repeats the same forward-the-buffer
  branch four times; unscannable packages route through a single
  `handleUnscannable` path that honours the fail mode.
- Overclaiming user-facing copy was rewritten. The proxy's block response no
  longer calls itself an "Agentic Firewall" or asserts "structural malicious
  intent"; it reports a verdict, its evidence, and that Korvyr is a research
  prototype. The dashboard copy was toned down correspondingly.
- The dashboard's proxy URL is configurable via `VITE_KORVYR_PROXY_URL` instead
  of being hard-coded.
- `pip install -e .` no longer packages `tests`, `data`, or other non-source
  directories.
- The proxy image installs with `npm ci --omit=dev` from the committed lockfile
  instead of `npm install --production`.

### Removed

- `korvyr/scanner/two_stage.py` and `scripts/evaluate_two_stage.py` — a
  superseded prototype of the hybrid decision layer, unreachable from the
  runtime and carrying its own duplicate copy of the rule vocabulary.
- `scripts/evaluate_hybrid.py`, `scripts/evaluate_hybrid_real.py`,
  `scripts/evaluate_precision.py`, `scripts/evaluate_rules_standalone.py`,
  `scripts/diagnose_cpg_failures.py`, `scripts/sweep_json.py` — superseded by
  `scripts/evaluate_production.py`, which replays the real scan path and already
  reports GNN-only, rules-only, and hybrid metrics plus CPG diagnostics.
- `scripts/test_rev_shell.py`, `scripts/test_rev_shell_2.py` — one-off regex
  tuning scripts that required a local malware corpus.
- Three empty placeholder modules: `korvyr/scanner/package_downloader.py`,
  `korvyr/graph/feature_engineering.py`, and `korvyr/model/explainer.py`.
- The hand-rolled Pillow chart fallback in `scripts/plot_diagnostics.py`;
  matplotlib (the `research` extra) is now required, and the aspirational target
  lines were dropped from the plots.
- Duplicate implementations of `package.json` reading (six copies) and bounded
  Levenshtein distance (two copies), now in `korvyr/utils.py`.
- Internal development notes (`DECISION.md`, `SUMMARY.md`, `READMECHANGES.md`,
  `Results_Finetue.md`, `hybrid_pipeline_summary.md`) and the LLM build prompts
  that had been checked in as documentation (`api_cli.md`, `proxy.md`). The
  measurements worth keeping were carried into `docs/evaluation.md`; the stale
  precision claims in those files were not.
- Two tracked evaluation reports that embedded absolute local filesystem paths,
  and a generated threshold-sweep JSON nothing referenced.

### Fixed

- Unused imports and dead locals across the package, scripts, and tests.
- A dead `fallback` branch in the API response builder that could never assign a
  value.
