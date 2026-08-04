"""Guards on what this repository publishes.

These assertions encode release decisions that are easy to undo by accident:
the rename must stay complete, the public-facing documents must stay present,
and the corpora/checkpoints/results that must never be committed must stay
ignored.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

LEGACY_NAMES = re.compile(
    r"supplyguard|supply_guard|supply-guard|GNN-npm-Vulnerabilities", re.IGNORECASE
)

# The only files allowed to name the pre-release project: the migration guide
# that tells existing users what was renamed, and the two places that enforce
# the rename (this test and the CI step that mirrors it).
LEGACY_NAME_ALLOWLIST = {
    "CHANGELOG.md",
    ".github/workflows/ci.yml",
    "tests/test_repo_hygiene.py",
}

REQUIRED_FILES = [
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".env.example",
    "Dockerfile",
    "docker-compose.yml",
    "pyproject.toml",
    ".github/workflows/ci.yml",
]

# Anything derived from the package corpus is either large, third-party, or
# actual malware. None of it belongs in a public repository. The patterns are
# root-anchored so korvyr/data/ and docs/results/ stay tracked.
MUST_BE_IGNORED = [
    "venv/",
    "node_modules/",
    "/data/",
    "/checkpoints/",
    "/models/",
    "/results/",
]


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return out.stdout.splitlines()


def test_required_public_files_exist():
    for rel_path in REQUIRED_FILES:
        assert (ROOT / rel_path).exists(), f"missing required file: {rel_path}"


def test_gitignore_excludes_generated_and_third_party_artifacts():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in MUST_BE_IGNORED:
        assert pattern in gitignore, f"{pattern} must stay git-ignored"


def test_no_legacy_project_names_in_tracked_files():
    """The rename to Korvyr must not regress."""
    offenders = []
    for rel_path in _tracked_files():
        path = ROOT / rel_path
        if not path.is_file() or path.suffix.lower() in {".png", ".jpg", ".ico", ".pt"}:
            continue
        if LEGACY_NAMES.search(rel_path):
            offenders.append(rel_path)
            continue
        if rel_path in LEGACY_NAME_ALLOWLIST:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if LEGACY_NAMES.search(text):
            offenders.append(rel_path)

    assert not offenders, f"legacy project names found in: {offenders}"


def test_no_absolute_local_paths_in_tracked_text():
    """Developer filesystem paths must not ship in documentation or code."""
    local_path = re.compile(r"[A-Z]:\\\\?Users\\\\?|/home/[a-z]+/|/Users/[a-z]+/")
    offenders = []
    for rel_path in _tracked_files():
        path = ROOT / rel_path
        if not path.is_file() or path.suffix.lower() not in {".md", ".py", ".js", ".yml", ".toml"}:
            continue
        if rel_path == "tests/test_repo_hygiene.py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if local_path.search(text):
            offenders.append(rel_path)

    assert not offenders, f"absolute local paths found in: {offenders}"


@pytest.mark.parametrize("directory", ["data", "checkpoints", "models", "results"])
def test_artifact_directories_are_untracked(directory):
    tracked = [f for f in _tracked_files() if f.startswith(f"{directory}/")]
    assert not tracked, f"{directory}/ must not be tracked, found: {tracked}"
