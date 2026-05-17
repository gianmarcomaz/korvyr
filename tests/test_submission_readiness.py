from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_submission_required_files_exist():
    # Project Silver expects a normal repo shape, not only an application folder.
    for rel_path in ("README.md", "Dockerfile", "pyproject.toml", "tests"):
        assert (ROOT / rel_path).exists(), f"missing required submission path: {rel_path}"


def test_dockerignore_does_not_hide_git_history():
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    blocked_entries = {
        line.strip()
        for line in dockerignore.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    assert ".git" not in blocked_entries
    assert ".git/" not in blocked_entries


def test_gitignore_excludes_generated_heavy_artifacts():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    for pattern in ("venv/", "node_modules/", "data/raw/", "data/processed/", "checkpoints/"):
        assert pattern in gitignore
