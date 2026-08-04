"""
Download and extract npm malicious packages from the Datadog
malicious-software-packages-dataset into data/raw/malicious/.

Downloads the repo as a ZIP archive (avoids git-clone issues with
invalid Windows file paths), then walks through the embedded sample
ZIPs and extracts npm packages.

Produces a CSV manifest at data/raw/malicious_manifest.csv with columns:
    package_name, version, ecosystem, path, num_js_files
"""

from __future__ import annotations

import csv
import io
import logging
import re
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from tqdm import tqdm

ARCHIVE_URL = (
    "https://github.com/DataDog/malicious-software-packages-dataset"
    "/archive/refs/heads/main.zip"
)
ZIP_PASSWORD = b"infected"

# Characters illegal in Windows file / directory names
_WIN_INVALID_RE = re.compile(r'[<>:"|?*\x00-\x1f]')

ROOT_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT_DIR / "data" / "raw"
REPO_DIR = RAW_DIR / "malicious_repo"
EXTRACT_DIR = RAW_DIR / "malicious"
MANIFEST_PATH = RAW_DIR / "malicious_manifest.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Windows path sanitisation
# ---------------------------------------------------------------------------

def _sanitize_name(name: str) -> str:
    """Replace characters that are illegal in Windows paths."""
    return _WIN_INVALID_RE.sub("_", name).rstrip(". ")


def _safe_extract_outer_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract the outer GitHub archive ZIP, sanitising member paths."""
    for info in zf.infolist():
        if info.is_dir():
            continue

        posix = PurePosixPath(info.filename)
        safe_parts = [_sanitize_name(p) for p in posix.parts]
        safe_rel = Path(*safe_parts) if safe_parts else None
        if safe_rel is None:
            continue

        target = dest / safe_rel

        if _WIN_INVALID_RE.search(info.filename):
            log.debug("Sanitised path: %s → %s", info.filename, safe_rel)

        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
        except OSError as exc:
            log.warning("Skipping file with problematic path %s: %s",
                        info.filename, exc)


# ---------------------------------------------------------------------------
# Download / extract the repo archive
# ---------------------------------------------------------------------------

def download_repo_archive() -> None:
    """Download the dataset repo as a ZIP and extract it into REPO_DIR."""
    if REPO_DIR.exists() and any(REPO_DIR.iterdir()):
        log.info("Repo archive already extracted at %s — skipping download",
                 REPO_DIR)
        return

    REPO_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Downloading repo archive from GitHub …")
    with urllib.request.urlopen(ARCHIVE_URL, timeout=300) as resp:
        archive_bytes = resp.read()
    log.info("Downloaded %.1f MB", len(archive_bytes) / 1e6)

    log.info("Extracting archive into %s …", REPO_DIR)
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        _safe_extract_outer_zip(zf, REPO_DIR)

    log.info("Archive extraction complete")


# ---------------------------------------------------------------------------
# Discover the inner sample ZIPs
# ---------------------------------------------------------------------------

def _find_samples_dir() -> Path:
    """Locate the samples/ directory inside the extracted archive.

    GitHub wraps the repo in a top-level folder like
    ``malicious-software-packages-dataset-main/``.
    """
    for child in REPO_DIR.iterdir():
        candidate = child / "samples"
        if candidate.is_dir():
            return candidate

    samples_direct = REPO_DIR / "samples"
    if samples_direct.is_dir():
        return samples_direct

    log.error("samples/ directory not found under %s", REPO_DIR)
    sys.exit(1)


def discover_zips(samples_dir: Path) -> list[Path]:
    return sorted(samples_dir.rglob("*.zip"))


# ---------------------------------------------------------------------------
# Parse the repo-relative path of each sample ZIP
# ---------------------------------------------------------------------------

def parse_zip_path(
    zip_path: Path, samples_dir: Path,
) -> tuple[str, str, str] | None:
    """Return (ecosystem, package_name, version) from the path.

    Expected layout under samples/:
        {ecosystem}/{category}/{package_name}/{version}/{date}-{name}-v{ver}.zip
    """
    try:
        rel = zip_path.relative_to(samples_dir)
        parts = rel.parts
        if len(parts) < 4:
            return None
        ecosystem = parts[0]
        package_name = parts[2]
        version = parts[3]
        return ecosystem, package_name, version
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def count_js_files(directory: Path) -> int:
    return sum(1 for _ in directory.rglob("*.js"))


def extract_sample_zip(zip_path: Path, dest: Path) -> bool:
    """Extract a password-protected sample ZIP into *dest*."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(path=dest, pwd=ZIP_PASSWORD)
        return True
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        log.warning("Skipping corrupted / unreadable ZIP %s: %s",
                    zip_path.name, exc)
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    download_repo_archive()

    samples_dir = _find_samples_dir()
    all_zips = discover_zips(samples_dir)
    log.info("Found %d ZIP files in repository", len(all_zips))

    npm_zips = []
    for zp in all_zips:
        parsed = parse_zip_path(zp, samples_dir)
        if parsed and parsed[0] == "npm":
            npm_zips.append((zp, *parsed))

    log.info("Filtered to %d npm ZIP files", len(npm_zips))

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict] = []

    for zip_path, ecosystem, package_name, version in tqdm(
        npm_zips, desc="Extracting npm packages", unit="pkg",
    ):
        dest = EXTRACT_DIR / ecosystem / _sanitize_name(package_name) / version
        dest.mkdir(parents=True, exist_ok=True)

        if not extract_sample_zip(zip_path, dest):
            continue

        num_js = count_js_files(dest)
        manifest_rows.append({
            "package_name": package_name,
            "version": version,
            "ecosystem": ecosystem,
            "path": str(dest.relative_to(ROOT_DIR)),
            "num_js_files": num_js,
        })

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "package_name", "version", "ecosystem", "path", "num_js_files",
            ],
        )
        writer.writeheader()
        writer.writerows(manifest_rows)

    log.info(
        "Done — extracted %d packages, manifest written to %s",
        len(manifest_rows),
        MANIFEST_PATH,
    )


if __name__ == "__main__":
    main()
