"""
Download benign npm packages for the Korvyr dataset.

Phase 1 — Top 5,000 packages by popularity via the npm search API.
Phase 2 — 15,000 diverse packages via varied search queries and the
          replicate/_all_docs endpoint as a fallback.

Tarballs are extracted into  data/raw/benign/{package_name}/{version}/
A CSV manifest is written to  data/raw/benign_manifest.csv

Rate-limited to 5 requests/second.  Packages with zero .js files after
extraction are deleted and omitted from the manifest.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import random
import shutil
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from tqdm import tqdm

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
REGISTRY_URL = "https://registry.npmjs.org"
ALL_DOCS_URL = "https://replicate.npmjs.com/_all_docs"

ROOT_DIR = Path(__file__).resolve().parent.parent
EXTRACT_DIR = ROOT_DIR / "data" / "raw" / "benign"
MANIFEST_PATH = ROOT_DIR / "data" / "raw" / "benign_manifest.csv"

TARGET_POPULAR = 5_000
TARGET_RANDOM = 15_000
TARGET_TOTAL = TARGET_POPULAR + TARGET_RANDOM

REQUESTS_PER_SEC = 5
PAGE_SIZE = 250

# Broad search terms used to gather a diverse set of packages in Phase 2.
DIVERSE_QUERIES = [
    "javascript", "node", "react", "typescript", "server", "utils", "cli",
    "api", "test", "data", "file", "web", "build", "tool", "lib", "config",
    "http", "json", "string", "array", "event", "stream", "path", "url",
    "crypto", "auth", "log", "error", "parse", "format", "validate",
    "convert", "css", "html", "dom", "component", "module", "plugin",
    "middleware", "router", "database", "mongo", "redis", "sql", "graphql",
    "rest", "websocket", "async", "promise", "queue", "cache", "storage",
    "email", "image", "video", "pdf", "csv", "xml", "yaml", "markdown",
    "webpack", "babel", "eslint", "jest", "mocha", "express", "fastify",
    "koa", "next", "vue", "angular", "svelte", "electron", "aws", "azure",
    "google", "docker", "kubernetes", "terraform", "git", "npm", "yarn",
    "lint", "debug", "proxy", "compress", "crypto", "token", "session",
    "upload", "download", "template", "render", "chart", "table", "form",
    "input", "button", "modal", "toast", "icon", "color", "theme", "font",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    def __init__(self, rps: int) -> None:
        self._interval = 1.0 / rps
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        remaining = self._interval - (now - self._last)
        if remaining > 0:
            time.sleep(remaining)
        self._last = time.monotonic()


_limiter = _RateLimiter(REQUESTS_PER_SEC)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _fetch_json(url: str, retries: int = 2) -> dict | None:
    """GET *url*, parse JSON, return dict or None on failure."""
    for attempt in range(1, retries + 2):
        _limiter.wait()
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except (urllib.error.HTTPError, urllib.error.URLError,
                json.JSONDecodeError, TimeoutError, OSError) as exc:
            if attempt > retries:
                log.debug("GET %s failed after %d attempts: %s", url, attempt, exc)
                return None
            time.sleep(1.0 * attempt)
    return None


def _download_bytes(url: str) -> bytes | None:
    """Download raw bytes from *url*, return None on failure."""
    _limiter.wait()
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except (urllib.error.HTTPError, urllib.error.URLError,
            TimeoutError, OSError) as exc:
        log.debug("Download %s failed: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Tarball helpers
# ---------------------------------------------------------------------------

def _tarball_url(name: str, version: str) -> str:
    """Construct the npm tarball URL for a package."""
    short_name = name.split("/", 1)[1] if name.startswith("@") else name
    quoted = urllib.parse.quote(name, safe="@/")
    return f"{REGISTRY_URL}/{quoted}/-/{short_name}-{version}.tgz"


def _extract_tgz(tgz_bytes: bytes, dest: Path) -> bool:
    """Extract a .tgz into *dest*.  Returns True on success."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
            tf.extractall(path=dest, filter="data")
        return True
    except (tarfile.TarError, OSError, EOFError) as exc:
        log.warning("Extraction failed for %s: %s", dest.name, exc)
        return False


def _count_js_files(directory: Path) -> int:
    return sum(1 for _ in directory.rglob("*.js"))


# ---------------------------------------------------------------------------
# Phase 1 — popular packages via search API
# ---------------------------------------------------------------------------

def fetch_popular_packages() -> list[dict]:
    """Return up to TARGET_POPULAR packages sorted by popularity."""
    packages: list[dict] = []
    seen: set[str] = set()

    pages = (TARGET_POPULAR + PAGE_SIZE - 1) // PAGE_SIZE
    for page in tqdm(range(pages), desc="Phase 1 — popular discovery"):
        offset = page * PAGE_SIZE
        url = (
            f"{SEARCH_URL}?text=javascript&popularity=1.0"
            f"&size={PAGE_SIZE}&from={offset}"
        )
        data = _fetch_json(url)
        if not data or not data.get("objects"):
            log.warning("Search returned no results at offset %d", offset)
            break

        for obj in data["objects"]:
            pkg = obj["package"]
            name = pkg["name"]
            if name in seen:
                continue
            seen.add(name)
            packages.append({
                "name": name,
                "version": pkg["version"],
                "weekly_downloads": obj.get("downloads", {}).get("weekly", 0),
            })

    log.info("Phase 1 discovered %d popular packages", len(packages))
    return packages[:TARGET_POPULAR]


# ---------------------------------------------------------------------------
# Phase 2 — diverse / random packages
# ---------------------------------------------------------------------------

def _fetch_diverse_via_search(
    exclude: set[str],
    target: int,
) -> list[dict]:
    """Gather diverse packages by issuing varied search queries."""
    packages: list[dict] = []
    seen = set(exclude)

    random.shuffle(DIVERSE_QUERIES)

    pbar = tqdm(total=target, desc="Phase 2a — diverse search")

    for query in DIVERSE_QUERIES:
        if len(packages) >= target:
            break

        max_offset = 8000
        offset = random.randint(0, max_offset)
        offset -= offset % PAGE_SIZE

        url = (
            f"{SEARCH_URL}?text={urllib.parse.quote(query)}"
            f"&popularity=1.0&size={PAGE_SIZE}&from={offset}"
        )
        data = _fetch_json(url)
        if not data or not data.get("objects"):
            continue

        for obj in data["objects"]:
            pkg = obj["package"]
            name = pkg["name"]
            if name in seen:
                continue
            seen.add(name)
            packages.append({
                "name": name,
                "version": pkg["version"],
                "weekly_downloads": obj.get("downloads", {}).get("weekly", 0),
            })
            pbar.update(1)
            if len(packages) >= target:
                break

    pbar.close()
    log.info("Phase 2a found %d diverse packages via search", len(packages))
    return packages


def _fetch_random_via_all_docs(
    exclude: set[str],
    target: int,
) -> list[dict]:
    """Fill remaining quota by sampling the replicate/_all_docs endpoint."""
    if target <= 0:
        return []

    data = _fetch_json(f"{ALL_DOCS_URL}?limit=0")
    if not data:
        log.error("Could not reach replicate endpoint — skipping random fill")
        return []
    total_rows = data["total_rows"]

    packages: list[dict] = []
    seen = set(exclude)
    offsets = random.sample(range(0, total_rows, 100), min(target * 3, total_rows // 100))

    pbar = tqdm(total=target, desc="Phase 2b — random _all_docs")

    for skip in offsets:
        if len(packages) >= target:
            break

        batch = _fetch_json(f"{ALL_DOCS_URL}?skip={skip}&limit=100")
        if not batch or not batch.get("rows"):
            continue

        for row in batch["rows"]:
            if len(packages) >= target:
                break
            name = row["id"]
            if name.startswith("_") or name in seen:
                continue
            seen.add(name)

            meta = _fetch_json(
                f"{REGISTRY_URL}/{urllib.parse.quote(name, safe='@/')}/latest"
            )
            if not meta or "version" not in meta:
                continue

            packages.append({
                "name": name,
                "version": meta["version"],
                "weekly_downloads": 0,
            })
            pbar.update(1)

    pbar.close()
    log.info("Phase 2b found %d random packages via _all_docs", len(packages))
    return packages


# ---------------------------------------------------------------------------
# Download + extract
# ---------------------------------------------------------------------------

def download_and_extract(
    packages: list[dict],
) -> list[dict]:
    """Download tarballs, extract, return manifest rows for kept packages."""
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []

    for pkg in tqdm(packages, desc="Downloading & extracting", unit="pkg"):
        name = pkg["name"]
        version = pkg["version"]
        dest = EXTRACT_DIR / name / version

        if dest.exists() and any(dest.iterdir()):
            num_js = _count_js_files(dest)
            if num_js > 0:
                manifest.append({
                    "package_name": name,
                    "version": version,
                    "path": str(dest.relative_to(ROOT_DIR)),
                    "weekly_downloads": pkg["weekly_downloads"],
                    "num_js_files": num_js,
                })
                continue

        url = _tarball_url(name, version)
        tgz = _download_bytes(url)

        if tgz is None:
            meta = _fetch_json(
                f"{REGISTRY_URL}/{urllib.parse.quote(name, safe='@/')}/latest"
            )
            if meta and meta.get("dist", {}).get("tarball"):
                tgz = _download_bytes(meta["dist"]["tarball"])

        if tgz is None:
            log.debug("Could not download tarball for %s@%s", name, version)
            continue

        dest.mkdir(parents=True, exist_ok=True)
        if not _extract_tgz(tgz, dest):
            shutil.rmtree(dest, ignore_errors=True)
            continue

        num_js = _count_js_files(dest)
        if num_js == 0:
            shutil.rmtree(dest, ignore_errors=True)
            continue

        manifest.append({
            "package_name": name,
            "version": version,
            "path": str(dest.relative_to(ROOT_DIR)),
            "weekly_downloads": pkg["weekly_downloads"],
            "num_js_files": num_js,
        })

    return manifest


# ---------------------------------------------------------------------------
# Manifest writer
# ---------------------------------------------------------------------------

MANIFEST_FIELDS = [
    "package_name", "version", "path", "weekly_downloads", "num_js_files",
]


def write_manifest(rows: list[dict]) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    log.info("Manifest written to %s (%d rows)", MANIFEST_PATH, len(rows))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=== Korvyr benign dataset download ===")
    log.info("Target: %d popular + %d diverse/random = %d total",
             TARGET_POPULAR, TARGET_RANDOM, TARGET_TOTAL)

    # Phase 1
    popular = fetch_popular_packages()
    popular_names = {p["name"] for p in popular}

    # Phase 2a — diverse search
    diverse = _fetch_diverse_via_search(popular_names, TARGET_RANDOM)
    diverse_names = {p["name"] for p in diverse}

    # Phase 2b — fill remaining from _all_docs if needed
    shortfall = TARGET_RANDOM - len(diverse)
    random_fill: list[dict] = []
    if shortfall > 0:
        random_fill = _fetch_random_via_all_docs(
            popular_names | diverse_names, shortfall,
        )

    all_packages = popular + diverse + random_fill
    log.info("Total packages collected: %d", len(all_packages))

    # Download, extract, filter
    manifest = download_and_extract(all_packages)

    # Write manifest
    write_manifest(manifest)
    log.info("Done — %d benign packages with JS files retained.", len(manifest))


if __name__ == "__main__":
    main()
