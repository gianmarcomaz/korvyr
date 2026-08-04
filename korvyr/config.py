"""Runtime configuration for the Korvyr scanner service and CLI.

Every knob is read from a ``KORVYR_``-prefixed environment variable so the
Docker image, docker-compose stack, CI, and local runs share one source of
truth. See ``.env.example`` for the documented defaults.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Default location of the trained GNN checkpoint, relative to the working
#: directory. The checkpoint is NOT distributed with this repository; see
#: "GNN checkpoint" in the README.
DEFAULT_MODEL_PATH = "models/gnn_v2_cuda.pt"

#: Largest tarball the API will accept, in bytes.
DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in _TRUE_VALUES


def model_path() -> Path:
    """Path to the GNN checkpoint (``KORVYR_MODEL_PATH``)."""
    return Path(_env_str("KORVYR_MODEL_PATH", DEFAULT_MODEL_PATH))


def require_gnn() -> bool:
    """Whether a missing/unloadable checkpoint is a fatal error.

    ``KORVYR_REQUIRE_GNN=true`` makes the API refuse to start without a
    working checkpoint instead of silently degrading to static-only scanning.
    Use it in deployments where a hybrid verdict is the contract.
    """
    return _env_bool("KORVYR_REQUIRE_GNN", False)


def api_port() -> int:
    """Port the FastAPI service binds to (``KORVYR_API_PORT``)."""
    return _env_int("KORVYR_API_PORT", 8000)


def max_workers() -> int:
    """Thread-pool size for lockfile fan-out scans (``KORVYR_MAX_WORKERS``)."""
    return _env_int("KORVYR_MAX_WORKERS", 4)


def max_upload_bytes() -> int:
    """Upload size ceiling for ``/scan/tarball`` (``KORVYR_MAX_UPLOAD_BYTES``)."""
    return _env_int("KORVYR_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)


def registry_url() -> str:
    """Upstream npm registry used for package downloads (``KORVYR_REGISTRY_URL``)."""
    return _env_str("KORVYR_REGISTRY_URL", "https://registry.npmjs.org").rstrip("/")


def api_url() -> str:
    """Scanner API base URL used by the CLI (``KORVYR_API_URL``)."""
    return _env_str("KORVYR_API_URL", "http://localhost:8000").rstrip("/")
