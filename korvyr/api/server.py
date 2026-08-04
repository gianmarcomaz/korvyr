"""FastAPI service exposing the Korvyr hybrid scan pipeline over HTTP.

Endpoints:
    GET  /health         service, device, and scan-mode status
    POST /scan/tarball   scan an uploaded ``.tgz`` package
    POST /scan/package   download ``name@version`` from the registry and scan it
    POST /scan/lockfile  fan out over every pinned dependency in a lockfile

The service degrades to static-only scanning when no GNN checkpoint is
available, unless ``KORVYR_REQUIRE_GNN`` is set (see ``korvyr.config``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
import torch
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from korvyr import config
from korvyr.model.checkpoint import load_model, resolve_device
from korvyr.scanner.scan_pipeline import ThresholdConfig, scan_package
from korvyr.scanner.tarball import UnsafeTarballError, extract_package, tarball_url

log = logging.getLogger(__name__)

API_VERSION = "0.1.0"


class AppState:
    """Process-wide singletons: the model and worker pool are built once."""

    model: Optional[torch.nn.Module] = None
    device: str = "cpu"
    model_checkpoint_loaded: bool = False
    threshold_config: ThresholdConfig = ThresholdConfig()
    thread_pool: Optional[ThreadPoolExecutor] = None
    # Process-local memo for lockfile fan-out; the proxy owns the durable cache.
    cache: dict[str, dict] = {}


state = AppState()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    state.device = resolve_device("auto")
    model_path = config.model_path()
    state.model = load_model(model_path, state.device, required=config.require_gnn())
    state.model_checkpoint_loaded = state.model is not None
    if state.model_checkpoint_loaded:
        log.info("Korvyr API ready in hybrid mode (checkpoint %s)", model_path)
    else:
        log.warning(
            "Korvyr API ready in STATIC-ONLY mode: no GNN checkpoint at %s. "
            "Verdicts come from the rules engine and manifest scanner only.",
            model_path,
        )
    state.thread_pool = ThreadPoolExecutor(max_workers=config.max_workers())
    try:
        yield
    finally:
        if state.thread_pool:
            state.thread_pool.shutdown()


app = FastAPI(title="Korvyr Scanner API", version=API_VERSION, lifespan=lifespan)


class PackageRequest(BaseModel):
    name: str
    version: str


def scan_mode() -> str:
    """``hybrid`` when a checkpoint is loaded, otherwise ``static-only``."""
    return "hybrid" if state.model is not None else "static-only"


def _run_pipeline(package_dir: str, package_name: str, version: str) -> dict:
    """Run the scan pipeline and shape it into the stable HTTP payload."""
    try:
        res = scan_package(
            package_dir=package_dir,
            model=state.model,
            device=state.device,
            threshold_config=state.threshold_config,
        )

        rules_matched = []
        if res.rules_result:
            for rule in res.rules_result.matched_rules:
                rules_matched.append(
                    {
                        "rule_id": rule.rule_id,
                        "severity": rule.severity,
                        "description": rule.description,
                        "file_path": rule.file_path,
                        "line_number": rule.line_number,
                        "matched_snippet": getattr(rule, "matched_code_snippet", ""),
                    }
                )

        payload = {
            "package_name": package_name,
            "version": version,
            "verdict": res.verdict,
            "confidence": res.confidence,
            "gnn_score": res.gnn_score,
            "scan_mode": scan_mode(),
            "decision_path": res.decision_path,
            "rules_matched": rules_matched,
            "evidence": res.evidence,
            "scan_time_ms": res.elapsed_ms,
        }
        if res.gnn_score < 0:
            # Negative score means the GNN did not produce a verdict for this
            # package (no checkpoint, unparseable sources, or inference error).
            payload["fallback"] = "rules_only"
        return payload
    except Exception as exc:
        log.exception("Scan pipeline failed for %s", package_name)
        return {
            "package_name": package_name,
            "version": version,
            "verdict": "error",
            "error_msg": str(exc),
            "confidence": 0.0,
            "gnn_score": -1.0,
            "scan_mode": scan_mode(),
            "decision_path": "error",
            "rules_matched": [],
            "evidence": [],
            "scan_time_ms": 0.0,
        }


def _extract_and_scan(tar_path: str | Path, temp_dir: str, name: str, version: str) -> dict:
    """Unpack a downloaded tarball and run the pipeline over its package root."""
    extract_dir = Path(temp_dir) / "extracted"
    try:
        package_dir = extract_package(tar_path, extract_dir)
    except (UnsafeTarballError, tarfile.TarError) as exc:
        raise HTTPException(
            status_code=400, detail={"error": f"Could not unpack tarball: {exc}"}
        ) from exc
    return _run_pipeline(str(package_dir), name, version)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": API_VERSION,
        "scan_mode": scan_mode(),
        "model_loaded": state.model is not None,
        "model_checkpoint_loaded": state.model_checkpoint_loaded,
        "device": state.device,
        "model_checkpoint": str(config.model_path()),
        "threshold_config": {
            "gnn_auto_pass": state.threshold_config.gnn_auto_pass,
            "gnn_auto_block": state.threshold_config.gnn_auto_block,
        },
    }


@app.post("/scan/tarball")
async def scan_tarball(tarball: UploadFile = File(...)):
    filename = tarball.filename or ""
    if not filename.endswith((".tgz", ".tar.gz")):
        raise HTTPException(status_code=400, detail={"error": "Invalid tarball format"})

    max_bytes = config.max_upload_bytes()
    temp_dir = tempfile.mkdtemp(prefix="korvyr-")
    try:
        tar_path = Path(temp_dir) / "package.tgz"
        written = 0
        with tar_path.open("wb") as fh:
            while chunk := await tarball.read(1024 * 1024):
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail={"error": f"Tarball exceeds {max_bytes} bytes"},
                    )
                fh.write(chunk)

        return _extract_and_scan(tar_path, temp_dir, filename, "unknown")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def download_package(name: str, version: str, dest_dir: str) -> str:
    """Download ``name@version`` from the configured registry into *dest_dir*."""
    url = tarball_url(config.registry_url(), name, version)
    tar_path = Path(dest_dir) / "package.tgz"

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=30.0)
        if resp.status_code == 404:
            raise HTTPException(
                status_code=404, detail={"error": "Package not found on npm registry"}
            )
        resp.raise_for_status()
        tar_path.write_bytes(resp.content)

    return str(tar_path)


@app.post("/scan/package")
async def scan_package_endpoint(req: PackageRequest):
    temp_dir = tempfile.mkdtemp(prefix="korvyr-")
    try:
        tar_path = await download_package(req.name, req.version, temp_dir)
        return _extract_and_scan(tar_path, temp_dir, req.name, req.version)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def scan_single_sync(name: str, version: str) -> dict:
    """Blocking download-and-scan used by the lockfile thread pool."""
    cache_key = f"{name}@{version}"
    if cache_key in state.cache:
        return state.cache[cache_key]

    temp_dir = tempfile.mkdtemp(prefix="korvyr-")
    try:
        url = tarball_url(config.registry_url(), name, version)
        tar_path = Path(temp_dir) / "package.tgz"
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return {
                    "package_name": name,
                    "version": version,
                    "verdict": "error",
                    "error_msg": "Download failed",
                }
            tar_path.write_bytes(resp.content)

        package_dir = extract_package(tar_path, Path(temp_dir) / "extracted")
        result = _run_pipeline(str(package_dir), name, version)
        state.cache[cache_key] = result
        return result
    except Exception as exc:
        return {
            "package_name": name,
            "version": version,
            "verdict": "error",
            "error_msg": str(exc),
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _lockfile_dependencies(lock_data: dict) -> dict[str, dict]:
    """Return ``{name: entry}`` for both lockfile v1 and v2/v3 layouts."""
    deps = lock_data.get("dependencies", {})
    if deps:
        return deps
    packages = lock_data.get("packages", {})
    return {
        key.replace("node_modules/", ""): value
        for key, value in packages.items()
        if key and isinstance(value, dict) and "version" in value
    }


@app.post("/scan/lockfile")
async def scan_lockfile(lockfile: UploadFile = File(...)):
    content = await lockfile.read()
    try:
        lock_data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail={"error": "Invalid lockfile JSON"}) from exc

    deps = _lockfile_dependencies(lock_data)
    if not deps:
        return {
            "total_packages": 0,
            "scan_time_seconds": 0,
            "scan_mode": scan_mode(),
            "results": {"clean": 0, "suspicious": 0, "malicious": 0},
            "flagged_packages": [],
        }

    t0 = time.perf_counter()
    loop = asyncio.get_running_loop()
    tasks = [
        loop.run_in_executor(state.thread_pool, scan_single_sync, name, info["version"])
        for name, info in deps.items()
        if isinstance(info, dict) and "version" in info
    ]
    results = await asyncio.gather(*tasks)

    summary = {"clean": 0, "suspicious": 0, "malicious": 0, "error": 0}
    flagged = []
    for result in results:
        verdict = result.get("verdict", "error")
        if verdict in summary:
            summary[verdict] += 1
        if verdict in ("suspicious", "malicious"):
            flagged.append(result)

    return {
        "total_packages": len(tasks),
        "scan_time_seconds": round(time.perf_counter() - t0, 2),
        "scan_mode": scan_mode(),
        "results": summary,
        "flagged_packages": flagged,
    }
