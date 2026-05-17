import os
import shutil
import tempfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Any, List, Optional
import json

import httpx
import torch
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from pydantic import BaseModel

from supplyguard.model.gin_classifier import SupplyGuardGIN
from supplyguard.scanner.scan_pipeline import scan_package, ThresholdConfig

# Runtime knobs are environment-driven so Docker, local dev, and tests share one entrypoint.
PORT = int(os.getenv("PORT", 8000))
MODEL_PATH = os.getenv("MODEL_PATH", "checkpoints/best_model.pt")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 4))
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB max tarball size

app = FastAPI(title="SupplyGuard Scanner API", version="0.1.0")

# FastAPI keeps the model and worker pool here instead of rebuilding them per request.
class AppState:
    model: Optional[torch.nn.Module] = None
    device: str = "cpu"
    threshold_config: ThresholdConfig = ThresholdConfig()
    thread_pool: Optional[ThreadPoolExecutor] = None
    cache: Dict[str, dict] = {} # Process-local cache; the proxy has the durable Redis path.

state = AppState()

@app.on_event("startup")
async def startup_event():
    # Detect device
    state.device = "cuda" if torch.cuda.is_available() else "cpu"
    
    # Load model
    state.model = SupplyGuardGIN(
        node_feat_dim=35, metadata_dim=8, hidden_dim=128,
        num_gin_layers=4, num_edge_types=4, dropout=0.3
    )
    
    if os.path.exists(MODEL_PATH):
        try:
            checkpoint = torch.load(MODEL_PATH, map_location=state.device, weights_only=False)
            state.model.load_state_dict(checkpoint["model_state_dict"])
            state.model.to(state.device)
            state.model.eval()
            print(f"Loaded model from {MODEL_PATH} on {state.device}")
        except Exception as e:
            print(f"Failed to load model: {e}")
    else:
        print(f"Warning: Model not found at {MODEL_PATH}. GNN scans will fail.")
        
    state.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

@app.on_event("shutdown")
async def shutdown_event():
    if state.thread_pool:
        state.thread_pool.shutdown()

class PackageRequest(BaseModel):
    name: str
    version: str

def _run_pipeline(package_dir: str, package_name: str, version: str) -> dict:
    try:
        # Keep the HTTP response shape stable even when scanner internals evolve.
        res = scan_package(
            package_dir=package_dir,
            model=state.model,
            device=state.device,
            threshold_config=state.threshold_config
        )
        
        fallback = None
        if res.gnn_score < 0: fallback = "rules_only"
        elif res.rules_result is None or not res.rules_result.matched_rules and res.rules_result.total_score == 0: 
            pass
            
        rules_matched = []
        if res.rules_result:
            for r in res.rules_result.matched_rules:
                rules_matched.append({
                    "rule_id": r.rule_id,
                    "severity": r.severity,
                    "description": r.description,
                    "file_path": r.file_path,
                    "line_number": r.line_number,
                    "matched_snippet": getattr(r, "matched_code_snippet", "")
                })

        out = {
            "package_name": package_name,
            "version": version,
            "verdict": res.verdict,
            "confidence": res.confidence,
            "gnn_score": res.gnn_score,
            "decision_path": res.decision_path,
            "rules_matched": rules_matched,
            "evidence": res.evidence,
            "scan_time_ms": res.elapsed_ms
        }
        if fallback:
            out["fallback"] = fallback
        return out
    except Exception as e:
        return {
            "package_name": package_name,
            "version": version,
            "verdict": "error",
            "error_msg": str(e),
            "confidence": 0.0,
            "gnn_score": -1.0,
            "decision_path": "error",
            "rules_matched": [],
            "evidence": [],
            "scan_time_ms": 0.0
        }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": state.model is not None,
        "device": state.device,
        "model_checkpoint": MODEL_PATH,
        "threshold_config": {
            "gnn_auto_pass": state.threshold_config.gnn_auto_pass,
            "gnn_auto_block": state.threshold_config.gnn_auto_block
        }
    }

@app.post("/scan/tarball")
async def scan_tarball(tarball: UploadFile = File(...)):
    if not tarball.filename.endswith(".tgz") and not tarball.filename.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail={"error": "Invalid tarball format"})
        
    temp_dir = tempfile.mkdtemp()
    try:
        tar_path = os.path.join(temp_dir, "package.tgz")
        with open(tar_path, "wb") as f:
            shutil.copyfileobj(tarball.file, f)
            
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        shutil.unpack_archive(tar_path, extract_dir)
        
        pkg_dir = os.path.join(extract_dir, "package")
        if not os.path.exists(pkg_dir):
            pkg_dir = extract_dir
            
        return _run_pipeline(pkg_dir, tarball.filename, "unknown")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

async def download_package(name: str, version: str, dest_dir: str):
    if name.startswith("@"):
        scope, pkg = name.split("/")
        url_name = f"{scope}%2f{pkg}"
    else:
        url_name = name
        
    url = f"https://registry.npmjs.org/{url_name}/-/{name.split('/')[-1]}-{version}.tgz"
    
    tar_path = os.path.join(dest_dir, "package.tgz")
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=30.0)
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail={"error": "Package not found on npm registry"})
        resp.raise_for_status()
        
        with open(tar_path, "wb") as f:
            f.write(resp.content)
            
    return tar_path

@app.post("/scan/package")
async def scan_package_endpoint(req: PackageRequest):
    temp_dir = tempfile.mkdtemp()
    try:
        tar_path = await download_package(req.name, req.version, temp_dir)
        
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        shutil.unpack_archive(tar_path, extract_dir)
        
        pkg_dir = os.path.join(extract_dir, "package")
        if not os.path.exists(pkg_dir):
            pkg_dir = extract_dir
            
        return _run_pipeline(pkg_dir, req.name, req.version)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def scan_single_sync(name: str, version: str) -> dict:
    cache_key = f"{name}@{version}"
    if cache_key in state.cache:
        return state.cache[cache_key]
        
    temp_dir = tempfile.mkdtemp()
    try:
        if name.startswith("@"):
            scope, pkg = name.split("/")
            url_name = f"{scope}%2f{pkg}"
        else:
            url_name = name
            
        url = f"https://registry.npmjs.org/{url_name}/-/{name.split('/')[-1]}-{version}.tgz"
        
        tar_path = os.path.join(temp_dir, "package.tgz")
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return {"package_name": name, "version": version, "verdict": "error", "error_msg": "Download failed"}
            with open(tar_path, "wb") as f:
                f.write(resp.content)
                
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        shutil.unpack_archive(tar_path, extract_dir)
        
        pkg_dir = os.path.join(extract_dir, "package")
        if not os.path.exists(pkg_dir):
            pkg_dir = extract_dir
            
        res = _run_pipeline(pkg_dir, name, version)
        state.cache[cache_key] = res
        return res
    except Exception as e:
        return {"package_name": name, "version": version, "verdict": "error", "error_msg": str(e)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/scan/lockfile")
async def scan_lockfile(lockfile: UploadFile = File(...)):
    content = await lockfile.read()
    try:
        lock_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail={"error": "Invalid lockfile JSON"})
        
    deps = lock_data.get("dependencies", {})
    if not deps and "packages" in lock_data:
        deps = {k.replace("node_modules/", ""): v for k, v in lock_data["packages"].items() if k and "version" in v}
        
    if not deps:
        return {"total_packages": 0, "scan_time_seconds": 0, "results": {"clean": 0, "suspicious": 0, "malicious": 0}, "flagged_packages": []}
        
    import time
    t0 = time.time()
    
    import asyncio
    loop = asyncio.get_running_loop()
    
    tasks = []
    for name, info in deps.items():
        if isinstance(info, dict) and "version" in info:
            version = info["version"]
            tasks.append(loop.run_in_executor(state.thread_pool, scan_single_sync, name, version))
            
    results = await asyncio.gather(*tasks)
    
    scan_time = time.time() - t0
    
    summary = {"clean": 0, "suspicious": 0, "malicious": 0, "error": 0}
    flagged = []
    
    for r in results:
        verdict = r.get("verdict", "error")
        if verdict in summary:
            summary[verdict] += 1
        if verdict in ("suspicious", "malicious"):
            flagged.append(r)
            
    return {
        "total_packages": len(tasks),
        "scan_time_seconds": round(scan_time, 2),
        "results": summary,
        "flagged_packages": flagged
    }
