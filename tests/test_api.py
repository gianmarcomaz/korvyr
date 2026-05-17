import io
import json
import os
import tarfile
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from supplyguard.api.server import app, state

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model_loaded" in data

@mock.patch("supplyguard.api.server._run_pipeline")
def test_scan_package_clean(mock_pipeline):
    mock_pipeline.return_value = {
        "package_name": "is-number",
        "version": "7.0.0",
        "verdict": "clean",
        "confidence": 0.99,
        "gnn_score": 0.01,
        "decision_path": "GNN confident clean",
        "rules_matched": [],
        "evidence": [],
        "scan_time_ms": 10.0
    }
    
    # We mock download_package so we don't actually hit npm in tests
    with mock.patch("supplyguard.api.server.download_package") as mock_dl:
        mock_dl.return_value = "dummy.tgz"
        with mock.patch("shutil.unpack_archive"):
            response = client.post("/scan/package", json={"name": "is-number", "version": "7.0.0"})
            
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "clean"
    assert data["package_name"] == "is-number"

@mock.patch("supplyguard.api.server._run_pipeline")
def test_scan_tarball_malicious(mock_pipeline):
    mock_pipeline.return_value = {
        "package_name": "evil-pkg",
        "version": "unknown",
        "verdict": "malicious",
        "confidence": 0.94,
        "gnn_score": 0.87,
        "decision_path": "GNN high confidence (0.87) + CRITICAL rule",
        "rules_matched": [{"rule_id": "CRIT_INSTALL_HOOK_NETWORK", "severity": "critical", "description": "...", "file_path": "a", "line_number": 1, "matched_snippet": "a"}],
        "evidence": [],
        "scan_time_ms": 10.0
    }
    
    # Create a dummy tarball in memory
    tar_io = io.BytesIO()
    with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
        dummy_info = tarfile.TarInfo("package/package.json")
        dummy_info.size = 2
        tar.addfile(dummy_info, io.BytesIO(b"{}"))
    tar_io.seek(0)
    
    response = client.post(
        "/scan/tarball", 
        files={"tarball": ("evil.tgz", tar_io, "application/gzip")}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert len(data["rules_matched"]) > 0

@mock.patch("supplyguard.api.server.scan_single_sync")
def test_scan_lockfile(mock_scan):
    # Mock behavior: 2 clean, 1 malicious
    def side_effect(name, version):
        if name == "evil-pkg":
            return {"package_name": name, "version": version, "verdict": "malicious"}
        return {"package_name": name, "version": version, "verdict": "clean"}
    mock_scan.side_effect = side_effect
    
    lockfile_data = {
        "name": "my-project",
        "version": "1.0.0",
        "dependencies": {
            "is-number": {"version": "7.0.0"},
            "is-odd": {"version": "3.0.0"},
            "evil-pkg": {"version": "1.0.0"}
        }
    }
    
    lockfile_bytes = json.dumps(lockfile_data).encode("utf-8")
    
    response = client.post(
        "/scan/lockfile",
        files={"lockfile": ("package-lock.json", lockfile_bytes, "application/json")}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["total_packages"] == 3
    assert data["results"]["clean"] == 2
    assert data["results"]["malicious"] == 1
    assert len(data["flagged_packages"]) == 1

def test_invalid_tarball():
    response = client.post(
        "/scan/tarball", 
        files={"tarball": ("not-a-tarball.txt", b"hello", "text/plain")}
    )
    assert response.status_code == 400

@mock.patch("httpx.AsyncClient.get", new_callable=mock.AsyncMock)
def test_package_not_found(mock_get):
    mock_resp = mock.Mock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp
    
    response = client.post("/scan/package", json={"name": "does-not-exist-abc", "version": "1.0.0"})
    assert response.status_code == 404
