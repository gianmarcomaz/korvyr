import io
import json
import tarfile
from unittest import mock

from fastapi.testclient import TestClient

from korvyr.api.server import _run_pipeline, app, state
from korvyr.scanner.rules_engine import MatchedRule, RulesResult
from korvyr.scanner.scan_pipeline import ScanResult, _run_gnn

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model_loaded" in data
    assert "model_checkpoint_loaded" in data
    assert data["scan_mode"] in {"hybrid", "static-only"}


def test_health_reports_static_only_without_checkpoint():
    """Without a loaded checkpoint the API must not imply GNN inference ran."""
    with mock.patch.object(state, "model", None):
        data = client.get("/health").json()
    assert data["scan_mode"] == "static-only"
    assert data["model_loaded"] is False


def test_run_gnn_returns_none_without_loaded_model():
    assert _run_gnn("tests/fixtures/clean-package", model=None, device="cpu") is None


@mock.patch("korvyr.api.server.scan_package")
def test_run_pipeline_serializes_rule_snippets(mock_scan_package):
    mock_scan_package.return_value = ScanResult(
        package_name="fixture",
        verdict="malicious",
        confidence=0.97,
        gnn_score=0.88,
        rules_result=RulesResult(
            matched_rules=[
                MatchedRule(
                    rule_id="CRIT_EXFIL_CREDENTIALS",
                    rule_name="Credential Exfiltration",
                    severity="critical",
                    description="credential variables are sent over the network",
                    file_path="install.js",
                    line_number=4,
                    matched_code_snippet="process.env.GITHUB_TOKEN",
                    score=10.0,
                )
            ],
            total_score=10.0,
            has_critical=True,
        ),
        decision_path="CRITICAL behavioral rule matched",
        evidence=["critical rule"],
        elapsed_ms=12.5,
    )

    payload = _run_pipeline("tests/fixtures/malicious-install-hook", "fixture", "1.0.0")

    assert payload["rules_matched"][0]["matched_snippet"] == "process.env.GITHUB_TOKEN"

@mock.patch("korvyr.api.server._run_pipeline")
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
    with mock.patch("korvyr.api.server.download_package") as mock_dl:
        mock_dl.return_value = "dummy.tgz"
        with mock.patch("korvyr.api.server.extract_package") as mock_extract:
            mock_extract.return_value = "tests/fixtures/clean-package"
            response = client.post("/scan/package", json={"name": "is-number", "version": "7.0.0"})


    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "clean"
    assert data["package_name"] == "is-number"

@mock.patch("korvyr.api.server._run_pipeline")
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

@mock.patch("korvyr.api.server.scan_single_sync")
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
