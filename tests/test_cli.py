import json
import os
import subprocess
import tempfile
from unittest import mock

import pytest
from click.testing import CliRunner

from supplyguard.cli.main import cli

def test_version_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "SupplyGuard v0.1.0" in result.output

def test_audit_no_lockfile():
    runner = CliRunner()
    orig_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Run in empty directory
            os.chdir(tmpdir)
            result = runner.invoke(cli, ["audit"])
            assert result.exit_code == 1
            assert "Could not find package-lock.json" in result.output
        finally:
            os.chdir(orig_cwd)

@mock.patch("httpx.Client.post")
def test_scan_json_output(mock_post):
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "package_name": "is-number",
        "version": "7.0.0",
        "verdict": "clean",
        "confidence": 0.99
    }
    mock_post.return_value = mock_resp
    
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "is-number@7.0.0", "--json"])
    
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["verdict"] == "clean"
    assert data["package_name"] == "is-number"

@mock.patch("httpx.Client.post")
def test_scan_connection_error(mock_post):
    import httpx
    mock_post.side_effect = httpx.ConnectError("Connection refused")
    
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "is-number@7.0.0"])
    
    assert result.exit_code == 1
    assert "Could not connect to SupplyGuard server" in result.output
