import json
import os
import tempfile
from unittest import mock

from click.testing import CliRunner

from korvyr.cli.main import cli


def test_version_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "korvyr, version" in result.output

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
    assert "Could not reach the Korvyr API" in result.output


@mock.patch("httpx.Client.post")
def test_scan_reports_static_only_mode(mock_post):
    """A static-only verdict must be labelled as such in the CLI output."""
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "package_name": "is-number",
        "version": "7.0.0",
        "verdict": "clean",
        "confidence": 0.5,
        "scan_mode": "static-only",
    }
    mock_post.return_value = mock_resp

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "is-number@7.0.0"])

    assert result.exit_code == 0
    assert "static-only verdict" in result.output
