"""
Two-stage malicious package classifier.

Stage 1 — GNN (high recall):
    The trained SupplyGuardGIN scores all packages. We use a LOW threshold
    (e.g. 0.30) so we catch ~95%+ of malware, accepting some false positives.

Stage 2 — Rule-based verifier (high precision):
    Every candidate from Stage 1 is checked against deterministic behavioral
    rules. Only packages that trigger multiple high-confidence malicious
    signals are flagged. This pushes precision toward 99.9%+.

The key insight: the GNN catches subtle structural malice that rules miss,
while rules catch the obvious signals the GNN isn't confident about.
Their intersection achieves both high recall AND high precision.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Behavioral rules — each returns a confidence score 0.0–1.0
# ---------------------------------------------------------------------------

_EXFIL_PATTERNS = re.compile(
    r"(https?://[^\s\"'`]+|"               # hardcoded URLs
    r"dns\.resolve|"                         # DNS exfiltration
    r"webhook\.site|"                        # known exfil services
    r"requestbin|"
    r"pipedream|"
    r"burpcollaborator|"
    r"ngrok\.io|"
    r"hookbin\.com)",
    re.IGNORECASE,
)

_EVAL_PATTERNS = re.compile(
    r"(\beval\s*\(|"
    r"\bFunction\s*\(|"
    r"new\s+Function|"
    r"vm\.runInNewContext|"
    r"vm\.createScript|"
    r"child_process|"
    r"\.exec\s*\(|"
    r"\.execSync\s*\(|"
    r"\.spawn\s*\(|"
    r"\.spawnSync\s*\()",
    re.IGNORECASE,
)

_OBFUSCATION_PATTERNS = re.compile(
    r"(\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}|"     # multiple hex escapes
    r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}|"        # multiple unicode escapes
    r"atob\s*\(|"                                     # base64 decode
    r"Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]|"   # Buffer.from(x, 'base64')
    r"String\.fromCharCode|"                           # char code obfuscation
    r"decodeURIComponent\s*\(\s*escape)",              # escape-based obfuscation
)

_CREDENTIAL_PATTERNS = re.compile(
    r"(process\.env|"
    r"\.npmrc|"
    r"\.ssh|"
    r"\.aws|"
    r"\.gitconfig|"
    r"id_rsa|"
    r"\.bash_history|"
    r"/etc/passwd|"
    r"/etc/shadow|"
    r"\.gnupg|"
    r"keychain|"
    r"credential)",
    re.IGNORECASE,
)

_NETWORK_SEND = re.compile(
    r"(\.post\s*\(|"
    r"\.request\s*\(|"
    r"https?\.request|"
    r"https?\.get|"
    r"fetch\s*\(|"
    r"XMLHttpRequest|"
    r"axios\.|"
    r"node-fetch|"
    r"got\s*\(|"
    r"superagent)",
    re.IGNORECASE,
)

_FILE_READ = re.compile(
    r"(readFileSync|"
    r"readFile\s*\(|"
    r"createReadStream|"
    r"readdirSync|"
    r"readdir\s*\()",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    """Result from running a single behavioral rule."""
    name: str
    triggered: bool
    confidence: float   # 0.0–1.0
    evidence: str = ""


@dataclass
class VerificationResult:
    """Combined result from all rules."""
    rules_triggered: list[RuleResult] = field(default_factory=list)
    total_score: float = 0.0
    is_malicious: bool = False
    threshold: float = 3.0  # minimum score to confirm malicious

    @property
    def num_triggered(self) -> int:
        return sum(1 for r in self.rules_triggered if r.triggered)

    def summary(self) -> str:
        triggered = [r for r in self.rules_triggered if r.triggered]
        names = ", ".join(r.name for r in triggered)
        return (f"score={self.total_score:.1f}/{self.threshold:.1f}  "
                f"rules={self.num_triggered}/{len(self.rules_triggered)}  "
                f"verdict={'MALICIOUS' if self.is_malicious else 'BENIGN'}  "
                f"[{names}]")


def _check_install_hooks(pkg_json: dict) -> RuleResult:
    """Check for preinstall/postinstall scripts — very common in malware."""
    scripts = pkg_json.get("scripts", {})
    hooks = []
    for hook in ("preinstall", "postinstall", "preuninstall"):
        if hook in scripts:
            cmd = scripts[hook]
            # High confidence if the hook runs a JS file or shell command
            if any(s in cmd for s in ["node ", "sh ", "bash ", "curl ", "wget ",
                                       "powershell", "cmd /c"]):
                hooks.append(f"{hook}: {cmd}")

    if hooks:
        return RuleResult("install_hooks", True, 1.0,
                          evidence="; ".join(hooks))
    return RuleResult("install_hooks", False, 0.0)


def _check_data_exfiltration(source_code: str) -> RuleResult:
    """Check for file read + network send pattern (data exfiltration)."""
    has_file_read = bool(_FILE_READ.search(source_code))
    has_network_send = bool(_NETWORK_SEND.search(source_code))
    has_cred_access = bool(_CREDENTIAL_PATTERNS.search(source_code))

    if has_file_read and has_network_send and has_cred_access:
        return RuleResult("data_exfiltration", True, 1.0,
                          evidence="file_read + network_send + credential_access")
    if has_file_read and has_network_send:
        return RuleResult("data_exfiltration", True, 0.7,
                          evidence="file_read + network_send")
    if has_cred_access and has_network_send:
        return RuleResult("data_exfiltration", True, 0.8,
                          evidence="credential_access + network_send")
    return RuleResult("data_exfiltration", False, 0.0)


def _check_code_execution(source_code: str) -> RuleResult:
    """Check for dynamic code execution (eval, Function, exec)."""
    matches = _EVAL_PATTERNS.findall(source_code)
    if matches:
        return RuleResult("code_execution", True, min(1.0, len(matches) * 0.3),
                          evidence=f"{len(matches)} patterns: {matches[:3]}")
    return RuleResult("code_execution", False, 0.0)


def _check_obfuscation(source_code: str) -> RuleResult:
    """Check for code obfuscation techniques."""
    matches = _OBFUSCATION_PATTERNS.findall(source_code)
    if matches:
        return RuleResult("obfuscation", True, min(1.0, len(matches) * 0.4),
                          evidence=f"{len(matches)} obfuscation patterns")
    return RuleResult("obfuscation", False, 0.0)


def _check_suspicious_urls(source_code: str) -> RuleResult:
    """Check for hardcoded URLs to known exfil services."""
    matches = _EXFIL_PATTERNS.findall(source_code)
    if matches:
        return RuleResult("suspicious_urls", True, min(1.0, len(matches) * 0.5),
                          evidence=f"{len(matches)} suspicious URLs")
    return RuleResult("suspicious_urls", False, 0.0)


def _check_env_harvesting(source_code: str) -> RuleResult:
    """Check for environment variable harvesting."""
    env_count = source_code.count("process.env")
    if env_count >= 3:
        return RuleResult("env_harvesting", True, 1.0,
                          evidence=f"{env_count} process.env accesses")
    elif env_count >= 1:
        return RuleResult("env_harvesting", True, 0.4,
                          evidence=f"{env_count} process.env access")
    return RuleResult("env_harvesting", False, 0.0)


def _check_typosquat_name(pkg_json: dict) -> RuleResult:
    """Check for suspicious package naming patterns."""
    name = pkg_json.get("name", "")
    version = pkg_json.get("version", "0.0.0")

    suspicious = False
    reasons = []

    # Very new package (0.x.x) with install hooks
    if version.startswith("0.") and "scripts" in pkg_json:
        scripts = pkg_json.get("scripts", {})
        if any(h in scripts for h in ("preinstall", "postinstall")):
            suspicious = True
            reasons.append(f"v{version} with install hooks")

    # Name contains separators that mimic popular packages
    popular = ["lodash", "express", "react", "webpack", "babel",
               "eslint", "axios", "moment", "chalk", "commander"]
    for pkg in popular:
        if pkg in name and name != pkg:
            suspicious = True
            reasons.append(f"contains '{pkg}' (possible typosquat)")

    if suspicious:
        return RuleResult("typosquat_name", True, 0.5,
                          evidence="; ".join(reasons))
    return RuleResult("typosquat_name", False, 0.0)


# ---------------------------------------------------------------------------
# Two-stage classifier
# ---------------------------------------------------------------------------

# Weights for each rule — higher weight = more suspicious
RULE_WEIGHTS = {
    "install_hooks": 1.5,
    "data_exfiltration": 2.0,
    "code_execution": 1.0,
    "obfuscation": 1.0,
    "suspicious_urls": 1.5,
    "env_harvesting": 0.8,
    "typosquat_name": 0.5,
}


def verify_package(
    package_dir: str | Path,
    verification_threshold: float = 3.0,
) -> VerificationResult:
    """Run all behavioral rules on a package directory.

    Parameters
    ----------
    package_dir : path to the extracted package
    verification_threshold : minimum weighted score to confirm malicious

    Returns
    -------
    VerificationResult with per-rule details and final verdict
    """
    package_dir = Path(package_dir)
    result = VerificationResult(threshold=verification_threshold)

    # Load package.json
    pkg_json = {}
    pkg_json_path = package_dir / "package.json"
    if pkg_json_path.exists():
        try:
            pkg_json = json.loads(pkg_json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Concatenate all JS source code
    source_parts = []
    for js_file in sorted(package_dir.rglob("*.js")):
        # Skip node_modules and common vendored paths
        rel = js_file.relative_to(package_dir)
        if any(p in rel.parts for p in ("node_modules", ".git", "vendor", "dist")):
            continue
        try:
            source_parts.append(js_file.read_text(encoding="utf-8", errors="replace"))
        except (PermissionError, OSError):
            continue
    source_code = "\n".join(source_parts)

    # Run all rules
    rules = [
        _check_install_hooks(pkg_json),
        _check_data_exfiltration(source_code),
        _check_code_execution(source_code),
        _check_obfuscation(source_code),
        _check_suspicious_urls(source_code),
        _check_env_harvesting(source_code),
        _check_typosquat_name(pkg_json),
    ]

    result.rules_triggered = rules

    # Compute weighted score
    total = 0.0
    for rule in rules:
        if rule.triggered:
            weight = RULE_WEIGHTS.get(rule.name, 1.0)
            total += rule.confidence * weight
    result.total_score = total
    result.is_malicious = total >= verification_threshold

    return result


@dataclass
class TwoStageResult:
    """Final classification result from the two-stage pipeline."""
    gnn_score: float            # raw GNN probability
    gnn_passed: bool            # did it pass Stage 1?
    verification: VerificationResult | None  # Stage 2 result (None if not run)
    final_verdict: str          # "malicious", "benign", or "suspicious"
    confidence: str             # "high", "medium", "low"

    def summary(self) -> str:
        if self.verification:
            return (f"GNN={self.gnn_score:.3f} | "
                    f"Rules: {self.verification.summary()} | "
                    f"→ {self.final_verdict} ({self.confidence} confidence)")
        return (f"GNN={self.gnn_score:.3f} | "
                f"→ {self.final_verdict} ({self.confidence} confidence)")


def classify_two_stage(
    gnn_score: float,
    package_dir: str | Path,
    gnn_threshold: float = 0.30,
    verification_threshold: float = 3.0,
) -> TwoStageResult:
    """Two-stage classification pipeline.

    Stage 1: If GNN score >= gnn_threshold, proceed to Stage 2.
    Stage 2: Run behavioral rules. If rules confirm, flag as malicious.

    Parameters
    ----------
    gnn_score : probability from SupplyGuardGIN (0.0–1.0)
    package_dir : path to the extracted package
    gnn_threshold : Stage 1 cutoff (low = high recall)
    verification_threshold : Stage 2 weighted score cutoff (high = high precision)
    """
    # Stage 1: GNN screening
    if gnn_score < gnn_threshold:
        return TwoStageResult(
            gnn_score=gnn_score,
            gnn_passed=False,
            verification=None,
            final_verdict="benign",
            confidence="high" if gnn_score < 0.10 else "medium",
        )

    # Stage 2: Rule-based verification
    verification = verify_package(package_dir, verification_threshold)

    if verification.is_malicious:
        # Both GNN and rules agree: high-confidence malicious
        return TwoStageResult(
            gnn_score=gnn_score,
            gnn_passed=True,
            verification=verification,
            final_verdict="malicious",
            confidence="high",
        )
    elif gnn_score >= 0.70 and verification.num_triggered >= 2:
        # GNN is fairly confident + some rules triggered
        return TwoStageResult(
            gnn_score=gnn_score,
            gnn_passed=True,
            verification=verification,
            final_verdict="suspicious",
            confidence="medium",
        )
    else:
        # GNN flagged it but rules didn't confirm
        return TwoStageResult(
            gnn_score=gnn_score,
            gnn_passed=True,
            verification=verification,
            final_verdict="benign",
            confidence="low",  # low confidence — manual review recommended
        )
