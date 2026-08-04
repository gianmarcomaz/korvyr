"""
Manifest-only scanner for npm lifecycle-hook malware.

This module inspects package.json directly, so attacks that live entirely in
preinstall/install/postinstall scripts can be detected even when no JavaScript
payload file survives parsing or graph construction.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from korvyr.scanner.rules_engine import MatchedRule, RulesResult

LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall")

MANIFEST_RULE_SCORES: dict[str, float] = {
    "CRIT_MANIFEST_CURL_PIPE": 15,
    "CRIT_MANIFEST_NODE_EVAL": 15,
    "HIGH_MANIFEST_ENCODED_PAYLOAD": 8,
    "HIGH_MANIFEST_SUSPICIOUS_URL": 8,
    "MED_MANIFEST_INSTALL_HOOK_ONLY": 3,
}

_CURL_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^|]{1,500}\|\s*(?:sh|bash|node|python)\b",
    re.IGNORECASE,
)
_NODE_EVAL = re.compile(
    r"\bnode\s+-[ep]\b\s*(?:([\"'])(?P<quoted>.*?)\1|(?P<bare>[^;&|]+))",
    re.IGNORECASE,
)
_NODE_EVAL_SUSPICIOUS = re.compile(
    r"(require\s*\(|Buffer\b|https?\b|eval\s*\(|Function\b|atob\b|base64)",
    re.IGNORECASE,
)
_BASE64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_DECODE_USAGE = re.compile(
    r"(Buffer\.from\s*\([^)]*base64|atob\s*\(|base64\s+-d|"
    r"from\s*\([^)]*,\s*[\"']base64[\"']|decodeURIComponent\s*\()",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s\"'`<>\\]+", re.IGNORECASE)

_URL_WHITELIST = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "github.com",
    "githubusercontent.com",
}

_BENIGN_HOOKS = (
    re.compile(r"^\s*husky\s+install\s*$", re.IGNORECASE),
    re.compile(r"^\s*patch-package\s*$", re.IGNORECASE),
)


def _snippet(value: str, max_len: int = 220) -> str:
    return value.replace("\n", "\\n")[:max_len]


def _is_benign_hook(command: str) -> bool:
    return any(pattern.search(command) for pattern in _BENIGN_HOOKS)


def _iter_lifecycle_hooks(pkg_json: dict) -> list[tuple[str, str]]:
    scripts = pkg_json.get("scripts", {})
    if not isinstance(scripts, dict):
        return []

    hooks: list[tuple[str, str]] = []
    for hook in LIFECYCLE_HOOKS:
        command = scripts.get(hook)
        if isinstance(command, str) and command.strip():
            hooks.append((hook, command))
    return hooks


def _is_valid_base64(token: str) -> bool:
    try:
        padded = token + ("=" * (-len(token) % 4))
        base64.b64decode(padded, validate=True)
        return True
    except Exception:
        return False


def _is_whitelisted_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    return any(host == allowed or host.endswith(f".{allowed}")
               for allowed in _URL_WHITELIST)


def _count_js_lines(package_dir: Path) -> int:
    total = 0
    for pattern in ("*.js", "*.mjs", "*.cjs"):
        for js_file in package_dir.rglob(pattern):
            rel_parts = js_file.relative_to(package_dir).parts
            if any(part in {"node_modules", ".git", "vendor", "dist"}
                   for part in rel_parts):
                continue
            try:
                total += js_file.read_text(
                    encoding="utf-8",
                    errors="replace",
                ).count("\n") + 1
            except OSError:
                continue
            if total >= 50:
                return total
    return total


def _has_test_dir(package_dir: Path) -> bool:
    return any((package_dir / name).exists()
               for name in ("test", "tests", "__tests__"))


def _readme_length(package_dir: Path) -> int:
    for readme in package_dir.glob("README*"):
        if readme.is_file():
            try:
                return len(readme.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                return 0
    return 0


def _dependency_count(pkg_json: dict) -> int:
    total = 0
    for key in (
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
    ):
        deps = pkg_json.get(key, {})
        if isinstance(deps, dict):
            total += len(deps)
    return total


def _make_rule(
    rule_id: str,
    severity: str,
    description: str,
    snippet: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "score": MANIFEST_RULE_SCORES[rule_id],
        "description": description,
        "file_path": "package.json",
        "matched_snippet": _snippet(snippet),
    }


def scan_manifest(package_dir: str) -> list[dict]:
    """Scan package.json lifecycle hooks for manifest-only malware evidence."""
    pkg_dir = Path(package_dir)
    pj_path = pkg_dir / "package.json"
    if not pj_path.exists():
        return []

    try:
        pkg_json = json.loads(pj_path.read_text(encoding="utf-8-sig", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    hooks = _iter_lifecycle_hooks(pkg_json)
    if not hooks:
        return []

    matches: list[dict] = []
    # Benign lifecycle hooks are common in real packages, so filter known-safe commands first.
    non_benign_hooks = [(hook, command) for hook, command in hooks
                        if not _is_benign_hook(command)]

    for hook, command in non_benign_hooks:
        hook_desc = f"scripts.{hook}: {command}"

        if _CURL_PIPE.search(command):
            matches.append(_make_rule(
                "CRIT_MANIFEST_CURL_PIPE",
                "critical",
                "Lifecycle hook pipes curl/wget output into an interpreter",
                hook_desc,
            ))

        node_eval = _NODE_EVAL.search(command)
        if node_eval:
            body = node_eval.group("quoted") or node_eval.group("bare") or ""
            if _NODE_EVAL_SUSPICIOUS.search(body):
                matches.append(_make_rule(
                    "CRIT_MANIFEST_NODE_EVAL",
                    "critical",
                    "Lifecycle hook uses node -e/-p with suspicious loader code",
                    hook_desc,
                ))

        if _DECODE_USAGE.search(command):
            b64_tokens = [m.group(0) for m in _BASE64_TOKEN.finditer(command)]
            if any(_is_valid_base64(token) for token in b64_tokens):
                matches.append(_make_rule(
                    "HIGH_MANIFEST_ENCODED_PAYLOAD",
                    "high",
                    "Lifecycle hook contains an encoded payload and decode path",
                    hook_desc,
                ))

        for url in _URL.findall(command):
            if not _is_whitelisted_url(url):
                matches.append(_make_rule(
                    "HIGH_MANIFEST_SUSPICIOUS_URL",
                    "high",
                    "Lifecycle hook references a non-registry remote URL",
                    hook_desc,
                ))
                break

    has_install_edge = any(hook in {"preinstall", "postinstall"}
                           for hook, _ in non_benign_hooks)
    if has_install_edge:
        if (
            _count_js_lines(pkg_dir) < 50
            and not _has_test_dir(pkg_dir)
            and _readme_length(pkg_dir) < 100
            and _dependency_count(pkg_json) == 0
        ):
            hook_summary = "; ".join(f"scripts.{h}: {c}"
                                     for h, c in non_benign_hooks)
            matches.append(_make_rule(
                "MED_MANIFEST_INSTALL_HOOK_ONLY",
                "medium",
                "Minimal package scaffold with lifecycle install hook",
                hook_summary,
            ))

    return matches


def manifest_rule_to_matched(rule: dict) -> MatchedRule:
    """Convert a manifest-scanner dict to the rules engine result shape."""
    return MatchedRule(
        rule_id=str(rule["rule_id"]),
        rule_name=str(rule["rule_id"]).replace("_", " ").title(),
        severity=str(rule["severity"]),
        description=str(rule["description"]),
        file_path=str(rule.get("file_path", "package.json")),
        matched_code_snippet=str(rule.get("matched_snippet", "")),
        score=float(rule.get("score", 0.0)),
    )


def merge_manifest_rules(
    rules_result: RulesResult,
    package_dir: str,
) -> RulesResult:
    """Append manifest scanner matches to an existing RulesResult."""
    for rule in scan_manifest(package_dir):
        matched = manifest_rule_to_matched(rule)
        rules_result.matched_rules.append(matched)
        rules_result.total_score += matched.score
        if matched.severity == "critical":
            rules_result.has_critical = True
    return rules_result
