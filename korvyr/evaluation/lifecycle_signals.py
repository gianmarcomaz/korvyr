"""Lifecycle script signal helpers for replay-only accuracy experiments."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from korvyr.evaluation.context_signals import (
    INSTALL_HOOKS,
    CandidateSignal,
    load_package_json,
    manifest_context,
)

NETWORK_TERMS = {
    "curl",
    "wget",
    "fetch(",
    "axios",
    "request(",
    "http://",
    "https://",
    "invoke-webrequest",
    "downloadfile",
}
SHELL_EXEC_TERMS = {
    "child_process",
    "exec(",
    "execsync",
    "spawn(",
    "powershell",
    "cmd.exe",
    "bash",
    "sh -c",
    "nc ",
    "netcat",
}
SECRET_TERMS = {
    "process.env",
    "npm_config",
    "npm config",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "ssh",
    ".npmrc",
}
OBFUSCATION_TERMS = {
    "eval(",
    "function(",
    "atob(",
    "base64",
    "fromcharcode",
    "\\x",
    "buffer.from",
}
BENIGN_BUILD_TERMS = {
    "node-gyp",
    "prebuild-install",
    "cmake-js",
    "node-pre-gyp",
    "tsc",
    "webpack",
    "rollup",
    "vite",
    "esbuild",
    "npm run build",
}


def _contains_any(text: str, terms: set[str]) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


def _hook_targets(command: str) -> list[str]:
    targets: list[str] = []
    for match in re.finditer(r"(?:^|\s)(?:node\s+)?([\w./\\-]+\.c?m?js)\b", command):
        target = match.group(1).strip("'\"")
        if target and target not in targets:
            targets.append(target)
    return targets


def _read_target_text(package_path: str, targets: list[str]) -> tuple[list[str], str]:
    base = Path(package_path)
    found: list[str] = []
    texts: list[str] = []
    for target in targets[:5]:
        candidate = (base / target).resolve()
        try:
            candidate.relative_to(base.resolve())
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")[:131072]
        except OSError:
            continue
        found.append(target)
        texts.append(text)
    return found, "\n".join(texts)


def lifecycle_context(record: dict[str, Any]) -> dict[str, Any]:
    """Extract lifecycle hook command and target-file traits."""
    package_path = str(record.get("package_path") or record.get("source_path") or "")
    manifest = load_package_json(package_path)
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        scripts = {}

    hook_commands = {
        hook: str(scripts.get(hook) or "")
        for hook in sorted(INSTALL_HOOKS)
        if hook in scripts
    }
    command_text = "\n".join(hook_commands.values())
    targets: list[str] = []
    for command in hook_commands.values():
        targets.extend(_hook_targets(command))
    target_files, target_text = _read_target_text(package_path, targets)
    combined_text = f"{command_text}\n{target_text}"

    network = _contains_any(combined_text, NETWORK_TERMS)
    shell_exec = _contains_any(combined_text, SHELL_EXEC_TERMS)
    secrets = _contains_any(combined_text, SECRET_TERMS)
    obfuscation = _contains_any(combined_text, OBFUSCATION_TERMS)
    benign_build = _contains_any(command_text, BENIGN_BUILD_TERMS)
    risk_score = sum([network, shell_exec, secrets, obfuscation])

    return {
        "hook_commands": hook_commands,
        "hook_command_text": command_text,
        "hook_targets": targets,
        "hook_target_files_found": target_files,
        "hook_target_text_chars": len(target_text),
        "hook_has_network": network,
        "hook_has_shell_exec": shell_exec,
        "hook_has_secret_terms": secrets,
        "hook_has_obfuscation": obfuscation,
        "hook_has_benign_build_terms": benign_build,
        "hook_risk_score": risk_score,
    }


def enrich_lifecycle_context(record: dict[str, Any]) -> dict[str, Any]:
    """Attach manifest and lifecycle context without mutating input."""
    out = dict(record)
    out["context"] = record.get("context") or manifest_context(record)
    out["lifecycle_context"] = lifecycle_context(record)
    return out


def _ctx(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("context") or manifest_context(record)


def _life(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("lifecycle_context") or lifecycle_context(record)


def lifecycle_candidate_signals() -> list[CandidateSignal]:
    """Return targeted lifecycle candidates for the residual install-hook region."""
    return [
        CandidateSignal(
            "confirm_mid_gnn_hook_network_or_shell",
            "confirmer",
            "Mid-GNN lifecycle hook whose command or target file has network or shell execution terms.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and (_life(record)["hook_has_network"] or _life(record)["hook_has_shell_exec"])
            ),
        ),
        CandidateSignal(
            "confirm_mid_gnn_hook_secret_terms",
            "confirmer",
            "Mid-GNN lifecycle hook whose command or target file references secrets or credentials.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and _life(record)["hook_has_secret_terms"]
            ),
        ),
        CandidateSignal(
            "confirm_mid_gnn_hook_obfuscation_terms",
            "confirmer",
            "Mid-GNN lifecycle hook whose command or target file has obfuscation terms.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and _life(record)["hook_has_obfuscation"]
            ),
        ),
        CandidateSignal(
            "confirm_mid_gnn_hook_risk_score_ge2",
            "confirmer",
            "Mid-GNN lifecycle hook with at least two risky hook trait families.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and _life(record)["hook_risk_score"] >= 2
            ),
        ),
        CandidateSignal(
            "confirm_mid_gnn_hook_risk_score_ge1_no_build",
            "confirmer",
            "Mid-GNN lifecycle hook with risk terms and no common native/build hook terms.",
            lambda record: (
                0.35 <= _ctx(record)["gnn_score"] < 0.80
                and _ctx(record)["has_lifecycle_hook"]
                and _life(record)["hook_risk_score"] >= 1
                and not _life(record)["hook_has_benign_build_terms"]
            ),
        ),
        CandidateSignal(
            "suppress_hook_build_context_low_metadata",
            "suppressor",
            "Lifecycle hook with common build/native-install terms and low metadata risk.",
            lambda record: (
                _ctx(record)["has_lifecycle_hook"]
                and _life(record)["hook_has_benign_build_terms"]
                and _ctx(record)["metadata_risk"] <= 0.15
            ),
        ),
    ]
