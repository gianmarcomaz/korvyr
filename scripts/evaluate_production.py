"""Canonical production-path evaluator for SupplyGuard.

This script evaluates package directories or tarballs through the same major
runtime stages as the scanner:

package/tarball -> package load -> CPG -> GNN -> rules -> metadata -> _decide

The hybrid verdict uses ``supplyguard.scanner.scan_pipeline._decide`` directly
so evaluation cannot drift from production decision logic.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import shutil
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.evaluation.reporting import (
    decision_bucket,
    render_markdown_report,
    summarize_records,
)
from supplyguard.graph.cpg_builder import build_cpg_with_diagnostics
from supplyguard.metadata.risk_scorer import compute_metadata_risk
from supplyguard.model.gin_classifier import SupplyGuardGIN
from supplyguard.scanner.manifest_scanner import merge_manifest_rules
from supplyguard.scanner.rules_engine import RulesResult, run_rules
from supplyguard.scanner.scan_pipeline import ThresholdConfig, _decide

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = ROOT / "models" / "gnn_v2_cuda.pt"
DEFAULT_OUTPUT_JSON = ROOT / "results" / "production_evaluation.json"
DEFAULT_OUTPUT_MD = ROOT / "results" / "production_evaluation.md"


@dataclass(frozen=True)
class EvalTarget:
    source_path: Path
    label: int
    source_type: str = "dir"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate SupplyGuard's production scan path on labeled packages.",
    )
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        metavar="PATH:LABEL",
        help="Evaluate a package directory with label 0 or 1. Can be repeated.",
    )
    parser.add_argument(
        "--tarball",
        action="append",
        default=[],
        metavar="PATH:LABEL",
        help="Evaluate a .tgz/.tar.gz package tarball with label 0 or 1. Can be repeated.",
    )
    parser.add_argument(
        "--from-existing-eval",
        type=Path,
        default=None,
        help="Load package paths and labels from an existing evaluation JSON.",
    )
    parser.add_argument(
        "--malicious-manifest",
        type=Path,
        default=ROOT / "data" / "raw" / "malicious_manifest.csv",
        help="CSV manifest for malicious package paths.",
    )
    parser.add_argument(
        "--benign-manifest",
        type=Path,
        default=ROOT / "data" / "raw" / "benign_manifest.csv",
        help="CSV manifest for benign package paths.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=0,
        help=(
            "Per-class sample size from manifests. 0 means use explicit packages "
            "or existing eval only."
        ),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--output-json", type=Path, default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", type=Path, default=DEFAULT_OUTPUT_MD)
    parser.add_argument("--device", default="auto", choices=("auto", "cpu", "cuda"))
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    return parser.parse_args()


def _parse_labeled_path(spec: str, source_type: str) -> EvalTarget:
    raw_path, sep, raw_label = spec.rpartition(":")
    if not sep or raw_label not in {"0", "1"}:
        raise ValueError(f"Expected PATH:LABEL with label 0 or 1, got: {spec}")
    path = Path(raw_path)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    return EvalTarget(path, int(raw_label), source_type)


def _collect_from_existing_eval(path: Path) -> list[EvalTarget]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    targets: list[EvalTarget] = []
    seen: set[str] = set()
    for package in data.get("packages", []):
        package_path = package.get("path")
        if not package_path or package_path in seen:
            continue
        seen.add(package_path)
        label = int(package.get("true_label", 0))
        targets.append(EvalTarget(Path(package_path), label, "dir"))
    return targets


def _collect_from_manifest(manifest_path: Path, label: int, limit: int, seed: int) -> list[EvalTarget]:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing manifest: {manifest_path}")

    targets: list[EvalTarget] = []
    with manifest_path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            rel_path = row.get("path") or row.get("local_path") or ""
            if not rel_path:
                continue
            root = Path(rel_path)
            if not root.is_absolute():
                root = ROOT / root
            if not root.exists():
                continue
            package_jsons = list(root.rglob("package.json"))
            if package_jsons:
                targets.append(EvalTarget(package_jsons[0].parent, label, "dir"))

    rng = random.Random(seed)
    rng.shuffle(targets)
    if limit > 0:
        return targets[:limit]
    return targets


def collect_targets(args: argparse.Namespace) -> list[EvalTarget]:
    targets: list[EvalTarget] = []
    targets.extend(_parse_labeled_path(spec, "dir") for spec in args.package)
    targets.extend(_parse_labeled_path(spec, "tarball") for spec in args.tarball)
    if args.from_existing_eval:
        targets.extend(_collect_from_existing_eval(args.from_existing_eval))
    if args.sample_size > 0:
        targets.extend(
            _collect_from_manifest(args.malicious_manifest, 1, args.sample_size, args.seed)
        )
        targets.extend(
            _collect_from_manifest(args.benign_manifest, 0, args.sample_size, args.seed)
        )

    seen: set[tuple[str, int, str]] = set()
    unique: list[EvalTarget] = []
    for target in targets:
        key = (str(target.source_path), target.label, target.source_type)
        if key not in seen:
            seen.add(key)
            unique.append(target)
    rng = random.Random(args.seed)
    rng.shuffle(unique)
    return unique


def _load_model(model_path: Path, device: torch.device) -> torch.nn.Module | None:
    if not model_path.exists():
        log.warning("Model checkpoint not found: %s", model_path)
        return None
    model = SupplyGuardGIN(
        node_feat_dim=35,
        metadata_dim=8,
        hidden_dim=128,
        num_gin_layers=4,
        num_edge_types=4,
        dropout=0.3,
    )
    state = torch.load(model_path, map_location=device, weights_only=False)
    model.load_state_dict(state["model_state_dict"])
    model.to(device)
    model.eval()
    log.info("Loaded model checkpoint %s", model_path)
    return model


def _extract_tarball(tarball: Path, temp_root: Path) -> Path:
    extract_dir = temp_root / tarball.stem
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:*") as archive:
        archive.extractall(extract_dir)
    package_dir = extract_dir / "package"
    return package_dir if package_dir.exists() else extract_dir


def _package_dir_for_target(target: EvalTarget, temp_root: Path) -> Path:
    if target.source_type == "tarball":
        return _extract_tarball(target.source_path, temp_root)
    return target.source_path


def _read_package_json(package_dir: Path) -> dict[str, Any]:
    path = package_dir / "package.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return {}


def evaluate_target(
    target: EvalTarget,
    model: torch.nn.Module | None,
    device: torch.device,
    cfg: ThresholdConfig,
    temp_root: Path,
) -> dict[str, Any]:
    package_dir = _package_dir_for_target(target, temp_root)
    record: dict[str, Any] = {
        "package_name": package_dir.name,
        "source_path": str(target.source_path),
        "package_path": str(package_dir),
        "source_type": target.source_type,
        "true_label": target.label,
        "gnn_score": -1.0,
        "gnn_error_type": "",
        "gnn_error_message": "",
        "cpg_status": "not_run",
        "cpg_error_type": "",
        "cpg_error_message": "",
        "rules_verdict": "clean",
        "rules_score": 0.0,
        "rules_critical": False,
        "rules_matched": [],
        "rules_details": [],
        "metadata_risk": 0.0,
        "hybrid_verdict": "unknown",
        "confidence": 0.0,
        "decision_path": "",
        "decision_bucket": "unknown",
    }

    data, cpg_diag = build_cpg_with_diagnostics(str(package_dir), label=target.label)
    record.update(
        {
            "cpg_status": cpg_diag["status"],
            "cpg_error_type": cpg_diag["error_type"],
            "cpg_error_message": cpg_diag["error_message"],
            "num_js_files": cpg_diag["num_js_files"],
            "num_nodes": cpg_diag["num_nodes"],
            "num_edges": cpg_diag["num_edges"],
        }
    )

    if data is None:
        record["gnn_error_type"] = cpg_diag["error_type"] or "CPG_NONE"
        record["gnn_error_message"] = cpg_diag["error_message"]
    elif model is None:
        record["gnn_error_type"] = "MODEL_UNAVAILABLE"
        record["gnn_error_message"] = "No model checkpoint loaded"
    else:
        try:
            data = data.to(device)
            with torch.no_grad():
                logit = model.forward_from_data(data)
                record["gnn_score"] = float(torch.sigmoid(logit).item())
        except Exception as exc:
            record["gnn_error_type"] = type(exc).__name__
            record["gnn_error_message"] = str(exc)

    try:
        rules_result = run_rules(str(package_dir))
        rules_result = merge_manifest_rules(rules_result, str(package_dir))
    except Exception as exc:
        rules_result = RulesResult()
        record["rules_error_type"] = type(exc).__name__
        record["rules_error_message"] = str(exc)

    record["rules_score"] = float(rules_result.total_score)
    record["rules_critical"] = bool(rules_result.has_critical)
    record["rules_matched"] = [rule.rule_id for rule in rules_result.matched_rules]
    record["rules_details"] = [
        {
            "rule_id": rule.rule_id,
            "rule_name": rule.rule_name,
            "severity": rule.severity,
            "description": rule.description,
            "score": float(getattr(rule, "score", 0.0)),
            "file_path": rule.file_path,
            "line_number": rule.line_number,
            "matched_code_snippet": rule.matched_code_snippet,
        }
        for rule in rules_result.matched_rules
    ]
    record["rules_verdict"] = (
        "malicious"
        if rules_result.has_critical or rules_result.total_score >= cfg.rules_block_threshold
        else "clean"
    )

    package_json = _read_package_json(package_dir)
    package_name = str(package_json.get("name") or package_dir.name)
    record["package_name"] = package_name
    record["metadata_risk"] = compute_metadata_risk(package_name, package_json)

    gnn_score = record["gnn_score"] if record["gnn_score"] >= 0 else None
    verdict, confidence, path, _ = _decide(
        gnn_score,
        rules_result,
        cfg,
        float(record["metadata_risk"]),
    )
    record["hybrid_verdict"] = verdict
    record["confidence"] = float(confidence)
    record["decision_path"] = path
    record["decision_bucket"] = decision_bucket(verdict, path)
    return record


def run_evaluation(args: argparse.Namespace) -> dict[str, Any]:
    device_name = "cuda" if args.device == "auto" and torch.cuda.is_available() else args.device
    if device_name == "auto":
        device_name = "cpu"
    device = torch.device(device_name)
    targets = collect_targets(args)
    if not targets:
        raise ValueError(
            "No evaluation targets found. Provide --package/--tarball, "
            "--from-existing-eval, or --sample-size with manifests."
        )

    model = _load_model(args.model_path, device)
    cfg = ThresholdConfig()
    t0 = time.perf_counter()
    temp_parent = ROOT / ".eval_tmp"
    temp_parent.mkdir(exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix="supplyguard_eval_", dir=temp_parent))
    try:
        records = [
            evaluate_target(target, model, device, cfg, temp_dir)
            for target in targets
        ]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            temp_parent.rmdir()
        except OSError:
            pass

    summary = summarize_records(records)
    summary["run"] = {
        "elapsed_seconds": round(time.perf_counter() - t0, 3),
        "model_path": str(args.model_path),
        "model_loaded": model is not None,
        "device": str(device),
        "target_count": len(targets),
        "threshold_config": cfg.__dict__,
    }
    return {"summary": summary, "packages": records}


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(message)s",
    )
    output = run_evaluation(args)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
    args.output_md.write_text(
        render_markdown_report(output["summary"], output["packages"]),
        encoding="utf-8",
    )
    hybrid = output["summary"]["metrics"]["hybrid"]
    log.info(
        "Hybrid precision=%.4f recall=%.4f TP=%d FP=%d FN=%d TN=%d",
        hybrid["precision"],
        hybrid["recall"],
        hybrid["tp"],
        hybrid["fp"],
        hybrid["fn"],
        hybrid["tn"],
    )
    log.info("Wrote %s and %s", args.output_json, args.output_md)


if __name__ == "__main__":
    main()
