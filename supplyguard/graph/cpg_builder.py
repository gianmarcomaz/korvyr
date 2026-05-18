"""
Build a Code Property Graph (CPG) from a JavaScript package directory.

Combines AST, CFG, and DFG into a single ``torch_geometric.data.Data``
object suitable for GNN training.

Edge-type encoding:
    0 → ast_child
    1 → cfg_next
    2 → cfg_branch
    3 → dfg_def_use
"""

from __future__ import annotations

import json
import logging
import csv
from pathlib import Path
from typing import Any

import torch
from torch_geometric.data import Data

from supplyguard.parsing.ast_extractor import (
    extract_ast,
    get_node_features,
    FEATURE_DIM,
)
from supplyguard.parsing.cfg_extractor import extract_cfg
from supplyguard.parsing.dfg_extractor import extract_dfg

log = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
CPG_FAILURES_PATH = ROOT_DIR / "data" / "processed" / "cpg_build_failures.csv"

EDGE_TYPE_MAP: dict[str, int] = {
    "ast_child": 0,
    "cfg_next": 1,
    "cfg_branch": 2,
    "dfg_def_use": 3,
}


def _count_js_files(package_dir: Path) -> int:
    return sum(
        1
        for p in package_dir.rglob("*")
        if p.suffix in (".js", ".mjs") and p.is_file()
    )


def _record_cpg_failure(
    package_dir: Path,
    error_type: str,
    error_message: str,
    num_js_files: int,
) -> None:
    """Append a CPG build failure row for offline diagnostics."""
    try:
        CPG_FAILURES_PATH.parent.mkdir(parents=True, exist_ok=True)
        write_header = not CPG_FAILURES_PATH.exists()
        with CPG_FAILURES_PATH.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "package_path",
                    "error_type",
                    "error_message",
                    "num_js_files",
                ],
            )
            if write_header:
                writer.writeheader()
            writer.writerow(
                {
                    "package_path": str(package_dir),
                    "error_type": error_type,
                    "error_message": error_message,
                    "num_js_files": num_js_files,
                }
            )
    except OSError:
        log.debug("Failed to write CPG failure CSV", exc_info=True)

# ---------------------------------------------------------------------------
# Package-level metadata helpers
# ---------------------------------------------------------------------------

def _read_package_json(package_dir: Path) -> dict:
    pj = package_dir / "package.json"
    if not pj.exists():
        return {}
    try:
        return json.loads(pj.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return {}


_NETWORK_KEYWORDS = (
    "http", "https", "fetch", "request", "axios",
    "curl", "wget", "net", "dns", "socket",
)


def _has_network_in_hook(scripts: dict) -> bool:
    for key in ("preinstall", "postinstall", "install"):
        cmd = scripts.get(key, "")
        if any(kw in cmd.lower() for kw in _NETWORK_KEYWORDS):
            return True
    return False


def _build_metadata_tensor(
    package_dir: Path,
    ast_nodes: list[dict],
    taint_flags: list[dict],
) -> torch.Tensor:
    """Return an 8-element float32 tensor of package-level features."""
    pj = _read_package_json(package_dir)
    scripts = pj.get("scripts", {})

    has_preinstall = float("preinstall" in scripts)
    has_postinstall = float("postinstall" in scripts)

    js_files = [
        p for p in package_dir.rglob("*")
        if p.suffix in (".js", ".mjs")
        and "node_modules" not in p.parts
        and p.is_file()
    ]
    num_js_files = len(js_files) / 100.0

    total_lines = 0
    for f in js_files:
        try:
            total_lines += f.read_text(encoding="utf-8", errors="replace").count("\n")
        except OSError:
            pass
    total_lines_norm = total_lines / 10_000.0

    has_net_hook = float(_has_network_in_hook(scripts))

    num_sources = sum(1 for t in taint_flags if t["flag_type"] == "source")
    num_sinks = sum(1 for t in taint_flags if t["flag_type"] == "sink")

    return torch.tensor(
        [
            has_preinstall,                     # [0]
            has_postinstall,                    # [1]
            num_js_files,                       # [2]
            total_lines_norm,                   # [3]
            has_net_hook,                       # [4]
            num_sources / 10.0,                 # [5]
            num_sinks / 10.0,                   # [6]
            float(num_sources > 0 and num_sinks > 0),  # [7]
        ],
        dtype=torch.float32,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _build_dummy_graph(package_dir: Path, label: int) -> Data:
    """Return a single-node graph with zero features, real metadata.

    Used when no JS/MJS survives filtering but a package.json is present.
    The GNN can still score the package via the metadata branch.
    """
    x = torch.zeros((1, FEATURE_DIM), dtype=torch.float32)
    edge_index = torch.zeros((2, 0), dtype=torch.long)
    edge_type = torch.zeros(0, dtype=torch.long)
    meta_tensor = _build_metadata_tensor(package_dir, [], [])
    y = torch.tensor(float(label), dtype=torch.float32)
    return Data(
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        y=y,
        metadata=meta_tensor,
        num_nodes=1,
    )


def _build_cpg_impl(
    package_dir: str,
    label: int,
    metadata: dict | None = None,
) -> Data | None:
    """Build a CPG ``Data`` object for the package at *package_dir*.

    Parameters
    ----------
    package_dir : str
        Path to the extracted package directory.
    label : int
        Ground-truth label (0 = benign, 1 = malicious).
    metadata : dict, optional
        Ignored for now — metadata is computed from the package contents.

    Returns
    -------
    torch_geometric.data.Data or None
        ``None`` if the package contains no JS files.
    """
    pkg = Path(package_dir)

    # --- AST ---
    ast_nodes, ast_edges = extract_ast(package_dir)
    if not ast_nodes:
        if (pkg / "package.json").exists():
            log.info(
                "No JS nodes in %s but package.json exists — returning dummy graph",
                package_dir,
            )
            return _build_dummy_graph(pkg, label)
        log.info("No JS nodes in %s — skipping", package_dir)
        return None

    # --- CFG ---
    try:
        cfg_edges = extract_cfg(ast_nodes, ast_edges)
    except Exception:
        log.warning("CFG extraction failed for %s — continuing", package_dir,
                    exc_info=True)
        cfg_edges = []

    # --- DFG ---
    try:
        dfg_edges, taint_flags = extract_dfg(ast_nodes, ast_edges)
    except Exception:
        log.warning("DFG extraction failed for %s — continuing", package_dir,
                    exc_info=True)
        dfg_edges = []
        taint_flags = []

    # --- Node features [num_nodes, 35] ---
    x = torch.tensor(
        [get_node_features(n) for n in ast_nodes],
        dtype=torch.float32,
    )

    # --- Edges ---
    # Remap node IDs → contiguous 0..N-1 indices
    id_to_idx = {n["id"]: i for i, n in enumerate(ast_nodes)}

    all_edges = ast_edges + cfg_edges + dfg_edges
    src_list: list[int] = []
    tgt_list: list[int] = []
    etype_list: list[int] = []

    for e in all_edges:
        s = id_to_idx.get(e["source_id"])
        t = id_to_idx.get(e["target_id"])
        if s is None or t is None:
            continue
        src_list.append(s)
        tgt_list.append(t)
        etype_list.append(EDGE_TYPE_MAP.get(e["edge_type"], 0))

    if src_list:
        edge_index = torch.tensor([src_list, tgt_list], dtype=torch.long)
        edge_type = torch.tensor(etype_list, dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_type = torch.zeros(0, dtype=torch.long)

    # --- Metadata [8] ---
    meta_tensor = _build_metadata_tensor(pkg, ast_nodes, taint_flags)

    # --- Label ---
    y = torch.tensor(float(label), dtype=torch.float32)

    return Data(
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        y=y,
        metadata=meta_tensor,
        num_nodes=x.size(0),
    )


def _infer_cpg_failure_step(exc: Exception) -> str:
    """Best-effort mapping from traceback frames to the CPG build sub-step."""
    tb = exc.__traceback__
    frame_names: list[str] = []
    while tb is not None:
        frame_names.append(tb.tb_frame.f_code.co_name)
        tb = tb.tb_next

    if "extract_ast" in frame_names or "_walk_tree" in frame_names:
        return "AST parsing"
    if "extract_cfg" in frame_names:
        return "CFG extraction"
    if "extract_dfg" in frame_names:
        return "DFG extraction"
    if "get_node_features" in frame_names:
        return "tensor construction: node features"
    if "_build_metadata_tensor" in frame_names:
        return "tensor construction: metadata"
    if "_build_cpg_impl" in frame_names:
        return "tensor construction/Data construction"
    return "unknown"


def build_cpg(
    package_dir: str,
    label: int,
    metadata: dict | None = None,
) -> Data | None:
    """Diagnostic wrapper around the CPG builder.

    Catches unexpected real-world package failures, logs enough detail to
    identify the failing sub-step, and appends a row to
    data/processed/cpg_build_failures.csv.
    """
    data, _ = build_cpg_with_diagnostics(package_dir, label, metadata)
    return data


def build_cpg_with_diagnostics(
    package_dir: str,
    label: int,
    metadata: dict | None = None,
) -> tuple[Data | None, dict[str, Any]]:
    """Build a CPG and return structured diagnostics for evaluation.

    The public ``build_cpg`` API intentionally degrades failures to ``None``.
    Evaluation needs the exact failure bucket, so this helper preserves that
    information without changing scanner behavior.
    """
    pkg = Path(package_dir)
    num_js_files = _count_js_files(pkg)
    diag: dict[str, Any] = {
        "status": "unknown",
        "error_type": "",
        "error_message": "",
        "num_js_files": num_js_files,
        "num_nodes": 0,
        "num_edges": 0,
    }
    try:
        data = _build_cpg_impl(package_dir, label, metadata)
        if data is None:
            diag.update(
                {
                    "status": "cpg_none",
                    "error_type": "CPG_NONE",
                    "error_message": "build_cpg returned None",
                }
            )
            return None, diag
        diag.update(
            {
                "status": "success",
                "num_nodes": int(data.num_nodes),
                "num_edges": int(data.edge_index.shape[1]),
            }
        )
        return data, diag
    except Exception as e:
        step = _infer_cpg_failure_step(e)
        error_type = f"{step}:{type(e).__name__}"
        error_message = str(e)
        diag.update(
            {
                "status": "failure",
                "error_type": error_type,
                "error_message": error_message,
            }
        )
        log.warning(
            "CPG build failed during %s for %s (%d JS files): %s: %s",
            step,
            package_dir,
            num_js_files,
            type(e).__name__,
            error_message,
            exc_info=True,
        )
        _record_cpg_failure(pkg, error_type, error_message, num_js_files)
        return None, diag
