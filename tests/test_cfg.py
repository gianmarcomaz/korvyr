"""Tests for korvyr.parsing.cfg_extractor."""

import tempfile
from pathlib import Path

from korvyr.parsing.ast_extractor import extract_ast
from korvyr.parsing.cfg_extractor import extract_cfg


def _build_cfg(js_code: str) -> tuple[list[dict], list[dict]]:
    """Helper: write *js_code* to a temp dir, run extract_ast + extract_cfg."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "test.js").write_text(js_code, encoding="utf-8")
        nodes, ast_edges = extract_ast(tmpdir)
        cfg_edges = extract_cfg(nodes, ast_edges)
        return nodes, cfg_edges


def _print_edges(label: str, nodes: list[dict], cfg_edges: list[dict]) -> None:
    node_by_id = {n["id"]: n for n in nodes}
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  {len(cfg_edges)} CFG edge(s)")
    print(f"{'='*60}")
    for e in cfg_edges:
        src = node_by_id[e["source_id"]]
        tgt = node_by_id[e["target_id"]]
        print(
            f"  [{e['edge_type']:12s}]  "
            f"{src['type']}({src['text'][:40]!r})  →  "
            f"{tgt['type']}({tgt['text'][:40]!r})"
        )
    print()


# ------------------------------------------------------------------
# Test 1 — sequential flow
# ------------------------------------------------------------------

JS_SEQUENTIAL = """\
const a = 1;
const b = 2;
const c = a + b;
"""


def test_sequential_flow():
    nodes, cfg_edges = _build_cfg(JS_SEQUENTIAL)
    _print_edges("Sequential flow", nodes, cfg_edges)

    next_edges = [e for e in cfg_edges if e["edge_type"] == "cfg_next"]
    assert len(next_edges) == 2, (
        f"expected exactly 2 cfg_next edges, got {len(next_edges)}"
    )


# ------------------------------------------------------------------
# Test 2 — if/else branching
# ------------------------------------------------------------------

JS_IF_ELSE = """\
const x = 1;
if (x > 0) {
  console.log("positive");
} else {
  console.log("negative");
}
const y = 2;
"""


def test_if_else_branching():
    nodes, cfg_edges = _build_cfg(JS_IF_ELSE)
    _print_edges("If/else branching", nodes, cfg_edges)

    branch_edges = [e for e in cfg_edges if e["edge_type"] == "cfg_branch"]
    assert len(branch_edges) >= 1, "expected at least one cfg_branch edge"


# ------------------------------------------------------------------
# Test 3 — try/catch
# ------------------------------------------------------------------

JS_TRY_CATCH = """\
try {
  dangerousFunction();
} catch (e) {
  console.log(e);
}
const done = true;
"""


def test_try_catch():
    nodes, cfg_edges = _build_cfg(JS_TRY_CATCH)
    _print_edges("Try/catch", nodes, cfg_edges)

    branch_edges = [e for e in cfg_edges if e["edge_type"] == "cfg_branch"]
    assert len(branch_edges) >= 1, "expected at least one cfg_branch edge"

    catch_node_ids = {
        n["id"] for n in nodes if "console.log" in n["text"]
    }
    into_catch = [
        e for e in branch_edges if e["target_id"] in catch_node_ids
    ]
    assert len(into_catch) >= 1, (
        "expected at least one cfg_branch edge connecting into the catch block"
    )
