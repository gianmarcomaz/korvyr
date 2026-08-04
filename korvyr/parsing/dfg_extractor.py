"""
Data Flow Graph (DFG) extractor — def-use chains and taint flags.

Walks the AST produced by ``extract_ast``, tracks variable definitions
and uses with simple lexical-scope stacking, and emits:

* **dfg_def_use** edges from definitions to uses.
* **taint_flags** labelling nodes as data-flow *sources* or *sinks*.

Out-of-scope for v1: closures, hoisting, destructuring, dynamic
property access, ``with`` statements.
"""

from __future__ import annotations

import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# Taint patterns
# ---------------------------------------------------------------------------

_TAINT_SOURCES_CALL: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Buffer\.from\b.*?base64", re.DOTALL),
     "Buffer.from with base64"),
    (re.compile(r"\batob\s*\("), "atob()"),
    (re.compile(r"\breadFileSync\s*\("), "fs.readFileSync"),
]

_TAINT_SOURCES_ANY: list[tuple[re.Pattern, str]] = [
    (re.compile(r"process\.env\b"), "process.env access"),
]

_TAINT_SINKS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\beval\s*\("), "eval()"),
    (re.compile(r"\bFunction\s*\("), "Function()"),
    (re.compile(r"\b(?:exec|execSync)\s*\("), "child_process.exec"),
    (re.compile(r"\b(?:spawn|spawnSync)\s*\("), "child_process.spawn"),
    (re.compile(r"\bhttps?\s*\.\s*(?:request|get)\s*\("), "http/https request"),
    (re.compile(r"\bfetch\s*\("), "fetch()"),
    (re.compile(r"\bwriteFileSync\s*\("), "fs.writeFileSync"),
    (re.compile(r"\bSocket\s*\("), "net.Socket"),
    (re.compile(r"\bdns\s*\.\s*lookup\s*\("), "dns.lookup"),
]

_SCOPE_TYPES = frozenset({
    "function_declaration",
    "arrow_function",
    "function_expression",
})

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_dfg(
    ast_nodes: list[dict],
    ast_edges: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Build def-use chains and taint flags from the AST.

    Parameters
    ----------
    ast_nodes, ast_edges
        Output of ``extract_ast``.

    Returns
    -------
    dfg_edges : list[dict]
        Each ``{"source_id": def_id, "target_id": use_id,
        "edge_type": "dfg_def_use"}``.
    taint_flags : list[dict]
        Each ``{"node_id": int, "flag_type": "source"|"sink",
        "detail": str}``.
    """
    ctx = _DFGContext(ast_nodes, ast_edges)
    ctx.run()
    return ctx.dfg_edges, ctx.taint_flags


# ---------------------------------------------------------------------------
# Internal context / state machine
# ---------------------------------------------------------------------------

class _DFGContext:

    def __init__(self, ast_nodes: list[dict], ast_edges: list[dict]) -> None:
        self.nodes = ast_nodes
        self.node_by_id: dict[int, dict] = {n["id"]: n for n in ast_nodes}

        self.children_of: dict[int, list[int]] = defaultdict(list)
        self.parent_of: dict[int, int] = {}
        for edge in ast_edges:
            if edge["edge_type"] == "ast_child":
                self.children_of[edge["source_id"]].append(edge["target_id"])
                self.parent_of[edge["target_id"]] = edge["source_id"]

        self.subtree_end = self._compute_subtree_ends()

        self.def_name_ids: set[int] = set()
        self.param_ids: set[int] = set()
        self._pre_identify_defs()

        self.scope_stack: list[dict[str, int]] = [{}]
        self.scope_ends: list[int] = []

        self.dfg_edges: list[dict] = []
        self.taint_flags: list[dict] = []

    # -- pre-computation ---------------------------------------------------

    def _compute_subtree_ends(self) -> dict[int, int]:
        """For each node, the largest node-id among its descendants."""
        ends: dict[int, int] = {}
        for node in reversed(self.nodes):
            nid = node["id"]
            kids = self.children_of.get(nid, [])
            ends[nid] = max([ends.get(c, c) for c in kids] + [nid])
        return ends

    def _pre_identify_defs(self) -> None:
        """Mark identifiers that are definition names (not uses)."""
        for node in self.nodes:
            ntype = node["type"]
            nid = node["id"]

            if ntype == "variable_declarator":
                for cid in self.children_of.get(nid, []):
                    if self.node_by_id[cid]["type"] == "identifier":
                        self.def_name_ids.add(cid)
                        break

            elif ntype == "function_declaration":
                for cid in self.children_of.get(nid, []):
                    if self.node_by_id[cid]["type"] == "identifier":
                        self.def_name_ids.add(cid)
                        break

            elif ntype == "formal_parameters":
                for cid in self.children_of.get(nid, []):
                    if self.node_by_id[cid]["type"] == "identifier":
                        self.param_ids.add(cid)

    # -- scope management --------------------------------------------------

    def _lookup(self, name: str) -> int | None:
        for scope in reversed(self.scope_stack):
            if name in scope:
                return scope[name]
        return None

    def _define(self, name: str, def_node_id: int) -> None:
        self.scope_stack[-1][name] = def_node_id

    def _push_scope(self, end_id: int) -> None:
        self.scope_stack.append({})
        self.scope_ends.append(end_id)

    def _pop_expired(self, current_id: int) -> None:
        while self.scope_ends and current_id > self.scope_ends[-1]:
            self.scope_stack.pop()
            self.scope_ends.pop()

    def _define_params(self, func_id: int) -> None:
        for cid in self.children_of.get(func_id, []):
            child = self.node_by_id[cid]
            if child["type"] == "formal_parameters":
                for pid in self.children_of.get(cid, []):
                    param = self.node_by_id[pid]
                    if param["type"] == "identifier":
                        self._define(param["text"], param["id"])
                break

    # -- taint detection ---------------------------------------------------

    def _detect_taint(self, node: dict) -> None:
        text = node["text"]
        ntype = node["type"]

        if ntype == "call_expression":
            for pat, detail in _TAINT_SOURCES_CALL:
                if pat.search(text):
                    self.taint_flags.append({
                        "node_id": node["id"],
                        "flag_type": "source",
                        "detail": detail,
                    })
                    break

        for pat, detail in _TAINT_SOURCES_ANY:
            if pat.search(text):
                self.taint_flags.append({
                    "node_id": node["id"],
                    "flag_type": "source",
                    "detail": detail,
                })
                break

        if ntype == "call_expression":
            for pat, detail in _TAINT_SINKS:
                if pat.search(text):
                    self.taint_flags.append({
                        "node_id": node["id"],
                        "flag_type": "sink",
                        "detail": detail,
                    })
                    break

    # -- main walk ---------------------------------------------------------

    def run(self) -> None:
        for node in self.nodes:
            nid = node["id"]
            ntype = node["type"]

            self._pop_expired(nid)

            # --- scope-creating nodes ---
            if ntype in _SCOPE_TYPES:
                if ntype == "function_declaration":
                    for cid in self.children_of.get(nid, []):
                        child = self.node_by_id[cid]
                        if child["type"] == "identifier":
                            self._define(child["text"], nid)
                            break
                self._push_scope(self.subtree_end[nid])
                self._define_params(nid)

            # --- variable definitions ---
            elif ntype == "variable_declarator":
                for cid in self.children_of.get(nid, []):
                    child = self.node_by_id[cid]
                    if child["type"] == "identifier":
                        self._define(child["text"], nid)
                        break

            # --- identifier uses ---
            elif ntype == "identifier":
                if nid not in self.def_name_ids and nid not in self.param_ids:
                    def_id = self._lookup(node["text"])
                    if def_id is not None:
                        self.dfg_edges.append({
                            "source_id": def_id,
                            "target_id": nid,
                            "edge_type": "dfg_def_use",
                        })

            # --- taint ---
            self._detect_taint(node)
