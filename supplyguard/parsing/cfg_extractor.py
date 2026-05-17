"""
Build a simplified Control Flow Graph from AST nodes and edges.

Takes the output of ``extract_ast`` and produces inter-statement edges
that capture sequential flow, branching (if/else, loops), and implicit
exception paths (try/catch).

Supported constructs:
    * Sequential statements              → ``cfg_next``
    * If / else branches                  → ``cfg_branch``
    * For / while / do-while loops        → ``cfg_branch``
    * Try / catch implicit exception path → ``cfg_branch``
    * Return / throw as terminal nodes    (no outgoing edge)

Out-of-scope for v1: switch, generators, async/await, labeled breaks.
"""

from __future__ import annotations

from collections import defaultdict

# ---------------------------------------------------------------------------
# Node-type sets
# ---------------------------------------------------------------------------

_TERMINAL_TYPES = frozenset({
    "return_statement",
    "throw_statement",
    "break_statement",
    "continue_statement",
})

_LOOP_TYPES = frozenset({
    "for_statement",
    "while_statement",
    "do_statement",
    "for_in_statement",
    "for_of_statement",
})

_BRANCHING_TYPES = frozenset({"if_statement", "try_statement"}) | _LOOP_TYPES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_statement(node: dict) -> bool:
    t = node["type"]
    return t.endswith("_statement") or t.endswith("_declaration")


def _stmt_children(
    block_id: int,
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> list[dict]:
    """Return the ordered statement-level children of a block node."""
    return [
        node_by_id[cid]
        for cid in children_of[block_id]
        if _is_statement(node_by_id[cid])
    ]


def _find_child_of_type(
    parent_id: int,
    target_type: str,
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> dict | None:
    for cid in children_of[parent_id]:
        if node_by_id[cid]["type"] == target_type:
            return node_by_id[cid]
    return None


def _first_stmt_in(
    body: dict | None,
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> dict | None:
    """First statement reachable inside *body* (block or bare statement)."""
    if body is None:
        return None
    if body["type"] == "statement_block":
        stmts = _stmt_children(body["id"], node_by_id, children_of)
        return stmts[0] if stmts else None
    if _is_statement(body):
        return body
    return None


def _last_stmt_in(
    body: dict | None,
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> dict | None:
    """Last statement in *body* (block or bare statement)."""
    if body is None:
        return None
    if body["type"] == "statement_block":
        stmts = _stmt_children(body["id"], node_by_id, children_of)
        return stmts[-1] if stmts else None
    if _is_statement(body):
        return body
    return None


# ---------------------------------------------------------------------------
# If / else
# ---------------------------------------------------------------------------

def _find_if_bodies(
    if_id: int,
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> tuple[dict | None, dict | None]:
    """Return ``(consequent_body, alternate_body)`` for an if_statement.

    Handles both the ``else_clause`` wrapper style and the style where
    the alternate is a direct child after the ``else`` keyword.
    """
    children = [node_by_id[cid] for cid in children_of[if_id]]

    consequent: dict | None = None
    alternate: dict | None = None
    seen_else = False

    for child in children:
        t = child["type"]

        if t == "else_clause":
            for sub_id in children_of[child["id"]]:
                sub = node_by_id[sub_id]
                if sub["type"] == "statement_block" or _is_statement(sub):
                    alternate = sub
                    break
            continue

        if t == "else":
            seen_else = True
            continue

        if t in ("parenthesized_expression", "(", ")", "{", "}", "if"):
            continue

        if t == "statement_block" or _is_statement(child):
            if seen_else and alternate is None:
                alternate = child
            elif not seen_else and consequent is None:
                consequent = child

    return consequent, alternate


def _add_if_edges(
    if_node: dict,
    next_stmt: dict | None,
    cfg_edges: list[dict],
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> None:
    consequent, alternate = _find_if_bodies(
        if_node["id"], node_by_id, children_of,
    )

    for body in (consequent, alternate):
        first = _first_stmt_in(body, node_by_id, children_of)
        if first is not None:
            cfg_edges.append({
                "source_id": if_node["id"],
                "target_id": first["id"],
                "edge_type": "cfg_branch",
            })
        if next_stmt is not None:
            last = _last_stmt_in(body, node_by_id, children_of)
            if last is not None and last["type"] not in _TERMINAL_TYPES:
                cfg_edges.append({
                    "source_id": last["id"],
                    "target_id": next_stmt["id"],
                    "edge_type": "cfg_next",
                })

    if alternate is None and next_stmt is not None:
        cfg_edges.append({
            "source_id": if_node["id"],
            "target_id": next_stmt["id"],
            "edge_type": "cfg_branch",
        })


# ---------------------------------------------------------------------------
# Loops
# ---------------------------------------------------------------------------

def _find_loop_body(
    loop_id: int,
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> dict | None:
    children = [node_by_id[cid] for cid in children_of[loop_id]]
    for child in children:
        if child["type"] == "statement_block":
            return child
    for child in reversed(children):
        if _is_statement(child):
            return child
    return None


def _add_loop_edges(
    loop_node: dict,
    next_stmt: dict | None,
    cfg_edges: list[dict],
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> None:
    body = _find_loop_body(loop_node["id"], node_by_id, children_of)

    first = _first_stmt_in(body, node_by_id, children_of)
    if first is not None:
        cfg_edges.append({
            "source_id": loop_node["id"],
            "target_id": first["id"],
            "edge_type": "cfg_branch",
        })

    if next_stmt is not None:
        cfg_edges.append({
            "source_id": loop_node["id"],
            "target_id": next_stmt["id"],
            "edge_type": "cfg_branch",
        })

    last = _last_stmt_in(body, node_by_id, children_of)
    if last is not None and last["type"] not in _TERMINAL_TYPES:
        cfg_edges.append({
            "source_id": last["id"],
            "target_id": loop_node["id"],
            "edge_type": "cfg_branch",
        })


# ---------------------------------------------------------------------------
# Try / catch
# ---------------------------------------------------------------------------

def _add_try_edges(
    try_node: dict,
    next_stmt: dict | None,
    cfg_edges: list[dict],
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> None:
    children = [node_by_id[cid] for cid in children_of[try_node["id"]]]

    try_body: dict | None = None
    catch_clause: dict | None = None

    for child in children:
        t = child["type"]
        if t == "statement_block" and try_body is None:
            try_body = child
        elif t == "catch_clause":
            catch_clause = child

    catch_body = (
        _find_child_of_type(catch_clause["id"], "statement_block",
                            node_by_id, children_of)
        if catch_clause else None
    )
    catch_stmts = (
        _stmt_children(catch_body["id"], node_by_id, children_of)
        if catch_body else []
    )
    catch_first = catch_stmts[0] if catch_stmts else None

    try_stmts = (
        _stmt_children(try_body["id"], node_by_id, children_of)
        if try_body else []
    )

    # Implicit exception edge: every try-body statement → catch entry
    if catch_first is not None:
        for stmt in try_stmts:
            cfg_edges.append({
                "source_id": stmt["id"],
                "target_id": catch_first["id"],
                "edge_type": "cfg_branch",
            })

    # Normal exit from try body → next_stmt
    if next_stmt is not None and try_stmts:
        last = try_stmts[-1]
        if last["type"] not in _TERMINAL_TYPES:
            cfg_edges.append({
                "source_id": last["id"],
                "target_id": next_stmt["id"],
                "edge_type": "cfg_next",
            })

    # Exit from catch body → next_stmt
    if next_stmt is not None and catch_stmts:
        last = catch_stmts[-1]
        if last["type"] not in _TERMINAL_TYPES:
            cfg_edges.append({
                "source_id": last["id"],
                "target_id": next_stmt["id"],
                "edge_type": "cfg_next",
            })


# ---------------------------------------------------------------------------
# Block-level sequencing
# ---------------------------------------------------------------------------

def _connect_block(
    stmts: list[dict],
    cfg_edges: list[dict],
    node_by_id: dict[int, dict],
    children_of: dict[int, list[int]],
) -> None:
    """Add CFG edges for an ordered sequence of sibling statements."""
    for i in range(len(stmts)):
        current = stmts[i]
        nxt = stmts[i + 1] if i + 1 < len(stmts) else None
        ctype = current["type"]

        if ctype in _TERMINAL_TYPES:
            continue

        if ctype == "if_statement":
            _add_if_edges(current, nxt, cfg_edges, node_by_id, children_of)
        elif ctype in _LOOP_TYPES:
            _add_loop_edges(current, nxt, cfg_edges, node_by_id, children_of)
        elif ctype == "try_statement":
            _add_try_edges(current, nxt, cfg_edges, node_by_id, children_of)
        elif nxt is not None:
            cfg_edges.append({
                "source_id": current["id"],
                "target_id": nxt["id"],
                "edge_type": "cfg_next",
            })


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_cfg(
    ast_nodes: list[dict],
    ast_edges: list[dict],
) -> list[dict]:
    """Build a CFG from the AST produced by ``extract_ast``.

    Parameters
    ----------
    ast_nodes : list[dict]
        Node dicts with at least ``id`` and ``type`` keys.
    ast_edges : list[dict]
        Parent→child edges with ``source_id``, ``target_id``,
        ``edge_type == "ast_child"``.

    Returns
    -------
    list[dict]
        CFG edges, each with keys ``source_id``, ``target_id``, and
        ``edge_type`` (``"cfg_next"`` or ``"cfg_branch"``).
    """
    node_by_id: dict[int, dict] = {n["id"]: n for n in ast_nodes}

    children_of: dict[int, list[int]] = defaultdict(list)
    for edge in ast_edges:
        if edge["edge_type"] == "ast_child":
            children_of[edge["source_id"]].append(edge["target_id"])

    cfg_edges: list[dict] = []

    for node in ast_nodes:
        if node["type"] in ("program", "statement_block"):
            stmts = _stmt_children(node["id"], node_by_id, children_of)
            _connect_block(stmts, cfg_edges, node_by_id, children_of)

    return cfg_edges
