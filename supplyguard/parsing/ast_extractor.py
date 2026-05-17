"""
AST extraction from JavaScript packages using tree-sitter.

Walks every .js / .mjs file in a package directory, builds an AST with
tree-sitter-javascript, and returns a flat list of node dicts plus
parent→child edges.  Also provides ``get_node_features`` which converts
a single node dict into a 35-dimensional numeric feature vector.

Feature layout (35 dims):
    0–22   one-hot node type (23 categories including OTHER)
    23     is_eval_call
    24     is_exec_call
    25     is_network_call
    26     is_file_op
    27     is_base64_indicator
    28     is_obfuscated
    29     is_env_access
    30     is_dangerous_import
    31     is_dynamic_require
    32     is_crypto_call
    33     is_timer_callback
    34     is_string_manipulation
"""

from __future__ import annotations

import logging
import re
from itertools import count
from pathlib import Path

log = logging.getLogger(__name__)

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser

JS_LANGUAGE = Language(tsjs.language())

MAX_FILE_SIZE = 200 * 1024  # 200 KB
MAX_AST_NODES = 30_000

# ---------------------------------------------------------------------------
# One-hot node-type categories (23 total, last is OTHER)
# ---------------------------------------------------------------------------

FEATURE_DIM = 35

NODE_TYPE_CATEGORIES: list[str] = [
    "expression_statement",
    "call_expression",
    "member_expression",
    "identifier",
    "string",
    "template_literal",
    "assignment_expression",
    "variable_declaration",
    "function_declaration",
    "arrow_function",
    "if_statement",
    "for_statement",
    "try_statement",
    "import_statement",
    "binary_expression",
    "return_statement",
    "object_expression",
    "array_expression",
    "new_expression",
    "await_expression",
    "yield_expression",
    "class_declaration",
    # index 22 → OTHER (implicit)
]

_TYPE_TO_INDEX: dict[str, int] = {t: i for i, t in enumerate(NODE_TYPE_CATEGORIES)}
# tree-sitter-javascript calls backtick strings "template_string"
_TYPE_TO_INDEX["template_string"] = _TYPE_TO_INDEX["template_literal"]

_NUM_TYPE_FEATURES = len(NODE_TYPE_CATEGORIES) + 1  # 17

# ---------------------------------------------------------------------------
# Regex patterns for the 8 binary flags
# ---------------------------------------------------------------------------

_EVAL_RE = re.compile(r"\b(eval|Function)\s*\(")

_EXEC_RE = re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\(")

_NETWORK_RE = re.compile(
    r"\bhttps?\s*\.\s*(?:get|post|request)\s*\("
    r"|\bfetch\s*\("
    r"|\baxios\s*\.\s*(?:get|post|request|put|delete)\s*\("
    r"|\bSocket\s*\("
    r"|\bdns\s*\.\s*lookup\s*\("
)

_FILE_OP_RE = re.compile(
    r"\b(?:readFileSync|writeFileSync|readFile|writeFile"
    r"|createReadStream|createWriteStream)\s*\("
)

_DANGEROUS_REQUIRE_RE = re.compile(
    r"""\brequire\s*\(\s*["'](?:http|https|child_process|net|dns|fs|os)['"]\s*\)"""
)

_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}")

_BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# Patterns for the 4 new binary flags
_DYNAMIC_REQUIRE_RE = re.compile(
    r"\brequire\s*\(\s*(?!"
    r"""["'][^"']*["']"""  # NOT a simple string literal
    r"\s*\))"
)

_CRYPTO_CALL_RE = re.compile(
    r"\b(?:createHash|createCipher|createDecipher(?:iv)?|createSign|createVerify"
    r"|createHmac|publicEncrypt|privateDecrypt|randomBytes|scrypt|pbkdf2)\s*\("
)

_TIMER_CALLBACK_RE = re.compile(
    r"\b(?:setTimeout|setInterval|setImmediate)\s*\("
)

_STRING_MANIP_RE = re.compile(
    r"\b(?:String\.fromCharCode|charCodeAt|Buffer\.from|atob|btoa"
    r"|decodeURIComponent|unescape)\s*\("
)


def _identifier_entropy(text: str) -> float:
    """Shannon entropy of a string — high entropy suggests obfuscated names."""
    import math
    from collections import Counter
    if len(text) < 2:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return entropy


# ---------------------------------------------------------------------------
# AST extraction
# ---------------------------------------------------------------------------

def extract_ast(package_dir: str) -> tuple[list[dict], list[dict]]:
    """Parse all JS/MJS files in *package_dir* and return ``(nodes, edges)``.

    Each **node** dict has keys:
        id, type, text (≤200 chars), file, start_line, end_line

    Each **edge** dict has keys:
        source_id (parent), target_id (child), edge_type ("ast_child")
    """
    root = Path(package_dir)
    parser = Parser(JS_LANGUAGE)

    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    id_gen = count()

    js_files = sorted(
        p
        for p in root.rglob("*")
        if p.suffix in (".js", ".mjs")
        and "node_modules" not in p.parts
        and not p.name.endswith(".min.js")
        and p.is_file()
        and p.stat().st_size <= MAX_FILE_SIZE
    )

    for js_file in js_files:
        try:
            source = js_file.read_bytes()
            tree = parser.parse(source)
            file_rel = str(js_file.relative_to(root))
            nodes, edges = _walk_tree(tree, source, file_rel, id_gen)
        except Exception:
            log.debug("Skipping %s — parse/read error", js_file, exc_info=True)
            continue

        all_nodes.extend(nodes)
        all_edges.extend(edges)

        if len(all_nodes) >= MAX_AST_NODES:
            log.info(
                "AST node cap (%d) reached after %s — stopping parse",
                MAX_AST_NODES, file_rel,
            )
            break

    return all_nodes, all_edges


def _walk_tree(
    tree, source: bytes, file_rel: str, id_gen: count,
) -> tuple[list[dict], list[dict]]:
    """Cursor-based DFS collecting every node and parent→child edges."""
    nodes: list[dict] = []
    edges: list[dict] = []

    cursor = tree.walk()
    parent_id_stack: list[int] = []
    visited_children = False

    while True:
        if not visited_children:
            ts_node = cursor.node
            node_id = next(id_gen)

            text = source[ts_node.start_byte : ts_node.end_byte].decode(
                "utf-8", errors="replace",
            )[:200]

            nodes.append(
                {
                    "id": node_id,
                    "type": ts_node.type,
                    "text": text,
                    "file": file_rel,
                    "start_line": ts_node.start_point[0] + 1,
                    "end_line": ts_node.end_point[0] + 1,
                }
            )

            if parent_id_stack:
                edges.append(
                    {
                        "source_id": parent_id_stack[-1],
                        "target_id": node_id,
                        "edge_type": "ast_child",
                    }
                )

            if cursor.goto_first_child():
                parent_id_stack.append(node_id)
            else:
                visited_children = True

        elif cursor.goto_next_sibling():
            visited_children = False

        elif cursor.goto_parent():
            parent_id_stack.pop()
            visited_children = True

        else:
            break

    return nodes, edges


# ---------------------------------------------------------------------------
# Feature vector (35 dims = 23 one-hot + 12 binary flags)
# ---------------------------------------------------------------------------

def get_node_features(node: dict) -> list[float]:
    """Return a 35-element numeric feature vector for *node*."""
    ntype = node["type"]
    text = node["text"]

    # ---- one-hot (23) ----
    type_vec = [0.0] * _NUM_TYPE_FEATURES
    type_vec[_TYPE_TO_INDEX.get(ntype, _NUM_TYPE_FEATURES - 1)] = 1.0

    # ---- binary flags 1–8 (original) ----
    is_call = ntype == "call_expression"

    is_eval_call = float(is_call and bool(_EVAL_RE.search(text)))
    is_exec_call = float(is_call and bool(_EXEC_RE.search(text)))
    is_network_call = float(is_call and bool(_NETWORK_RE.search(text)))
    is_file_op = float(is_call and bool(_FILE_OP_RE.search(text)))

    is_base64 = 0.0
    if "base64" in text:
        is_base64 = 1.0
    elif ntype == "string":
        inner = text.strip("\"'`")
        if len(inner) > 40 and _BASE64_CHARS_RE.match(inner):
            is_base64 = 1.0

    is_obfuscated = 0.0
    if ntype == "string" and len(text) >= 200:
        is_obfuscated = 1.0
    elif _HEX_ESCAPE_RE.search(text):
        is_obfuscated = 1.0
    elif _UNICODE_ESCAPE_RE.search(text):
        is_obfuscated = 1.0
    elif node["start_line"] == node["end_line"] and len(text) >= 200:
        is_obfuscated = 1.0
    elif ntype == "identifier" and len(text) >= 3:
        entropy = _identifier_entropy(text)
        if entropy > 3.5 and len(text) > 8:
            is_obfuscated = 1.0

    is_env_access = float("process.env" in text)
    is_dangerous_import = float(is_call and bool(_DANGEROUS_REQUIRE_RE.search(text)))

    # ---- binary flags 9–12 (new) ----
    is_dynamic_require = float(
        is_call and bool(_DYNAMIC_REQUIRE_RE.search(text))
    )
    is_crypto_call = float(is_call and bool(_CRYPTO_CALL_RE.search(text)))
    is_timer_callback = float(is_call and bool(_TIMER_CALLBACK_RE.search(text)))
    is_string_manipulation = float(bool(_STRING_MANIP_RE.search(text)))

    return type_vec + [
        is_eval_call,        # 23
        is_exec_call,        # 24
        is_network_call,     # 25
        is_file_op,          # 26
        is_base64,           # 27
        is_obfuscated,       # 28
        is_env_access,       # 29
        is_dangerous_import, # 30
        is_dynamic_require,  # 31
        is_crypto_call,      # 32
        is_timer_callback,   # 33
        is_string_manipulation,  # 34
    ]
