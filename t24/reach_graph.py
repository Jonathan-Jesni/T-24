"""reach_graph.py — Call-graph builder for T-24 reachability analysis.

Responsibilities
----------------
- Walk the product root for .py files.
- Delegate per-file parsing to reach_parse.py.
- Build an adjacency-list call graph from the ParsedFile collection.
- Over-approximate unresolved obj.method() calls by adding edges to ALL
  product-defined functions whose *short* name matches, regardless of class.
  The method index keys are short names; values are (ParsedFile, qualified_name).
- Collect entry-point nodes.

Graph nodes: (forward_slash_rel_path, function_name)
  function_name is either a plain name ("upload"), a qualified name
  ("Loader.load"), or "<module>" for genuine module-level statements.
"""
from __future__ import annotations

import pathlib

from t24.reach_parse import (
    ParsedFile,
    UncertainSite,
    parse_file,
    path_to_dotted,
    rel_fwd,
    rel_fwd_product,
)

__all__ = [
    "ParsedFile",
    "UncertainSite",
    "parse_file",
    "path_to_dotted",
    "rel_fwd",
    "build_graph",
    "collect_entry_nodes",
]

_MODULE_LEVEL = "<module>"

Node = tuple[str, str]  # (fwd_slash_rel_path, func_name)


def build_graph(
    parsed_files: list[ParsedFile],
) -> dict[Node, list[tuple[Node, int, str]]]:
    """Return adjacency list node → [(neighbor, line, call_str)].

    Cross-file edges are built by matching callee fq-names against
    known product dotted paths (e.g. "svc.helpers.parse").

    Over-approximation for method calls: an unresolved obj.method() call
    (including self.method()) adds edges to ALL product-defined functions
    whose *short* name equals `method`, regardless of class.
    """
    dotted_to_file: dict[str, ParsedFile] = {pf.dotted_path: pf for pf in parsed_files}

    # Short-name → [(ParsedFile, qualified_name)]
    # e.g. "load" → [(pf, "Loader.load")]
    method_index: dict[str, list[tuple[ParsedFile, str]]] = {}
    for pf in parsed_files:
        for func_name in pf.calls:
            if func_name == _MODULE_LEVEL:
                continue
            # short name is the part after the last dot (handles Cls.meth)
            short = func_name.rsplit(".", 1)[-1]
            method_index.setdefault(short, []).append((pf, func_name))

    graph: dict[Node, list[tuple[Node, int, str]]] = {}

    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            src: Node = (pf.rel_path, func_name)
            edges = graph.setdefault(src, [])

            for callee_fq, line, call_str in call_list:
                resolved = _resolve_to_product(callee_fq, dotted_to_file)
                if resolved:
                    edges.append((resolved, line, call_str))
                    continue
                # Same-file function (plain name)?
                if callee_fq in pf.calls:
                    edges.append(((pf.rel_path, callee_fq), line, call_str))

        # Over-approximation: unresolved obj.method() → all product methods
        for func_name, mcalls in pf.method_calls.items():
            src = (pf.rel_path, func_name)
            edges = graph.setdefault(src, [])
            for method_name, line, call_str in mcalls:
                for target_pf, target_func in method_index.get(method_name, []):
                    dst: Node = (target_pf.rel_path, target_func)
                    if dst not in [e[0] for e in edges]:
                        edges.append((dst, line, call_str))

    return graph


def collect_entry_nodes(
    parsed_files: list[ParsedFile],
    explicit: list[str],
    cwd: pathlib.Path,
) -> list[Node]:
    """Return entry-point nodes."""
    if explicit:
        nodes: list[Node] = []
        for ep in explicit:
            if ":" in ep:
                path_part, func_part = ep.rsplit(":", 1)
                ep_path = pathlib.Path(path_part)
                if not ep_path.is_absolute():
                    ep_path = cwd / ep_path
                try:
                    rel = ep_path.relative_to(cwd).as_posix()
                except ValueError:
                    rel = ep_path.as_posix().replace("\\", "/")
                nodes.append((rel, func_part))
            else:
                ep_path = pathlib.Path(ep)
                try:
                    rel = ep_path.relative_to(cwd).as_posix()
                except ValueError:
                    rel = ep_path.as_posix().replace("\\", "/")
                nodes.append((rel, _MODULE_LEVEL))
        return nodes

    auto: list[Node] = []
    for pf in parsed_files:
        for ep in pf.entry_points:
            auto.append((pf.rel_path, ep))
    return auto


def _resolve_to_product(
    callee_fq: str,
    dotted_to_file: dict[str, ParsedFile],
) -> Node | None:
    """Try to split callee_fq into (module_dotted_path, func_name) for a product module."""
    parts = callee_fq.rsplit(".", 1)
    if len(parts) == 2:
        mod, func = parts
        if mod in dotted_to_file:
            pf = dotted_to_file[mod]
            return (pf.rel_path, func)
    return None
