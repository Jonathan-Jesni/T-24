"""reach_graph.py — Call-graph builder and BFS reachability engine.

Builds a graph of the form:
    node: (file_stem_or_path, function_name)
    edges: node → list[(callee_node, file, line, call_expr_str)]

Entry points are discovered by:
  1. Looking for Flask-decorated functions (*.route / *.get / *.post / etc.)
  2. Module-level statements not inside any function
  3. Explicit overrides passed by the caller

BFS from all entry-point nodes finds the shortest evidence path to each target.
"""
from __future__ import annotations

import ast
import pathlib
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Iterator

from t24.reach_imports import (
    build_import_map,
    resolve_call_target,
    resolve_name_ref,
)

# Flask HTTP-method decorator names that mark route functions
_FLASK_HTTP_DECORATORS = frozenset(
    {"route", "get", "post", "put", "delete", "patch"}
)

# Node in the call graph: (relative_file_path, function_name)
Node = tuple[str, str]  # (rel_file, func_name)

_MODULE_LEVEL = "<module>"


@dataclass
class ParsedFile:
    rel_path: str
    tree: ast.Module
    aliases: dict[str, str]
    # func_name → list of (callee_fq, line, call_str)
    calls: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    # sibling module refs: local name of sibling import → callee func qualified as "stem.func"
    entry_points: list[str] = field(default_factory=list)


def _is_flask_decorator(decorator: ast.expr) -> bool:
    """Return True if decorator looks like a Flask route decorator."""
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    if isinstance(decorator, ast.Attribute):
        return decorator.attr in _FLASK_HTTP_DECORATORS
    if isinstance(decorator, ast.Name):
        return decorator.id in _FLASK_HTTP_DECORATORS
    return False


def _func_entry_points(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if this function is auto-detected as an entry point."""
    return any(_is_flask_decorator(d) for d in func.decorator_list)


def _collect_calls_in_body(
    stmts: list[ast.stmt],
    aliases: dict[str, str],
    func_name: str,
    calls_map: dict[str, list[tuple[str, int, str]]],
) -> None:
    """Walk statements and collect (callee_fq, line, call_str) into calls_map[func_name]."""
    bucket = calls_map.setdefault(func_name, [])

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            fq = resolve_call_target(node.func, aliases)
            if fq:
                call_str = ast.unparse(node.func)
                bucket.append((fq, node.lineno, call_str))
            # Also scan keyword values for references like Loader=yaml.FullLoader
            for kw in node.keywords:
                ref = resolve_name_ref(kw.value, aliases)
                if ref:
                    ref_str = ast.unparse(kw.value)
                    bucket.append((ref, kw.value.lineno, ref_str))
            self.generic_visit(node)

    visitor = _Visitor()
    for stmt in stmts:
        visitor.visit(stmt)


def parse_file(path: pathlib.Path, root: pathlib.Path, sibling_stems: frozenset[str]) -> ParsedFile:
    """Parse a Python file and build its call map."""
    rel = str(path.relative_to(root.parent))
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(path))
    aliases = build_import_map(tree, sibling_stems)

    pf = ParsedFile(rel_path=rel, tree=tree, aliases=aliases)
    module_stmts: list[ast.stmt] = []

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _collect_calls_in_body(node.body, aliases, node.name, pf.calls)
            if _func_entry_points(node):
                pf.entry_points.append(node.name)
        elif isinstance(node, ast.If):
            # if __name__ == "__main__": ...
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
            ):
                _collect_calls_in_body(node.body, aliases, _MODULE_LEVEL, pf.calls)
                pf.entry_points.append(_MODULE_LEVEL)
        else:
            module_stmts.append(node)

    # Module-level statements (outside any function/if-main)
    if module_stmts:
        _collect_calls_in_body(module_stmts, aliases, _MODULE_LEVEL, pf.calls)

    return pf


def _stem(rel_path: str) -> str:
    return pathlib.Path(rel_path).stem


def build_graph(
    parsed_files: list[ParsedFile],
) -> dict[Node, list[tuple[Node, int, str]]]:
    """Return adjacency list: node → [(callee_node, line, call_str)].

    Edges within a file: (rel_path, caller) → (rel_path, callee).
    Edges across files via sibling import: (rel_path, caller) → (sibling_rel, callee).
    """
    # Build stem → ParsedFile lookup for cross-file resolution
    stem_to_file: dict[str, ParsedFile] = {_stem(pf.rel_path): pf for pf in parsed_files}

    graph: dict[Node, list[tuple[Node, int, str]]] = {}

    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            src_node: Node = (pf.rel_path, func_name)
            edges = graph.setdefault(src_node, [])
            for callee_fq, line, call_str in call_list:
                # Check if callee_fq looks like "stem.func" and stem is a sibling
                parts = callee_fq.split(".", 1)
                if len(parts) == 2 and parts[0] in stem_to_file:
                    sibling = stem_to_file[parts[0]]
                    callee_func = parts[1]
                    dst_node: Node = (sibling.rel_path, callee_func)
                    edges.append((dst_node, line, call_str))
                else:
                    # Same-file function reference
                    if callee_fq in pf.calls:
                        dst_node = (pf.rel_path, callee_fq)
                        edges.append((dst_node, line, call_str))

    return graph


def collect_entry_nodes(
    parsed_files: list[ParsedFile],
    explicit: list[str],
    root: pathlib.Path,
) -> list[Node]:
    """Return all entry-point nodes.

    explicit: list of "abs_path:func" or "rel_path:func" strings.
    If non-empty, only those nodes are used (auto-detection disabled).
    """
    if explicit:
        nodes: list[Node] = []
        for ep in explicit:
            if ":" in ep:
                path_part, func_part = ep.rsplit(":", 1)
                ep_path = pathlib.Path(path_part)
                if not ep_path.is_absolute():
                    ep_path = root.parent / ep_path
                rel = str(ep_path.relative_to(root.parent))
                nodes.append((rel, func_part))
            else:
                # bare file — treat as module-level
                ep_path = pathlib.Path(ep)
                rel = str(ep_path.relative_to(root.parent))
                nodes.append((rel, _MODULE_LEVEL))
        return nodes

    # Auto-detection
    auto: list[Node] = []
    for pf in parsed_files:
        for ep in pf.entry_points:
            auto.append((pf.rel_path, ep))
    return auto


@dataclass
class EvidenceHop:
    file: str
    line: int
    function: str
    call: str


@dataclass
class ReachResult:
    target: str
    reachable: bool
    evidence: list[EvidenceHop]
    files_found: int
    files_parsed: int


def _matches_target(call_fq: str, target: str) -> bool:
    """True when call_fq equals target or call_fq starts with target (prefix match)."""
    return call_fq == target or call_fq.startswith(target + ".")


def bfs_reach(
    graph: dict[Node, list[tuple[Node, int, str]]],
    entry_nodes: list[Node],
    parsed_files: list[ParsedFile],
    targets: list[str],
    template_targets: list[str],
    root: pathlib.Path,
) -> list[ReachResult]:
    """BFS from entry nodes; return shortest evidence path for each target."""
    files_found = len(parsed_files) + _count_templates(root)
    files_parsed = sum(1 for pf in parsed_files if pf.tree is not None)

    # Build fq-call lookup per node: node → list of (fq_callee, line, call_str)
    # (already in graph; also need raw calls for target matching)
    fq_calls: dict[Node, list[tuple[str, int, str]]] = {}
    stem_to_file: dict[str, ParsedFile] = {_stem(pf.rel_path): pf for pf in parsed_files}

    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            node: Node = (pf.rel_path, func_name)
            fq_calls[node] = call_list

    # Discover render_template calls for template scanning
    # Map: node → list of template names it renders
    renders: dict[Node, list[str]] = {}
    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            node = (pf.rel_path, func_name)
            for fq, line, call_str in call_list:
                if fq == "flask.render_template" or fq.endswith(".render_template"):
                    # parse the template name from call_str via AST
                    tmpl_names = _extract_template_names(pf, func_name, line)
                    renders.setdefault(node, []).extend(tmpl_names)

    results: list[ReachResult] = []
    for target in targets:
        evidence, reached = _bfs(
            graph, fq_calls, entry_nodes, target, root,
            parsed_files, renders, template_targets=[], is_filter=False,
        )
        results.append(ReachResult(
            target=target,
            reachable=reached,
            evidence=evidence,
            files_found=files_found,
            files_parsed=files_parsed,
        ))

    for tf in template_targets:
        evidence, reached = _bfs(
            graph, fq_calls, entry_nodes, tf, root,
            parsed_files, renders, template_targets=[tf], is_filter=True,
        )
        results.append(ReachResult(
            target=tf,
            reachable=reached,
            evidence=evidence,
            files_found=files_found,
            files_parsed=files_parsed,
        ))

    return results


def _bfs(
    graph: dict[Node, list[tuple[Node, int, str]]],
    fq_calls: dict[Node, list[tuple[str, int, str]]],
    entry_nodes: list[Node],
    target: str,
    root: pathlib.Path,
    parsed_files: list[ParsedFile],
    renders: dict[Node, list[str]],
    template_targets: list[str],
    is_filter: bool,
) -> tuple[list[EvidenceHop], bool]:
    """BFS; return (evidence_hops, reached)."""
    # path: node → list of EvidenceHop leading to that node
    visited: dict[Node, list[EvidenceHop]] = {}
    queue: deque[tuple[Node, list[EvidenceHop]]] = deque()

    for en in entry_nodes:
        if en not in visited:
            visited[en] = []
            queue.append((en, []))

    while queue:
        node, path = queue.popleft()
        rel_file, func_name = node

        # Check if this node directly calls/references the target
        for fq, line, call_str in fq_calls.get(node, []):
            if not is_filter and _matches_target(fq, target):
                hop = EvidenceHop(file=rel_file, line=line, function=func_name, call=call_str)
                return path + [hop], True

        # For template filter targets: check templates rendered from this node
        if is_filter and template_targets:
            for tmpl_name in renders.get(node, []):
                tmpl_path = root / "templates" / tmpl_name
                if tmpl_path.exists():
                    hit_line = _scan_template_for_filter(tmpl_path, target)
                    if hit_line is not None:
                        # Add a hop for the render_template call
                        render_line = _find_render_line(fq_calls, node)
                        if render_line:
                            render_hop = EvidenceHop(
                                file=rel_file,
                                line=render_line,
                                function=func_name,
                                call=f"render_template({tmpl_name!r})",
                            )
                            tmpl_rel = str(tmpl_path.relative_to(root.parent))
                            filter_hop = EvidenceHop(
                                file=tmpl_rel,
                                line=hit_line,
                                function="<template>",
                                call=f"|{target}",
                            )
                            return path + [render_hop, filter_hop], True

        # Expand edges
        for neighbor, line, call_str in graph.get(node, []):
            if neighbor not in visited:
                hop = EvidenceHop(
                    file=rel_file,
                    line=line,
                    function=func_name,
                    call=call_str,
                )
                visited[neighbor] = path + [hop]
                queue.append((neighbor, path + [hop]))

    return [], False


def _extract_template_names(pf: ParsedFile, func_name: str, target_line: int) -> list[str]:
    """Extract string literal template names from render_template calls in this func."""
    names: list[str] = []
    for node in ast.walk(pf.tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        fname = (
            func.attr if isinstance(func, ast.Attribute) else
            func.id if isinstance(func, ast.Name) else None
        )
        if fname != "render_template":
            continue
        if node.args and isinstance(node.args[0], ast.Constant):
            names.append(str(node.args[0].value))
    return names


def _scan_template_for_filter(tmpl_path: pathlib.Path, filter_name: str) -> int | None:
    """Scan a Jinja2 template file for a filter; return 1-based line number or None."""
    pattern = re.compile(r"\|\s*" + re.escape(filter_name) + r"\b")
    try:
        lines = tmpl_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for i, line in enumerate(lines, 1):
        if pattern.search(line):
            return i
    return None


def _find_render_line(fq_calls: dict[Node, list[tuple[str, int, str]]], node: Node) -> int | None:
    for fq, line, _ in fq_calls.get(node, []):
        if fq == "flask.render_template" or fq.endswith(".render_template"):
            return line
    return None


def _count_templates(root: pathlib.Path) -> int:
    tmpl_dir = root / "templates"
    if not tmpl_dir.exists():
        return 0
    return sum(1 for _ in tmpl_dir.rglob("*") if _.is_file())
