"""reach_bfs.py — BFS reachability engine for T-24.

Performs breadth-first search over the call graph built by reach_graph.py
to find the shortest evidence path from any entry point to each target.

Also handles template-filter scanning and aggregates uncertainty sites.
"""
from __future__ import annotations

import ast
import pathlib
import re
from collections import deque
from dataclasses import dataclass, field

from t24.reach_graph import Node, ParsedFile, UncertainSite

_MODULE_LEVEL = "<module>"


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
    uncertain: bool = False
    uncertain_sites: list[dict] = field(default_factory=list)  # {file, line, reason}


def _matches_target(call_fq: str, target: str) -> bool:
    return call_fq == target or call_fq.startswith(target + ".")


def bfs_reach(
    graph: dict[Node, list[tuple[Node, int, str]]],
    entry_nodes: list[Node],
    parsed_files: list[ParsedFile],
    targets: list[str],
    template_targets: list[str],
    root: pathlib.Path,
    cwd: pathlib.Path,
) -> list[ReachResult]:
    """BFS from entry nodes; return one ReachResult per target and per filter."""
    files_found = len(parsed_files) + _count_templates(root)
    files_parsed = len(parsed_files)

    # Aggregate all uncertainty sites across the whole project
    all_uncertain_sites: list[dict] = []
    for pf in parsed_files:
        for site in pf.uncertain_sites:
            all_uncertain_sites.append({"file": site.file, "line": site.line, "reason": site.reason})

    fq_calls: dict[Node, list[tuple[str, int, str]]] = {}
    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            fq_calls[(pf.rel_path, func_name)] = call_list

    # render_template call map: node → list of template names
    renders: dict[Node, list[str]] = {}
    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            node: Node = (pf.rel_path, func_name)
            for fq, line, _ in call_list:
                if fq.endswith(".render_template") or fq == "flask.render_template":
                    for name in _extract_template_names(pf):
                        renders.setdefault(node, []).append(name)

    results: list[ReachResult] = []
    for target in targets:
        evidence, reached = _bfs(graph, fq_calls, entry_nodes, target, root, cwd,
                                  renders, is_filter=False)
        uncertain = not reached and bool(all_uncertain_sites)
        results.append(ReachResult(
            target=target, reachable=reached, evidence=evidence,
            files_found=files_found, files_parsed=files_parsed,
            uncertain=uncertain,
            uncertain_sites=all_uncertain_sites if uncertain else [],
        ))

    for tf in template_targets:
        evidence, reached = _bfs(graph, fq_calls, entry_nodes, tf, root, cwd,
                                  renders, is_filter=True)
        uncertain = not reached and bool(all_uncertain_sites)
        results.append(ReachResult(
            target=tf, reachable=reached, evidence=evidence,
            files_found=files_found, files_parsed=files_parsed,
            uncertain=uncertain,
            uncertain_sites=all_uncertain_sites if uncertain else [],
        ))

    return results


def _bfs(
    graph: dict[Node, list[tuple[Node, int, str]]],
    fq_calls: dict[Node, list[tuple[str, int, str]]],
    entry_nodes: list[Node],
    target: str,
    root: pathlib.Path,
    cwd: pathlib.Path,
    renders: dict[Node, list[str]],
    is_filter: bool,
) -> tuple[list[EvidenceHop], bool]:
    visited: dict[Node, list[EvidenceHop]] = {}
    queue: deque[tuple[Node, list[EvidenceHop]]] = deque()

    for en in entry_nodes:
        if en not in visited:
            visited[en] = []
            queue.append((en, []))

    while queue:
        node, path = queue.popleft()
        rel_file, func_name = node

        if not is_filter:
            for fq, line, call_str in fq_calls.get(node, []):
                if _matches_target(fq, target):
                    hop = EvidenceHop(file=rel_file, line=line,
                                      function=func_name, call=call_str)
                    return path + [hop], True
        else:
            for tmpl_name in renders.get(node, []):
                tmpl_path = root / "templates" / tmpl_name
                if tmpl_path.exists():
                    hit_line = _scan_template_for_filter(tmpl_path, target)
                    if hit_line is not None:
                        render_line = _find_render_line(fq_calls, node)
                        if render_line:
                            tmpl_rel = tmpl_path.relative_to(cwd).as_posix()
                            render_hop = EvidenceHop(
                                file=rel_file, line=render_line,
                                function=func_name,
                                call=f"render_template({tmpl_name!r})",
                            )
                            filter_hop = EvidenceHop(
                                file=tmpl_rel, line=hit_line,
                                function="<template>",
                                call=f"|{target}",
                            )
                            return path + [render_hop, filter_hop], True

        for neighbor, line, call_str in graph.get(node, []):
            if neighbor not in visited:
                hop = EvidenceHop(file=rel_file, line=line,
                                   function=func_name, call=call_str)
                visited[neighbor] = path + [hop]
                queue.append((neighbor, path + [hop]))

    return [], False


def _extract_template_names(pf: ParsedFile) -> list[str]:
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
    pattern = re.compile(r"\|\s*" + re.escape(filter_name) + r"\b")
    try:
        lines = tmpl_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for i, line in enumerate(lines, 1):
        if pattern.search(line):
            return i
    return None


def _find_render_line(
    fq_calls: dict[Node, list[tuple[str, int, str]]], node: Node
) -> int | None:
    for fq, line, _ in fq_calls.get(node, []):
        if fq.endswith(".render_template") or fq == "flask.render_template":
            return line
    return None


def _count_templates(root: pathlib.Path) -> int:
    tmpl_dir = root / "templates"
    if not tmpl_dir.exists():
        return 0
    return sum(1 for _ in tmpl_dir.rglob("*") if _.is_file())
