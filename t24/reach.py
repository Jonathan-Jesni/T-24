"""reach.py — Public API for T-24 reachability analysis.

Usage::

    from t24.reach import scan, ReachResult, EvidenceHop

    results = scan(
        product_root=pathlib.Path("demo_product"),
        targets=["yaml.full_load", "yaml.FullLoader", "PIL.ImageMath.eval"],
        template_filters=["xmlattr"],
        entry_points=[],   # empty = auto-detect Flask routes
    )
    for r in results:
        print(r.target, r.reachable, r.evidence)
"""
from __future__ import annotations

import ast
import pathlib

from t24.reach_graph import (
    EvidenceHop,
    ReachResult,
    ParsedFile,
    bfs_reach,
    build_graph,
    collect_entry_nodes,
    parse_file,
)
from t24.reach_imports import build_import_map

__all__ = ["scan", "ReachResult", "EvidenceHop"]


def scan(
    product_root: pathlib.Path | str,
    targets: list[str],
    template_filters: list[str],
    entry_points: list[str],
) -> list[ReachResult]:
    """Analyse *product_root* and return reachability results.

    Parameters
    ----------
    product_root:
        Directory to walk for ``*.py`` files.
    targets:
        Fully-qualified symbol names to check, e.g. ``["yaml.full_load"]``.
    template_filters:
        Jinja2 filter names to check in templates, e.g. ``["xmlattr"]``.
    entry_points:
        Explicit ``"path:func"`` overrides.  Empty list = auto-detect.

    Returns
    -------
    One :class:`ReachResult` per target + one per template filter.
    """
    root = pathlib.Path(product_root).resolve()

    # --- Collect all .py files ---
    py_files = sorted(root.rglob("*.py"))
    files_found_base = len(py_files)

    # Sibling stems = all file stems in the project (for cross-file import resolution)
    sibling_stems: frozenset[str] = frozenset(p.stem for p in py_files)

    # --- Parse each file; record failures ---
    parsed: list[ParsedFile] = []
    parse_failures = 0

    for py_path in py_files:
        try:
            pf = parse_file(py_path, root, sibling_stems)
            parsed.append(pf)
        except SyntaxError:
            parse_failures += 1

    if not targets and not template_filters:
        return []

    # --- Build call graph ---
    graph = build_graph(parsed)

    # --- Collect entry nodes ---
    entries = collect_entry_nodes(parsed, entry_points, root)

    # --- BFS ---
    results = bfs_reach(
        graph=graph,
        entry_nodes=entries,
        parsed_files=parsed,
        targets=targets,
        template_targets=template_filters,
        root=root,
    )

    # Patch files_found / files_parsed to reflect parse failures
    actual_found = files_found_base
    actual_parsed = files_found_base - parse_failures
    for r in results:
        object.__setattr__(r, "files_found", actual_found) if hasattr(r, "__setattr__") else None
        r.files_found = actual_found
        r.files_parsed = actual_parsed

    return results
