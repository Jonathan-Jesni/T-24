"""reach.py — Public API for T-24 reachability analysis.

Usage::

    from t24.reach import scan, ReachResult, EvidenceHop

    results = scan(
        product_root=pathlib.Path("demo_product"),
        targets=["yaml.full_load", "yaml.FullLoader", "PIL.ImageMath.eval"],
        template_filters=["xmlattr"],
        entry_points=[],   # empty = auto-detect Flask routes + module-level
    )
    for r in results:
        print(r.target, r.reachable, r.evidence)
        if r.uncertain:
            print("  uncertain sites:", r.uncertain_sites)
"""
from __future__ import annotations

import pathlib

from t24.reach_graph import (
    ParsedFile,
    build_graph,
    collect_entry_nodes,
    parse_file,
    path_to_dotted,
)
from t24.reach_bfs import EvidenceHop, ReachResult, bfs_reach

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
    cwd = pathlib.Path.cwd()

    if not targets and not template_filters:
        return []

    py_files = sorted(root.rglob("*.py"))
    files_found_base = len(py_files)

    # Compute dotted paths for all product modules (needed for import resolution)
    product_dotted_paths: frozenset[str] = frozenset(
        path_to_dotted(p, root) for p in py_files
    )

    # Build the set of top-level module names we are targeting so the parser
    # can flag bare module references (e.g. passing `yaml` as a value).
    target_modules: frozenset[str] = frozenset(
        t.split(".")[0] for t in targets if t
    )

    parsed: list[ParsedFile] = []
    parse_failures = 0

    for py_path in py_files:
        try:
            pf = parse_file(
                py_path, root, product_dotted_paths, cwd,
                target_modules=target_modules,
            )
            parsed.append(pf)
        except SyntaxError:
            parse_failures += 1

    graph = build_graph(parsed)
    entries = collect_entry_nodes(parsed, entry_points, cwd)

    results = bfs_reach(
        graph=graph,
        entry_nodes=entries,
        parsed_files=parsed,
        targets=targets,
        template_targets=template_filters,
        root=root,
        cwd=cwd,
    )

    # Patch in accurate file counts (includes parse failures)
    actual_parsed = files_found_base - parse_failures
    for r in results:
        r.files_found = files_found_base
        r.files_parsed = actual_parsed

    return results
