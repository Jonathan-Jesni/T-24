"""reach_imports.py — Build a per-module import map from an AST.

An ImportMap maps local names (as they appear in source) to their
fully-qualified external identifiers, e.g.:

    import yaml               → {"yaml": "yaml"}
    import yaml as y          → {"y": "yaml"}
    from yaml import full_load → {"full_load": "yaml.full_load"}
    from yaml import full_load as fl → {"fl": "yaml.full_load"}
    from PIL import ImageMath  → {"ImageMath": "PIL.ImageMath"}
    import PIL.ImageMath       → {"PIL": "PIL", "PIL.ImageMath": "PIL.ImageMath"}

For *local* sibling imports (e.g. ``import config`` where config.py lives in
the same directory), the alias maps to the module's file-stem so the call graph
can follow cross-file hops.
"""
from __future__ import annotations

import ast
import pathlib
from typing import NamedTuple


class ImportMap(NamedTuple):
    """Local-name → fully-qualified name for one source file."""
    aliases: dict[str, str]   # local alias → fq name (e.g. "y" → "yaml.full_load")
    # sibling module stems present in the project (file stems without .py)
    sibling_stems: frozenset[str]


def build_import_map(tree: ast.Module, sibling_stems: frozenset[str]) -> dict[str, str]:
    """Return alias→fq_name dict for all imports in *tree*.

    sibling_stems: set of file stems (without .py) in the same project directory.
    Local imports whose module name is in sibling_stems are kept as-is so the
    call graph can resolve cross-file calls.
    """
    aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # e.g. import yaml  or  import yaml as y  or  import PIL.ImageMath
                local = alias.asname if alias.asname else alias.name
                # Keep dotted name as-is for attribute-chain resolution
                aliases[local] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                if module:
                    fq = f"{module}.{alias.name}"
                else:
                    # relative import with no module (from . import foo)
                    fq = alias.name
                aliases[local] = fq

    return aliases


def resolve_call_target(
    call_node: ast.expr,
    aliases: dict[str, str],
) -> str | None:
    """Given a Call's func node, return the fully-qualified target name or None."""
    if isinstance(call_node, ast.Attribute):
        # e.g. yaml.full_load(...)  or  ImageMath.eval(...)
        obj_fq = _resolve_name(call_node.value, aliases)
        if obj_fq is None:
            return None
        return f"{obj_fq}.{call_node.attr}"
    elif isinstance(call_node, ast.Name):
        # e.g. full_load(...)  or  fl(...)
        return aliases.get(call_node.id)
    return None


def resolve_name_ref(
    name_node: ast.expr,
    aliases: dict[str, str],
) -> str | None:
    """Resolve a Name or Attribute node that is NOT being called (e.g. Loader=yaml.FullLoader)."""
    if isinstance(name_node, ast.Attribute):
        obj_fq = _resolve_name(name_node.value, aliases)
        if obj_fq is None:
            return None
        return f"{obj_fq}.{name_node.attr}"
    elif isinstance(name_node, ast.Name):
        return aliases.get(name_node.id)
    return None


def _resolve_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _resolve_name(node.value, aliases)
        if parent:
            return f"{parent}.{node.attr}"
    return None
