"""reach_imports.py — Per-module import-alias map builder.

Resolves import statements to fully-qualified names so the call graph can
follow edges across files and packages.

Supported import forms
----------------------
    import yaml                  → {"yaml": "yaml"}
    import yaml as y             → {"y": "yaml"}
    import PIL.ImageMath         → {"PIL": "PIL", "PIL.ImageMath": "PIL.ImageMath"}
    from yaml import full_load   → {"full_load": "yaml.full_load"}
    from yaml import full_load as fl → {"fl": "yaml.full_load"}
    from PIL import ImageMath    → {"ImageMath": "PIL.ImageMath"}
    from .helpers import parse   → resolved against the module's own dotted path
    from svc.loader import load  → {"load": "svc.loader.load"}

For product-local modules (whose dotted paths are in *product_dotted_paths*),
aliases map to the dotted module path so the call graph can follow them.
"""
from __future__ import annotations

import ast


def build_import_map(
    tree: ast.Module,
    product_dotted_paths: frozenset[str],
    own_dotted_path: str = "",
) -> dict[str, str]:
    """Return alias→fq_name dict for all imports in *tree*.

    Parameters
    ----------
    product_dotted_paths:
        Dotted paths of every Python module in the product root
        (e.g. ``frozenset({"app", "svc.loader", "svc.helpers"})``).
    own_dotted_path:
        Dotted path of the file being parsed (used to resolve relative imports).
        E.g. ``"svc.loader"`` for ``svc/loader.py``.
    """
    aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                fq = alias.name
                aliases[local] = fq
                # Also register the top-level name for attribute-chain resolution
                top = alias.name.split(".")[0]
                if top != local:
                    aliases.setdefault(top, top)

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level  # 0 = absolute, 1 = from . , 2 = from .. , etc.

            if level > 0:
                # Relative import — resolve against own_dotted_path
                base = _relative_base(own_dotted_path, level)
                module = f"{base}.{module}" if module else base

            for alias in node.names:
                if alias.name == "*":
                    # Star import — handled separately as an uncertainty trigger
                    continue
                local = alias.asname if alias.asname else alias.name
                fq = f"{module}.{alias.name}" if module else alias.name
                aliases[local] = fq

    return aliases


def _relative_base(own_dotted_path: str, level: int) -> str:
    """Return the package path for a relative import.

    level=1: from . → own package
    level=2: from .. → parent package
    """
    parts = own_dotted_path.split(".")
    # Remove `level` trailing components (1 removes the module name itself)
    base_parts = parts[: max(0, len(parts) - level)]
    return ".".join(base_parts)


def resolve_call_target(
    call_node: ast.expr,
    aliases: dict[str, str],
) -> str | None:
    """Given a Call's func node, return the fully-qualified target name or None."""
    if isinstance(call_node, ast.Attribute):
        obj_fq = _resolve_name(call_node.value, aliases)
        if obj_fq is None:
            return None
        return f"{obj_fq}.{call_node.attr}"
    elif isinstance(call_node, ast.Name):
        return aliases.get(call_node.id)
    return None


def resolve_name_ref(
    name_node: ast.expr,
    aliases: dict[str, str],
) -> str | None:
    """Resolve a Name or Attribute node used as a reference (not called)."""
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


def has_star_import(tree: ast.Module) -> bool:
    """Return True if the module contains any ``from x import *`` statement."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if any(a.name == "*" for a in node.names):
                return True
    return False
