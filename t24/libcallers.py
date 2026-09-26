"""libcallers.py — AST scan of an installed library's own source files.

Given a package import name and a symbol's last name component, scans
all .py files in the library and returns every call site inside a
library function OTHER than the symbol's own definition.

Matches:
  - Name(id == symbol)         e.g.  rebuild_proxies(...)
  - Attribute(attr == symbol)  e.g.  self.rebuild_proxies(...)

Excludes:
  - The function whose name equals `symbol` (the definition itself).
  - Calls where the receiver is exactly the name "builtins"
    (e.g. builtins.eval — that is the stdlib built-in, not the lib symbol).

Returns:
  list[dict]  — each dict has keys "file" (relative to library root),
                "line" (int), "function" (str, enclosing func name).
  None        — library source is unavailable (C-extension, namespace pkg,
                find_spec returned None, or origin is None).
"""
from __future__ import annotations

import ast
import importlib.util
import pathlib
import logging

log = logging.getLogger(__name__)

_BUILTINS = frozenset({"builtins", "__builtins__"})


def find_internal_callers(
    import_name: str,
    symbol_last: str,
) -> list[dict] | None:
    """Scan the installed library for internal callers of *symbol_last*.

    Parameters
    ----------
    import_name:   top-level importable name (e.g. "requests", "PIL")
    symbol_last:   the last name component to search for (e.g. "rebuild_proxies")

    Returns None when the library source cannot be located.
    Returns [] when source is found but there are no internal callers.
    Returns a list of hop dicts otherwise.
    """
    lib_root = _locate_library_root(import_name)
    if lib_root is None:
        return None

    hops: list[dict] = []
    for py_file in sorted(lib_root.rglob("*.py")):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        rel = _rel_posix(py_file, lib_root)
        _collect_calls(tree, rel, symbol_last, hops)

    return hops


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _locate_library_root(import_name: str) -> pathlib.Path | None:
    """Return the directory that is the root of the library's Python source."""
    try:
        spec = importlib.util.find_spec(import_name)
    except (ModuleNotFoundError, ValueError):
        return None

    if spec is None:
        return None

    # Package with a directory (most common case)
    if spec.submodule_search_locations:
        locs = list(spec.submodule_search_locations)
        if locs:
            p = pathlib.Path(locs[0])
            if p.is_dir():
                return p

    # Single-file module
    if spec.origin:
        p = pathlib.Path(spec.origin)
        if p.is_file():
            return p.parent

    return None


def _rel_posix(path: pathlib.Path, root: pathlib.Path) -> str:
    """Return forward-slash path relative to root, or path.name on failure."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _collect_calls(
    tree: ast.AST,
    rel_file: str,
    symbol_last: str,
    hops: list[dict],
) -> None:
    """Walk *tree* and append hop dicts for each internal call site found."""
    for func_node in ast.walk(tree):
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        enclosing = func_node.name
        # Skip the function that IS the vulnerable symbol definition
        if enclosing == symbol_last:
            continue
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if _is_call_to(node.func, symbol_last):
                hops.append({
                    "file": rel_file,
                    "line": node.lineno,
                    "function": enclosing,
                })


def _is_call_to(func_node: ast.expr, symbol_last: str) -> bool:
    """Return True if *func_node* is a call to *symbol_last*.

    Accepts:
      - Name(id=symbol_last)           e.g.  rebuild_proxies(...)
      - Attribute(attr=symbol_last)    e.g.  self.rebuild_proxies(...)

    Rejects calls whose Attribute receiver is "builtins" / "__builtins__".
    """
    if isinstance(func_node, ast.Name):
        return func_node.id == symbol_last
    if isinstance(func_node, ast.Attribute):
        if func_node.attr != symbol_last:
            return False
        # Ignore builtins.eval style calls
        receiver = func_node.value
        if isinstance(receiver, ast.Name) and receiver.id in _BUILTINS:
            return False
        return True
    return False
