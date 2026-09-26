"""reach_parse.py — Per-file parsing helpers for T-24 reachability analysis.

Extracted from reach_graph.py to keep every file under 300 lines.
Call-collection logic lives in reach_collect.py.

Responsibilities
----------------
- Parse a single .py file into a ParsedFile.
- Build entry-point lists (Flask decorators, add_url_rule, module-level).
- Delegate call collection to reach_collect.collect_calls_in_stmts.
- Path utilities (path_to_dotted, rel_fwd, rel_fwd_product).
"""
from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field

from t24.reach_imports import (
    build_import_map,
    has_star_import,
)
from t24.reach_collect import collect_calls_in_stmts

_FLASK_HTTP_DECORATORS = frozenset({"route", "get", "post", "put", "delete", "patch"})
_MODULE_LEVEL = "<module>"


@dataclass
class UncertainSite:
    file: str
    line: int
    reason: str


@dataclass
class ParsedFile:
    rel_path: str                             # forward-slash, relative to scan base
    dotted_path: str                          # e.g. "svc.helpers"
    tree: ast.Module
    aliases: dict[str, str]
    calls: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    uncertain_sites: list[UncertainSite] = field(default_factory=list)
    # method_calls: unresolved obj.method(); key is the *caller* function name
    method_calls: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Flask / entry-point helpers
# ---------------------------------------------------------------------------

def _is_flask_decorator(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    if isinstance(decorator, ast.Attribute):
        return decorator.attr in _FLASK_HTTP_DECORATORS
    if isinstance(decorator, ast.Name):
        return decorator.id in _FLASK_HTTP_DECORATORS
    return False


def _detect_add_url_rule(tree: ast.Module, aliases: dict[str, str]) -> list[str]:
    """Return function names registered via app.add_url_rule(path, view_func=f)."""
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        attr = func.attr if isinstance(func, ast.Attribute) else None
        if attr != "add_url_rule":
            continue
        for kw in node.keywords:
            if kw.arg == "view_func" and isinstance(kw.value, ast.Name):
                names.append(kw.value.id)
        if len(node.args) >= 3 and isinstance(node.args[2], ast.Name):
            names.append(node.args[2].id)
    return names


# ---------------------------------------------------------------------------
# Path utilities
# ---------------------------------------------------------------------------

def path_to_dotted(path: pathlib.Path, root: pathlib.Path) -> str:
    """Convert a file path to a dotted module path relative to root."""
    rel = path.relative_to(root)
    parts = list(rel.parts)
    if parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def rel_fwd(path: pathlib.Path, base: pathlib.Path) -> str:
    """Return *path* relative to *base* with forward slashes.

    When *path* is not under *base* (e.g. the product lives in /tmp while the
    CWD is the repo), fall back to making it relative to its own parent so we
    always return a useful relative path rather than raising ValueError.
    """
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix().replace("\\", "/")


def rel_fwd_product(path: pathlib.Path, cwd: pathlib.Path, product_root: pathlib.Path) -> str:
    """Return a forward-slash relative path for evidence output.

    Preference order:
    1. Relative to CWD if the file is under CWD.
    2. Otherwise relative to product_root.parent.
    """
    try:
        return path.relative_to(cwd).as_posix()
    except ValueError:
        pass
    try:
        return path.relative_to(product_root.parent).as_posix()
    except ValueError:
        pass
    return path.name


# ---------------------------------------------------------------------------
# Main parse function
# ---------------------------------------------------------------------------

def parse_file(
    path: pathlib.Path,
    root: pathlib.Path,
    product_dotted_paths: frozenset[str],
    cwd: pathlib.Path,
    target_modules: frozenset[str] | None = None,
) -> ParsedFile:
    """Parse one Python file and build its call map.

    Class methods are stored under the qualified name "ClassName.method_name"
    so they are never conflated with module-level code.  The module-level sweep
    skips class bodies entirely (class bodies run at import; method bodies do not).
    """
    if target_modules is None:
        target_modules = frozenset()

    rel = rel_fwd_product(path, cwd, root)
    dotted = path_to_dotted(path, root)
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(path))
    aliases = build_import_map(tree, product_dotted_paths, own_dotted_path=dotted)

    pf = ParsedFile(rel_path=rel, dotted_path=dotted, tree=tree, aliases=aliases)

    if has_star_import(tree):
        pf.uncertain_sites.append(UncertainSite(
            file=rel, line=1, reason="from X import * — cannot statically resolve names",
        ))

    module_stmts: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            collect_calls_in_stmts(
                node.body, aliases, node.name, pf, target_modules
            )
            if any(_is_flask_decorator(d) for d in node.decorator_list):
                pf.entry_points.append(node.name)
        elif isinstance(node, ast.ClassDef):
            _collect_class_methods(node, aliases, pf, target_modules)
        elif isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"):
                collect_calls_in_stmts(
                    node.body, aliases, _MODULE_LEVEL, pf, target_modules
                )
                pf.entry_points.append(_MODULE_LEVEL)
        else:
            module_stmts.append(node)

    if module_stmts:
        collect_calls_in_stmts(module_stmts, aliases, _MODULE_LEVEL, pf, target_modules)
    if _MODULE_LEVEL not in pf.entry_points:
        pf.entry_points.append(_MODULE_LEVEL)

    for ep_name in _detect_add_url_rule(tree, aliases):
        if ep_name not in pf.entry_points:
            pf.entry_points.append(ep_name)

    return pf


def _collect_class_methods(
    class_node: ast.ClassDef,
    aliases: dict[str, str],
    pf: ParsedFile,
    target_modules: frozenset[str],
) -> None:
    """Collect calls inside each method body under "ClassName.method_name"."""
    class_name = class_node.name
    for item in class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = f"{class_name}.{item.name}"
            collect_calls_in_stmts(
                item.body, aliases, qualified, pf, target_modules
            )
        elif isinstance(item, ast.ClassDef):
            _collect_class_methods(item, aliases, pf, target_modules)
