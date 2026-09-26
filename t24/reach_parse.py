"""reach_parse.py — Per-file parsing helpers for T-24 reachability analysis.

Extracted from reach_graph.py to keep every file under 300 lines.

Responsibilities
----------------
- Parse a single .py file into a ParsedFile.
- Build entry-point lists (Flask decorators, add_url_rule, module-level).
- Collect call edges, separating top-level functions, class methods
  (stored as "ClassName.method"), and module-level code.
- Detect dynamic-access patterns that cannot be resolved (uncertainty sites).
"""
from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field

from t24.reach_imports import (
    build_import_map,
    resolve_call_target,
    resolve_name_ref,
    has_star_import,
)

_FLASK_HTTP_DECORATORS = frozenset({"route", "get", "post", "put", "delete", "patch"})
_MODULE_LEVEL = "<module>"
_DYNAMIC_IMPORTERS = frozenset({"import_module", "__import__", "getattr"})


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
# Dynamic-access / uncertainty detection
# ---------------------------------------------------------------------------

def _is_dynamic_access(
    node: ast.Call,
    aliases: dict[str, str],
    rel_path: str,
    target_modules: frozenset[str],
) -> list[UncertainSite]:
    """Return UncertainSite entries if this call is a dynamic-access pattern."""
    sites: list[UncertainSite] = []
    func = node.func

    # getattr(obj, expr) where expr is not a plain Constant
    if isinstance(func, ast.Name) and func.id == "getattr":
        if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            sites.append(UncertainSite(
                file=rel_path, line=node.lineno,
                reason="getattr() with dynamic attribute name",
            ))

    # importlib.import_module(...) or __import__(...)
    fq = resolve_call_target(func, aliases)
    if fq and (fq.endswith(".import_module") or fq == "__import__"
               or fq == "importlib.import_module"):
        sites.append(UncertainSite(
            file=rel_path, line=node.lineno,
            reason=f"dynamic import via {ast.unparse(func)}",
        ))

    # Positional args that are bare module name references → module object as value
    for arg in node.args:
        if isinstance(arg, ast.Name):
            resolved = aliases.get(arg.id)
            if resolved and resolved in target_modules:
                sites.append(UncertainSite(
                    file=rel_path, line=node.lineno,
                    reason=f"module object passed as a value: {arg.id}",
                ))

    return sites


# ---------------------------------------------------------------------------
# Call collection helpers
# ---------------------------------------------------------------------------

def _receiver_is_known_import(receiver: ast.expr, aliases: dict[str, str]) -> bool:
    """Return True if the receiver of an attribute call is a known import alias.

    A *known* receiver is one whose root name appears in the alias map as a
    mapping to a third-party or standard-library name (i.e. it was imported).
    Local names (``self``, bare class instances, unresolved variables) are NOT
    in ``aliases`` and therefore return False, causing the call to be treated
    as an unresolved method call (sound over-approximation).
    """
    if isinstance(receiver, ast.Name):
        return receiver.id in aliases
    if isinstance(receiver, ast.Attribute):
        # Chained: yaml.FullLoader.something — walk to the root Name
        return _receiver_is_known_import(receiver.value, aliases)
    # Call expressions like Loader() — the class is likely a local Name
    if isinstance(receiver, ast.Call):
        return _receiver_is_known_import(receiver.func, aliases)
    return False


# ---------------------------------------------------------------------------
# Call collection
# ---------------------------------------------------------------------------

def _collect_calls_in_stmts(
    stmts: list[ast.stmt],
    aliases: dict[str, str],
    func_name: str,
    pf: ParsedFile,
    target_modules: frozenset[str],
) -> None:
    """Walk stmts; populate pf.calls[func_name] and pf.method_calls[func_name]."""
    bucket = pf.calls.setdefault(func_name, [])
    mbucket = pf.method_calls.setdefault(func_name, [])

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # Dynamic access detection (including module-as-value)
            for site in _is_dynamic_access(node, aliases, pf.rel_path, target_modules):
                pf.uncertain_sites.append(site)

            fq = resolve_call_target(node.func, aliases)
            if fq and isinstance(node.func, ast.Attribute):
                # If the receiver is not a known import alias (e.g. `self`,
                # a local instance, or an unknown name), treat the call as an
                # unresolved method call for sound over-approximation instead
                # of recording a fake fully-qualified target like "self._p".
                receiver = node.func.value
                receiver_is_known = _receiver_is_known_import(receiver, aliases)
                if receiver_is_known:
                    call_str = ast.unparse(node.func)
                    bucket.append((fq, node.lineno, call_str))
                else:
                    method_name = node.func.attr
                    call_str = ast.unparse(node.func)
                    mbucket.append((method_name, node.lineno, call_str))
            elif fq:
                call_str = ast.unparse(node.func)
                bucket.append((fq, node.lineno, call_str))
            elif isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
                call_str = ast.unparse(node.func)
                mbucket.append((method_name, node.lineno, call_str))

            # Keyword-argument references: Loader=yaml.FullLoader
            for kw in node.keywords:
                ref = resolve_name_ref(kw.value, aliases)
                if ref:
                    ref_str = ast.unparse(kw.value)
                    bucket.append((ref, kw.value.lineno, ref_str))

            # Positional-argument references: run(yaml.full_load, raw)
            for arg in node.args:
                ref = resolve_name_ref(arg, aliases)
                if ref:
                    ref_str = ast.unparse(arg)
                    bucket.append((ref, arg.lineno, ref_str))

            self.generic_visit(node)

    _Visitor().visit(ast.Module(body=stmts, type_ignores=[]))


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
        # path is outside base — use path relative to its own root ancestor
        # (the product root's parent), which keeps it relative and slash-clean.
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
    # Last resort: just the filename
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

    # Detect star imports as uncertainty sites
    if has_star_import(tree):
        pf.uncertain_sites.append(UncertainSite(
            file=rel, line=1, reason="from X import * — cannot statically resolve names",
        ))

    module_stmts: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _collect_calls_in_stmts(
                node.body, aliases, node.name, pf, target_modules
            )
            if any(_is_flask_decorator(d) for d in node.decorator_list):
                pf.entry_points.append(node.name)
        elif isinstance(node, ast.ClassDef):
            # Process each method as "ClassName.method_name" — do NOT sweep
            # class-level statements into <module> (they run at import, but we
            # model them conservatively: only method *bodies* matter here).
            _collect_class_methods(node, aliases, pf, target_modules)
        elif isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"):
                _collect_calls_in_stmts(
                    node.body, aliases, _MODULE_LEVEL, pf, target_modules
                )
                pf.entry_points.append(_MODULE_LEVEL)
        else:
            module_stmts.append(node)

    # Module-level statements always collected
    if module_stmts:
        _collect_calls_in_stmts(module_stmts, aliases, _MODULE_LEVEL, pf, target_modules)
    # Always register <module> so module-level code is an entry point
    if _MODULE_LEVEL not in pf.entry_points:
        pf.entry_points.append(_MODULE_LEVEL)

    # add_url_rule detection
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
            _collect_calls_in_stmts(
                item.body, aliases, qualified, pf, target_modules
            )
        elif isinstance(item, ast.ClassDef):
            # Nested class — recurse with outer.inner naming
            _collect_class_methods(item, aliases, pf, target_modules)
