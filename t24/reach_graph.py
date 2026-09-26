"""reach_graph.py — Call-graph builder for T-24 reachability analysis.

Responsibilities
----------------
- Parse every .py file in the product root.
- Build an import-alias map per file (via reach_imports).
- Collect function→calls edges, including:
    * standard calls and keyword-argument references
    * positional arguments that resolve to target names (callback pattern)
    * method calls on unresolved local objects (sound over-approximation)
    * module-level code (always an entry point)
    * Flask route decorators AND add_url_rule() calls
- Detect dynamic-access patterns that cannot be resolved (uncertainty sites).

Graph nodes: (forward_slash_rel_path, function_name)
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

# Dynamic-access function names that signal uncertainty
_DYNAMIC_IMPORTERS = frozenset({"import_module", "__import__", "getattr"})

Node = tuple[str, str]  # (fwd_slash_rel_path, func_name)


@dataclass
class UncertainSite:
    file: str
    line: int
    reason: str


@dataclass
class ParsedFile:
    rel_path: str                             # forward-slash, relative to cwd
    dotted_path: str                          # e.g. "svc.helpers"
    tree: ast.Module
    aliases: dict[str, str]
    calls: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    uncertain_sites: list[UncertainSite] = field(default_factory=list)
    # method_calls: list of (method_name, line, call_str) for unresolved obj.method()
    method_calls: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)


def _is_flask_decorator(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    if isinstance(decorator, ast.Attribute):
        return decorator.attr in _FLASK_HTTP_DECORATORS
    if isinstance(decorator, ast.Name):
        return decorator.id in _FLASK_HTTP_DECORATORS
    return False


def _is_dynamic_access(node: ast.Call, aliases: dict[str, str], rel_path: str) -> list[UncertainSite]:
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

    return sites


def _collect_calls_in_stmts(
    stmts: list[ast.stmt],
    aliases: dict[str, str],
    func_name: str,
    pf: ParsedFile,
) -> None:
    """Walk stmts; populate pf.calls[func_name] and pf.method_calls[func_name]."""
    bucket = pf.calls.setdefault(func_name, [])
    mbucket = pf.method_calls.setdefault(func_name, [])

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # Dynamic access detection
            for site in _is_dynamic_access(node, aliases, pf.rel_path):
                pf.uncertain_sites.append(site)

            fq = resolve_call_target(node.func, aliases)
            if fq:
                call_str = ast.unparse(node.func)
                bucket.append((fq, node.lineno, call_str))
            elif isinstance(node.func, ast.Attribute):
                # Unresolved obj.method() — record for over-approximation
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
        # view_func keyword
        for kw in node.keywords:
            if kw.arg == "view_func" and isinstance(kw.value, ast.Name):
                names.append(kw.value.id)
        # positional: add_url_rule(rule, endpoint, view_func)
        if len(node.args) >= 3 and isinstance(node.args[2], ast.Name):
            names.append(node.args[2].id)
    return names


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
    """Return path relative to base with forward slashes."""
    return path.relative_to(base).as_posix()


def parse_file(
    path: pathlib.Path,
    root: pathlib.Path,
    product_dotted_paths: frozenset[str],
    cwd: pathlib.Path,
) -> ParsedFile:
    """Parse one Python file and build its call map."""
    rel = rel_fwd(path, cwd)
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
            _collect_calls_in_stmts(node.body, aliases, node.name, pf)
            if any(_is_flask_decorator(d) for d in node.decorator_list):
                pf.entry_points.append(node.name)
        elif isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"):
                _collect_calls_in_stmts(node.body, aliases, _MODULE_LEVEL, pf)
                pf.entry_points.append(_MODULE_LEVEL)
        else:
            module_stmts.append(node)

    # Module-level statements always collected (every module is an entry point)
    if module_stmts:
        _collect_calls_in_stmts(module_stmts, aliases, _MODULE_LEVEL, pf)
    # Always register <module> so module-level code is reachable
    if _MODULE_LEVEL not in pf.entry_points:
        pf.entry_points.append(_MODULE_LEVEL)

    # add_url_rule detection
    for ep_name in _detect_add_url_rule(tree, aliases):
        if ep_name not in pf.entry_points:
            pf.entry_points.append(ep_name)

    return pf


def build_graph(
    parsed_files: list[ParsedFile],
) -> dict[Node, list[tuple[Node, int, str]]]:
    """Return adjacency list node → [(neighbor, line, call_str)].

    Cross-file edges are built by matching callee fq-names against
    known product dotted paths (e.g. "svc.helpers.parse").

    Over-approximation for method calls: an unresolved obj.method() call
    adds edges to ALL product-defined functions named `method`.
    """
    # dotted_module → ParsedFile
    dotted_to_file: dict[str, ParsedFile] = {pf.dotted_path: pf for pf in parsed_files}
    # method_name → list of (ParsedFile, func_name) that define it
    method_index: dict[str, list[tuple[ParsedFile, str]]] = {}
    for pf in parsed_files:
        for func_name in pf.calls:
            if func_name != _MODULE_LEVEL:
                method_index.setdefault(func_name, []).append((pf, func_name))

    graph: dict[Node, list[tuple[Node, int, str]]] = {}

    for pf in parsed_files:
        for func_name, call_list in pf.calls.items():
            src: Node = (pf.rel_path, func_name)
            edges = graph.setdefault(src, [])

            for callee_fq, line, call_str in call_list:
                # Try to match callee_fq against a product function
                # e.g. "svc.helpers.parse" → dotted "svc.helpers", func "parse"
                resolved = _resolve_to_product(callee_fq, dotted_to_file)
                if resolved:
                    edges.append((resolved, line, call_str))
                    continue
                # Same-file function?
                if callee_fq in pf.calls:
                    edges.append(((pf.rel_path, callee_fq), line, call_str))

        # Over-approximation: unresolved obj.method() → all product methods named method
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
                rel = ep_path.relative_to(cwd).as_posix()
                nodes.append((rel, func_part))
            else:
                ep_path = pathlib.Path(ep)
                rel = ep_path.relative_to(cwd).as_posix()
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
    # Try progressively shorter dotted prefixes
    parts = callee_fq.rsplit(".", 1)
    if len(parts) == 2:
        mod, func = parts
        if mod in dotted_to_file:
            pf = dotted_to_file[mod]
            return (pf.rel_path, func)
    return None
