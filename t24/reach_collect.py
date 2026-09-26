"""reach_collect.py — Call-edge collection helpers for T-24 reachability.

Extracted from reach_parse.py to keep every file under 300 lines.

Responsibilities
----------------
- Detect dynamic-access patterns (getattr, importlib, star imports, module-as-value).
- Collect call edges from function/method/module-level statement bodies.
- Classify each call as either a resolved FQ call or an unresolved method call
  (the latter triggers the sound over-approximation in reach_graph.build_graph).
"""
from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from t24.reach_imports import (
    resolve_call_target,
    resolve_name_ref,
)

if TYPE_CHECKING:
    from t24.reach_parse import ParsedFile, UncertainSite


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
        return _receiver_is_known_import(receiver.value, aliases)
    if isinstance(receiver, ast.Call):
        return _receiver_is_known_import(receiver.func, aliases)
    return False


def _is_dynamic_access(
    node: ast.Call,
    aliases: dict[str, str],
    rel_path: str,
    target_modules: frozenset[str],
) -> list["UncertainSite"]:
    """Return UncertainSite entries if this call is a dynamic-access pattern."""
    # Import here to avoid circular import at module load time
    from t24.reach_parse import UncertainSite  # noqa: PLC0415

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


def collect_calls_in_stmts(
    stmts: list[ast.stmt],
    aliases: dict[str, str],
    func_name: str,
    pf: "ParsedFile",
    target_modules: frozenset[str],
) -> None:
    """Walk stmts; populate pf.calls[func_name] and pf.method_calls[func_name]."""
    bucket = pf.calls.setdefault(func_name, [])
    mbucket = pf.method_calls.setdefault(func_name, [])

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            for site in _is_dynamic_access(node, aliases, pf.rel_path, target_modules):
                pf.uncertain_sites.append(site)

            fq = resolve_call_target(node.func, aliases)
            if fq and isinstance(node.func, ast.Attribute):
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
