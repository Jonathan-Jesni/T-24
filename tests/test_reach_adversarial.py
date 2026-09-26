"""tests/test_reach_adversarial.py

Adversarial reachability tests. Each scenario was a false "not reached"
with the original engine. Tests are written FIRST so failures can be
observed before the fixes are applied.

Soundness principle: when the engine cannot prove a target is unreachable,
it reports uncertainty, never "not reached".
"""
from __future__ import annotations

import pathlib
import pytest

from t24.reach import scan, ReachResult, EvidenceHop

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "reach_adversarial"


def _scan(scenario: str, targets: list[str], **kw) -> dict[str, ReachResult]:
    root = FIXTURES / scenario
    results = scan(
        product_root=root,
        targets=targets,
        template_filters=kw.get("filters", []),
        entry_points=kw.get("entry_points", []),
    )
    return {r.target: r for r in results}


# ---------------------------------------------------------------------------
# 1. Method call: obj.method() where method calls the target
# ---------------------------------------------------------------------------

class TestMethodCall:
    """Loader().load(x) where load() calls yaml.full_load — must be reached.

    Approach: when a call obj.method() cannot be resolved to an external
    library (obj is a local Name, not a known import alias), emit graph edges
    to ALL product-defined functions named `method`, regardless of class.
    This is a sound over-approximation.
    """

    def test_reached(self):
        r = _scan("method_call", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load must be reached via Loader().load()"
        )

    def test_evidence_present(self):
        r = _scan("method_call", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence


# ---------------------------------------------------------------------------
# 2. Package with relative imports (dotted path resolution)
# ---------------------------------------------------------------------------

class TestRelativeImports:
    """app.py -> svc.loader.load -> svc.helpers.parse -> yaml.full_load.

    Approach: modules identified by dotted path relative to product root
    (e.g. svc.helpers); relative imports (from .helpers import parse) resolved
    against the package's dotted path.
    """

    def test_reached(self):
        r = _scan("relative_imports", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load must be reached through svc package relative imports"
        )

    def test_evidence_spans_three_files(self):
        r = _scan("relative_imports", ["yaml.full_load"])
        evidence = r["yaml.full_load"].evidence
        files = {hop.file for hop in evidence}
        assert any("app.py" in f for f in files)
        assert any("helpers.py" in f for f in files)


# ---------------------------------------------------------------------------
# 3. Callback: target passed as a function argument
# ---------------------------------------------------------------------------

class TestCallback:
    """run(yaml.full_load, raw) — target is passed as a Name argument.

    Approach: any Name or Attribute expression that resolves to a target,
    appearing anywhere in a call (including positional/keyword args), counts
    as a reference hop.
    """

    def test_reached(self):
        r = _scan("callback", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load passed as callback arg must be reached"
        )

    def test_evidence_present(self):
        r = _scan("callback", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence


# ---------------------------------------------------------------------------
# 4. add_url_rule: view_func= registers an entry point
# ---------------------------------------------------------------------------

class TestAddUrlRule:
    """app.add_url_rule('/a', view_func=a) — function a() is an entry point.

    Approach: detect add_url_rule calls at module level; treat view_func=<name>
    (and the second positional argument when it is a Name) as entry points.
    """

    def test_reached(self):
        r = _scan("add_url_rule", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load must be reached via add_url_rule-registered view func"
        )

    def test_evidence_present(self):
        r = _scan("add_url_rule", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence


# ---------------------------------------------------------------------------
# 5. Module-level code: CFG = yaml.full_load(...) at module top level
# ---------------------------------------------------------------------------

class TestModuleLevel:
    """Module-level statements run on import, so every module is an entry point.

    Approach: all module-level statements (outside any function) are collected
    under function name "<module>" and that node is always an entry point.
    """

    def test_reached(self):
        r = _scan("module_level", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load at module level must be reached"
        )

    def test_evidence_function_is_module(self):
        r = _scan("module_level", ["yaml.full_load"])
        evidence = r["yaml.full_load"].evidence
        assert evidence
        assert any(hop.function == "<module>" for hop in evidence)


# ---------------------------------------------------------------------------
# 6. Dynamic access → uncertain (NOT a hop, but uncertain=True)
# ---------------------------------------------------------------------------

class TestDynamicAccess:
    """getattr(yaml, ...), importlib.import_module, __import__, star import.

    These cannot be statically resolved. The engine must NOT mark them as
    'not reached' — instead set uncertain=True with uncertain_sites entries.
    The verdict engine will turn this into under_investigation.
    """

    def test_not_reachable_but_uncertain(self):
        r = _scan("dynamic_access", ["yaml.full_load"])
        res = r["yaml.full_load"]
        assert res.reachable is False
        assert res.uncertain is True

    def test_uncertain_sites_present(self):
        r = _scan("dynamic_access", ["yaml.full_load"])
        res = r["yaml.full_load"]
        assert len(res.uncertain_sites) >= 1

    def test_uncertain_site_has_required_fields(self):
        r = _scan("dynamic_access", ["yaml.full_load"])
        for site in r["yaml.full_load"].uncertain_sites:
            assert "file" in site
            assert "line" in site
            assert "reason" in site


# ---------------------------------------------------------------------------
# 7. Name collision: safe.parse uses yaml.safe_load; unsafe.parse never imported
# ---------------------------------------------------------------------------

class TestNameCollision:
    """app.py imports safe.parse (which uses yaml.safe_load, not full_load).
    unsafe.py also defines parse() with yaml.full_load but is never imported.

    Expected: NOT reached, NOT uncertain.
    The graph must only follow actual import edges, not every function with
    the same name.
    """

    def test_not_reached(self):
        r = _scan("name_collision", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is False

    def test_not_uncertain(self):
        r = _scan("name_collision", ["yaml.full_load"])
        assert r["yaml.full_load"].uncertain is False

    def test_evidence_empty(self):
        r = _scan("name_collision", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence == []


# ---------------------------------------------------------------------------
# 8. Path normalisation: forward slashes on every OS
# ---------------------------------------------------------------------------

class TestPathNormalisation:
    """Evidence file paths must use forward slashes, relative to CWD."""

    def test_forward_slashes_in_direct_call(self):
        """Reuse the direct_call fixture from the main suite."""
        root = pathlib.Path("tests/fixtures/reach/direct_call")
        results = scan(
            product_root=root,
            targets=["yaml.full_load"],
            template_filters=[],
            entry_points=[],
        )
        r = {res.target: res for res in results}["yaml.full_load"]
        assert r.reachable
        for hop in r.evidence:
            assert "\\" not in hop.file, f"Backslash in path: {hop.file!r}"
            assert hop.file.startswith("tests/"), (
                f"Path not relative to CWD: {hop.file!r}"
            )

    def test_forward_slashes_cross_file(self):
        """Cross-file scenario: both hops must use forward slashes."""
        root = pathlib.Path("tests/fixtures/reach/cross_file")
        results = scan(
            product_root=root,
            targets=["yaml.full_load"],
            template_filters=[],
            entry_points=[],
        )
        r = {res.target: res for res in results}["yaml.full_load"]
        for hop in r.evidence:
            assert "\\" not in hop.file, f"Backslash in path: {hop.file!r}"
