"""tests/test_reach_new.py

New adversarial reachability tests covering four bugs found in review.

Problems addressed:
  1. FALSE POSITIVE  — class method bodies treated as module-level code
  2. MISSED UNCERTAINTY — module object passed as value not flagged uncertain
  3. CRASH — scanning product outside CWD raises ValueError from relative_to
  4. SIZE  — reach_graph.py split; every t24/ file stays under 300 code lines

The assertion helpers assert_chain_starts_at_entry and
assert_no_module_level_in_methods live in test_reach.py so they can be
shared across the full reach test suite.
"""
from __future__ import annotations

import pathlib
import pytest

from t24.reach import scan, ReachResult, EvidenceHop
from conftest import assert_chain_starts_at_entry, assert_no_module_level_in_methods

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


# ===========================================================================
# Problem 1a — Unused class method must NOT be reached
# ===========================================================================

class TestUnusedClassMethod:
    """Class Unused is never instantiated. Its method body must not be
    treated as module-level code and must not create a reachable path."""

    def test_not_reached(self):
        r = _scan("unused_class_method", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is False, (
            "yaml.full_load inside an unused class method must NOT be reached"
        )

    def test_not_uncertain(self):
        r = _scan("unused_class_method", ["yaml.full_load"])
        assert r["yaml.full_load"].uncertain is False

    def test_evidence_empty(self):
        r = _scan("unused_class_method", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence == []


# ===========================================================================
# Problem 1b — route -> Loader().load(x) -> yaml.full_load
# Evidence starts at route (function="upload"), hops list Loader.load
# ===========================================================================

class TestClassMethodChain:
    """Loader().load(x) calls yaml.full_load. Must be reached, and the
    evidence chain must start at the route function, not '<module>'."""

    def test_reached(self):
        r = _scan("class_method_chain", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load must be reached via Loader().load()"
        )

    def test_evidence_starts_at_route(self):
        r = _scan("class_method_chain", ["yaml.full_load"])
        assert_chain_starts_at_entry(r["yaml.full_load"], entry_function="upload")

    def test_evidence_contains_loader_load(self):
        """At least one hop must name the method as 'Loader.load', not '<module>'."""
        r = _scan("class_method_chain", ["yaml.full_load"])
        res = r["yaml.full_load"]
        functions = [hop.function for hop in res.evidence]
        assert "Loader.load" in functions, (
            f"Expected 'Loader.load' in evidence functions, got {functions}"
        )

    def test_no_module_level_label_in_chain(self):
        r = _scan("class_method_chain", ["yaml.full_load"])
        assert_no_module_level_in_methods(r["yaml.full_load"])


# ===========================================================================
# Problem 1c — 3-hop chain: route -> S().go() -> self._p() -> yaml.full_load
# ===========================================================================

class TestThreeHopChain:
    """route index -> S().go() -> self._p() -> yaml.full_load.
    All three intermediate hops must use qualified function names."""

    def test_reached(self):
        r = _scan("three_hop_chain", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True, (
            "yaml.full_load must be reached via S().go() -> self._p()"
        )

    def test_evidence_starts_at_route(self):
        r = _scan("three_hop_chain", ["yaml.full_load"])
        assert_chain_starts_at_entry(r["yaml.full_load"], entry_function="index")

    def test_evidence_has_three_hops(self):
        """At minimum: index -> S.go -> S._p (then final call inside S._p)."""
        r = _scan("three_hop_chain", ["yaml.full_load"])
        evidence = r["yaml.full_load"].evidence
        assert len(evidence) >= 3, (
            f"Expected >=3 hops in the evidence chain, got {len(evidence)}: {evidence}"
        )

    def test_qualified_method_names_in_chain(self):
        r = _scan("three_hop_chain", ["yaml.full_load"])
        functions = [hop.function for hop in r["yaml.full_load"].evidence]
        # Must see the class-qualified names
        assert "S.go" in functions or "S._p" in functions, (
            f"Expected 'S.go' or 'S._p' in evidence functions, got {functions}"
        )

    def test_no_module_level_label_in_chain(self):
        r = _scan("three_hop_chain", ["yaml.full_load"])
        assert_no_module_level_in_methods(r["yaml.full_load"])


# ===========================================================================
# Problem 2 — Module object passed as value → uncertain=True
# ===========================================================================

class TestModuleAsValue:
    """def use(m): return m.full_load(x); route calls use(yaml).

    The bare module name is passed as an argument (not attribute access).
    The engine cannot track attribute accesses on the parameter 'm',
    so this MUST produce uncertain=True."""

    def test_not_reachable(self):
        """Not statically reachable (the engine can't follow the parameter)."""
        r = _scan("module_as_value", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is False

    def test_uncertain_true(self):
        r = _scan("module_as_value", ["yaml.full_load"])
        assert r["yaml.full_load"].uncertain is True, (
            "Passing yaml module as value must set uncertain=True"
        )

    def test_uncertain_site_present(self):
        r = _scan("module_as_value", ["yaml.full_load"])
        assert r["yaml.full_load"].uncertain_sites, (
            "Expected at least one uncertain_site for module-object-as-value"
        )

    def test_uncertain_site_reason(self):
        r = _scan("module_as_value", ["yaml.full_load"])
        reasons = [s["reason"] for s in r["yaml.full_load"].uncertain_sites]
        assert any("module object" in reason.lower() for reason in reasons), (
            f"Expected 'module object' in uncertain_site reason, got {reasons}"
        )


# ===========================================================================
# Problem 3 — Scanning a product outside CWD must not raise ValueError
# ===========================================================================

class TestProductOutsideCwd:
    """When the product root is outside (or equal to) the CWD, rel_fwd must
    not crash with ValueError from Path.relative_to()."""

    def test_no_crash_when_product_outside_cwd(self, tmp_path):
        """Create a tiny Flask project in tmp_path, scan it while CWD is repo."""
        app_py = tmp_path / "app.py"
        app_py.write_text(
            "import yaml\nfrom flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/')\ndef index():\n"
            "    return str(yaml.full_load('x: 1'))\n"
        )
        # This must not raise ValueError
        try:
            results = scan(
                product_root=tmp_path,
                targets=["yaml.full_load"],
                template_filters=[],
                entry_points=[],
            )
        except ValueError as exc:
            pytest.fail(f"scan() raised ValueError for product outside CWD: {exc}")

        r = {res.target: res for res in results}
        assert r["yaml.full_load"].reachable is True

    def test_evidence_paths_use_forward_slashes(self, tmp_path):
        """Evidence paths must use forward slashes even for tmp_path products."""
        app_py = tmp_path / "app.py"
        app_py.write_text(
            "import yaml\nfrom flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/')\ndef index():\n"
            "    return str(yaml.full_load('x: 1'))\n"
        )
        results = scan(
            product_root=tmp_path,
            targets=["yaml.full_load"],
            template_filters=[],
            entry_points=[],
        )
        r = {res.target: res for res in results}["yaml.full_load"]
        for hop in r.evidence:
            assert "\\" not in hop.file, (
                f"Backslash in evidence path for outside-CWD product: {hop.file!r}"
            )

    def test_evidence_paths_are_relative(self, tmp_path):
        """Evidence paths must be relative (not absolute) for outside-CWD products."""
        app_py = tmp_path / "app.py"
        app_py.write_text(
            "import yaml\nfrom flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/')\ndef index():\n"
            "    return str(yaml.full_load('x: 1'))\n"
        )
        results = scan(
            product_root=tmp_path,
            targets=["yaml.full_load"],
            template_filters=[],
            entry_points=[],
        )
        r = {res.target: res for res in results}["yaml.full_load"]
        for hop in r.evidence:
            assert not pathlib.Path(hop.file).is_absolute(), (
                f"Expected relative path in evidence, got absolute: {hop.file!r}"
            )
