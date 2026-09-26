"""Tests for t24.reach module.

All fixture projects live under tests/fixtures/reach/<scenario>/.
No demo_product is touched; no network calls.
"""
from __future__ import annotations

import pathlib
import pytest

from t24.reach import scan, ReachResult, EvidenceHop

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "reach"


def first_hop(result: ReachResult) -> EvidenceHop:
    assert result.evidence, f"Expected evidence for {result.target}, got []"
    return result.evidence[0]


def last_hop(result: ReachResult) -> EvidenceHop:
    assert result.evidence, f"Expected evidence for {result.target}, got []"
    return result.evidence[-1]


# ---------------------------------------------------------------------------
# Helper: run scan on a fixture directory for one target
# ---------------------------------------------------------------------------

def reach(scenario: str, targets: list[str], *, filters: list[str] | None = None,
          entry_points: list[str] | None = None) -> dict[str, ReachResult]:
    root = FIXTURES / scenario
    results = scan(
        product_root=root,
        targets=targets,
        template_filters=filters or [],
        entry_points=entry_points or [],
    )
    return {r.target: r for r in results}


# ---------------------------------------------------------------------------
# 1. Direct call: yaml.full_load called inside a Flask route
# ---------------------------------------------------------------------------

class TestDirectCall:
    def test_target_reached(self):
        r = reach("direct_call", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True

    def test_evidence_not_empty(self):
        r = reach("direct_call", ["yaml.full_load"])
        assert len(r["yaml.full_load"].evidence) >= 1

    def test_last_hop_call_matches(self):
        r = reach("direct_call", ["yaml.full_load"])
        hop = last_hop(r["yaml.full_load"])
        assert "full_load" in hop.call

    def test_coverage_full(self):
        r = reach("direct_call", ["yaml.full_load"])
        res = r["yaml.full_load"]
        assert res.files_found == res.files_parsed


# ---------------------------------------------------------------------------
# 2. Aliased module import: import yaml as y; y.full_load(...)
# ---------------------------------------------------------------------------

class TestAliasImport:
    def test_target_reached_via_alias(self):
        r = reach("alias_import", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True

    def test_evidence_present(self):
        r = reach("alias_import", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence


# ---------------------------------------------------------------------------
# 3. From-import alias: from yaml import full_load as fl; fl(...)
# ---------------------------------------------------------------------------

class TestFromImportAlias:
    def test_target_reached_via_from_alias(self):
        r = reach("from_import_alias", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True

    def test_evidence_present(self):
        r = reach("from_import_alias", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence


# ---------------------------------------------------------------------------
# 4. Attribute chain: from PIL import ImageMath; ImageMath.eval(...)
# ---------------------------------------------------------------------------

class TestPILAttributeChain:
    def test_imagemath_eval_reached(self):
        r = reach("pil_attribute_chain", ["PIL.ImageMath.eval"])
        assert r["PIL.ImageMath.eval"].reachable is True

    def test_evidence_present(self):
        r = reach("pil_attribute_chain", ["PIL.ImageMath.eval"])
        assert r["PIL.ImageMath.eval"].evidence


# ---------------------------------------------------------------------------
# 5. Reference without a call: yaml.load(..., Loader=yaml.FullLoader)
# ---------------------------------------------------------------------------

class TestLoaderReference:
    def test_fullloader_reached_as_reference(self):
        r = reach("loader_reference", ["yaml.FullLoader"])
        assert r["yaml.FullLoader"].reachable is True

    def test_evidence_present(self):
        r = reach("loader_reference", ["yaml.FullLoader"])
        assert r["yaml.FullLoader"].evidence


# ---------------------------------------------------------------------------
# 6. Cross-file hop: app.py -> config.py -> yaml.full_load
# ---------------------------------------------------------------------------

class TestCrossFile:
    def test_target_reached_across_files(self):
        r = reach("cross_file", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True

    def test_evidence_spans_two_files(self):
        r = reach("cross_file", ["yaml.full_load"])
        evidence = r["yaml.full_load"].evidence
        files = {hop.file for hop in evidence}
        # Must touch both app.py and config.py
        assert any("app.py" in f for f in files)
        assert any("config.py" in f for f in files)

    def test_first_hop_is_entry_point(self):
        r = reach("cross_file", ["yaml.full_load"])
        hop = first_hop(r["yaml.full_load"])
        assert "app.py" in hop.file

    def test_last_hop_is_vulnerable_call(self):
        r = reach("cross_file", ["yaml.full_load"])
        hop = last_hop(r["yaml.full_load"])
        assert "full_load" in hop.call


# ---------------------------------------------------------------------------
# 7. Imported but never called — NOT reached
# ---------------------------------------------------------------------------

class TestImportedNeverCalled:
    def test_not_reached(self):
        r = reach("imported_never_called", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is False

    def test_evidence_empty(self):
        r = reach("imported_never_called", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence == []


# ---------------------------------------------------------------------------
# 8. Called only from a function no entry point reaches — NOT reached
# ---------------------------------------------------------------------------

class TestUnreachableFunction:
    def test_not_reached(self):
        r = reach("unreachable_function", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is False

    def test_evidence_empty(self):
        r = reach("unreachable_function", ["yaml.full_load"])
        assert r["yaml.full_load"].evidence == []


# ---------------------------------------------------------------------------
# 9. Template filter present
# ---------------------------------------------------------------------------

class TestTemplateFilterPresent:
    def test_xmlattr_reached(self):
        r = reach("template_filter", [], filters=["xmlattr"])
        assert r["xmlattr"].reachable is True

    def test_evidence_points_to_template(self):
        r = reach("template_filter", [], filters=["xmlattr"])
        hop = last_hop(r["xmlattr"])
        assert "label.html" in hop.file
        assert "|xmlattr" in hop.call or "xmlattr" in hop.call


# ---------------------------------------------------------------------------
# 10. Template filter absent
# ---------------------------------------------------------------------------

class TestTemplateFilterAbsent:
    def test_xmlattr_not_reached(self):
        r = reach("template_filter_absent", [], filters=["xmlattr"])
        assert r["xmlattr"].reachable is False

    def test_evidence_empty(self):
        r = reach("template_filter_absent", [], filters=["xmlattr"])
        assert r["xmlattr"].evidence == []


# ---------------------------------------------------------------------------
# 11. Syntax error in one file: files_parsed < files_found
# ---------------------------------------------------------------------------

class TestSyntaxError:
    def test_files_parsed_less_than_found(self):
        r = reach("syntax_error", ["yaml.full_load"])
        res = r["yaml.full_load"]
        assert res.files_found == 2
        assert res.files_parsed == 1

    def test_target_still_reached_from_good_file(self):
        # good.py has yaml.full_load in a Flask route
        r = reach("syntax_error", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is True


# ---------------------------------------------------------------------------
# 12. Explicit entry-point override
# ---------------------------------------------------------------------------

class TestExplicitEntryPoint:
    def test_without_explicit_entry_not_reached(self):
        """not_a_route() has no Flask decorator → not auto-detected."""
        r = reach("explicit_entry", ["yaml.full_load"])
        assert r["yaml.full_load"].reachable is False

    def test_with_explicit_entry_reached(self):
        """Passing app.py:not_a_route as explicit entry → reached."""
        root = FIXTURES / "explicit_entry"
        entry = [f"{root / 'app.py'}:not_a_route"]
        results = scan(
            product_root=root,
            targets=["yaml.full_load"],
            template_filters=[],
            entry_points=entry,
        )
        r = {res.target: res for res in results}
        assert r["yaml.full_load"].reachable is True
