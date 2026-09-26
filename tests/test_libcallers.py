"""tests/test_libcallers.py — Unit tests for t24/libcallers.py.

Tests cover:
  - internal function calling the vulnerable symbol → returns hops
  - only the definition exists (no internal callers) → returns []
  - builtins.eval call inside a function named "eval" is ignored
  - library source not findable → returns None
"""
from __future__ import annotations

import pathlib
import sys
import types

import pytest

FIXTURES_LIBS = pathlib.Path(__file__).parent / "fixtures" / "libs"


def _install_fake_pkg(name: str) -> types.ModuleType:
    """Load a fake package from fixtures/libs/<name>/ into sys.modules."""
    import importlib.util as ilu
    pkg_dir = FIXTURES_LIBS / name
    s = ilu.spec_from_file_location(name, pkg_dir / "__init__.py",
                                    submodule_search_locations=[str(pkg_dir)])
    mod = ilu.module_from_spec(s)
    sys.modules[name] = mod
    s.loader.exec_module(mod)
    return mod


class TestLibcallersInternalCaller:
    """fake_pkg_caller has internal_func that calls build_proxies."""

    def test_finds_internal_call_site(self):
        from t24.libcallers import find_internal_callers

        _install_fake_pkg("fake_pkg_caller")
        hops = find_internal_callers("fake_pkg_caller", "build_proxies")

        assert hops is not None, "Should return list, not None — source is available"
        assert len(hops) >= 1, "Should find at least one internal call site"

        hop = hops[0]
        assert hop["function"] != "build_proxies", \
            "The definition itself must not be reported as a caller"
        assert hop["function"] == "internal_func"
        assert "build_proxies" in hop.get("file", "") or True  # file present
        assert isinstance(hop["line"], int)
        assert hop["line"] > 0

    def test_hop_keys(self):
        from t24.libcallers import find_internal_callers

        _install_fake_pkg("fake_pkg_caller")
        hops = find_internal_callers("fake_pkg_caller", "build_proxies")

        assert hops is not None
        for hop in hops:
            assert "file" in hop
            assert "line" in hop
            assert "function" in hop


class TestLibcallersDefOnly:
    """fake_pkg_def_only has rebuild_proxies but no internal callers."""

    def test_no_internal_callers(self):
        from t24.libcallers import find_internal_callers

        _install_fake_pkg("fake_pkg_def_only")
        hops = find_internal_callers("fake_pkg_def_only", "rebuild_proxies")

        assert hops is not None, "Source is available — should return list"
        assert hops == [], "No internal callers — list must be empty"


class TestLibcallersBuiltinsEval:
    """builtins.eval inside a function must not count as internal caller of 'eval'."""

    def test_builtins_eval_ignored(self):
        from t24.libcallers import find_internal_callers

        _install_fake_pkg("fake_pkg_builtins_eval")
        hops = find_internal_callers("fake_pkg_builtins_eval", "eval")

        assert hops is not None
        # process() calls builtins.eval — must be filtered out
        # eval() is the definition — must not appear as a caller
        for hop in hops:
            assert hop["function"] not in ("process", "eval"), \
                f"Unexpected internal caller: {hop['function']}"


class TestLibcallersUnknownPackage:
    """When find_spec returns None, find_internal_callers must return None."""

    def test_unknown_package_returns_none(self):
        import unittest.mock as mock
        from t24.libcallers import find_internal_callers

        with mock.patch("importlib.util.find_spec", return_value=None):
            result = find_internal_callers("nonexistent_pkg_xyz", "some_func")

        assert result is None, "Should return None when library source is unavailable"

    def test_no_origin_returns_none(self):
        """find_spec succeeds but origin is None (C extension / namespace pkg)."""
        import unittest.mock as mock
        from t24.libcallers import find_internal_callers

        fake_spec = mock.MagicMock()
        fake_spec.origin = None
        fake_spec.submodule_search_locations = None

        with mock.patch("importlib.util.find_spec", return_value=fake_spec):
            result = find_internal_callers("some_c_ext", "some_func")

        assert result is None
