"""tests/test_qualify.py — Unit tests for t24/qualify.py."""
from __future__ import annotations

import pytest


class TestQualify:
    def test_bare_symbol_prefixed_with_import_name(self):
        """'full_load' from PyYAML → 'yaml.full_load'."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("PyYAML", ["full_load", "FullLoader"])
        assert "yaml.full_load" in result
        assert "yaml.FullLoader" in result

    def test_already_qualified_not_double_prefixed(self):
        """'PIL.ImageMath.eval' from Pillow stays as is."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("Pillow", ["PIL.ImageMath.eval"])
        assert "PIL.ImageMath.eval" in result
        assert "PIL.PIL.ImageMath.eval" not in result

    def test_jinja2_xmlattr(self):
        """'xmlattr' from jinja2 uses import name 'jinja2'."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("jinja2", ["xmlattr"])
        assert "jinja2.xmlattr" in result

    def test_requests_no_symbols(self):
        """Empty symbols list returns empty list."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("requests", [])
        assert result == []

    def test_pillow_bare_symbol(self):
        """Bare symbol from Pillow gets 'PIL.' prefix."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("Pillow", ["Image"])
        assert "PIL.Image" in result

    def test_pyyaml_canonical_name(self):
        """Package name normalization: 'pyyaml' → import name 'yaml'."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("pyyaml", ["full_load"])
        assert "yaml.full_load" in result

    def test_unknown_package_uses_package_name(self):
        """Unknown package falls back to the package name as import prefix."""
        from t24.qualify import qualify_symbols

        result = qualify_symbols("somelib", ["do_thing"])
        assert "somelib.do_thing" in result

    def test_template_filter_kind_returned_separately(self):
        """template_filter kind symbols are returned in template_filters list."""
        from t24.qualify import qualify_symbols_with_kind

        py_targets, tpl_filters = qualify_symbols_with_kind("jinja2", [
            {"name": "xmlattr", "kind": "template_filter"},
        ])
        assert py_targets == []
        assert "xmlattr" in tpl_filters

    def test_mixed_kinds(self):
        """Mixed python and template_filter symbols split correctly."""
        from t24.qualify import qualify_symbols_with_kind

        py_targets, tpl_filters = qualify_symbols_with_kind("jinja2", [
            {"name": "xmlattr", "kind": "template_filter"},
            {"name": "Environment", "kind": "python"},
        ])
        assert "jinja2.Environment" in py_targets
        assert "xmlattr" in tpl_filters
