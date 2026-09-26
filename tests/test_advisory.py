"""tests/test_advisory.py — Unit tests for t24/advisory.py."""
from __future__ import annotations

import json
import pathlib
import unittest.mock as mock
from typing import Any

import pytest

ADVISORIES_DIR = pathlib.Path(__file__).parent.parent / "advisories"
FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"


def _load_expected() -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / "expected_extractions.json").read_text())


def _make_cache(tmp_path: pathlib.Path, cve: str, data: dict) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / f"{cve}.json").write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# Cache-hit path
# ---------------------------------------------------------------------------

class TestCacheHit:
    def test_cache_hit_returns_extraction(self, tmp_path):
        """When a cache file exists, advisory.extract() uses it directly."""
        from t24.advisory import extract, AdvisoryExtraction

        cve = "CVE-2020-14343"
        expected = _load_expected()[cve]

        cache_entry = {
            "provider": "cache",
            "model": "cached",
            "timestamp": "2026-01-01T00:00:00Z",
            "raw_response": "{}",
            "extraction": expected,
        }
        _make_cache(tmp_path, cve, cache_entry)

        advisory_path = ADVISORIES_DIR / f"{cve}.md"
        result = extract(
            advisory_path=advisory_path,
            cache_dir=tmp_path / "cache",
            offline=True,
        )

        assert isinstance(result, AdvisoryExtraction)
        assert result.cve == cve
        assert result.package == "PyYAML"
        assert "full_load" in result.symbols
        assert "FullLoader" in result.symbols
        assert result.affected_range == "< 5.4"
        assert result.fixed_version == "5.4"
        assert result.advisory_source == "https://github.com/advisories/GHSA-8q59-q68h-6hv4"

    def test_cache_hit_all_four_advisories(self, tmp_path):
        """Cache-based extraction works for all four demo CVEs."""
        from t24.advisory import extract

        expected_all = _load_expected()
        for cve, expected in expected_all.items():
            if cve.startswith("_"):
                continue
            cache_entry = {
                "provider": "cache",
                "model": "cached",
                "timestamp": "2026-01-01T00:00:00Z",
                "raw_response": "{}",
                "extraction": expected,
            }
            _make_cache(tmp_path, cve, cache_entry)

        for cve, expected in expected_all.items():
            if cve.startswith("_"):
                continue
            advisory_path = ADVISORIES_DIR / f"{cve}.md"
            result = extract(
                advisory_path=advisory_path,
                cache_dir=tmp_path / "cache",
                offline=True,
            )
            assert result.cve == cve, f"Wrong CVE for {cve}"
            assert result.package == expected["package"]
            assert set(result.symbols) == set(expected["symbols"])


# ---------------------------------------------------------------------------
# Verbatim-symbol filter
# ---------------------------------------------------------------------------

class TestVerbatimSymbolCheck:
    def test_fabricated_symbol_dropped(self, tmp_path):
        """Symbols not present verbatim in advisory text are dropped."""
        from t24.advisory import _verbatim_filter

        advisory_text = "This advisory mentions full_load and FullLoader as vulnerable."
        symbols_raw = [
            {"name": "full_load", "kind": "python"},
            {"name": "FullLoader", "kind": "python"},
            {"name": "safe_load",  "kind": "python"},   # fabricated — not in text
            {"name": "FakeClass",  "kind": "python"},   # fabricated
        ]
        kept = _verbatim_filter(symbols_raw, advisory_text)
        names = [s["name"] for s in kept]
        assert "full_load" in names
        assert "FullLoader" in names
        assert "safe_load" not in names
        assert "FakeClass" not in names

    def test_case_sensitive_check(self, tmp_path):
        """Verbatim check is case-sensitive."""
        from t24.advisory import _verbatim_filter

        advisory_text = "full_load is mentioned"
        symbols_raw = [
            {"name": "full_load", "kind": "python"},
            {"name": "Full_Load", "kind": "python"},  # different case
        ]
        kept = _verbatim_filter(symbols_raw, advisory_text)
        names = [s["name"] for s in kept]
        assert "full_load" in names
        assert "Full_Load" not in names


# ---------------------------------------------------------------------------
# SOURCE line parsing
# ---------------------------------------------------------------------------

class TestSourceLineParsing:
    def test_source_url_extracted(self, tmp_path):
        """The SOURCE: line is parsed from the advisory markdown."""
        from t24.advisory import _parse_source_url

        text = "# Title\n\nSOURCE: https://github.com/advisories/GHSA-8q59-q68h-6hv4\n\n## Summary"
        url = _parse_source_url(text)
        assert url == "https://github.com/advisories/GHSA-8q59-q68h-6hv4"

    def test_missing_source_raises(self, tmp_path):
        """Missing SOURCE: line raises ValueError."""
        from t24.advisory import _parse_source_url

        with pytest.raises(ValueError, match="SOURCE"):
            _parse_source_url("# Title\n\nNo source line here.")


# ---------------------------------------------------------------------------
# No provider available
# ---------------------------------------------------------------------------

class TestNoProvider:
    def test_no_cache_no_key_raises_runtime_error(self, tmp_path):
        """When cache is empty and no provider key is set, RuntimeError is raised."""
        from t24.advisory import extract

        empty_cache = tmp_path / "cache"
        empty_cache.mkdir()

        advisory_path = ADVISORIES_DIR / "CVE-2020-14343.md"

        with mock.patch.dict("os.environ", {}, clear=True):
            # Remove any env keys that might exist
            env_patch = {
                "WATSONX_APIKEY": "",
                "FIREWORKS_API_KEY": "",
            }
            with mock.patch.dict("os.environ", env_patch):
                with pytest.raises(RuntimeError, match="No cached extraction"):
                    extract(
                        advisory_path=advisory_path,
                        cache_dir=empty_cache,
                        offline=True,
                    )


# ---------------------------------------------------------------------------
# Mocked provider call
# ---------------------------------------------------------------------------

class TestMockedProvider:
    def test_llm_result_is_cached(self, tmp_path):
        """A successful LLM call writes the result to cache."""
        from t24.advisory import extract

        cve = "CVE-2020-14343"
        advisory_path = ADVISORIES_DIR / f"{cve}.md"
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        expected = _load_expected()[cve]
        mock_llm_result = {
            "package": expected["package"],
            "affected_range": expected["affected_range"],
            "fixed_version": expected["fixed_version"],
            "symbols": [{"name": s, "kind": "python"} for s in expected["symbols"]],
            "preconditions": expected["preconditions"],
        }

        with mock.patch("t24.advisory.call_provider", return_value=mock_llm_result) as mock_call:
            result = extract(
                advisory_path=advisory_path,
                cache_dir=cache_dir,
            )

        assert mock_call.called
        assert result.package == "PyYAML"
        # Cache file must now exist
        cache_file = cache_dir / f"{cve}.json"
        assert cache_file.exists()
        cached = json.loads(cache_file.read_text())
        assert "extraction" in cached
        assert "provider" in cached
        assert "timestamp" in cached


def test_published_range_has_no_stray_whitespace():
    """Regression: '- **Vulnerable versions:** < 5.4' parsed as ' < 5.4'."""
    from t24.advisory import _extract_range_from_text, _extract_fixed_from_text
    text = open("advisories/CVE-2020-14343.md", encoding="utf-8").read()
    assert _extract_range_from_text(text) == _extract_range_from_text(text).strip() != ""
    assert _extract_fixed_from_text(text) == _extract_fixed_from_text(text).strip() != ""


def test_equivalent_ranges_do_not_warn():
    """'>=2.3.0,<2.31.0' and '>= 2.3.0, < 2.31.0' are the same range."""
    from t24.advisory import _same_range
    assert _same_range(">=2.3.0,<2.31.0", ">= 2.3.0, < 2.31.0")
    assert not _same_range("<5.4", "<5.3")
