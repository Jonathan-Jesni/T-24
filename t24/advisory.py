"""advisory.py — LLM advisory reader + verbatim-symbol check.

Provider order: watsonx.ai Granite → Fireworks → cache (offline).
The LLM ONLY extracts fields — it never sets a verdict.

Environment variables
---------------------
WATSONX_APIKEY, WATSONX_PROJECT_ID, WATSONX_URL, WATSONX_MODEL
FIREWORKS_API_KEY, FIREWORKS_MODEL

Cache
-----
cache/<CVE>.json  — written after every successful LLM call.
If the file exists, it is loaded immediately (offline-safe).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from t24.advisory_providers import call_provider, LLMResult

log = logging.getLogger(__name__)

_SOURCE_RE = re.compile(r"^SOURCE:\s*(\S+)", re.MULTILINE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_RANGE_RE = re.compile(r"Vulnerable version range[:\s]+([^\n]+)", re.IGNORECASE)
_FIXED_RE = re.compile(r"First patched version[:\s]+([^\n]+)", re.IGNORECASE)


@dataclass
class AdvisoryExtraction:
    cve: str
    package: str
    affected_range: str
    fixed_version: str
    symbols: list[str]            # verbatim-checked names
    preconditions: list[str]
    advisory_source: str
    raw_advisory_text: str


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract(
    advisory_path: Path,
    cache_dir: Path | None = None,
    offline: bool = False,
) -> AdvisoryExtraction:
    """Extract advisory fields, using cache when available.

    Raises RuntimeError when cache is empty, offline=True (or no provider key),
    and no provider is available.
    """
    advisory_text = advisory_path.read_text(encoding="utf-8", errors="replace")
    cve = _cve_from_path(advisory_path)
    advisory_source = _parse_source_url(advisory_text)

    if cache_dir is None:
        cache_dir = Path("cache")

    cache_file = cache_dir / f"{cve}.json"

    if cache_file.exists():
        cached = json.loads(cache_file.read_text(encoding="utf-8"))
        return _extraction_from_cache(cached, cve, advisory_text, advisory_source)

    if offline:
        raise RuntimeError(
            f"No cached extraction for {cve} and no provider key set. "
            f"Add FIREWORKS_API_KEY to .env or run with a populated cache/."
        )

    raw = call_provider(advisory_text, cve)
    extraction = _build_extraction(raw, cve, advisory_text, advisory_source)
    cache_dir.mkdir(parents=True, exist_ok=True)
    _write_cache(cache_file, raw, extraction)
    return extraction


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _extraction_from_cache(
    cached: dict[str, Any],
    cve: str,
    advisory_text: str,
    advisory_source: str,
) -> AdvisoryExtraction:
    data = cached.get("extraction", cached)
    symbols_raw = data.get("symbols", [])
    if symbols_raw and isinstance(symbols_raw[0], dict):
        symbols_filtered = _verbatim_filter(symbols_raw, advisory_text)
        symbol_names = [s["name"] for s in symbols_filtered]
    else:
        symbol_names = [s for s in symbols_raw if isinstance(s, str) and s in advisory_text]
    return AdvisoryExtraction(
        cve=cve,
        package=data.get("package", ""),
        affected_range=data.get("affected_range", "").strip(),
        fixed_version=data.get("fixed_version", "").strip(),
        symbols=symbol_names,
        preconditions=data.get("preconditions", []),
        advisory_source=data.get("advisory_source", advisory_source),
        raw_advisory_text=advisory_text,
    )


def _write_cache(cache_file: Path, raw: Any, extraction: AdvisoryExtraction) -> None:
    entry = {
        "provider": getattr(raw, "_provider", "unknown"),
        "model": getattr(raw, "_model", "unknown"),
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "raw_response": getattr(raw, "_raw_text", str(raw)),
        "extraction": {
            "cve": extraction.cve,
            "package": extraction.package,
            "affected_range": extraction.affected_range,
            "fixed_version": extraction.fixed_version,
            "symbols": [{"name": s, "kind": "python"} for s in extraction.symbols],
            "preconditions": extraction.preconditions,
            "advisory_source": extraction.advisory_source,
        },
    }
    cache_file.write_text(json.dumps(entry, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Verbatim-symbol filter (AGENTS.md § 5)
# ---------------------------------------------------------------------------

def _verbatim_filter(
    symbols_raw: list[dict[str, str]],
    advisory_text: str,
) -> list[dict[str, str]]:
    """Drop any symbol whose name is not a verbatim substring of advisory_text."""
    kept = []
    for sym in symbols_raw:
        name = sym.get("name", "")
        if name and name in advisory_text:
            kept.append(sym)
        else:
            log.warning("Dropping symbol %r — not found verbatim in advisory text", name)
    return kept


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_source_url(text: str) -> str:
    m = _SOURCE_RE.search(text)
    if not m:
        raise ValueError("Advisory text is missing a SOURCE: line")
    return m.group(1)


def _cve_from_path(path: Path) -> str:
    m = _CVE_RE.search(path.stem)
    return m.group(0) if m else path.stem


def _same_range(a: str, b: str) -> bool:
    """True when two version ranges mean the same thing (">=2.3,<2.31" == ">= 2.3, < 2.31")."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    try:
        return SpecifierSet(a) == SpecifierSet(b)
    except InvalidSpecifier:
        return a.replace(" ", "") == b.replace(" ", "")


def _extract_range_from_text(text: str) -> str:
    m = _RANGE_RE.search(text)
    return m.group(1).strip().strip("*`").strip() if m else ""


def _extract_fixed_from_text(text: str) -> str:
    m = _FIXED_RE.search(text)
    return m.group(1).strip().strip("*`").strip() if m else ""


def _build_extraction(
    raw: dict[str, Any],
    cve: str,
    advisory_text: str,
    advisory_source: str,
) -> AdvisoryExtraction:
    symbols_raw = raw.get("symbols", [])
    if symbols_raw and isinstance(symbols_raw[0], str):
        symbols_raw = [{"name": s, "kind": "python"} for s in symbols_raw]

    symbol_names = [s["name"] for s in _verbatim_filter(symbols_raw, advisory_text)]

    advisory_range = _extract_range_from_text(advisory_text)
    advisory_fixed = _extract_fixed_from_text(advisory_text)
    llm_range = raw.get("affected_range", "").strip()
    llm_fixed = raw.get("fixed_version", "").strip()

    if advisory_range and llm_range and not _same_range(llm_range, advisory_range):
        log.warning("LLM affected_range %r differs from advisory %r — using advisory",
                    llm_range, advisory_range)
    if advisory_fixed and llm_fixed and llm_fixed != advisory_fixed:
        log.warning("LLM fixed_version %r differs from advisory %r — using advisory",
                    llm_fixed, advisory_fixed)

    return AdvisoryExtraction(
        cve=cve,
        package=raw.get("package", ""),
        affected_range=advisory_range or llm_range,
        fixed_version=advisory_fixed or llm_fixed,
        symbols=symbol_names,
        preconditions=raw.get("preconditions", []),
        advisory_source=advisory_source,
        raw_advisory_text=advisory_text,
    )


# Keep _call_provider importable for tests that mock it
_call_provider = call_provider
