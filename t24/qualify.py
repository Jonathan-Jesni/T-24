"""qualify.py — Turn extracted symbols into fully-qualified reach targets.

Uses the distribution's import name via importlib.metadata top_level.txt when
the package is installed, then falls back to a documented static map.

Static map (authoritative for offline/test use):
    PyYAML  → yaml
    Pillow  → PIL
    Jinja2  → jinja2
    requests → requests
"""
from __future__ import annotations

import logging
from packaging.utils import canonicalize_name

log = logging.getLogger(__name__)

# Distribution name (canonical) → import-name prefix
_STATIC_MAP: dict[str, str] = {
    "pyyaml":    "yaml",
    "pillow":    "PIL",
    "jinja2":    "jinja2",
    "requests":  "requests",
    "flask":     "flask",
}


def _import_name(package: str) -> str:
    """Return the top-level import name for *package*.

    1. Try importlib.metadata to read top_level.txt.
    2. Fall back to _STATIC_MAP.
    3. Fall back to the canonical package name itself.
    """
    canonical = canonicalize_name(package)

    # 1. importlib.metadata
    try:
        from importlib.metadata import packages_distributions  # Python 3.11+
        # packages_distributions maps import_name → [dist_name, ...]
        # We need the inverse: dist_name → import_names
        dist_to_imports: dict[str, list[str]] = {}
        for imp, dists in packages_distributions().items():
            for dist in dists:
                dist_to_imports.setdefault(canonicalize_name(dist), []).append(imp)
        if canonical in dist_to_imports:
            top_level = dist_to_imports[canonical]
            # Pick the shortest (most likely root) name
            chosen = min(top_level, key=len)
            log.debug("importlib.metadata: %s → %s", package, chosen)
            return chosen
    except Exception:
        pass

    # 2. Static map
    if canonical in _STATIC_MAP:
        return _STATIC_MAP[canonical]

    # 3. Fallback: use canonical name with hyphens replaced by underscores
    return canonical.replace("-", "_")


def qualify_symbols(package: str, symbols: list[str]) -> list[str]:
    """Return fully-qualified import paths for *symbols* from *package*.

    Rules:
    - If the symbol already starts with the import prefix (or a longer dotted
      path), return it unchanged (no double-prefix).
    - Otherwise, prepend the import prefix.
    """
    if not symbols:
        return []

    prefix = _import_name(package)
    result: list[str] = []
    for sym in symbols:
        if sym.startswith(prefix + ".") or sym == prefix:
            result.append(sym)
        else:
            result.append(f"{prefix}.{sym}")
    return result


def qualify_symbols_with_kind(
    package: str,
    symbol_dicts: list[dict[str, str]],
) -> tuple[list[str], list[str]]:
    """Split symbol dicts into (python_targets, template_filter_names).

    Returns:
        py_targets:    fully-qualified Python symbol names for reach.scan()
        tpl_filters:   bare filter names for template scanning
    """
    py_syms: list[str] = []
    tpl_filters: list[str] = []

    for s in symbol_dicts:
        name = s.get("name", "")
        kind = s.get("kind", "python")
        if kind == "template_filter":
            tpl_filters.append(name)
        else:
            py_syms.append(name)

    return qualify_symbols(package, py_syms), tpl_filters
