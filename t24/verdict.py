"""verdict.py — Deterministic verdict engine.

The LLM NEVER sets a status. This is the only place a status is assigned.

Decision tree (from docs/PLAN.md § 4.4 + user requirements):

1. package not listed           → not_affected / component_not_present
2. listed but unpinned          → under_investigation, "version not pinned"
3. pinned, not in range         → not_affected / vulnerable_code_not_present
4. in range, any target reached → affected, evidence = shortest chain
5. in range, any reach uncertain → under_investigation, lists uncertain_sites
6. in range, symbols named, none reached, files_parsed==files_found, not uncertain:
   a. For each python symbol: libcallers returns None
      → under_investigation, "library source unavailable"
   b. For each python symbol: libcallers returns ≥1 hop
      → under_investigation, reason cites file:line:function
   c. All python symbols have zero internal callers (template_filter symbols skip check)
      → not_affected / vulnerable_code_not_in_execute_path
      Preconditions no longer block this; they appear in reason as informational text.
7. otherwise (no symbols, parse failures)
   → under_investigation with specific reason
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from t24.reach_bfs import EvidenceHop, ReachResult
from t24.inventory import VersionCheck
from t24.libcallers import find_internal_callers


@dataclass
class VerdictResult:
    cve: str
    package: str
    installed: str | None
    affected_range: str
    fixed_version: str
    symbols: list[str]
    status: Literal["affected", "not_affected", "under_investigation", "fixed"]
    justification: str | None
    evidence: list[EvidenceHop]
    reason: str
    advisory_source: str
    drafts: list[str] = field(default_factory=list)


def decide(
    cve: str,
    version_check: VersionCheck,
    reach_results: list[ReachResult],
    symbols: list[str],
    preconditions: list[str],
    advisory_source: str,
    fixed_version: str = "",
    package_display: str = "",
    template_filter_symbols: list[str] | None = None,
) -> VerdictResult:
    """Apply the deterministic decision tree and return a VerdictResult.

    Parameters
    ----------
    cve:                    CVE identifier
    version_check:          result from inventory.check_installed_packages
    reach_results:          list of ReachResult from reach.scan (may be empty)
    symbols:                verbatim-checked symbol names from advisory extraction
    preconditions:          runtime preconditions (informational only; no longer block)
    advisory_source:        URL from SOURCE: line
    fixed_version:          first fixed version string
    package_display:        original package name for display
    template_filter_symbols: symbols that are Jinja2 template filters — these skip
                             the libcallers check (only templates invoke them)
    """
    pkg = package_display or version_check.package
    tpl_filter_set = set(template_filter_symbols or [])

    def _make(status, justification, evidence, reason) -> VerdictResult:
        return VerdictResult(
            cve=cve,
            package=pkg,
            installed=version_check.installed,
            affected_range=version_check.affected_range,
            fixed_version=fixed_version,
            symbols=symbols,
            status=status,
            justification=justification,
            evidence=evidence,
            reason=reason,
            advisory_source=advisory_source,
        )

    # ── Rule 1: package not listed ──────────────────────────────────────────
    if not version_check.present:
        return _make(
            "not_affected",
            "component_not_present",
            [],
            f"{pkg} is not listed in requirements.txt",
        )

    # ── Rule 2: listed but unpinned ─────────────────────────────────────────
    if version_check.in_range is None:
        return _make(
            "under_investigation",
            None,
            [],
            f"{pkg} version is not pinned — cannot determine if in affected range",
        )

    # ── Rule 3: pinned, not in range ────────────────────────────────────────
    if not version_check.in_range:
        return _make(
            "not_affected",
            "vulnerable_code_not_present",
            [],
            f"{pkg} {version_check.installed} is outside affected range "
            f"{version_check.affected_range}",
        )

    # ── In-range from here ──────────────────────────────────────────────────

    # ── Rule 4: any target reached ──────────────────────────────────────────
    for rr in reach_results:
        if rr.reachable and rr.evidence:
            return _make(
                "affected",
                None,
                rr.evidence,
                f"{rr.target} is reachable from {rr.evidence[0].function}",
            )

    # ── Rule 5: any reach result uncertain ──────────────────────────────────
    uncertain_results = [rr for rr in reach_results if rr.uncertain]
    if uncertain_results:
        sites_summary = "; ".join(
            f"{s.get('file','?')}:{s.get('line','?')} — {s.get('reason','?')}"
            for rr in uncertain_results
            for s in rr.uncertain_sites[:3]
        )
        return _make(
            "under_investigation",
            None,
            [],
            f"Static analysis uncertain — dynamic access patterns found: {sites_summary}",
        )

    # Check coverage (only matters for the not_affected path)
    files_found = max((rr.files_found for rr in reach_results), default=0)
    files_parsed = max((rr.files_parsed for rr in reach_results), default=0)
    full_coverage = (files_found == files_parsed) and files_found > 0

    # ── Rule 6: symbols named, none reached, full coverage ──────────────────
    if symbols and reach_results and full_coverage:
        # Belt-and-suspenders: none should be reachable at this point
        if not any(rr.reachable for rr in reach_results):
            # Check library-internal callers for each python symbol
            # Template-filter symbols are exempt (only templates can invoke them)
            python_symbols = [s for s in symbols if s not in tpl_filter_set]

            under_reason = _check_internal_callers(pkg, python_symbols)
            if under_reason is not None:
                return _make("under_investigation", None, [], under_reason)

            # All python symbols have zero internal callers — safe to emit not_affected
            symbol_list = ", ".join(symbols)
            reason = (
                f"{symbol_list}: no path from any entry point reaches the vulnerable symbol"
            )
            if preconditions:
                reason += (
                    f"; note: advisory preconditions (not statically verifiable): "
                    + "; ".join(preconditions)
                )
            return _make(
                "not_affected",
                "vulnerable_code_not_in_execute_path",
                [],
                reason,
            )

    # ── Rule 7: everything else → under_investigation ───────────────────────
    if not symbols:
        reason = f"No vulnerable symbols named in advisory — cannot rule out exploitation"
    elif not full_coverage:
        reason = (
            f"Parse coverage incomplete ({files_parsed}/{files_found} files) — "
            f"cannot confirm symbol is unreachable"
        )
    else:
        reason = "Insufficient information for definitive verdict"

    return _make("under_investigation", None, [], reason)


def _check_internal_callers(pkg: str, python_symbols: list[str]) -> str | None:
    """Check each python symbol for internal callers inside the library.

    Returns an under_investigation reason string if any symbol has internal
    callers or source is unavailable.  Returns None when all symbols are clear.
    """
    from packaging.utils import canonicalize_name
    try:
        from t24.qualify import _import_name
        import_name = _import_name(pkg)
    except Exception:
        import_name = canonicalize_name(pkg).replace("-", "_")

    for sym in python_symbols:
        # Use the last component of a dotted name for the search
        sym_last = sym.rsplit(".", 1)[-1]
        hops = find_internal_callers(import_name, sym_last)
        if hops is None:
            return (
                f"Library source unavailable for {pkg}; "
                f"cannot rule out internal callers of {sym}"
            )
        if hops:
            first = hops[0]
            f_file = first.get("file", "?")
            f_line = first.get("line", "?")
            f_func = first.get("function", "?")
            extra = f" (+{len(hops) - 1} more)" if len(hops) > 1 else ""
            return (
                f"{pkg} calls {sym} internally "
                f"({f_file}:{f_line} {f_func}){extra}; "
                f"the product uses {pkg}, so the vulnerable code can run on its behalf"
            )
    return None
