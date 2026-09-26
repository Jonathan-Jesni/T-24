"""verdict.py — Deterministic verdict engine.

The LLM NEVER sets a status. This is the only place a status is assigned.

Decision tree (from docs/PLAN.md § 4.4 + user requirements):

1. package not listed           → not_affected / component_not_present
2. listed but unpinned          → under_investigation, "version not pinned"
3. pinned, not in range         → not_affected / vulnerable_code_not_present
4. in range, any target reached → affected, evidence = shortest chain
5. in range, any reach uncertain → under_investigation, lists uncertain_sites
6. in range, symbols named, none reached, files_parsed==files_found, no preconditions
                                → not_affected / vulnerable_code_not_in_execute_path
7. otherwise (no symbols, parse failures, preconditions)
                                → under_investigation with specific reason
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from t24.reach_bfs import EvidenceHop, ReachResult
from t24.inventory import VersionCheck


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
) -> VerdictResult:
    """Apply the deterministic decision tree and return a VerdictResult.

    Parameters
    ----------
    cve:             CVE identifier
    version_check:   result from inventory.check_installed_packages
    reach_results:   list of ReachResult from reach.scan (may be empty)
    symbols:         verbatim-checked symbol names from advisory extraction
    preconditions:   runtime preconditions from advisory extraction
    advisory_source: URL from SOURCE: line
    fixed_version:   first fixed version string
    package_display: original package name for display (defaults to version_check.package)
    """
    pkg = package_display or version_check.package

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
            f"{pkg} {version_check.installed} is outside affected range {version_check.affected_range}",
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
            for s in rr.uncertain_sites[:3]  # cap at 3 for readability
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

    # ── Rule 6: symbols named, none reached, full coverage, no preconditions
    if symbols and reach_results and full_coverage and not preconditions:
        # Verify no symbol was reachable (belt-and-suspenders)
        if not any(rr.reachable for rr in reach_results):
            symbol_list = ", ".join(symbols)
            return _make(
                "not_affected",
                "vulnerable_code_not_in_execute_path",
                [],
                f"{symbol_list}: no path from any entry point reaches the vulnerable symbol",
            )

    # ── Rule 7: everything else → under_investigation ───────────────────────
    if preconditions:
        reason = (
            f"Preconditions cannot be verified statically: "
            + "; ".join(preconditions)
        )
    elif not symbols:
        reason = f"No vulnerable symbols named in advisory — cannot rule out exploitation"
    elif not full_coverage:
        reason = (
            f"Parse coverage incomplete ({files_parsed}/{files_found} files) — "
            f"cannot confirm symbol is unreachable"
        )
    else:
        reason = "Insufficient information for definitive verdict"

    return _make("under_investigation", None, [], reason)
