"""cli_output.py — Output helpers for the T-24 CLI.

Extracted from cli.py to keep both files under 300 lines.
Handles dossier serialization, path utilities, and console table printing.
"""
from __future__ import annotations

import pathlib


def rel_path(path: pathlib.Path) -> str:
    """Return a forward-slash relative path, preferring CWD-relative."""
    cwd = pathlib.Path.cwd()
    try:
        return path.relative_to(cwd).as_posix()
    except ValueError:
        pass
    return path.as_posix()


def build_dossier(
    product_name: str,
    scanned_at: str,
    duration_s: float,
    verdicts: list,
    clock_obj,
    files_found: int,
    files_parsed: int,
    vex_path: str,
) -> dict:
    """Build the dossier dict per docs/DATA_CONTRACT.md."""
    counts = {
        "affected": sum(1 for v in verdicts if v.status == "affected"),
        "not_affected": sum(1 for v in verdicts if v.status == "not_affected"),
        "under_investigation": sum(1 for v in verdicts if v.status == "under_investigation"),
    }
    findings = []
    for v in verdicts:
        f = {
            "cve": v.cve,
            "package": v.package,
            "installed": v.installed,
            "affected_range": v.affected_range,
            "fixed_version": v.fixed_version,
            "symbols": v.symbols,
            "status": v.status,
            "justification": v.justification if v.status == "not_affected" else None,
            "evidence": [
                {"file": h.file, "line": h.line, "function": h.function, "call": h.call}
                for h in (v.evidence if v.status == "affected" else [])
            ],
            "reason": v.reason,
            "advisory_source": v.advisory_source,
            "drafts": v.drafts,
        }
        findings.append(f)

    return {
        "product": product_name,
        "scanned_at": scanned_at,
        "duration_s": duration_s,
        "summary": {
            "advisories": len(verdicts),
            "affected": counts["affected"],
            "not_affected": counts["not_affected"],
            "under_investigation": counts["under_investigation"],
            "emergency_releases_avoided": counts["not_affected"],
        },
        "clock": clock_obj.to_dict() if clock_obj else None,
        "findings": findings,
        "coverage": {"files_found": files_found, "files_parsed": files_parsed},
        "vex_path": vex_path,
    }


def print_table(verdicts: list, duration: float) -> None:
    """Print a summary table of verdicts to stdout."""
    rows = [(v.cve, v.package, v.status, v.reason[:60]) for v in verdicts]
    headers = ("CVE", "Package", "Status", "Reason")
    col_w = [max(len(r[i]) for r in rows + [headers]) for i in range(4)]
    sep = "  ".join("-" * w for w in col_w)
    header = "  ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
    print()
    print(header)
    print(sep)
    for row in rows:
        print("  ".join(row[i].ljust(col_w[i]) for i in range(4)))
    print()
    print(f"Triaged {len(verdicts)} advisories in {duration:.1f}s")
    print()
