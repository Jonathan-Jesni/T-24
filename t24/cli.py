"""cli.py — Argparse CLI for T-24 triage.

Usage::

    python -m t24 scan demo_product \\
        --advisories advisories \\
        --exploited CVE-2020-14343=2026-09-27T02:00:00Z \\
        --out out [--baseline path] [--offline]

Outputs:
    out/vex.json, out/dossier.json, out/drafts/ (when affected + exploited)
"""
from __future__ import annotations

import argparse
import json
import logging
import pathlib
import sys
import time
from datetime import datetime, timezone

from t24.cli_output import rel_path, build_dossier, print_table

log = logging.getLogger(__name__)


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
        env_file = pathlib.Path(__file__).parent.parent / ".env"
        if env_file.exists():
            load_dotenv(env_file)
    except ImportError:
        pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="t24",
        description="Prove whether you're affected before the CRA clock runs out.",
    )
    sub = p.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan a product against advisories.")
    scan.add_argument("product", help="Path to product directory")
    scan.add_argument("--advisories", default="advisories")
    scan.add_argument("--out", default="out")
    scan.add_argument("--cache", default="cache")
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--exploited", action="append", default=[], metavar="CVE=ISO8601")
    scan.add_argument("--aware-at", dest="aware_at")
    scan.add_argument("--baseline")
    scan.add_argument("--entry-points", dest="entry_points", default="")
    return p


def run_scan(args: argparse.Namespace) -> int:
    """Execute the scan sub-command; return exit code."""
    _load_dotenv()

    from t24.advisory import extract
    from t24.qualify import qualify_symbols_with_kind
    from t24.inventory import check_installed_packages, VersionCheck
    from t24.reach import scan as reach_scan
    from t24.verdict import decide
    from t24.clock import make_clock, parse_aware_at
    from t24.vex import build_vex, write_vex
    from t24.report import render_early_warning, render_notification
    from packaging.utils import canonicalize_name

    product_root = pathlib.Path(args.product).resolve()
    advisories_dir = pathlib.Path(args.advisories)
    out_dir = pathlib.Path(args.out)
    cache_dir = pathlib.Path(args.cache)

    # Parse --exploited CVE=ISO entries
    exploited_map: dict[str, datetime] = {}
    default_aware_at = parse_aware_at(args.aware_at) if args.aware_at else None

    for entry in args.exploited:
        if "=" not in entry:
            print(f"Error: --exploited must be CVE=ISO8601, got: {entry!r}", file=sys.stderr)
            return 1
        cve_part, ts_part = entry.split("=", 1)
        exploited_map[cve_part.strip()] = parse_aware_at(ts_part.strip())

    for entry in args.exploited:
        cve_part = entry.split("=", 1)[0].strip()
        if cve_part not in exploited_map and default_aware_at:
            exploited_map[cve_part] = default_aware_at

    # Load baseline dossier
    baseline_statuses: dict[str, str] = {}
    if args.baseline:
        try:
            bl = json.loads(pathlib.Path(args.baseline).read_text())
            for f in bl.get("findings", []):
                baseline_statuses[f["cve"]] = f["status"]
        except Exception as exc:
            log.warning("Failed to load baseline: %s", exc)

    entry_points = [e.strip() for e in args.entry_points.split(",") if e.strip()]

    advisory_files = sorted(advisories_dir.glob("CVE-*.md"))
    if not advisory_files:
        print(f"No CVE-*.md files found in {advisories_dir}", file=sys.stderr)
        return 1

    req_file = product_root / "requirements.txt"
    if not req_file.exists():
        print(f"requirements.txt not found in {product_root}", file=sys.stderr)
        return 1
    requirements_text = req_file.read_text()

    start = time.monotonic()
    scanned_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    extractions = []
    for adv_path in advisory_files:
        try:
            extractions.append(extract(advisory_path=adv_path, cache_dir=cache_dir,
                                       offline=args.offline))
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    version_checks = check_installed_packages(requirements_text, extractions)
    vc_map = {vc.package: vc for vc in version_checks}

    # Collect all targets for a single reach scan
    all_py_targets: list[str] = []
    all_tpl_filters: list[str] = []
    for ext in extractions:
        sym_dicts = [{"name": s, "kind": "python"} for s in ext.symbols]
        py_t, tpl_f = qualify_symbols_with_kind(ext.package, sym_dicts)
        all_py_targets.extend(py_t)
        all_tpl_filters.extend(tpl_f)

    reach_results = reach_scan(
        product_root=product_root,
        targets=list(dict.fromkeys(all_py_targets)),
        template_filters=list(dict.fromkeys(all_tpl_filters)),
        entry_points=entry_points,
    )

    reach_map: dict[str, list] = {}
    for rr in reach_results:
        reach_map.setdefault(rr.target, []).append(rr)

    files_found = max((rr.files_found for rr in reach_results), default=0)
    files_parsed = max((rr.files_parsed for rr in reach_results), default=0)

    verdicts = []
    for ext in extractions:
        canonical = canonicalize_name(ext.package)
        vc = vc_map.get(canonical) or VersionCheck(
            package=canonical, present=False, installed=None,
            affected_range=ext.affected_range, in_range=False,
        )
        sym_dicts = [{"name": s, "kind": "python"} for s in ext.symbols]
        py_targets, tpl_targets = qualify_symbols_with_kind(ext.package, sym_dicts)
        relevant_rr = [rr for t in py_targets + tpl_targets for rr in reach_map.get(t, [])]

        verdict = decide(
            cve=ext.cve, version_check=vc, reach_results=relevant_rr,
            symbols=ext.symbols, preconditions=ext.preconditions,
            advisory_source=ext.advisory_source, fixed_version=ext.fixed_version,
            package_display=ext.package,
        )
        if (args.baseline and ext.cve in baseline_statuses
                and baseline_statuses[ext.cve] == "affected"
                and verdict.status != "affected"):
            verdict.status = "fixed"  # type: ignore[assignment]
            verdict.reason = "Previously affected; no longer reachable"
        verdicts.append(verdict)

    duration = time.monotonic() - start

    # Clock — earliest affected+exploited finding
    clock_obj = None
    affected_exploited = sorted(
        [v for v in verdicts if v.status == "affected" and v.cve in exploited_map],
        key=lambda v: exploited_map[v.cve],
    )
    if affected_exploited:
        clock_obj = make_clock(affected_exploited[0].cve,
                               exploited_map[affected_exploited[0].cve])

    # Draft reports
    drafts_dir = out_dir / "drafts"
    for v in verdicts:
        v.drafts = []
        if v.status == "affected" and v.cve in exploited_map and clock_obj:
            ew = render_early_warning(verdict=v, clock=clock_obj,
                                      product_name=product_root.name, drafts_dir=drafts_dir)
            notif = render_notification(verdict=v, clock=clock_obj,
                                        product_name=product_root.name, drafts_dir=drafts_dir)
            v.drafts = [rel_path(ew), rel_path(notif)]

    # Write VEX
    out_dir.mkdir(parents=True, exist_ok=True)
    vex_path = out_dir / "vex.json"
    vex_doc = build_vex(verdicts, product_id=product_root.name)
    write_vex(vex_doc, vex_path)

    dossier = build_dossier(
        product_name=product_root.name, scanned_at=scanned_at,
        duration_s=round(duration, 3), verdicts=verdicts, clock_obj=clock_obj,
        files_found=files_found, files_parsed=files_parsed, vex_path=rel_path(vex_path),
    )
    (out_dir / "dossier.json").write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    print_table(verdicts, duration)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
