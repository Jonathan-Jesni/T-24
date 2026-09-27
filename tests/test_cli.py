"""tests/test_cli.py — End-to-end tests for the T-24 CLI.

Runs the full scan pipeline on demo_product with the LLM provider mocked
to return the answers in tests/fixtures/expected_extractions.json.

Expected verdicts:
  CVE-2020-14343  → affected, 2-hop chain, clock present
  CVE-2023-50447  → not_affected (vulnerable_code_not_in_execute_path), even with non-empty preconditions
  CVE-2024-22195  → not_affected (vulnerable_code_not_in_execute_path), even with non-empty preconditions
  CVE-2023-32681  → under_investigation ("internally" in reason), because requests calls
                    rebuild_proxies internally via resolve_redirects
"""
from __future__ import annotations

import json
import pathlib
import unittest.mock as mock

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"
DEMO_PRODUCT = REPO_ROOT / "demo_product"
ADVISORIES_DIR = REPO_ROOT / "advisories"


def _fake_find_internal_callers(import_name, symbol_last):
    """Hermetic stand-in for find_internal_callers used across e2e tests.

    Simulates realistic library behaviour without touching the real
    installed packages:
      - rebuild_proxies  → has an internal caller (requests/sessions.py)
      - everything else  → no internal callers
    """
    if symbol_last == "rebuild_proxies":
        return [{"file": "requests/sessions.py", "line": 245,
                 "function": "resolve_redirects"}]
    return []


def _load_expected() -> dict:
    return json.loads((FIXTURES_DIR / "expected_extractions.json").read_text())


def _build_cache(cache_dir: pathlib.Path) -> None:
    """Populate a cache directory with fixture extractions so no LLM is needed."""
    expected = _load_expected()
    cache_dir.mkdir(parents=True, exist_ok=True)
    for cve, data in expected.items():
        if cve.startswith("_"):
            continue
        entry = {
            "provider": "fixture",
            "model": "fixture",
            "timestamp": "2026-09-27T02:00:00Z",
            "raw_response": "{}",
            "extraction": data,
        }
        (cache_dir / f"{cve}.json").write_text(json.dumps(entry), encoding="utf-8")


class TestEndToEnd:
    @pytest.fixture(autouse=True)
    def _patch_libcallers(self):
        """Patch find_internal_callers for all e2e tests to keep them hermetic.

        rebuild_proxies gets an internal caller; everything else returns [].
        """
        with mock.patch("t24.verdict.find_internal_callers",
                        side_effect=_fake_find_internal_callers):
            yield

    def test_full_scan_four_verdicts(self, tmp_path):
        """Full scan produces the four expected verdicts.

        Pillow and Jinja2 must be not_affected even when their mocked extractions
        carry non-empty preconditions (the new rule ignores preconditions as
        a blocking condition).

        requests must be under_investigation because rebuild_proxies is called
        internally by the library itself (resolve_redirects).
        """
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)

        out_dir = tmp_path / "out"
        ret = main([
            "scan",
            str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])
        assert ret == 0

        dossier = json.loads((out_dir / "dossier.json").read_text())
        findings = {f["cve"]: f for f in dossier["findings"]}

        # CVE-2020-14343 → affected
        f0 = findings["CVE-2020-14343"]
        assert f0["status"] == "affected"
        assert f0["justification"] is None
        assert len(f0["evidence"]) >= 2, "Expected 2-hop chain"

        # CVE-2023-50447 → not_affected (even though preconditions are non-empty)
        f1 = findings["CVE-2023-50447"]
        assert f1["status"] == "not_affected", \
            "Pillow: preconditions alone must not block not_affected"
        assert f1["justification"] == "vulnerable_code_not_in_execute_path"
        assert f1["evidence"] == []

        # CVE-2024-22195 → not_affected (even though preconditions are non-empty)
        f2 = findings["CVE-2024-22195"]
        assert f2["status"] == "not_affected", \
            "Jinja2: preconditions alone must not block not_affected"
        assert f2["justification"] == "vulnerable_code_not_in_execute_path"

        # CVE-2023-32681 → under_investigation because rebuild_proxies is called
        # internally by requests (via resolve_redirects)
        f3 = findings["CVE-2023-32681"]
        assert f3["status"] == "under_investigation"
        assert f3["justification"] is None
        assert "internally" in f3["reason"].lower(), \
            f"Expected 'internally' in reason, got: {f3['reason']!r}"

    def test_two_hop_chain_for_yaml(self, tmp_path):
        """CVE-2020-14343 evidence must be a 2-hop cross-file chain."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])

        dossier = json.loads((out_dir / "dossier.json").read_text())
        findings = {f["cve"]: f for f in dossier["findings"]}
        evidence = findings["CVE-2020-14343"]["evidence"]

        assert len(evidence) >= 2
        # First hop: in app.py, function upload_config
        first = evidence[0]
        assert "app.py" in first["file"]
        assert first["function"] == "upload_config"

        # Last hop: yaml.full_load call
        last = evidence[-1]
        assert "full_load" in last["call"]

    def test_clock_present_for_exploited(self, tmp_path):
        """Clock must be non-null when CVE-2020-14343 is affected and exploited."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])

        dossier = json.loads((out_dir / "dossier.json").read_text())
        clock = dossier["clock"]
        assert clock is not None
        assert clock["cve"] == "CVE-2020-14343"
        assert clock["aware_at"] == "2026-09-27T02:00:00Z"
        assert clock["early_warning_due"] == "2026-09-28T02:00:00Z"
        assert clock["notification_due"] == "2026-09-30T02:00:00Z"
        assert clock["final_report_due"] == "2026-10-11T02:00:00Z"

    def test_no_clock_without_exploited_flag(self, tmp_path):
        """Clock must be null when --exploited is not given."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
        ])

        dossier = json.loads((out_dir / "dossier.json").read_text())
        assert dossier["clock"] is None

    def test_drafts_generated_for_exploited(self, tmp_path):
        """Draft reports are generated for the exploited+affected CVE."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])

        dossier = json.loads((out_dir / "dossier.json").read_text())
        findings = {f["cve"]: f for f in dossier["findings"]}

        # Affected+exploited CVE has drafts
        assert len(findings["CVE-2020-14343"]["drafts"]) == 2
        for draft_path in findings["CVE-2020-14343"]["drafts"]:
            assert pathlib.Path(draft_path).exists() or (tmp_path / draft_path).exists() or \
                   (out_dir / "drafts" / pathlib.Path(draft_path).name).exists()

        # Non-affected CVEs have no drafts
        assert findings["CVE-2023-50447"]["drafts"] == []

    def test_dossier_matches_data_contract(self, tmp_path):
        """dossier.json shape matches docs/DATA_CONTRACT.md exactly."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])

        dossier = json.loads((out_dir / "dossier.json").read_text())

        # Top-level required keys
        for key in ("product", "scanned_at", "duration_s", "summary",
                    "clock", "findings", "coverage", "vex_path"):
            assert key in dossier, f"Missing top-level key: {key}"

        # Summary keys
        for key in ("advisories", "affected", "not_affected",
                    "under_investigation", "emergency_releases_avoided"):
            assert key in dossier["summary"], f"Missing summary key: {key}"

        # Clock keys (non-null here)
        clock = dossier["clock"]
        assert clock is not None
        for key in ("cve", "aware_at", "early_warning_due",
                    "notification_due", "final_report_due"):
            assert key in clock, f"Missing clock key: {key}"

        # Finding keys
        for f in dossier["findings"]:
            for key in ("cve", "package", "installed", "affected_range",
                        "fixed_version", "symbols", "status", "justification",
                        "evidence", "reason", "advisory_source", "drafts"):
                assert key in f, f"Missing finding key: {key}"
            # Invariants from DATA_CONTRACT
            if f["status"] != "not_affected":
                assert f["justification"] is None, \
                    f"{f['cve']}: justification must be null for {f['status']}"
            if f["status"] != "affected":
                assert f["evidence"] == [], \
                    f"{f['cve']}: evidence must be [] for {f['status']}"

        # Coverage keys
        for key in ("files_found", "files_parsed"):
            assert key in dossier["coverage"]

    def test_vex_json_written(self, tmp_path):
        """out/vex.json is written with valid OpenVEX 0.2.0 structure."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
        ])

        vex = json.loads((out_dir / "vex.json").read_text())
        assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert vex["author"] == "T-24"
        assert len(vex["statements"]) == 4

    def test_summary_counts(self, tmp_path):
        """Summary counts are: 1 affected, 2 not_affected, 1 under_investigation."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])

        dossier = json.loads((out_dir / "dossier.json").read_text())
        s = dossier["summary"]
        assert s["advisories"] == 4
        assert s["affected"] == 1
        assert s["not_affected"] == 2
        assert s["under_investigation"] == 1
        assert s["emergency_releases_avoided"] == 2


class TestClockSurvivedFix:
    """Change 1 — CRA clock and drafts must survive a 'fixed' verdict.

    When a finding was 'affected' in the baseline and the re-scan produces
    'fixed', the clock block must still be present and both draft files must
    be generated.  The notification's corrective-measures section must mention
    the fix and cite the baseline evidence path.
    """

    @pytest.fixture(autouse=True)
    def _patch_libcallers(self):
        with mock.patch("t24.verdict.find_internal_callers",
                        side_effect=_fake_find_internal_callers):
            yield

    def _run_before_scan(self, tmp_path) -> pathlib.Path:
        """Run the 'before' scan: CVE-2020-14343 is affected."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out_before"
        ret = main([
            "scan",
            str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
        ])
        assert ret == 0
        return out_dir / "dossier.json"

    def test_clock_present_for_fixed_exploited(self, tmp_path):
        """After fix, clock must remain non-null when exploited flag is set."""
        from t24.cli import main

        before_dossier = self._run_before_scan(tmp_path)

        # Second scan: same product, same code (still "affected" without a real
        # fix, but we simulate a non-affected result by providing a baseline
        # where status was "affected" and the new scan returns not_affected.
        # We fake this by making a modified baseline that says "affected" and
        # running the scan without --exploited on a code path that returns
        # not_affected — then the baseline promotion logic sets it to "fixed".
        # For simplicity, use the real before-dossier as the baseline; since
        # demo_product is still unmodified the verdict will be "affected" again,
        # but we can still test the "fixed" path by constructing a synthetic
        # baseline that says "affected" and a scan that *would* produce not_affected.

        # Build a synthetic baseline: CVE-2020-14343 was "affected" with evidence
        synthetic_baseline = {
            "findings": [
                {
                    "cve": "CVE-2020-14343",
                    "status": "affected",
                    "evidence": [
                        {"file": "demo_product/config.py", "line": 5,
                         "function": "load_settings", "call": "yaml.full_load"}
                    ],
                }
            ]
        }
        baseline_path = tmp_path / "synthetic_baseline.json"
        baseline_path.write_text(json.dumps(synthetic_baseline))

        # Build a cache that tells the engine CVE-2020-14343 has no symbols
        # so the reach scan returns no hits and verdict becomes not_affected/under_inv.
        # We'll patch decide() to return not_affected so baseline promotion fires.
        from t24.verdict import VerdictResult

        fixed_verdict = VerdictResult(
            cve="CVE-2020-14343",
            package="PyYAML",
            installed="5.4",
            affected_range="<5.4",
            fixed_version="5.4",
            symbols=["full_load"],
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            evidence=[],
            reason="full_load: no path from any entry point",
            advisory_source="https://github.com/advisories/GHSA-8q59-q68h-6hv4",
        )

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out_after"

        import t24.verdict as _verdict_mod
        _real_decide = _verdict_mod.decide

        def _patched_decide(cve, **kwargs):
            if cve == "CVE-2020-14343":
                return fixed_verdict
            return _real_decide(cve=cve, **kwargs)

        with mock.patch("t24.verdict.decide", side_effect=_patched_decide):
            ret = main([
                "scan",
                str(DEMO_PRODUCT),
                "--advisories", str(ADVISORIES_DIR),
                "--out", str(out_dir),
                "--cache", str(cache_dir),
                "--offline",
                "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
                "--baseline", str(baseline_path),
            ])
        assert ret == 0

        dossier = json.loads((out_dir / "dossier.json").read_text())
        findings = {f["cve"]: f for f in dossier["findings"]}
        f = findings["CVE-2020-14343"]

        # Status must be "fixed"
        assert f["status"] == "fixed", f"Expected fixed, got {f['status']!r}"

        # Clock must still be non-null
        assert dossier["clock"] is not None, "Clock must survive a fix"
        assert dossier["clock"]["cve"] == "CVE-2020-14343"

        # Both draft files must be present
        assert len(f["drafts"]) == 2, f"Expected 2 drafts, got {f['drafts']}"

    def test_notification_cites_fix_and_baseline_evidence(self, tmp_path):
        """Notification draft for a fixed finding must state the fix and cite baseline evidence."""
        from t24.report import render_notification
        from t24.verdict import VerdictResult
        from t24.reach_bfs import EvidenceHop
        from t24.clock import make_clock
        from datetime import datetime, timezone

        verdict = VerdictResult(
            cve="CVE-2020-14343",
            package="PyYAML",
            installed="5.4",
            affected_range="<5.4",
            fixed_version="5.4",
            symbols=["full_load"],
            status="fixed",
            justification=None,
            evidence=[],
            reason="Previously affected; no longer reachable",
            advisory_source="https://github.com/advisories/GHSA-8q59-q68h-6hv4",
        )
        clock = make_clock("CVE-2020-14343",
                           datetime(2026, 9, 27, 2, 0, 0, tzinfo=timezone.utc))
        bl_evidence = [
            {"file": "demo_product/config.py", "line": 5,
             "function": "load_settings", "call": "yaml.full_load"}
        ]

        path = render_notification(
            verdict=verdict,
            clock=clock,
            product_name="demo_product",
            drafts_dir=tmp_path / "drafts",
            baseline_evidence=bl_evidence,
        )
        text = path.read_text()

        # Must mention the fix was applied
        assert "FIX APPLIED" in text, "Notification must state fix was applied"
        # Must cite the baseline evidence file:line
        assert "demo_product/config.py:5" in text, \
            "Notification must cite baseline evidence path"
        # Standard fields still present
        assert "CVE-2020-14343" in text
        assert "DRAFT" in text


class TestPublishSnapshot:
    """Change 2 — --publish copies outputs and rewrites paths."""

    @pytest.fixture(autouse=True)
    def _patch_libcallers(self):
        with mock.patch("t24.verdict.find_internal_callers",
                        side_effect=_fake_find_internal_callers):
            yield

    def test_publish_creates_dossier_vex_and_drafts(self, tmp_path):
        """--publish <dir> copies dossier.json, vex.json and drafts/ into dir."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        publish_dir = tmp_path / "pub"

        ret = main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
            "--publish", str(publish_dir),
        ])
        assert ret == 0

        # Published copies exist
        assert (publish_dir / "dossier.json").exists()
        assert (publish_dir / "vex.json").exists()
        assert (publish_dir / "drafts").is_dir()
        # Draft files copied
        drafts = list((publish_dir / "drafts").iterdir())
        assert len(drafts) >= 2

    def test_publish_rewrites_vex_path_and_drafts(self, tmp_path):
        """Paths in the published dossier are relative to the publish dir."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        publish_dir = tmp_path / "pub"

        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
            "--publish", str(publish_dir),
        ])

        published = json.loads((publish_dir / "dossier.json").read_text())

        # vex_path must be "vex.json" (relative to pub dir)
        assert published["vex_path"] == "vex.json", \
            f"Expected 'vex.json', got {published['vex_path']!r}"

        # Draft paths must be "drafts/<filename>"
        findings = {f["cve"]: f for f in published["findings"]}
        for draft_p in findings["CVE-2020-14343"]["drafts"]:
            assert draft_p.startswith("drafts/"), \
                f"Expected draft path to start with 'drafts/', got {draft_p!r}"
            assert "/" not in draft_p[len("drafts/"):], \
                f"Unexpected subdirectory in draft path: {draft_p!r}"

    def test_original_dossier_unchanged(self, tmp_path):
        """--publish must not alter the original out/dossier.json paths."""
        from t24.cli import main

        cache_dir = tmp_path / "cache"
        _build_cache(cache_dir)
        out_dir = tmp_path / "out"
        publish_dir = tmp_path / "pub"

        main([
            "scan", str(DEMO_PRODUCT),
            "--advisories", str(ADVISORIES_DIR),
            "--out", str(out_dir),
            "--cache", str(cache_dir),
            "--offline",
            "--exploited", "CVE-2020-14343=2026-09-27T02:00:00Z",
            "--publish", str(publish_dir),
        ])

        original = json.loads((out_dir / "dossier.json").read_text())
        # Original vex_path must still point into out/
        assert original["vex_path"] != "vex.json", \
            "Original dossier vex_path should not be rewritten"
