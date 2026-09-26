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
