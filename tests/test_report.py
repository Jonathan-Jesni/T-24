"""tests/test_report.py — Unit tests for t24/report.py."""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone
from t24.reach_bfs import EvidenceHop
from t24.verdict import VerdictResult
from t24.clock import CRAClock, make_clock


def _make_verdict_affected():
    hop = EvidenceHop(file="demo_product/app.py", line=14,
                      function="upload_config", call="config.load_settings")
    hop2 = EvidenceHop(file="demo_product/config.py", line=5,
                       function="load_settings", call="yaml.full_load")
    return VerdictResult(
        cve="CVE-2020-14343",
        package="PyYAML",
        installed="5.3.1",
        affected_range="< 5.4",
        fixed_version="5.4",
        symbols=["full_load"],
        status="affected",
        justification=None,
        evidence=[hop, hop2],
        reason="full_load is reachable from upload_config",
        advisory_source="https://github.com/advisories/GHSA-8q59-q68h-6hv4",
    )


def _make_clock():
    aware_at = datetime(2026, 9, 27, 2, 0, 0, tzinfo=timezone.utc)
    return make_clock("CVE-2020-14343", aware_at)


class TestEarlyWarningDraft:
    def test_early_warning_contains_required_fields(self, tmp_path):
        """Early warning draft must contain: product, CVE, banner, deadlines."""
        from t24.report import render_early_warning

        verdict = _make_verdict_affected()
        clock = _make_clock()
        drafts_dir = tmp_path / "drafts"
        path = render_early_warning(
            verdict=verdict,
            clock=clock,
            product_name="demo_product",
            drafts_dir=drafts_dir,
        )

        text = path.read_text()
        assert "CVE-2020-14343" in text
        assert "demo_product" in text
        assert "DRAFT" in text
        assert "T-24 does not submit to ENISA" in text
        assert "actively exploited" in text.lower() or "exploit" in text.lower()
        # Deadline dates present
        assert "2026-09-28" in text  # early_warning_due

    def test_early_warning_cites_evidence_file_line(self, tmp_path):
        """Evidence file:line must appear in the draft."""
        from t24.report import render_early_warning

        verdict = _make_verdict_affected()
        clock = _make_clock()
        drafts_dir = tmp_path / "drafts"
        path = render_early_warning(verdict=verdict, clock=clock,
                                    product_name="demo_product", drafts_dir=drafts_dir)
        text = path.read_text()
        # Evidence hop file:line
        assert "demo_product/app.py:14" in text or ("demo_product/app.py" in text and "14" in text)

    def test_early_warning_path(self, tmp_path):
        """Output file must be named early_warning_<CVE>.md."""
        from t24.report import render_early_warning

        verdict = _make_verdict_affected()
        clock = _make_clock()
        path = render_early_warning(verdict=verdict, clock=clock,
                                    product_name="demo_product",
                                    drafts_dir=tmp_path / "drafts")
        assert path.name == "early_warning_CVE-2020-14343.md"


class TestNotificationDraft:
    def test_notification_contains_required_fields(self, tmp_path):
        """Notification must include impact, corrective measures, and sensitivity."""
        from t24.report import render_notification

        verdict = _make_verdict_affected()
        clock = _make_clock()
        drafts_dir = tmp_path / "drafts"
        path = render_notification(verdict=verdict, clock=clock,
                                   product_name="demo_product", drafts_dir=drafts_dir)

        text = path.read_text()
        assert "CVE-2020-14343" in text
        assert "DRAFT" in text
        assert "T-24 does not submit to ENISA" in text
        # Notification due date
        assert "2026-09-30" in text

    def test_notification_path(self, tmp_path):
        """Output file must be named notification_<CVE>.md."""
        from t24.report import render_notification

        verdict = _make_verdict_affected()
        clock = _make_clock()
        path = render_notification(verdict=verdict, clock=clock,
                                   product_name="demo_product",
                                   drafts_dir=tmp_path / "drafts")
        assert path.name == "notification_CVE-2020-14343.md"
