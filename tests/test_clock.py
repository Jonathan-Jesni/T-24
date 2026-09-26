"""tests/test_clock.py — Unit tests for t24/clock.py."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta


class TestClockArithmetic:
    def test_correct_deadlines(self):
        """24h / 72h / 14d deadlines computed correctly."""
        from t24.clock import make_clock

        aware_at = datetime(2026, 9, 27, 2, 0, 0, tzinfo=timezone.utc)
        clock = make_clock("CVE-2020-14343", aware_at)

        assert clock.cve == "CVE-2020-14343"
        assert clock.aware_at == aware_at
        assert clock.early_warning_due == aware_at + timedelta(hours=24)
        assert clock.notification_due == aware_at + timedelta(hours=72)
        assert clock.final_report_due == aware_at + timedelta(days=14)

    def test_expected_dates(self):
        """Concrete date check from DATA_CONTRACT example."""
        from t24.clock import make_clock

        aware_at = datetime(2026, 9, 27, 2, 0, 0, tzinfo=timezone.utc)
        clock = make_clock("CVE-2020-14343", aware_at)

        assert clock.early_warning_due == datetime(2026, 9, 28, 2, 0, 0, tzinfo=timezone.utc)
        assert clock.notification_due == datetime(2026, 9, 30, 2, 0, 0, tzinfo=timezone.utc)
        assert clock.final_report_due == datetime(2026, 10, 11, 2, 0, 0, tzinfo=timezone.utc)

    def test_timezone_aware_required(self):
        """Naive datetimes raise ValueError."""
        import pytest
        from t24.clock import make_clock

        naive = datetime(2026, 9, 27, 2, 0, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            make_clock("CVE-2020-14343", naive)

    def test_iso_parsing(self):
        """parse_aware_at handles ISO 8601 Z suffix."""
        from t24.clock import parse_aware_at

        dt = parse_aware_at("2026-09-27T02:00:00Z")
        assert dt.tzinfo is not None
        assert dt == datetime(2026, 9, 27, 2, 0, 0, tzinfo=timezone.utc)

    def test_clock_serialization(self):
        """to_dict matches DATA_CONTRACT field names."""
        from t24.clock import make_clock

        aware_at = datetime(2026, 9, 27, 2, 0, 0, tzinfo=timezone.utc)
        clock = make_clock("CVE-2020-14343", aware_at)
        d = clock.to_dict()

        assert d["cve"] == "CVE-2020-14343"
        assert d["aware_at"] == "2026-09-27T02:00:00Z"
        assert d["early_warning_due"] == "2026-09-28T02:00:00Z"
        assert d["notification_due"] == "2026-09-30T02:00:00Z"
        assert d["final_report_due"] == "2026-10-11T02:00:00Z"
