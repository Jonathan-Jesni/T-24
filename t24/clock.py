"""clock.py — CRA Article 14 report deadline calculator.

Only invoked when a finding is affected AND --actively-exploited is set.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta


@dataclass
class CRAClock:
    cve: str
    aware_at: datetime
    early_warning_due: datetime
    notification_due: datetime
    final_report_due: datetime

    def to_dict(self) -> dict[str, str]:
        """Serialize to DATA_CONTRACT-compatible dict."""
        return {
            "cve": self.cve,
            "aware_at": _iso(self.aware_at),
            "early_warning_due": _iso(self.early_warning_due),
            "notification_due": _iso(self.notification_due),
            "final_report_due": _iso(self.final_report_due),
        }


def make_clock(cve: str, aware_at: datetime) -> CRAClock:
    """Compute the three CRA Article 14 deadlines from aware_at.

    Parameters
    ----------
    cve:       CVE identifier
    aware_at:  Timezone-aware datetime when the manufacturer became aware.

    Raises
    ------
    ValueError if aware_at is timezone-naive.
    """
    if aware_at.tzinfo is None:
        raise ValueError(
            f"aware_at must be timezone-aware; got naive datetime {aware_at!r}"
        )
    return CRAClock(
        cve=cve,
        aware_at=aware_at,
        early_warning_due=aware_at + timedelta(hours=24),
        notification_due=aware_at + timedelta(hours=72),
        final_report_due=aware_at + timedelta(days=14),
    )


def parse_aware_at(iso_str: str) -> datetime:
    """Parse an ISO 8601 string (with Z or +00:00) into a timezone-aware datetime."""
    # Replace trailing Z with +00:00 for fromisoformat compatibility
    iso_str = iso_str.strip()
    if iso_str.endswith("Z"):
        iso_str = iso_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: datetime) -> str:
    """Serialize datetime to ISO 8601 UTC string with Z suffix."""
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
