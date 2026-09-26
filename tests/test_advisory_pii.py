"""tests/test_advisory_pii.py — Test that no file under advisories/ contains an email address."""
from __future__ import annotations

import pathlib
import re

ADVISORIES_DIR = pathlib.Path(__file__).parent.parent / "advisories"
# Matches email-like patterns that are NOT inside a URL (i.e. not preceded by /).
# Personal emails appear as standalone text; mailing-list archive emails
# appear only embedded in HTTPS URL paths like /list/package-announce@lists...
_EMAIL_RE = re.compile(
    r"(?<![/a-zA-Z0-9_\-])"       # not preceded by URL path characters
    r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
    r"(?![/a-zA-Z0-9_\-])"        # not followed by URL path characters
)


def _is_in_url_context(text: str, match_start: int) -> bool:
    """Return True if the email appears inside a URL string."""
    # Look for https:// or http:// in the preceding 200 chars on the same line
    line_start = text.rfind("\n", 0, match_start) + 1
    prefix = text[line_start:match_start]
    return "https://" in prefix or "http://" in prefix


def test_no_personal_emails_in_advisories() -> None:
    """No file under advisories/ may contain a personal email address."""
    violations: list[str] = []
    for path in sorted(ADVISORIES_DIR.iterdir()):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _EMAIL_RE.finditer(text):
            addr = m.group(1)
            if not _is_in_url_context(text, m.start()):
                violations.append(f"{path.name}: {addr!r}")
    assert not violations, (
        "Personal email addresses found in advisories/:\n  "
        + "\n  ".join(violations)
    )
