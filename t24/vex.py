"""vex.py — OpenVEX 0.2.0 serializer.

Writes out/vex.json conforming to https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
"""
from __future__ import annotations

import json
import pathlib
import uuid
from datetime import datetime, timezone
from typing import Any

from t24.verdict import VerdictResult

_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_TOOLING = "T-24 / IBM Bob Hackathon"


def build_vex(
    verdicts: list[VerdictResult],
    product_id: str,
) -> dict[str, Any]:
    """Build an OpenVEX 0.2.0 document dict."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    statements = [_build_statement(v, product_id) for v in verdicts]

    return {
        "@context": _OPENVEX_CONTEXT,
        "@id": f"https://t24.local/vex/{uuid.uuid4()}",
        "author": "T-24",
        "timestamp": now,
        "tooling": _TOOLING,
        "statements": statements,
    }


def write_vex(doc: dict[str, Any], path: pathlib.Path) -> None:
    """Write the VEX document to *path* as pretty-printed JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Statement builder
# ---------------------------------------------------------------------------

def _build_statement(v: VerdictResult, product_id: str) -> dict[str, Any]:
    stmt: dict[str, Any] = {
        "vulnerability": {"name": v.cve},
        "products": [{"@id": product_id}],
        "status": v.status,
    }

    # justification only on not_affected
    if v.status == "not_affected" and v.justification:
        stmt["justification"] = v.justification

    # impact_statement carries evidence chain + reason
    stmt["impact_statement"] = _build_impact(v)

    return stmt


def _build_impact(v: VerdictResult) -> str:
    """Build a human-readable impact statement for the VEX statement."""
    parts: list[str] = [v.reason]
    if v.evidence:
        chain = " → ".join(
            f"{h.file}:{h.line} [{h.function}] {h.call}"
            for h in v.evidence
        )
        parts.append(f"Evidence chain: {chain}")
    if v.advisory_source:
        parts.append(f"Advisory: {v.advisory_source}")
    return " | ".join(parts)
