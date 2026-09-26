"""report.py — ENISA CRA Article 14 draft report renderer.

Writes Markdown drafts to out/drafts/.
Only for findings that are *affected* AND actively exploited.

Every factual sentence cites file:line or advisory SOURCE URL.
A banner at the top reminds reviewers these are drafts.
"""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone
from string import Template

from t24.clock import CRAClock
from t24.verdict import VerdictResult

_BANNER = (
    "> **DRAFT for human review. "
    "T-24 does not submit to ENISA.**"
)


def _undent(text: str, width: int = 8) -> str:
    """Strip the templates' fixed 8-space indent line by line.

    textwrap.dedent stops working once an interpolated multi-line value (the
    evidence list) adds unindented lines, which left the whole draft indented
    and rendered as a Markdown code block.
    """
    pad = " " * width
    lines = text.splitlines()
    out = [ln[width:] if ln.startswith(pad) else ln for ln in lines]
    return "\n".join(ln if ln.strip() else "" for ln in out).rstrip() + "\n"


def render_early_warning(
    verdict: VerdictResult,
    clock: CRAClock,
    product_name: str,
    drafts_dir: pathlib.Path,
) -> pathlib.Path:
    """Render CRA Art. 14 §1 early warning draft.

    Required by CRA Art. 14 §1: whether the vulnerability is actively
    exploited, the product affected, and where relevant the Member States
    concerned.
    """
    drafts_dir.mkdir(parents=True, exist_ok=True)
    evidence_text = _format_evidence(verdict)
    now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    content = _undent(f"""\
        {_BANNER}

        # CRA Art. 14 §1 — Early Warning: {verdict.cve}

        **Prepared:** {now_utc}
        **Deadline:** {clock.early_warning_due.strftime("%Y-%m-%dT%H:%M:%SZ")} (24 h from aware_at)

        ## Product

        - **Product:** {product_name}
        - **Component:** {verdict.package} {verdict.installed or "(unknown version)"}
        - **Affected range:** {verdict.affected_range} (fixed in {verdict.fixed_version})
          Source: {verdict.advisory_source}

        ## Vulnerability

        - **CVE:** {verdict.cve}
        - **Status:** {verdict.status}
        - **Actively exploited:** yes (passed via --exploited flag)
        - **Reason:** {verdict.reason}

        ## Evidence Chain

        {evidence_text}

        ## CRA Deadlines

        | Deadline | Date |
        |----------|------|
        | Early warning (24 h) | {clock.early_warning_due.strftime("%Y-%m-%dT%H:%M:%SZ")} |
        | Notification (72 h) | {clock.notification_due.strftime("%Y-%m-%dT%H:%M:%SZ")} |
        | Final report (14 d) | {clock.final_report_due.strftime("%Y-%m-%dT%H:%M:%SZ")} |

        ## Notes

        This early warning is a machine-generated draft. It must be reviewed,
        completed (Member States, if applicable), and submitted by a qualified
        human before the deadline above.
    """)

    out_path = drafts_dir / f"early_warning_{verdict.cve}.md"
    out_path.write_text(content, encoding="utf-8")
    return out_path


def render_notification(
    verdict: VerdictResult,
    clock: CRAClock,
    product_name: str,
    drafts_dir: pathlib.Path,
) -> pathlib.Path:
    """Render CRA Art. 14 §2 notification draft.

    Required by CRA Art. 14 §2: general info on product, the vulnerability and
    exploit, corrective measures taken or available, and sensitivity.
    """
    drafts_dir.mkdir(parents=True, exist_ok=True)
    evidence_text = _format_evidence(verdict)
    now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    content = _undent(f"""\
        {_BANNER}

        # CRA Art. 14 §2 — Notification: {verdict.cve}

        **Prepared:** {now_utc}
        **Deadline:** {clock.notification_due.strftime("%Y-%m-%dT%H:%M:%SZ")} (72 h from aware_at)

        ## 1. Product Information

        - **Product:** {product_name}
        - **Component:** {verdict.package} {verdict.installed or "(unknown version)"}
        - **Affected range:** {verdict.affected_range}
        - **Fixed version:** {verdict.fixed_version}

        Advisory source: {verdict.advisory_source}

        ## 2. Vulnerability Description

        - **CVE:** {verdict.cve}
        - **Status:** {verdict.status}
        - **Vulnerable symbols:** {", ".join(verdict.symbols) or "(none named)"}
        - **Actively exploited:** yes

        ## 3. Impact and Evidence

        {evidence_text}

        **Reason:** {verdict.reason}

        ## 4. Corrective Measures

        - Upgrade {verdict.package} to version {verdict.fixed_version} or later.
        - Review all call sites that reach the vulnerable symbol.
        - See advisory for workarounds: {verdict.advisory_source}

        ## 5. Information Sensitivity

        This notification contains technical details about an exploited
        vulnerability in a production component. Distribution should be
        limited to ENISA, relevant national authorities, and the internal
        security team until a patch is deployed.

        ## CRA Deadlines

        | Deadline | Date |
        |----------|------|
        | Early warning (24 h) | {clock.early_warning_due.strftime("%Y-%m-%dT%H:%M:%SZ")} |
        | Notification (72 h) | {clock.notification_due.strftime("%Y-%m-%dT%H:%M:%SZ")} |
        | Final report (14 d) | {clock.final_report_due.strftime("%Y-%m-%dT%H:%M:%SZ")} |
    """)

    out_path = drafts_dir / f"notification_{verdict.cve}.md"
    out_path.write_text(content, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_evidence(verdict: VerdictResult) -> str:
    if not verdict.evidence:
        return "_No evidence chain recorded._"
    lines = []
    for i, hop in enumerate(verdict.evidence, 1):
        lines.append(
            f"{i}. `{hop.file}:{hop.line}` — `{hop.function}` calls `{hop.call}`"
        )
    return "\n".join(lines)
