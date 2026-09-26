"""tests/test_vex.py — Unit tests for t24/vex.py."""
from __future__ import annotations

import json
from t24.reach_bfs import EvidenceHop
from t24.verdict import VerdictResult


def _make_verdict(
    cve="CVE-2020-14343",
    status="affected",
    justification=None,
    evidence=None,
    reason="test reason",
    package="PyYAML",
    installed="5.3.1",
    affected_range="< 5.4",
    fixed_version="5.4",
    symbols=None,
    advisory_source="https://github.com/advisories/GHSA-8q59-q68h-6hv4",
):
    return VerdictResult(
        cve=cve,
        package=package,
        installed=installed,
        affected_range=affected_range,
        fixed_version=fixed_version,
        symbols=symbols or [],
        status=status,
        justification=justification,
        evidence=evidence or [],
        reason=reason,
        advisory_source=advisory_source,
    )


class TestVexDocument:
    def test_valid_openvex_keys(self, tmp_path):
        """Output must contain all required OpenVEX 0.2.0 top-level keys."""
        from t24.vex import build_vex

        verdicts = [_make_verdict()]
        doc = build_vex(verdicts, product_id="demo_product")

        assert "@context" in doc
        assert "@id" in doc
        assert "timestamp" in doc
        assert "author" in doc
        assert "tooling" in doc
        assert "statements" in doc
        assert doc["author"] == "T-24"

    def test_statements_per_verdict(self, tmp_path):
        """One statement per verdict."""
        from t24.vex import build_vex

        verdicts = [_make_verdict(), _make_verdict(cve="CVE-2023-50447", status="not_affected",
                                                    justification="vulnerable_code_not_in_execute_path")]
        doc = build_vex(verdicts, product_id="demo_product")
        assert len(doc["statements"]) == 2

    def test_justification_only_on_not_affected(self, tmp_path):
        """justification appears only when status == not_affected."""
        from t24.vex import build_vex

        v1 = _make_verdict(status="affected")
        v2 = _make_verdict(cve="CVE-2023-50447", status="not_affected",
                           justification="vulnerable_code_not_in_execute_path")
        v3 = _make_verdict(cve="CVE-2023-32681", status="under_investigation")
        doc = build_vex(build_vex([v1, v2, v3], product_id="demo_product")
                        if False else [v1, v2, v3], product_id="demo_product")

        stmts = {s["vulnerability"]["name"]: s for s in doc["statements"]}
        assert "justification" not in stmts["CVE-2020-14343"]
        assert stmts["CVE-2023-50447"]["justification"] == "vulnerable_code_not_in_execute_path"
        assert "justification" not in stmts["CVE-2023-32681"]

    def test_evidence_in_impact_statement(self, tmp_path):
        """Impact statement includes evidence chain text for affected verdicts."""
        from t24.vex import build_vex

        hop = EvidenceHop(file="app.py", line=14, function="upload_config",
                          call="yaml.full_load")
        v = _make_verdict(status="affected", evidence=[hop])
        doc = build_vex([v], product_id="demo_product")

        stmt = doc["statements"][0]
        assert "impact_statement" in stmt
        assert "app.py" in stmt["impact_statement"]
        assert "yaml.full_load" in stmt["impact_statement"]

    def test_write_and_reload(self, tmp_path):
        """write_vex writes valid JSON that can be reloaded."""
        from t24.vex import write_vex, build_vex

        verdicts = [_make_verdict()]
        doc = build_vex(verdicts, product_id="demo_product")
        out_path = tmp_path / "vex.json"
        write_vex(doc, out_path)

        reloaded = json.loads(out_path.read_text())
        assert reloaded["author"] == "T-24"
        assert len(reloaded["statements"]) == 1
