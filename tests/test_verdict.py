"""tests/test_verdict.py — Unit tests for t24/verdict.py."""
from __future__ import annotations

import unittest.mock as mock

from t24.reach import EvidenceHop


def _make_hop(file="app.py", line=10, function="upload", call="yaml.full_load"):
    return EvidenceHop(file=file, line=line, function=function, call=call)


def _make_reach_result(
    target="yaml.full_load",
    reachable=False,
    evidence=None,
    uncertain=False,
    uncertain_sites=None,
    files_found=3,
    files_parsed=3,
):
    from t24.reach_bfs import ReachResult
    return ReachResult(
        target=target,
        reachable=reachable,
        evidence=evidence or [],
        uncertain=uncertain,
        uncertain_sites=uncertain_sites or [],
        files_found=files_found,
        files_parsed=files_parsed,
    )


def _vc(package="pyyaml", present=True, installed="5.3.1", affected_range="< 5.4",
         in_range=True):
    from t24.inventory import VersionCheck
    return VersionCheck(
        package=package,
        present=present,
        installed=installed,
        affected_range=affected_range,
        in_range=in_range,
    )


class TestVerdictNotAffectedComponentNotPresent:
    def test_package_not_listed(self):
        from t24.verdict import decide

        vc = _vc(present=False, installed=None, in_range=False)
        result = decide(
            cve="CVE-2020-14343",
            version_check=vc,
            reach_results=[],
            symbols=["full_load"],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "not_affected"
        assert result.justification == "component_not_present"
        assert result.evidence == []


class TestVerdictUnpinned:
    def test_package_unpinned(self):
        from t24.verdict import decide

        vc = _vc(present=True, installed=None, in_range=None)
        result = decide(
            cve="CVE-2020-14343",
            version_check=vc,
            reach_results=[],
            symbols=["full_load"],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "under_investigation"
        assert "not pinned" in result.reason


class TestVerdictNotAffectedVersionRange:
    def test_version_out_of_range(self):
        from t24.verdict import decide

        vc = _vc(installed="5.4.1", in_range=False)
        result = decide(
            cve="CVE-2020-14343",
            version_check=vc,
            reach_results=[],
            symbols=["full_load"],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "not_affected"
        assert result.justification == "vulnerable_code_not_present"


class TestVerdictAffected:
    def test_in_range_and_reachable(self):
        from t24.verdict import decide

        hop = _make_hop()
        rr = _make_reach_result(reachable=True, evidence=[hop])
        vc = _vc(in_range=True)

        result = decide(
            cve="CVE-2020-14343",
            version_check=vc,
            reach_results=[rr],
            symbols=["full_load"],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "affected"
        assert result.justification is None
        assert result.evidence == [hop]


class TestVerdictNotAffectedExecutePath:
    def test_in_range_not_reachable_full_coverage_no_internal_callers(self):
        """not_affected when: in range, not reached, full coverage, no internal callers."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(in_range=True)

        with mock.patch("t24.verdict.find_internal_callers", return_value=[]):
            result = decide(
                cve="CVE-2023-50447",
                version_check=vc,
                reach_results=[rr],
                symbols=["eval"],
                preconditions=[],
                advisory_source="https://example.com",
                package_display="Pillow",
            )
        assert result.status == "not_affected"
        assert result.justification == "vulnerable_code_not_in_execute_path"

    def test_preconditions_do_not_block_not_affected_when_no_internal_callers(self):
        """Preconditions no longer block not_affected — they become informational."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(in_range=True)

        with mock.patch("t24.verdict.find_internal_callers", return_value=[]):
            result = decide(
                cve="CVE-2023-50447",
                version_check=vc,
                reach_results=[rr],
                symbols=["eval"],
                preconditions=["attacker must control the expression"],
                advisory_source="https://example.com",
                package_display="Pillow",
            )
        assert result.status == "not_affected"
        assert result.justification == "vulnerable_code_not_in_execute_path"

    def test_preconditions_appear_in_reason_as_informational(self):
        """When not_affected, preconditions appear somewhere in reason."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(in_range=True)

        with mock.patch("t24.verdict.find_internal_callers", return_value=[]):
            result = decide(
                cve="CVE-2023-50447",
                version_check=vc,
                reach_results=[rr],
                symbols=["eval"],
                preconditions=["attacker must control the expression"],
                advisory_source="https://example.com",
                package_display="Pillow",
            )
        assert result.status == "not_affected"
        # precondition text preserved informatively
        assert "attacker must control" in result.reason

    def test_partial_coverage_blocks_not_affected(self):
        """Parse failure must force under_investigation."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=2)
        vc = _vc(in_range=True)

        with mock.patch("t24.verdict.find_internal_callers", return_value=[]):
            result = decide(
                cve="CVE-2023-50447",
                version_check=vc,
                reach_results=[rr],
                symbols=["PIL.ImageMath.eval"],
                preconditions=[],
                advisory_source="https://example.com",
            )
        assert result.status == "under_investigation"

    def test_uncertain_blocks_not_affected(self):
        """uncertain=True must force under_investigation even with full coverage."""
        from t24.verdict import decide

        rr = _make_reach_result(
            reachable=False, uncertain=True, files_found=3, files_parsed=3
        )
        vc = _vc(in_range=True)

        result = decide(
            cve="CVE-2024-22195",
            version_check=vc,
            reach_results=[rr],
            symbols=["xmlattr"],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "under_investigation"


class TestVerdictInternalCallers:
    """New rule: when libcallers finds internal call sites → under_investigation."""

    def test_internal_callers_cause_under_investigation(self):
        """Symbol not reached by product, but library calls it internally → under_investigation."""
        from t24.verdict import decide

        rr = _make_reach_result(
            target="requests.rebuild_proxies",
            reachable=False,
            files_found=3,
            files_parsed=3,
        )
        vc = _vc(package="requests", in_range=True)

        internal_hop = {
            "file": "requests/sessions.py",
            "line": 245,
            "function": "resolve_redirects",
        }

        with mock.patch("t24.verdict.find_internal_callers", return_value=[internal_hop]):
            result = decide(
                cve="CVE-2023-32681",
                version_check=vc,
                reach_results=[rr],
                symbols=["rebuild_proxies"],
                preconditions=[],
                advisory_source="https://example.com",
                package_display="requests",
            )

        assert result.status == "under_investigation"
        assert "internally" in result.reason.lower()
        assert "rebuild_proxies" in result.reason

    def test_internal_callers_reason_cites_file_and_line(self):
        """Reason string must cite the internal call site."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(package="requests", in_range=True)

        internal_hop = {
            "file": "requests/sessions.py",
            "line": 245,
            "function": "resolve_redirects",
        }

        with mock.patch("t24.verdict.find_internal_callers", return_value=[internal_hop]):
            result = decide(
                cve="CVE-2023-32681",
                version_check=vc,
                reach_results=[rr],
                symbols=["rebuild_proxies"],
                preconditions=[],
                advisory_source="https://example.com",
                package_display="requests",
            )

        assert "requests/sessions.py" in result.reason
        assert "245" in result.reason

    def test_libcallers_unavailable_causes_under_investigation(self):
        """When library source is unavailable (None) → under_investigation."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(package="requests", in_range=True)

        with mock.patch("t24.verdict.find_internal_callers", return_value=None):
            result = decide(
                cve="CVE-2023-32681",
                version_check=vc,
                reach_results=[rr],
                symbols=["rebuild_proxies"],
                preconditions=[],
                advisory_source="https://example.com",
                package_display="requests",
            )

        assert result.status == "under_investigation"
        assert "unavailable" in result.reason.lower() or "source" in result.reason.lower()

    def test_template_filter_symbol_skips_libcallers(self):
        """Symbols with kind=template_filter skip the libcallers check."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(package="jinja2", in_range=True)

        # Mock find_internal_callers should NOT be called for template_filter symbols
        with mock.patch("t24.verdict.find_internal_callers") as mock_lc:
            mock_lc.return_value = []  # shouldn't matter
            result = decide(
                cve="CVE-2024-22195",
                version_check=vc,
                reach_results=[rr],
                symbols=["xmlattr"],
                preconditions=[],
                advisory_source="https://example.com",
                package_display="jinja2",
                template_filter_symbols=["xmlattr"],
            )
        # template_filter symbols skip libcallers → not_affected
        assert result.status == "not_affected"
        mock_lc.assert_not_called()


class TestVerdictPreconditions:
    def test_preconditions_no_longer_block_when_no_internal_callers(self):
        """Preconditions alone must NOT block not_affected when libcallers returns []."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(in_range=True)

        with mock.patch("t24.verdict.find_internal_callers", return_value=[]):
            result = decide(
                cve="CVE-2023-50447",
                version_check=vc,
                reach_results=[rr],
                symbols=["eval"],
                preconditions=["proxies must be configured with credentials"],
                advisory_source="https://example.com",
            )
        assert result.status == "not_affected"


class TestVerdictNoSymbols:
    def test_no_symbols_under_investigation(self):
        """No symbols named → under_investigation."""
        from t24.verdict import decide

        vc = _vc(in_range=True)

        result = decide(
            cve="CVE-2023-32681",
            version_check=vc,
            reach_results=[],
            symbols=[],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "under_investigation"


class TestVerdictEvidenceEmpty:
    def test_not_affected_evidence_is_empty(self):
        """evidence must be [] for not_affected verdicts."""
        from t24.verdict import decide

        vc = _vc(present=False, installed=None, in_range=False)
        result = decide(
            cve="CVE-2020-14343",
            version_check=vc,
            reach_results=[],
            symbols=[],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.evidence == []
        assert result.justification is not None

    def test_under_investigation_evidence_is_empty(self):
        """evidence must be [] for under_investigation."""
        from t24.verdict import decide

        vc = _vc(in_range=True)
        result = decide(
            cve="CVE-2023-32681",
            version_check=vc,
            reach_results=[],
            symbols=[],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.evidence == []
        assert result.justification is None
