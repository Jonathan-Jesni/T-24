"""tests/test_verdict.py — Unit tests for t24/verdict.py."""
from __future__ import annotations

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
    def test_in_range_not_reachable_full_coverage(self):
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(in_range=True)

        result = decide(
            cve="CVE-2023-50447",
            version_check=vc,
            reach_results=[rr],
            symbols=["PIL.ImageMath.eval"],
            preconditions=[],
            advisory_source="https://example.com",
        )
        assert result.status == "not_affected"
        assert result.justification == "vulnerable_code_not_in_execute_path"

    def test_partial_coverage_blocks_not_affected(self):
        """Parse failure must force under_investigation."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=2)
        vc = _vc(in_range=True)

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


class TestVerdictPreconditions:
    def test_preconditions_force_under_investigation(self):
        """Preconditions (unprovable statically) → under_investigation."""
        from t24.verdict import decide

        rr = _make_reach_result(reachable=False, files_found=3, files_parsed=3)
        vc = _vc(in_range=True)

        result = decide(
            cve="CVE-2023-32681",
            version_check=vc,
            reach_results=[rr],
            symbols=[],
            preconditions=["proxies must be configured with credentials"],
            advisory_source="https://example.com",
        )
        assert result.status == "under_investigation"
        assert "proxies must be configured" in result.reason


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
