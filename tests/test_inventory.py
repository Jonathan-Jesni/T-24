"""Tests for t24.inventory module."""
import pytest
from collections import namedtuple

from t24.inventory import (
    VersionCheck,
    parse_requirements,
    check_version,
    check_installed_packages,
)

Advisory = namedtuple("Advisory", ["package", "affected_range"])


# ---------------------------------------------------------------------------
# parse_requirements
# ---------------------------------------------------------------------------

class TestParseRequirements:
    def test_flask(self):
        assert parse_requirements("Flask==2.3.0") == {"flask": "2.3.0"}

    def test_pyyaml_normalisation(self):
        assert parse_requirements("PyYAML==5.3.1") == {"pyyaml": "5.3.1"}

    def test_jinja2_case_fold(self):
        assert parse_requirements("Jinja2==3.1.2") == {"jinja2": "3.1.2"}

    def test_requests(self):
        assert parse_requirements("requests==2.30.0") == {"requests": "2.30.0"}

    def test_blank_lines_ignored(self):
        text = "\nFlask==2.3.0\n\nrequests==2.30.0\n"
        result = parse_requirements(text)
        assert result == {"flask": "2.3.0", "requests": "2.30.0"}

    def test_comments_ignored(self):
        text = "# this is a comment\nFlask==2.3.0\n# another comment"
        result = parse_requirements(text)
        assert result == {"flask": "2.3.0"}

    def test_extras_stripped(self):
        result = parse_requirements("requests[security]==2.30.0")
        assert "requests" in result
        assert "requests[security]" not in result
        assert result["requests"] == "2.30.0"

    def test_multiple_packages(self):
        text = "Flask==2.3.0\nPyYAML==5.3.1\nJinja2==3.1.2\nrequests==2.30.0"
        result = parse_requirements(text)
        assert result == {
            "flask": "2.3.0",
            "pyyaml": "5.3.1",
            "jinja2": "3.1.2",
            "requests": "2.30.0",
        }


# ---------------------------------------------------------------------------
# check_version
# ---------------------------------------------------------------------------

class TestCheckVersion:
    def test_less_than_affected(self):
        assert check_version("5.3.1", "< 5.4") is True

    def test_less_than_boundary_safe(self):
        assert check_version("5.4", "< 5.4") is False

    def test_less_than_large_version_affected(self):
        assert check_version("9.5.0", "< 10.2.0") is True

    def test_less_than_large_version_boundary_safe(self):
        assert check_version("10.2.0", "< 10.2.0") is False

    def test_less_than_patch_affected(self):
        assert check_version("3.1.2", "< 3.1.3") is True

    def test_less_than_patch_boundary_safe(self):
        assert check_version("3.1.3", "< 3.1.3") is False

    def test_range_within_bounds(self):
        assert check_version("2.30.0", ">= 2.3.0, < 2.31.0") is True

    def test_range_at_upper_bound_safe(self):
        assert check_version("2.31.0", ">= 2.3.0, < 2.31.0") is False

    def test_range_below_lower_bound_safe(self):
        assert check_version("2.2.0", ">= 2.3.0, < 2.31.0") is False


# ---------------------------------------------------------------------------
# check_installed_packages
# ---------------------------------------------------------------------------

class TestCheckInstalledPackages:
    REQS = "Flask==2.3.0\nPyYAML==5.3.1\nJinja2==3.1.2\nrequests==2.30.0"

    def _result_for(self, results, package_canonical):
        return next(r for r in results if r.package == package_canonical)

    def test_flask_affected(self):
        advisories = [Advisory("Flask", "< 2.4.0")]
        results = check_installed_packages(self.REQS, advisories)
        r = self._result_for(results, "flask")
        assert r.installed == "2.3.0"
        assert r.in_range is True

    def test_pyyaml_case_insensitive_match(self):
        advisories = [Advisory("PyYAML", "< 5.4")]
        results = check_installed_packages(self.REQS, advisories)
        r = self._result_for(results, "pyyaml")
        assert r.installed == "5.3.1"
        assert r.in_range is True

    def test_requests_range_in_range(self):
        advisories = [Advisory("requests", ">= 2.3.0, < 2.31.0")]
        results = check_installed_packages(self.REQS, advisories)
        r = self._result_for(results, "requests")
        assert r.installed == "2.30.0"
        assert r.in_range is True

    def test_jinja2_not_affected(self):
        advisories = [Advisory("Jinja2", "< 3.1.2")]
        results = check_installed_packages(self.REQS, advisories)
        r = self._result_for(results, "jinja2")
        assert r.installed == "3.1.2"
        assert r.in_range is False

    def test_package_not_in_requirements(self):
        advisories = [Advisory("numpy", "< 1.24.0")]
        results = check_installed_packages(self.REQS, advisories)
        r = self._result_for(results, "numpy")
        assert r.installed is None
        assert r.in_range is False

    def test_affected_range_preserved(self):
        advisories = [Advisory("Flask", "< 2.4.0")]
        results = check_installed_packages(self.REQS, advisories)
        r = self._result_for(results, "flask")
        assert r.affected_range == "< 2.4.0"

    def test_multiple_advisories(self):
        advisories = [
            Advisory("Flask", "< 2.4.0"),
            Advisory("numpy", "< 1.24.0"),
            Advisory("requests", ">= 2.3.0, < 2.31.0"),
        ]
        results = check_installed_packages(self.REQS, advisories)
        assert len(results) == 3
        flask_r = self._result_for(results, "flask")
        numpy_r = self._result_for(results, "numpy")
        requests_r = self._result_for(results, "requests")
        assert flask_r.in_range is True
        assert numpy_r.installed is None
        assert numpy_r.in_range is False
        assert requests_r.in_range is True
