"""Inventory helpers for T-24: parse requirements and cross-reference advisories."""
from __future__ import annotations

from dataclasses import dataclass

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name


@dataclass
class VersionCheck:
    package: str            # canonical name
    present: bool           # True if package appears in requirements.txt at all
    installed: str | None   # version string if pinned with ==, else None
    affected_range: str
    in_range: bool | None   # None when present but not pinned (under_investigation)


def parse_requirements(text: str) -> dict[str, str | None]:
    """Parse requirements.txt text → {canonical_name: version_or_None}.

    The value is the pinned version string when the specifier is ``==x.y.z``,
    or ``None`` when the package is listed but not pinned (e.g. ``requests>=2``).
    Packages not listed at all do not appear in the returned dict.
    """
    result: dict[str, str | None] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        req = Requirement(line)
        name = canonicalize_name(req.name)
        pinned = next(
            (spec.version for spec in req.specifier if spec.operator == "=="),
            None,
        )
        result[name] = pinned
    return result


def check_version(installed: str, affected_range: str) -> bool:
    """Return True if installed version is within the affected_range specifier."""
    return installed in SpecifierSet(affected_range)


def check_installed_packages(
    requirements_text: str,
    advisories: list,   # objects with .package and .affected_range attributes
) -> list[VersionCheck]:
    """Cross-reference installed packages against advisory affected ranges.

    Three cases per advisory package:
    - Not listed in requirements.txt → present=False, in_range=False
      (later verdict: not_affected / component_not_present)
    - Listed but not pinned with == → present=True, installed=None, in_range=None
      (later verdict: under_investigation, reason "version not pinned")
    - Pinned → present=True, installed=<version>, in_range=True|False
    """
    installed_map = parse_requirements(requirements_text)
    results: list[VersionCheck] = []
    for advisory in advisories:
        canonical = canonicalize_name(advisory.package)
        if canonical not in installed_map:
            results.append(VersionCheck(
                package=canonical,
                present=False,
                installed=None,
                affected_range=advisory.affected_range,
                in_range=False,
            ))
            continue

        installed_version = installed_map[canonical]
        if installed_version is None:
            # Listed but not pinned
            results.append(VersionCheck(
                package=canonical,
                present=True,
                installed=None,
                affected_range=advisory.affected_range,
                in_range=None,
            ))
            continue

        results.append(VersionCheck(
            package=canonical,
            present=True,
            installed=installed_version,
            affected_range=advisory.affected_range,
            in_range=check_version(installed_version, advisory.affected_range),
        ))
    return results
