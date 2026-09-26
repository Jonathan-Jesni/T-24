"""Inventory helpers for T-24: parse requirements and cross-reference advisories."""
from dataclasses import dataclass

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name


@dataclass
class VersionCheck:
    package: str        # canonical name
    installed: str | None
    affected_range: str
    in_range: bool


def parse_requirements(text: str) -> dict[str, str]:
    """Parse requirements.txt text → {canonical_name: version_string}."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        req = Requirement(line)
        name = canonicalize_name(req.name)
        # Extract the pinned version from the specifier set (==x.y.z)
        version = next(
            (spec.version for spec in req.specifier if spec.operator == "=="),
            None,
        )
        if version is not None:
            result[name] = version
    return result


def check_version(installed: str, affected_range: str) -> bool:
    """Return True if installed version is within the affected_range specifier."""
    return installed in SpecifierSet(affected_range)


def check_installed_packages(
    requirements_text: str,
    advisories: list,   # objects with .package and .affected_range attributes
) -> list[VersionCheck]:
    """Cross-reference installed packages against advisory affected ranges."""
    installed_map = parse_requirements(requirements_text)
    results: list[VersionCheck] = []
    for advisory in advisories:
        canonical = canonicalize_name(advisory.package)
        installed_version = installed_map.get(canonical)
        in_range = (
            check_version(installed_version, advisory.affected_range)
            if installed_version is not None
            else False
        )
        results.append(VersionCheck(
            package=canonical,
            installed=installed_version,
            affected_range=advisory.affected_range,
            in_range=in_range,
        ))
    return results
