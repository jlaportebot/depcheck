"""Data models for depcheck."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class HealthStatus(enum.Enum):
    """Health status of a dependency."""

    HEALTHY = "healthy"
    OUTDATED = "outdated"
    VULNERABLE = "vulnerable"
    UNMAINTAINED = "unmaintained"
    YANKED = "yanked"
    REMOVED = "removed"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """Represents a known vulnerability for a package."""

    vuln_id: str
    summary: str
    severity: str
    url: str
    aliases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.vuln_id,
            "summary": self.summary,
            "severity": self.severity,
            "url": self.url,
            "aliases": self.aliases,
        }


@dataclass
class LicenseInfo:
    """License information for a package."""

    spdx_id: str = ""
    raw_license: str = ""
    category: str = "unknown"  # permissive, copyleft, proprietary, public_domain, restricted, unknown
    is_compliant: bool = True
    compliance_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "spdx_id": self.spdx_id,
            "raw_license": self.raw_license,
            "category": self.category,
            "is_compliant": self.is_compliant,
            "compliance_note": self.compliance_note,
        }


@dataclass
class PackageReport:
    """Health report for a single package."""

    name: str
    installed_version: str
    latest_version: str | None = None
    status: HealthStatus = HealthStatus.UNKNOWN
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    last_release_date: str | None = None
    is_yanked: bool = False
    is_removed: bool = False
    error: str | None = None
    license_info: LicenseInfo | None = None

    @property
    def is_outdated(self) -> bool:
        """Check if the package is outdated compared to latest version.

        Uses packaging.Version for proper PEP 440 version comparison
        instead of string comparison (e.g., "1.10.0" > "1.9.0").
        """
        if self.installed_version and self.latest_version:
            try:
                from packaging.version import Version

                return Version(self.installed_version) < Version(self.latest_version)
            except Exception:
                # Fallback to string comparison if versions can't be parsed
                return self.installed_version != self.latest_version
        return False

    @property
    def is_unmaintained(self) -> bool:
        """Check if the package hasn't been updated in over a year."""
        return self.status == HealthStatus.UNMAINTAINED

    @property
    def is_vulnerable(self) -> bool:
        """Check if the package has known vulnerabilities."""
        return self.status == HealthStatus.VULNERABLE

    @property
    def has_license_issue(self) -> bool:
        """Check if the package has a license compliance issue."""
        return self.license_info is not None and not self.license_info.is_compliant

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "status": self.status.value,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "last_release_date": self.last_release_date,
            "is_yanked": self.is_yanked,
            "is_removed": self.is_removed,
            "error": self.error,
            "license": self.license_info.to_dict() if self.license_info else None,
        }


@dataclass
class ScanResult:
    """Aggregated result of scanning a project's dependencies."""

    project_path: str
    packages: list[PackageReport] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total number of packages scanned."""
        return len(self.packages)

    @property
    def healthy_count(self) -> int:
        """Number of healthy packages."""
        return sum(1 for p in self.packages if p.status == HealthStatus.HEALTHY)

    @property
    def outdated_count(self) -> int:
        """Number of outdated packages."""
        return sum(1 for p in self.packages if p.status == HealthStatus.OUTDATED)

    @property
    def vulnerable_count(self) -> int:
        """Number of vulnerable packages."""
        return sum(1 for p in self.packages if p.status == HealthStatus.VULNERABLE)

    @property
    def unmaintained_count(self) -> int:
        """Number of unmaintained packages."""
        return sum(1 for p in self.packages if p.status == HealthStatus.UNMAINTAINED)

    @property
    def yanked_count(self) -> int:
        """Number of yanked packages."""
        return sum(1 for p in self.packages if p.status == HealthStatus.YANKED)

    @property
    def removed_count(self) -> int:
        """Number of removed packages."""
        return sum(1 for p in self.packages if p.status == HealthStatus.REMOVED)

    @property
    def license_issues_count(self) -> int:
        """Number of packages with license compliance issues."""
        return sum(1 for p in self.packages if p.has_license_issue)

    def has_vulnerabilities(self) -> bool:
        """Check if any packages have vulnerabilities."""
        return self.vulnerable_count > 0

    def has_issues(self) -> bool:
        """Check if any packages have any issues (not healthy)."""
        return any(p.status != HealthStatus.HEALTHY for p in self.packages)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "files_scanned": self.files_scanned,
            "summary": {
                "total": self.total,
                "healthy": self.healthy_count,
                "outdated": self.outdated_count,
                "vulnerable": self.vulnerable_count,
                "unmaintained": self.unmaintained_count,
                "yanked": self.yanked_count,
                "removed": self.removed_count,
                "license_issues": self.license_issues_count,
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


@dataclass
class ParsedDependency:
    """A dependency parsed from a requirements file."""

    name: str
    version: str | None = None
    specifier: str | None = None
