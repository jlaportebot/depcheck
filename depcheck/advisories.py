"""Security advisory tracker for depcheck.

Fetches, indexes, and searches security advisories from multiple sources
(OSV.dev, GitHub Advisory Database, PyPA Advisory Database). Provides
advisory lookup, timeline tracking, affected version ranges, and
remediation guidance.
"""

from __future__ import annotations

import datetime
import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from depcheck.models import PackageReport, ScanResult, Vulnerability
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies, scan_project


# ─── Constants ─────────────────────────────────────────────────────────────

PYPA_ADVISORY_URL = "https://raw.githubusercontent.com/pypa/advisory-database/main/vulns"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
REQUEST_TIMEOUT = 30.0

# Severity ordering for comparison
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


# ─── Data Models ───────────────────────────────────────────────────────────


class AdvisorySource(enum.Enum):
    """Source of the security advisory."""

    OSV = "osv"
    PYPA = "pypa"
    GITHUB = "github"
    MANUAL = "manual"


class AdvisoryStatus(enum.Enum):
    """Status of the advisory."""

    ACTIVE = "active"
    PATCHED = "patched"
    WITHDRAWN = "withdrawn"
    DISPUTED = "disputed"


@dataclass
class AffectedRange:
    """Version range affected by an advisory."""

    introduced: str  # First affected version
    fixed: str | None = None  # Version where the fix was introduced
    last_affected: str | None = None  # Last known affected version

    def to_dict(self) -> dict[str, Any]:
        return {
            "introduced": self.introduced,
            "fixed": self.fixed,
            "last_affected": self.last_affected,
        }


@dataclass
class AdvisoryEntry:
    """A single security advisory entry."""

    advisory_id: str  # e.g., "OSV-2023-123", "GHSA-xxxx-xxxx", "PYSEC-2023-123"
    source: AdvisorySource
    package: str
    summary: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    url: str
    aliases: list[str] = field(default_factory=list)  # CVE IDs, etc.
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    status: AdvisoryStatus = AdvisoryStatus.ACTIVE
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    epss_score: float | None = None  # Exploit Prediction Scoring System
    cwe_ids: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        """Numeric rank for severity comparison."""
        return SEVERITY_ORDER.get(self.severity.upper(), 0)

    @property
    def is_patchable(self) -> bool:
        """Whether a fix version is available."""
        return any(r.fixed is not None for r in self.affected_ranges)

    @property
    def fix_version(self) -> str | None:
        """The earliest fix version, if available."""
        fix_versions = [r.fixed for r in self.affected_ranges if r.fixed is not None]
        if not fix_versions:
            return None
        # Return the earliest fix version
        try:
            from packaging.version import Version
            return str(min(Version(v) for v in fix_versions))
        except Exception:
            return fix_versions[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "source": self.source.value,
            "package": self.package,
            "summary": self.summary,
            "severity": self.severity,
            "url": self.url,
            "aliases": self.aliases,
            "affected_ranges": [r.to_dict() for r in self.affected_ranges],
            "published": self.published,
            "modified": self.modified,
            "status": self.status.value,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "cwe_ids": self.cwe_ids,
            "is_patchable": self.is_patchable,
            "fix_version": self.fix_version,
        }


@dataclass
class PackageAdvisorySummary:
    """Advisory summary for a single package."""

    package: str
    version: str
    total_advisories: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unknown_count: int = 0
    patchable_count: int = 0
    unpatchable_count: int = 0
    advisories: list[AdvisoryEntry] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def has_unpatched(self) -> bool:
        return self.unpatchable_count > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "total_advisories": self.total_advisories,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "unknown_count": self.unknown_count,
            "patchable_count": self.patchable_count,
            "unpatchable_count": self.unpatchable_count,
            "advisories": [a.to_dict() for a in self.advisories],
        }


@dataclass
class AdvisoryReport:
    """Complete advisory report for a project."""

    project_path: str
    packages: list[PackageAdvisorySummary] = field(default_factory=list)
    total_advisories: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_patchable: int = 0
    total_unpatchable: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def affected_packages(self) -> list[PackageAdvisorySummary]:
        """Packages with at least one advisory."""
        return [p for p in self.packages if p.total_advisories > 0]

    @property
    def clean_packages(self) -> list[PackageAdvisorySummary]:
        """Packages with no advisories."""
        return [p for p in self.packages if p.total_advisories == 0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "total_advisories": self.total_advisories,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "total_medium": self.total_medium,
            "total_low": self.total_low,
            "total_patchable": self.total_patchable,
            "total_unpatchable": self.total_unpatchable,
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


# ─── Advisory Fetching ─────────────────────────────────────────────────────


def _fetch_osv_advisories(
    package_name: str, version: str, osv_client: OSVClient
) -> list[AdvisoryEntry]:
    """Fetch advisories from OSV.dev for a specific package version."""
    vulns = osv_client.query_vulnerabilities(package_name, version)
    entries: list[AdvisoryEntry] = []

    for vuln in vulns:
        # Parse affected ranges from the OSV data (we only have summary from OSVClient)
        affected_ranges: list[AffectedRange] = []
        # OSV vulnerability IDs contain the source info
        if vuln.vuln_id.startswith("GHSA"):
            source = AdvisorySource.GITHUB
        elif vuln.vuln_id.startswith("PYSEC"):
            source = AdvisorySource.PYPA
        else:
            source = AdvisorySource.OSV

        entry = AdvisoryEntry(
            advisory_id=vuln.vuln_id,
            source=source,
            package=package_name,
            summary=vuln.summary,
            severity=vuln.severity.upper(),
            url=vuln.url,
            aliases=vuln.aliases,
            affected_ranges=affected_ranges,
            status=AdvisoryStatus.ACTIVE,
        )

        # Try to extract CVE from aliases
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                entry.cwe_ids.append(alias)

        entries.append(entry)

    return entries


def _fetch_github_advisories(
    package_name: str, ecosystem: str = "PIP"
) -> list[AdvisoryEntry]:
    """Fetch advisories from GitHub Advisory Database.

    Uses the GitHub REST API to search for advisories affecting a package.
    """
    entries: list[AdvisoryEntry] = []

    try:
        client = httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=True)
        params = {
            "ecosystem": ecosystem,
            "package": package_name,
            "per_page": 50,
        }
        response = client.get(GITHUB_ADVISORY_URL, params=params)
        client.close()

        if response.status_code != 200:
            return entries

        data = response.json()
        if not isinstance(data, list):
            return entries

        for adv in data:
            ghsa_id = adv.get("ghsa_id", "")
            summary = adv.get("summary", "No summary available")
            severity = adv.get("severity", "UNKNOWN").upper()
            url = f"https://github.com/advisories/{ghsa_id}"

            # Parse CVE aliases
            aliases = adv.get("cve_id", "")
            alias_list = [aliases] if aliases else []

            # Parse affected versions
            affected_ranges: list[AffectedRange] = []
            for vuln in adv.get("vulnerabilities", []):
                for rng in vuln.get("vulnerable_range", "").split(","):
                    rng = rng.strip()
                    if rng:
                        affected_ranges.append(
                            AffectedRange(introduced=rng)
                        )
                # Check for patched versions
                patched = vuln.get("patched_versions", "")
                if patched and affected_ranges:
                    affected_ranges[-1].fixed = patched.strip()

            # Parse CVSS
            cvss_score = None
            cvss = adv.get("cvss", {})
            if isinstance(cvss, dict):
                cvss_score = cvss.get("score")

            entry = AdvisoryEntry(
                advisory_id=ghsa_id,
                source=AdvisorySource.GITHUB,
                package=package_name,
                summary=summary,
                severity=severity,
                url=url,
                aliases=alias_list,
                affected_ranges=affected_ranges,
                published=adv.get("published_at"),
                modified=adv.get("updated_at"),
                status=AdvisoryStatus.ACTIVE,
                cvss_score=cvss_score,
            )
            entries.append(entry)

    except (httpx.HTTPError, Exception):
        pass

    return entries


def _fetch_pypa_advisory(package_name: str) -> list[AdvisoryEntry]:
    """Fetch advisory from the PyPA Advisory Database.

    The PyPA advisory database is a GitHub-hosted repository of
    Python package security advisories in OSV format.
    """
    entries: list[AdvisoryEntry] = []

    try:
        # PyPA advisories are stored as individual JSON files
        # The URL pattern is: PYPA_ADVISORY_URL/package_name/YYYY/PYSEC-YYYY-NNN.json
        # We use the OSV API instead since PyPA feeds into OSV
        client = httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=True)
        # Use OSV's batch query for PyPA-sourced advisories
        url = f"https://api.osv.dev/v1/query"
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI",
            },
        }
        response = client.post(url, json=payload)
        client.close()

        if response.status_code != 200:
            return entries

        data = response.json()
        vulns = data.get("vulns", [])

        for vuln_data in vulns:
            vuln_id = vuln_data.get("id", "")
            if not vuln_id.startswith("PYSEC"):
                continue  # Only include PyPA-sourced advisories here

            summary = vuln_data.get("summary", "No summary available")
            severity = "UNKNOWN"

            # Extract severity
            severity_list = vuln_data.get("severity", [])
            for sev in severity_list:
                score_str = sev.get("score", "")
                if "CVSS" in score_str:
                    parts = score_str.split("/")
                    impact_values = [
                        p.split(":")[1] for p in parts
                        if any(p.startswith(x) for x in ("C:", "I:", "A:"))
                    ]
                    if all(v == "N" for v in impact_values):
                        severity = "LOW"
                    elif any(v == "H" for v in impact_values):
                        severity = "HIGH"
                    else:
                        severity = "MEDIUM"

            # Parse affected ranges
            affected_ranges: list[AffectedRange] = []
            for affected in vuln_data.get("affected", []):
                for rng in affected.get("ranges", []):
                    events = rng.get("events", [])
                    introduced = ""
                    fixed = None
                    for event in events:
                        if "introduced" in event:
                            introduced = event["introduced"]
                        if "fixed" in event:
                            fixed = event["fixed"]
                    if introduced:
                        affected_ranges.append(
                            AffectedRange(introduced=introduced, fixed=fixed)
                        )

            aliases = vuln_data.get("aliases", [])
            url_link = f"https://osv.dev/vulnerability/{vuln_id}"

            entry = AdvisoryEntry(
                advisory_id=vuln_id,
                source=AdvisorySource.PYPA,
                package=package_name,
                summary=summary,
                severity=severity,
                url=url_link,
                aliases=aliases,
                affected_ranges=affected_ranges,
                published=vuln_data.get("published"),
                modified=vuln_data.get("modified"),
                status=AdvisoryStatus.ACTIVE,
            )
            entries.append(entry)

    except (httpx.HTTPError, Exception):
        pass

    return entries


# ─── Core Logic ────────────────────────────────────────────────────────────


def lookup_advisories(
    package_name: str,
    version: str | None = None,
    sources: list[AdvisorySource] | None = None,
) -> list[AdvisoryEntry]:
    """Look up security advisories for a package.

    Args:
        package_name: The package to look up.
        version: Specific version to check (optional).
        sources: Which advisory sources to query (default: all).

    Returns:
        List of AdvisoryEntry objects.
    """
    if sources is None:
        sources = [AdvisorySource.OSV, AdvisorySource.PYPA, AdvisorySource.GITHUB]

    all_entries: list[AdvisoryEntry] = []
    seen_ids: set[str] = set()

    # Fetch from OSV (includes PyPA advisories via OSV)
    if AdvisorySource.OSV in sources and version:
        with OSVClient() as client:
            osv_entries = _fetch_osv_advisories(package_name, version, client)
            for entry in osv_entries:
                if entry.advisory_id not in seen_ids:
                    seen_ids.add(entry.advisory_id)
                    all_entries.append(entry)

    # Fetch from GitHub Advisory Database
    if AdvisorySource.GITHUB in sources:
        ghsa_entries = _fetch_github_advisories(package_name)
        for entry in ghsa_entries:
            if entry.advisory_id not in seen_ids:
                seen_ids.add(entry.advisory_id)
                all_entries.append(entry)

    # Fetch from PyPA Advisory Database (direct)
    if AdvisorySource.PYPA in sources:
        pypa_entries = _fetch_pypa_advisory(package_name)
        for entry in pypa_entries:
            if entry.advisory_id not in seen_ids:
                seen_ids.add(entry.advisory_id)
                all_entries.append(entry)

    # Sort by severity (descending)
    all_entries.sort(key=lambda e: e.severity_rank, reverse=True)

    return all_entries


def run_advisories(
    project_path: str | Path,
    check_vulnerabilities: bool = True,
    sources: list[AdvisorySource] | None = None,
) -> AdvisoryReport:
    """Run a complete advisory scan for a project.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check vulnerabilities.
        sources: Which advisory sources to query.

    Returns:
        An AdvisoryReport with advisory summaries for all packages.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return AdvisoryReport(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Scan the project
    scan_result = scan_project(
        project_path=str(project_path),
        check_vulnerabilities=check_vulnerabilities,
    )

    if scan_result.errors and not scan_result.packages:
        return AdvisoryReport(
            project_path=str(project_path),
            errors=scan_result.errors,
        )

    # Build advisory summaries
    summaries: list[PackageAdvisorySummary] = []
    total_advisories = 0
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_patchable = 0
    total_unpatchable = 0

    for pkg in scan_result.packages:
        # Look up advisories for this package
        advisories = lookup_advisories(
            package_name=pkg.name,
            version=pkg.installed_version if pkg.installed_version != "unknown" else None,
            sources=sources,
        )

        # If we have vulnerabilities from the scan, include them too
        for vuln in pkg.vulnerabilities:
            # Check if this vuln is already in advisories
            if not any(a.advisory_id == vuln.vuln_id for a in advisories):
                # Convert to advisory entry
                if vuln.vuln_id.startswith("GHSA"):
                    source = AdvisorySource.GITHUB
                elif vuln.vuln_id.startswith("PYSEC"):
                    source = AdvisorySource.PYPA
                else:
                    source = AdvisorySource.OSV

                advisories.append(
                    AdvisoryEntry(
                        advisory_id=vuln.vuln_id,
                        source=source,
                        package=pkg.name,
                        summary=vuln.summary,
                        severity=vuln.severity.upper(),
                        url=vuln.url,
                        aliases=vuln.aliases,
                        status=AdvisoryStatus.ACTIVE,
                    )
                )

        summary = PackageAdvisorySummary(
            package=pkg.name,
            version=pkg.installed_version,
            total_advisories=len(advisories),
            advisories=advisories,
        )

        # Count by severity
        for adv in advisories:
            sev = adv.severity.upper()
            if sev == "CRITICAL":
                summary.critical_count += 1
                total_critical += 1
            elif sev == "HIGH":
                summary.high_count += 1
                total_high += 1
            elif sev == "MEDIUM":
                summary.medium_count += 1
                total_medium += 1
            elif sev == "LOW":
                summary.low_count += 1
                total_low += 1
            else:
                summary.unknown_count += 1

            if adv.is_patchable:
                summary.patchable_count += 1
                total_patchable += 1
            else:
                summary.unpatchable_count += 1
                total_unpatchable += 1

        total_advisories += len(advisories)
        summaries.append(summary)

    return AdvisoryReport(
        project_path=str(project_path),
        packages=summaries,
        total_advisories=total_advisories,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        total_patchable=total_patchable,
        total_unpatchable=total_unpatchable,
    )


def search_advisories(
    package_name: str,
    severity: str | None = None,
    source: AdvisorySource | None = None,
    patched_only: bool = False,
    unpatched_only: bool = False,
) -> list[AdvisoryEntry]:
    """Search advisories with filters.

    Args:
        package_name: Package to search advisories for.
        severity: Filter by severity level.
        source: Filter by advisory source.
        patched_only: Only show advisories with a known fix.
        unpatched_only: Only show advisories without a known fix.

    Returns:
        Filtered list of AdvisoryEntry objects.
    """
    entries = lookup_advisories(package_name)

    if severity:
        entries = [e for e in entries if e.severity.upper() == severity.upper()]

    if source:
        entries = [e for e in entries if e.source == source]

    if patched_only:
        entries = [e for e in entries if e.is_patchable]

    if unpatched_only:
        entries = [e for e in entries if not e.is_patchable]

    return entries


# ─── Rendering ─────────────────────────────────────────────────────────────


def _severity_style(severity: str) -> str:
    """Get Rich style for a severity level."""
    styles = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[green]LOW[/green]",
        "UNKNOWN": "[dim]UNKNOWN[/dim]",
    }
    return styles.get(severity.upper(), severity)


def render_advisories_table(report: AdvisoryReport, console: Console | None = None) -> None:
    """Render advisory report as Rich tables."""
    if console is None:
        console = Console()

    console.print(f"\n[bold]Security Advisories: {report.project_path}[/bold]\n")

    # Summary panel
    summary_text = (
        f"Total advisories: [bold]{report.total_advisories}[/bold]\n"
        f"Critical: {report.total_critical}  High: {report.total_high}  "
        f"Medium: {report.total_medium}  Low: {report.total_low}\n"
        f"Patchable: [green]{report.total_patchable}[/green]  "
        f"Unpatchable: [red]{report.total_unpatchable}[/red]"
    )
    border = "red" if report.total_critical > 0 else "yellow" if report.total_high > 0 else "green"
    console.print(Panel(summary_text, title="Advisory Summary", border_style=border))

    # Per-package advisory summary
    affected = report.affected_packages
    if affected:
        summary_table = Table(title="Affected Packages", show_lines=True)
        summary_table.add_column("Package", style="bold")
        summary_table.add_column("Version")
        summary_table.add_column("Total", justify="right")
        summary_table.add_column("Critical", justify="right")
        summary_table.add_column("High", justify="right")
        summary_table.add_column("Medium", justify="right")
        summary_table.add_column("Low", justify="right")
        summary_table.add_column("Patchable", justify="right")
        summary_table.add_column("Fix Version")

        for pkg in affected:
            fix_versions: set[str] = set()
            for adv in pkg.advisories:
                if adv.fix_version:
                    fix_versions.add(adv.fix_version)

            fix_str = ", ".join(sorted(fix_versions)) if fix_versions else "[dim]—[/dim]"

            summary_table.add_row(
                pkg.package,
                pkg.version,
                str(pkg.total_advisories),
                str(pkg.critical_count) if pkg.critical_count else "[dim]0[/dim]",
                str(pkg.high_count) if pkg.high_count else "[dim]0[/dim]",
                str(pkg.medium_count) if pkg.medium_count else "[dim]0[/dim]",
                str(pkg.low_count) if pkg.low_count else "[dim]0[/dim]",
                str(pkg.patchable_count),
                fix_str,
            )

        console.print(summary_table)

    # Detailed advisory list
    if affected:
        detail_table = Table(title="Advisory Details", show_lines=True)
        detail_table.add_column("ID", style="bold")
        detail_table.add_column("Package")
        detail_table.add_column("Severity")
        detail_table.add_column("Source")
        detail_table.add_column("Summary", max_width=50)
        detail_table.add_column("Fix Version")
        detail_table.add_column("URL", max_width=30)

        for pkg in affected:
            for adv in pkg.advisories:
                fix = adv.fix_version or "[dim]—[/dim]"
                url_short = adv.url[:50] + "..." if len(adv.url) > 50 else adv.url
                detail_table.add_row(
                    adv.advisory_id,
                    pkg.package,
                    _severity_style(adv.severity),
                    adv.source.value,
                    adv.summary[:80] + "..." if len(adv.summary) > 80 else adv.summary,
                    fix,
                    url_short,
                )

        console.print(detail_table)
    else:
        console.print("\n[green]✓ No security advisories found for any dependency[/green]")


def render_advisories_json(report: AdvisoryReport, console: Console | None = None) -> None:
    """Render advisory report as JSON."""
    output = json.dumps(report.to_dict(), indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
