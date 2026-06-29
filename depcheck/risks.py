"""Multi-dimensional risk assessment for depcheck.

Evaluates each dependency across multiple risk dimensions (vulnerability,
maintenance, age, popularity, license) and computes a composite risk
score with severity classification and remediation priorities.
"""

from __future__ import annotations

import datetime
import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus, PackageReport
from depcheck.scanner import scan_project

# ─── Enums ─────────────────────────────────────────────────────────────────


class RiskDimension(enum.Enum):
    """Dimensions of dependency risk."""

    VULNERABILITY = "vulnerability"
    MAINTENANCE = "maintenance"
    AGE = "age"
    POPULARITY = "popularity"
    LICENSE = "license"


class RiskSeverity(enum.Enum):
    """Severity level for a risk assessment."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class RemediationAction(enum.Enum):
    """Suggested remediation action."""

    UPDATE = "update"
    REPLACE = "replace"
    REMOVE = "remove"
    PIN = "pin"
    AUDIT = "audit"
    MONITOR = "monitor"
    NONE = "none"


# ─── Scoring Weights ───────────────────────────────────────────────────────

# Default weights for composite score (must sum to 1.0)
DEFAULT_WEIGHTS: dict[RiskDimension, float] = {
    RiskDimension.VULNERABILITY: 0.35,
    RiskDimension.MAINTENANCE: 0.25,
    RiskDimension.AGE: 0.15,
    RiskDimension.POPULARITY: 0.15,
    RiskDimension.LICENSE: 0.10,
}

# Severity thresholds for composite score
SEVERITY_THRESHOLDS = {
    RiskSeverity.CRITICAL: 0.80,
    RiskSeverity.HIGH: 0.60,
    RiskSeverity.MEDIUM: 0.40,
    RiskSeverity.LOW: 0.20,
    RiskSeverity.MINIMAL: 0.0,
}

# Health status to risk score mapping
_HEALTH_RISK: dict[HealthStatus, float] = {
    HealthStatus.VULNERABLE: 1.0,
    HealthStatus.YANKED: 0.9,
    HealthStatus.REMOVED: 0.9,
    HealthStatus.UNMAINTAINED: 0.7,
    HealthStatus.OUTDATED: 0.4,
    HealthStatus.HEALTHY: 0.1,
    HealthStatus.UNKNOWN: 0.5,
}


# ─── Data Models ───────────────────────────────────────────────────────────


@dataclass
class DimensionScore:
    """Risk score for a single dimension."""

    dimension: RiskDimension
    score: float  # 0.0 (no risk) to 1.0 (maximum risk)
    weight: float
    details: str = ""
    contributing_factors: list[str] = field(default_factory=list)

    @property
    def weighted_score(self) -> float:
        """Score multiplied by its weight."""
        return self.score * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension.value,
            "score": round(self.score, 4),
            "weight": round(self.weight, 4),
            "weighted_score": round(self.weighted_score, 4),
            "details": self.details,
            "contributing_factors": self.contributing_factors,
        }


@dataclass
class RiskEntry:
    """Risk assessment for a single package."""

    package: str
    version: str
    composite_score: float  # 0.0 to 1.0
    severity: RiskSeverity = RiskSeverity.MINIMAL
    dimension_scores: list[DimensionScore] = field(default_factory=list)
    top_risk_dimension: RiskDimension | None = None
    remediation: RemediationAction = RemediationAction.NONE
    remediation_details: str = ""
    is_direct: bool = False
    is_dev: bool = False
    is_optional: bool = False

    @property
    def severity_rank(self) -> int:
        """Numeric rank for severity comparison (higher = more severe)."""
        ranks = {
            RiskSeverity.CRITICAL: 4,
            RiskSeverity.HIGH: 3,
            RiskSeverity.MEDIUM: 2,
            RiskSeverity.LOW: 1,
            RiskSeverity.MINIMAL: 0,
        }
        return ranks.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "composite_score": round(self.composite_score, 4),
            "severity": self.severity.value,
            "dimension_scores": [ds.to_dict() for ds in self.dimension_scores],
            "top_risk_dimension": self.top_risk_dimension.value
            if self.top_risk_dimension
            else None,
            "remediation": self.remediation.value,
            "remediation_details": self.remediation_details,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "is_optional": self.is_optional,
        }


@dataclass
class RiskReport:
    """Complete risk assessment report for a project."""

    project_path: str
    entries: list[RiskEntry] = field(default_factory=list)
    weights: dict[RiskDimension, float] = field(default_factory=dict)
    total_packages: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    minimal_count: int = 0
    direct_risk_count: int = 0  # Direct deps with medium+ risk
    avg_score: float = 0.0
    max_score: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def at_risk_packages(self) -> list[RiskEntry]:
        """Packages with medium or higher risk."""
        return [e for e in self.entries if e.severity_rank >= 2]

    @property
    def priority_remediations(self) -> list[RiskEntry]:
        """Packages needing immediate action, sorted by risk."""
        action_required = {
            RemediationAction.UPDATE,
            RemediationAction.REPLACE,
            RemediationAction.REMOVE,
        }
        return sorted(
            [e for e in self.entries if e.remediation in action_required],
            key=lambda e: e.composite_score,
            reverse=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "total_packages": self.total_packages,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "minimal_count": self.minimal_count,
            "direct_risk_count": self.direct_risk_count,
            "avg_score": round(self.avg_score, 4),
            "max_score": round(self.max_score, 4),
            "entries": [e.to_dict() for e in self.entries],
            "errors": self.errors,
        }


# ─── Dimension Scoring Functions ───────────────────────────────────────────


def _score_vulnerability(pkg: PackageReport) -> DimensionScore:
    """Score the vulnerability risk dimension.

    Based on: number of vulnerabilities, their severity, and
    whether patches are available.
    """
    if not pkg.vulnerabilities:
        return DimensionScore(
            dimension=RiskDimension.VULNERABILITY,
            score=0.0,
            weight=DEFAULT_WEIGHTS[RiskDimension.VULNERABILITY],
            details="No known vulnerabilities",
        )

    # Weight by severity
    sev_weights = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "UNKNOWN": 0.3}
    total_weight = 0.0
    factors: list[str] = []
    patchable_count = 0

    for vuln in pkg.vulnerabilities:
        w = sev_weights.get(vuln.severity.upper(), 0.3)
        total_weight += w
        factors.append(f"{vuln.vuln_id} ({vuln.severity})")

        # Check if patchable (has URL with fix info)
        if vuln.url:
            patchable_count += 1

    # Normalize: 1 vuln with CRITICAL → 1.0, more vulns cap at 1.0
    score = min(total_weight / 1.0, 1.0)
    patch_status = (
        f", {patchable_count} patchable" if patchable_count > 0 else ", no patches available"
    )

    return DimensionScore(
        dimension=RiskDimension.VULNERABILITY,
        score=score,
        weight=DEFAULT_WEIGHTS[RiskDimension.VULNERABILITY],
        details=f"{len(pkg.vulnerabilities)} vulnerability(ies){patch_status}",
        contributing_factors=factors[:5],
    )


def _score_maintenance(pkg: PackageReport) -> DimensionScore:
    """Score the maintenance risk dimension.

    Based on: health status, last release date, and whether the
    package appears actively maintained.
    """
    health_risk = _HEALTH_RISK.get(pkg.status, 0.5)
    factors: list[str] = []

    if pkg.status == HealthStatus.UNMAINTAINED:
        factors.append("Package appears unmaintained")
    elif pkg.status == HealthStatus.OUTDATED:
        factors.append("Newer version available")

    # Adjust based on last release date
    age_risk = 0.0
    if pkg.last_release_date:
        try:
            last_release = datetime.datetime.strptime(pkg.last_release_date, "%Y-%m-%d").replace(
                tzinfo=datetime.UTC
            )
            days_since = (datetime.datetime.now(datetime.UTC) - last_release).days

            if days_since > 730:  # 2+ years
                age_risk = 0.8
                factors.append(f"Last release {days_since}d ago (>2 years)")
            elif days_since > 365:  # 1+ year
                age_risk = 0.5
                factors.append(f"Last release {days_since}d ago (>1 year)")
            elif days_since > 180:  # 6+ months
                age_risk = 0.2
                factors.append(f"Last release {days_since}d ago")
            else:
                factors.append(f"Last release {days_since}d ago (recent)")
        except (ValueError, TypeError):
            pass
    else:
        age_risk = 0.3
        factors.append("Last release date unknown")

    # Combine health and age risk
    score = max(health_risk, age_risk)

    return DimensionScore(
        dimension=RiskDimension.MAINTENANCE,
        score=score,
        weight=DEFAULT_WEIGHTS[RiskDimension.MAINTENANCE],
        details=f"Health: {pkg.status.value}, age risk: {age_risk:.2f}",
        contributing_factors=factors,
    )


def _score_age(pkg: PackageReport) -> DimensionScore:
    """Score the age/obsolescence risk dimension.

    Based on: how far behind the latest version the installed
    version is, and whether the package is significantly outdated.
    """
    factors: list[str] = []
    if pkg.status == HealthStatus.OUTDATED:
        score = 0.5
        details = "Installed version is not the latest"
        factors = ["Outdated version detected"]
    elif pkg.status == HealthStatus.HEALTHY:
        score = 0.0
        details = "Up to date"
        factors = []
    elif pkg.status == HealthStatus.UNKNOWN:
        score = 0.3
        details = "Version status unknown"
        factors = ["Could not determine latest version"]
    else:
        # VULNERABLE, YANKED, REMOVED, UNMAINTAINED
        score = 0.7
        details = f"Package status: {pkg.status.value}"
        factors = [f"Package is {pkg.status.value}"]

    return DimensionScore(
        dimension=RiskDimension.AGE,
        score=score,
        weight=DEFAULT_WEIGHTS[RiskDimension.AGE],
        details=details,
        contributing_factors=factors,
    )


def _score_popularity(pkg: PackageReport) -> DimensionScore:
    """Score the popularity risk dimension.

    Based on: whether the package is well-established or niche.
    Since we don't have download counts from the scan, we use
    heuristics from the package health status.
    """
    # Heuristic: healthy packages are likely popular, unknown/unmaintained less so
    popularity_risk: dict[HealthStatus, float] = {
        HealthStatus.HEALTHY: 0.05,  # Popular, low risk
        HealthStatus.OUTDATED: 0.15,  # Still used, slightly higher risk
        HealthStatus.VULNERABLE: 0.3,  # May be widely used but risky
        HealthStatus.UNMAINTAINED: 0.7,  # Losing popularity
        HealthStatus.YANKED: 0.9,  # Should not be used
        HealthStatus.REMOVED: 0.95,  # Gone
        HealthStatus.UNKNOWN: 0.4,  # Can't tell
    }

    score = popularity_risk.get(pkg.status, 0.4)
    factors: list[str] = []

    if pkg.status in (HealthStatus.YANKED, HealthStatus.REMOVED):
        factors.append("Package no longer available on PyPI")
    elif pkg.status == HealthStatus.UNMAINTAINED:
        factors.append("Package may have low community engagement")

    return DimensionScore(
        dimension=RiskDimension.POPULARITY,
        score=score,
        weight=DEFAULT_WEIGHTS[RiskDimension.POPULARITY],
        details=f"Estimated popularity risk: {score:.2f}",
        contributing_factors=factors,
    )


def _score_license(pkg: PackageReport) -> DimensionScore:
    """Score the license risk dimension.

    Based on: whether the license is known, permissive, or copyleft.
    """
    if pkg.license_info is None:
        return DimensionScore(
            dimension=RiskDimension.LICENSE,
            score=0.5,
            weight=DEFAULT_WEIGHTS[RiskDimension.LICENSE],
            details="License unknown",
            contributing_factors=["No license information available"],
        )

    category = pkg.license_info.category.lower() if pkg.license_info.category else "unknown"
    spdx = pkg.license_info.spdx_id or "Unknown"

    # License risk by category
    license_risk: dict[str, float] = {
        "permissive": 0.0,  # MIT, Apache-2.0, BSD
        "weak_copyleft": 0.4,  # LGPL, MPL
        "copyleft": 0.8,  # GPL, AGPL
        "proprietary": 0.9,  # Proprietary
        "public_domain": 0.0,  # Unlicense, CC0
        "unknown": 0.5,
    }

    score = license_risk.get(category, 0.5)
    factors: list[str] = []

    if category == "copyleft":
        factors.append(f"Copyleft license: {spdx}")
    elif category == "proprietary":
        factors.append(f"Proprietary license: {spdx}")
    elif category == "weak_copyleft":
        factors.append(f"Weak copyleft license: {spdx}")
    elif category == "unknown":
        factors.append(f"Uncategorized license: {spdx}")

    return DimensionScore(
        dimension=RiskDimension.LICENSE,
        score=score,
        weight=DEFAULT_WEIGHTS[RiskDimension.LICENSE],
        details=f"License: {spdx} ({category})",
        contributing_factors=factors,
    )


# ─── Composite Scoring ─────────────────────────────────────────────────────


def _classify_severity(score: float) -> RiskSeverity:
    """Classify a composite score into a severity level."""
    if score >= SEVERITY_THRESHOLDS[RiskSeverity.CRITICAL]:
        return RiskSeverity.CRITICAL
    elif score >= SEVERITY_THRESHOLDS[RiskSeverity.HIGH]:
        return RiskSeverity.HIGH
    elif score >= SEVERITY_THRESHOLDS[RiskSeverity.MEDIUM]:
        return RiskSeverity.MEDIUM
    elif score >= SEVERITY_THRESHOLDS[RiskSeverity.LOW]:
        return RiskSeverity.LOW
    else:
        return RiskSeverity.MINIMAL


def _determine_remediation(entry: RiskEntry) -> tuple[RemediationAction, str]:
    """Determine the recommended remediation action for a risk entry."""
    # Check for critical/high vulnerability → update immediately
    vuln_score = next(
        (ds for ds in entry.dimension_scores if ds.dimension == RiskDimension.VULNERABILITY),
        None,
    )
    if vuln_score and vuln_score.score >= 0.8:
        return RemediationAction.UPDATE, "Update to a patched version immediately"

    # Check for yanked/removed → replace or remove
    maint_score = next(
        (ds for ds in entry.dimension_scores if ds.dimension == RiskDimension.MAINTENANCE),
        None,
    )
    if maint_score and maint_score.score >= 0.9:
        return RemediationAction.REPLACE, "Replace with an actively maintained alternative"

    # Check for copyleft/proprietary license in a likely commercial project
    license_score = next(
        (ds for ds in entry.dimension_scores if ds.dimension == RiskDimension.LICENSE),
        None,
    )
    if license_score and license_score.score >= 0.8:
        return (
            RemediationAction.AUDIT,
            "Audit license compliance; consider a permissively-licensed alternative",
        )

    # Check for outdated with moderate vulnerability
    if vuln_score and vuln_score.score >= 0.3:
        return RemediationAction.UPDATE, "Update to the latest version to address vulnerabilities"

    # Check for unmaintained
    if maint_score and maint_score.score >= 0.5:
        return (
            RemediationAction.MONITOR,
            "Monitor for updates; consider alternatives if no activity soon",
        )

    # Check for any low-level risk
    if entry.composite_score >= 0.2:
        return RemediationAction.MONITOR, "Low risk; monitor for changes"

    return RemediationAction.NONE, "No action needed"


# ─── Core Logic ────────────────────────────────────────────────────────────


def assess_package_risk(
    pkg: PackageReport,
    weights: dict[RiskDimension, float] | None = None,
) -> RiskEntry:
    """Assess risk for a single package.

    Args:
        pkg: The package report to assess.
        weights: Custom dimension weights (default: DEFAULT_WEIGHTS).

    Returns:
        A RiskEntry with the complete risk assessment.
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    # Score each dimension
    scorers = {
        RiskDimension.VULNERABILITY: _score_vulnerability,
        RiskDimension.MAINTENANCE: _score_maintenance,
        RiskDimension.AGE: _score_age,
        RiskDimension.POPULARITY: _score_popularity,
        RiskDimension.LICENSE: _score_license,
    }

    dimension_scores: list[DimensionScore] = []
    for dim, scorer in scorers.items():
        ds = scorer(pkg)
        ds.weight = weights.get(dim, DEFAULT_WEIGHTS[dim])
        dimension_scores.append(ds)

    # Compute composite score
    composite = sum(ds.weighted_score for ds in dimension_scores)

    # Determine severity
    severity = _classify_severity(composite)

    # Find top risk dimension
    top_dim = max(dimension_scores, key=lambda ds: ds.score)
    top_risk = top_dim.dimension if top_dim.score > 0 else None

    # Build entry
    entry = RiskEntry(
        package=pkg.name,
        version=pkg.installed_version,
        composite_score=composite,
        severity=severity,
        dimension_scores=dimension_scores,
        top_risk_dimension=top_risk,
    )

    # Determine remediation
    remediation, details = _determine_remediation(entry)
    entry.remediation = remediation
    entry.remediation_details = details

    return entry


def assess_risks(
    project_path: str | Path,
    weights: dict[RiskDimension, float] | None = None,
    min_severity: RiskSeverity = RiskSeverity.LOW,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
) -> RiskReport:
    """Run a complete risk assessment for a project.

    Args:
        project_path: Path to the project directory.
        weights: Custom dimension weights.
        min_severity: Minimum severity to include in results.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.

    Returns:
        A RiskReport with risk assessments for all packages.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return RiskReport(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    if weights is None:
        weights = DEFAULT_WEIGHTS

    # Scan the project
    scan_result = scan_project(
        project_path=str(project_path),
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )

    if scan_result.errors and not scan_result.packages:
        return RiskReport(
            project_path=str(project_path),
            weights=weights,
            errors=scan_result.errors,
        )

    # Assess risk for each package
    entries: list[RiskEntry] = []
    severity_counts = {
        RiskSeverity.CRITICAL: 0,
        RiskSeverity.HIGH: 0,
        RiskSeverity.MEDIUM: 0,
        RiskSeverity.LOW: 0,
        RiskSeverity.MINIMAL: 0,
    }
    direct_risk = 0

    for pkg in scan_result.packages:
        entry = assess_package_risk(pkg, weights=weights)
        severity_counts[entry.severity] += 1

        if entry.is_direct and entry.severity_rank >= 2:  # RiskSeverity.MEDIUM
            direct_risk += 1

        entries.append(entry)

    # Sort by composite score (descending)
    entries.sort(key=lambda e: e.composite_score, reverse=True)

    # Compute aggregate stats
    scores = [e.composite_score for e in entries]
    avg_score = sum(scores) / len(scores) if scores else 0.0
    max_score = max(scores) if scores else 0.0

    # Filter by minimum severity
    _ = {
        RiskSeverity.CRITICAL: 4,
        RiskSeverity.HIGH: 3,
        RiskSeverity.MEDIUM: 2,
        RiskSeverity.LOW: 1,
        RiskSeverity.MINIMAL: 0,
    }.get(min_severity, 0)

    # We keep all entries but the report tracks counts

    return RiskReport(
        project_path=str(project_path),
        entries=entries,
        weights=weights,
        total_packages=len(entries),
        critical_count=severity_counts[RiskSeverity.CRITICAL],
        high_count=severity_counts[RiskSeverity.HIGH],
        medium_count=severity_counts[RiskSeverity.MEDIUM],
        low_count=severity_counts[RiskSeverity.LOW],
        minimal_count=severity_counts[RiskSeverity.MINIMAL],
        direct_risk_count=direct_risk,
        avg_score=avg_score,
        max_score=max_score,
    )


# ─── Rendering ─────────────────────────────────────────────────────────────


def _severity_style(severity: RiskSeverity) -> str:
    """Get a Rich-styled severity label."""
    styles = {
        RiskSeverity.CRITICAL: "[bold red]CRITICAL[/bold red]",
        RiskSeverity.HIGH: "[red]HIGH[/red]",
        RiskSeverity.MEDIUM: "[yellow]MEDIUM[/yellow]",
        RiskSeverity.LOW: "[green]LOW[/green]",
        RiskSeverity.MINIMAL: "[dim]MINIMAL[/dim]",
    }
    return styles.get(severity, str(severity))


def _remediation_style(action: RemediationAction) -> str:
    """Get a Rich-styled remediation label."""
    styles = {
        RemediationAction.UPDATE: "[cyan]UPDATE[/cyan]",
        RemediationAction.REPLACE: "[magenta]REPLACE[/magenta]",
        RemediationAction.REMOVE: "[red]REMOVE[/red]",
        RemediationAction.PIN: "[blue]PIN[/blue]",
        RemediationAction.AUDIT: "[yellow]AUDIT[/yellow]",
        RemediationAction.MONITOR: "[dim]MONITOR[/dim]",
        RemediationAction.NONE: "[green]OK[/green]",
    }
    return styles.get(action, str(action))


def render_risks_table(report: RiskReport, console: Console | None = None) -> None:
    """Render risk assessment report as Rich tables."""
    if console is None:
        console = Console()

    console.print(f"\n[bold]Risk Assessment: {report.project_path}[/bold]\n")

    # Summary panel
    status = (
        "[red]⚠ AT RISK[/red]"
        if report.critical_count + report.high_count > 0
        else "[green]✓ LOW RISK[/green]"
    )
    border = "red" if report.critical_count > 0 else "yellow" if report.high_count > 0 else "green"

    summary = (
        f"Status: {status}\n"
        f"Total packages: {report.total_packages}\n"
        f"Critical: {report.critical_count}  High: {report.high_count}  "
        f"Medium: {report.medium_count}  Low: {report.low_count}\n"
        f"Average risk score: {report.avg_score:.2f}  Max: {report.max_score:.2f}\n"
        f"Direct deps at risk: {report.direct_risk_count}"
    )
    console.print(Panel(summary, title="Risk Summary", border_style=border))

    # Risk heatmap table
    if report.entries:
        risk_table = Table(title="Risk Heatmap", show_lines=True)
        risk_table.add_column("Package", style="bold")
        risk_table.add_column("Version")
        risk_table.add_column("Score", justify="right")
        risk_table.add_column("Severity")
        risk_table.add_column("Top Risk")
        risk_table.add_column("Vuln", justify="right")
        risk_table.add_column("Maint", justify="right")
        risk_table.add_column("Age", justify="right")
        risk_table.add_column("Pop", justify="right")
        risk_table.add_column("License", justify="right")
        risk_table.add_column("Action")

        for entry in report.entries:
            # Get individual dimension scores
            dim_map = {ds.dimension: ds for ds in entry.dimension_scores}
            vuln_s = f"{dim_map.get(RiskDimension.VULNERABILITY, DimensionScore(RiskDimension.VULNERABILITY, 0, 0)).score:.1f}"
            maint_s = f"{dim_map.get(RiskDimension.MAINTENANCE, DimensionScore(RiskDimension.MAINTENANCE, 0, 0)).score:.1f}"
            age_s = f"{dim_map.get(RiskDimension.AGE, DimensionScore(RiskDimension.AGE, 0, 0)).score:.1f}"
            pop_s = f"{dim_map.get(RiskDimension.POPULARITY, DimensionScore(RiskDimension.POPULARITY, 0, 0)).score:.1f}"
            lic_s = f"{dim_map.get(RiskDimension.LICENSE, DimensionScore(RiskDimension.LICENSE, 0, 0)).score:.1f}"

            risk_table.add_row(
                entry.package,
                entry.version,
                f"{entry.composite_score:.2f}",
                _severity_style(entry.severity),
                entry.top_risk_dimension.value if entry.top_risk_dimension else "—",
                vuln_s,
                maint_s,
                age_s,
                pop_s,
                lic_s,
                _remediation_style(entry.remediation),
            )

        console.print(risk_table)

    # Priority remediations
    priority = report.priority_remediations
    if priority:
        remed_table = Table(title="Priority Remediations")
        remed_table.add_column("Package", style="bold")
        remed_table.add_column("Score", justify="right")
        remed_table.add_column("Severity")
        remed_table.add_column("Action")
        remed_table.add_column("Details", max_width=60)

        for entry in priority[:10]:  # Top 10
            remed_table.add_row(
                entry.package,
                f"{entry.composite_score:.2f}",
                _severity_style(entry.severity),
                _remediation_style(entry.remediation),
                entry.remediation_details,
            )

        console.print(remed_table)
    else:
        console.print("\n[green]✓ No priority remediations needed[/green]")


def render_risks_json(report: RiskReport, console: Console | None = None) -> None:
    """Render risk assessment report as JSON."""
    output = json.dumps(report.to_dict(), indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
