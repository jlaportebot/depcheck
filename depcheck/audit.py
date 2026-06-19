"""Comprehensive security audit for depcheck.

Provides deep vulnerability analysis with severity breakdowns,
dependency graph risk analysis, risk scoring, and actionable
remediation advice.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from depcheck.models import HealthStatus, PackageReport
from depcheck.scanner import scan_project

# ── Risk levels ──────────────────────────────────────────────────────────


class RiskLevel(enum.Enum):
    """Overall risk level for a project."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class Severity(enum.Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


# Severity sort order for ranking
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
    "MODERATE": 2,  # GitHub Advisory uses "MODERATE"
}


# ── Data models ──────────────────────────────────────────────────────────


@dataclass
class SeverityBreakdown:
    """Count of vulnerabilities by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    def to_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "unknown": self.unknown,
            "total": self.total,
        }


@dataclass
class VulnerabilityDetail:
    """Detailed vulnerability info for the audit report."""

    vuln_id: str
    package: str
    installed_version: str
    severity: str
    summary: str
    url: str
    aliases: list[str] = field(default_factory=list)
    fix_available: bool = False
    fixed_in_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id,
            "package": self.package,
            "installed_version": self.installed_version,
            "severity": self.severity,
            "summary": self.summary,
            "url": self.url,
            "aliases": self.aliases,
            "fix_available": self.fix_available,
            "fixed_in_version": self.fixed_in_version,
        }


@dataclass
class PackageRisk:
    """Risk assessment for a single package."""

    name: str
    version: str
    risk_score: float  # 0-100
    risk_level: RiskLevel
    issues: list[str] = field(default_factory=list)
    vulnerability_count: int = 0
    highest_severity: str = "NONE"
    is_outdated: bool = False
    is_unmaintained: bool = False
    is_yanked: bool = False
    is_removed: bool = False
    latest_version: str | None = None
    last_release_date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level.value,
            "issues": self.issues,
            "vulnerability_count": self.vulnerability_count,
            "highest_severity": self.highest_severity,
            "is_outdated": self.is_outdated,
            "is_unmaintained": self.is_unmaintained,
            "is_yanked": self.is_yanked,
            "is_removed": self.is_removed,
            "latest_version": self.latest_version,
            "last_release_date": self.last_release_date,
        }


@dataclass
class RemediationAction:
    """A specific remediation action for the audit report."""

    package: str
    action: str  # "upgrade", "replace", "remove", "pin", "review"
    description: str
    urgency: str  # "critical", "high", "medium", "low"
    from_version: str | None = None
    to_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "action": self.action,
            "description": self.description,
            "urgency": self.urgency,
            "from_version": self.from_version,
            "to_version": self.to_version,
        }


@dataclass
class AuditResult:
    """Complete security audit result."""

    project_path: str
    total_packages: int = 0
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.NONE
    severity_breakdown: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    vulnerable_packages: list[PackageRisk] = field(default_factory=list)
    all_risks: list[PackageRisk] = field(default_factory=list)
    remediations: list[RemediationAction] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityDetail] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "total_packages": self.total_packages,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level.value,
            "severity_breakdown": self.severity_breakdown.to_dict(),
            "vulnerable_packages": [p.to_dict() for p in self.vulnerable_packages],
            "all_risks": [p.to_dict() for p in self.all_risks],
            "remediations": [r.to_dict() for r in self.remediations],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "files_scanned": self.files_scanned,
            "errors": self.errors,
        }


# ── Risk scoring ─────────────────────────────────────────────────────────

# Weights for different risk factors
_VULN_SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 40.0,
    "HIGH": 25.0,
    "MODERATE": 15.0,
    "MEDIUM": 15.0,
    "LOW": 5.0,
    "UNKNOWN": 10.0,
}

_OUTDATED_PENALTY = 5.0
_UNMAINTAINED_PENALTY = 15.0
_YANKED_PENALTY = 30.0
_REMOVED_PENALTY = 50.0


def _compute_package_risk(pkg: PackageReport) -> PackageRisk:
    """Compute risk score and level for a single package.

    Scoring model:
    - Each vulnerability contributes based on severity (CRITICAL=40, HIGH=25, etc.)
    - Multiple vulns stack but with diminishing returns
    - Outdated: +5, Unmaintained: +15, Yanked: +30, Removed: +50
    - Score is capped at 100
    """
    score = 0.0
    issues: list[str] = []
    vuln_count = len(pkg.vulnerabilities)
    highest_sev = "NONE"

    # Vulnerability scoring with diminishing returns
    if pkg.vulnerabilities:
        # Sort by severity (highest first)
        sorted_vulns = sorted(
            pkg.vulnerabilities,
            key=lambda v: _SEVERITY_ORDER.get(v.severity.upper(), 0),
            reverse=True,
        )
        highest_sev = sorted_vulns[0].severity.upper()

        for i, vuln in enumerate(sorted_vulns):
            base_weight = _VULN_SEVERITY_WEIGHTS.get(vuln.severity.upper(), 10.0)
            # Diminishing returns: 1st vuln = full weight, 2nd = 0.7x, 3rd = 0.5x, etc.
            multiplier = 1.0 / (1.0 + i * 0.5)
            score += base_weight * multiplier

        sev_label = highest_sev
        if vuln_count == 1:
            issues.append(f"1 {sev_label} vulnerability")
        else:
            issues.append(f"{vuln_count} vulnerabilities (highest: {sev_label})")

    # Status-based penalties
    if pkg.is_removed:
        score += _REMOVED_PENALTY
        issues.append("Package removed from PyPI")
    elif pkg.is_yanked:
        score += _YANKED_PENALTY
        issues.append("Version yanked from PyPI")
    elif pkg.status == HealthStatus.UNMAINTAINED:
        score += _UNMAINTAINED_PENALTY
        issues.append(f"No updates in >1 year (last: {pkg.last_release_date or 'unknown'})")
    elif pkg.is_outdated:
        score += _OUTDATED_PENALTY
        issues.append(f"Outdated: {pkg.installed_version} → {pkg.latest_version}")

    # License issue penalty
    if pkg.has_license_issue:
        score += 5.0
        issues.append("License compliance issue")

    # Cap at 100
    score = min(score, 100.0)

    # Determine risk level
    if score >= 75:
        risk_level = RiskLevel.CRITICAL
    elif score >= 50:
        risk_level = RiskLevel.HIGH
    elif score >= 25:
        risk_level = RiskLevel.MEDIUM
    elif score > 0:
        risk_level = RiskLevel.LOW
    else:
        risk_level = RiskLevel.NONE

    return PackageRisk(
        name=pkg.name,
        version=pkg.installed_version,
        risk_score=score,
        risk_level=risk_level,
        issues=issues,
        vulnerability_count=vuln_count,
        highest_severity=highest_sev,
        is_outdated=pkg.is_outdated,
        is_unmaintained=pkg.is_unmaintained,
        is_yanked=pkg.is_yanked,
        is_removed=pkg.is_removed,
        latest_version=pkg.latest_version,
        last_release_date=pkg.last_release_date,
    )


def _compute_project_risk(risks: list[PackageRisk]) -> tuple[float, RiskLevel]:
    """Compute overall project risk score from individual package risks.

    The project score is a weighted average where the worst packages
    have more influence. Uses a power-mean approach.
    """
    if not risks:
        return 0.0, RiskLevel.NONE

    scores = [r.risk_score for r in risks]
    total = len(scores)

    if total == 0:
        return 0.0, RiskLevel.NONE

    # Weighted mean: give 3x weight to packages above the median
    sorted_scores = sorted(scores, reverse=True)
    median = sorted_scores[len(sorted_scores) // 2] if len(sorted_scores) > 1 else sorted_scores[0]

    weighted_sum = 0.0
    weight_total = 0.0
    for s in scores:
        weight = 3.0 if s >= median and s > 0 else 1.0
        weighted_sum += s * weight
        weight_total += weight

    score = weighted_sum / weight_total if weight_total > 0 else 0.0

    # Boost if any package is CRITICAL
    if any(r.risk_level == RiskLevel.CRITICAL for r in risks):
        score = max(score, 50.0)  # Floor at HIGH if any critical package

    # Determine level
    if score >= 75:
        level = RiskLevel.CRITICAL
    elif score >= 50:
        level = RiskLevel.HIGH
    elif score >= 25:
        level = RiskLevel.MEDIUM
    elif score > 0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.NONE

    return score, level


# ── Remediation engine ──────────────────────────────────────────────────


def _generate_remediations(pkg: PackageReport, risk: PackageRisk) -> list[RemediationAction]:
    """Generate specific remediation actions for a package."""
    actions: list[RemediationAction] = []

    if pkg.is_removed:
        actions.append(
            RemediationAction(
                package=pkg.name,
                action="remove",
                description=(
                    f"{pkg.name} no longer exists on PyPI — "
                    "remove immediately and find an alternative"
                ),
                urgency="critical",
                from_version=pkg.installed_version,
            )
        )
        return actions

    if pkg.is_yanked:
        actions.append(
            RemediationAction(
                package=pkg.name,
                action="pin",
                description=f"Version {pkg.installed_version} was yanked — pin to a safe version",
                urgency="high",
                from_version=pkg.installed_version,
            )
        )

    # Vulnerability remediations
    if pkg.vulnerabilities:
        # Check if upgrading would fix (if latest version is newer)
        if pkg.latest_version and pkg.is_outdated:
            # Heuristic: if latest version is newer, upgrading likely fixes some vulns
            actions.append(
                RemediationAction(
                    package=pkg.name,
                    action="upgrade",
                    description=(
                        f"Upgrade from {pkg.installed_version} to "
                        f"{pkg.latest_version} to address vulnerabilities"
                    ),
                    urgency="critical" if risk.highest_severity in ("CRITICAL", "HIGH") else "high",
                    from_version=pkg.installed_version,
                    to_version=pkg.latest_version,
                )
            )
        else:
            # No upgrade available — need to review or replace
            highest = risk.highest_severity
            if highest in ("CRITICAL", "HIGH"):
                actions.append(
                    RemediationAction(
                        package=pkg.name,
                        action="review",
                        description=(
                            f"No safe upgrade available — review {pkg.name} "
                            "for alternative packages or apply patches"
                        ),
                        urgency="critical",
                        from_version=pkg.installed_version,
                    )
                )
            else:
                actions.append(
                    RemediationAction(
                        package=pkg.name,
                        action="review",
                        description=f"Review {pkg.name} for known workarounds or mitigations",
                        urgency="medium",
                        from_version=pkg.installed_version,
                    )
                )

    # Outdated but not vulnerable
    if pkg.is_outdated and not pkg.vulnerabilities:
        actions.append(
            RemediationAction(
                package=pkg.name,
                action="upgrade",
                description=(
                    f"Upgrade from {pkg.installed_version} to "
                    f"{pkg.latest_version} for latest patches"
                ),
                urgency="low",
                from_version=pkg.installed_version,
                to_version=pkg.latest_version,
            )
        )

    # Unmaintained
    if pkg.is_unmaintained and not pkg.is_removed:
        actions.append(
            RemediationAction(
                package=pkg.name,
                action="replace",
                description=(
                    f"{pkg.name} appears unmaintained "
                    f"(last release: {pkg.last_release_date or 'unknown'}) "
                    "— consider an actively maintained alternative"
                ),
                urgency="medium",
                from_version=pkg.installed_version,
            )
        )

    return actions


def _compute_severity_breakdown(packages: list[PackageReport]) -> SeverityBreakdown:
    """Count vulnerabilities by severity across all packages."""
    breakdown = SeverityBreakdown()
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            sev = vuln.severity.upper()
            if sev in ("CRITICAL",):
                breakdown.critical += 1
            elif sev in ("HIGH",):
                breakdown.high += 1
            elif sev in ("MEDIUM", "MODERATE"):
                breakdown.medium += 1
            elif sev in ("LOW",):
                breakdown.low += 1
            else:
                breakdown.unknown += 1
    return breakdown


def _build_vulnerability_details(packages: list[PackageReport]) -> list[VulnerabilityDetail]:
    """Build detailed vulnerability entries for the audit report."""
    details: list[VulnerabilityDetail] = []
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            fix_available = pkg.is_outdated and pkg.latest_version is not None
            details.append(
                VulnerabilityDetail(
                    vuln_id=vuln.vuln_id,
                    package=pkg.name,
                    installed_version=pkg.installed_version,
                    severity=vuln.severity,
                    summary=vuln.summary,
                    url=vuln.url,
                    aliases=vuln.aliases,
                    fix_available=fix_available,
                    fixed_in_version=pkg.latest_version if fix_available else None,
                )
            )
    # Sort by severity (highest first), then by package name
    details.sort(
        key=lambda d: (_SEVERITY_ORDER.get(d.severity.upper(), 0), d.package),
        reverse=True,
    )
    return details


# ── Main audit function ─────────────────────────────────────────────────


def run_audit(
    project_path: str,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
) -> AuditResult:
    """Run a comprehensive security audit on a project.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.

    Returns:
        An AuditResult with risk scores, severity breakdowns,
        and remediation actions.
    """
    result = scan_project(
        project_path=project_path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )

    # Compute per-package risks
    all_risks: list[PackageRisk] = []
    vulnerable_risks: list[PackageRisk] = []
    all_remediations: list[RemediationAction] = []

    for pkg in result.packages:
        risk = _compute_package_risk(pkg)
        all_risks.append(risk)

        if risk.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
            vulnerable_risks.append(risk)

        if risk.risk_score > 0:
            remediations = _generate_remediations(pkg, risk)
            all_remediations.extend(remediations)

    # Sort risks by score (highest first)
    all_risks.sort(key=lambda r: r.risk_score, reverse=True)
    vulnerable_risks.sort(key=lambda r: r.risk_score, reverse=True)

    # Sort remediations by urgency
    urgency_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_remediations.sort(key=lambda r: urgency_order.get(r.urgency, 4))

    # Compute project-level risk
    project_score, project_level = _compute_project_risk(all_risks)

    # Compute severity breakdown
    severity_breakdown = _compute_severity_breakdown(result.packages)

    # Build vulnerability details
    vuln_details = _build_vulnerability_details(result.packages)

    return AuditResult(
        project_path=result.project_path,
        total_packages=result.total,
        risk_score=project_score,
        risk_level=project_level,
        severity_breakdown=severity_breakdown,
        vulnerable_packages=vulnerable_risks,
        all_risks=all_risks,
        remediations=all_remediations,
        vulnerabilities=vuln_details,
        files_scanned=result.files_scanned,
        errors=result.errors,
    )


# ── Rendering ────────────────────────────────────────────────────────────


_RISK_STYLES: dict[RiskLevel, tuple[str, str]] = {
    RiskLevel.CRITICAL: ("🔴", "bold red"),
    RiskLevel.HIGH: ("🟠", "bold yellow"),
    RiskLevel.MEDIUM: ("🟡", "yellow"),
    RiskLevel.LOW: ("🟢", "green"),
    RiskLevel.NONE: ("✅", "bold green"),
}

_SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "CRITICAL": ("🔴", "bold red"),
    "HIGH": ("🟠", "red"),
    "MEDIUM": ("🟡", "yellow"),
    "MODERATE": ("🟡", "yellow"),
    "LOW": ("🟢", "green"),
    "UNKNOWN": ("⚪", "white"),
}

_URGENCY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


def render_audit_table(audit: AuditResult, console: Console | None = None) -> None:
    """Render the audit report as Rich tables.

    Args:
        audit: The audit result to render.
        console: Rich console (created if not provided).
    """
    from rich.console import Console as RichConsole
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    if console is None:
        console = RichConsole()
    assert console is not None

    # ── Header ───────────────────────────────────────────────────────

    risk_icon, risk_style = _RISK_STYLES.get(audit.risk_level, ("⚪", "white"))
    risk_text = Text()
    risk_text.append("Security Audit: ", style="bold")
    risk_text.append(audit.project_path, style="cyan")
    risk_text.append("\n")
    risk_text.append(f"  Risk Score: {audit.risk_score:.1f}/100  ")
    risk_text.append(f"{risk_icon} {audit.risk_level.value.upper()}", style=risk_style)
    risk_text.append(f"\n  Packages: {audit.total_packages}  ")
    risk_text.append(
        f"Vulnerabilities: {audit.severity_breakdown.total}",
        style="red" if audit.severity_breakdown.total > 0 else "green",
    )

    console.print(Panel(risk_text, border_style=risk_style, padding=(1, 2)))

    # ── Severity breakdown ───────────────────────────────────────────

    if audit.severity_breakdown.total > 0:
        sev_table = Table(title="Vulnerability Severity Breakdown", show_lines=False)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        sev_table.add_column("Bar", min_width=20)

        for sev_name, count in [
            ("CRITICAL", audit.severity_breakdown.critical),
            ("HIGH", audit.severity_breakdown.high),
            ("MEDIUM", audit.severity_breakdown.medium),
            ("LOW", audit.severity_breakdown.low),
            ("UNKNOWN", audit.severity_breakdown.unknown),
        ]:
            if count > 0:
                icon, style = _SEVERITY_STYLES.get(sev_name, ("⚪", "white"))
                bar_len = min(int(count / max(audit.severity_breakdown.total, 1) * 20), 20)
                bar = "█" * bar_len
                sev_table.add_row(
                    f"{icon} {sev_name}",
                    str(count),
                    f"[{style}]{bar}[/{style}]",
                )

        console.print(sev_table)
        console.print()

    # ── At-risk packages ─────────────────────────────────────────────

    if audit.vulnerable_packages:
        risk_table = Table(title="At-Risk Packages", show_lines=False)
        risk_table.add_column("Risk", width=6)
        risk_table.add_column("Package", style="bold")
        risk_table.add_column("Version", style="cyan")
        risk_table.add_column("Score", justify="right")
        risk_table.add_column("Issues")

        for pkg_risk in audit.vulnerable_packages:
            icon, style = _RISK_STYLES.get(pkg_risk.risk_level, ("⚪", "white"))
            issues_text = "; ".join(pkg_risk.issues) if pkg_risk.issues else "—"
            risk_table.add_row(
                f"[{style}]{icon}[/{style}]",
                pkg_risk.name,
                pkg_risk.version,
                f"[{style}]{pkg_risk.risk_score:.0f}[/{style}]",
                issues_text,
            )

        console.print(risk_table)
        console.print()

    # ── Vulnerability details ────────────────────────────────────────

    if audit.vulnerabilities:
        vuln_table = Table(title="Vulnerability Details", show_lines=True)
        vuln_table.add_column("ID", style="bold cyan", max_width=20)
        vuln_table.add_column("Package", style="bold")
        vuln_table.add_column("Severity", width=10)
        vuln_table.add_column("Summary", max_width=50, no_wrap=True)
        vuln_table.add_column("Fix", width=6)

        for vuln in audit.vulnerabilities:
            sev_icon, sev_style = _SEVERITY_STYLES.get(vuln.severity.upper(), ("⚪", "white"))
            fix_icon = "✅" if vuln.fix_available else "❌"
            summary = vuln.summary[:80] + "…" if len(vuln.summary) > 80 else vuln.summary

            vuln_table.add_row(
                vuln.vuln_id,
                vuln.package,
                f"[{sev_style}]{sev_icon} {vuln.severity}[/{sev_style}]",
                summary,
                fix_icon,
            )

        console.print(vuln_table)
        console.print()

    # ── Remediation actions ──────────────────────────────────────────

    if audit.remediations:
        rem_table = Table(title="Remediation Actions", show_lines=False)
        rem_table.add_column("Urgency", width=10)
        rem_table.add_column("Action", style="bold")
        rem_table.add_column("Package", style="cyan")
        rem_table.add_column("Description")

        for rem in audit.remediations:
            urgency_style = _URGENCY_STYLES.get(rem.urgency, "white")
            rem_table.add_row(
                f"[{urgency_style}]{rem.urgency.upper()}[/{urgency_style}]",
                rem.action.upper(),
                rem.package,
                rem.description,
            )

        console.print(rem_table)
        console.print()

    # ── Clean report ─────────────────────────────────────────────────

    if not audit.vulnerable_packages and not audit.vulnerabilities:
        console.print(
            Panel(
                "[bold green]✅ No security issues found![/bold green]\n"
                "All dependencies appear healthy.",
                border_style="green",
                padding=(1, 2),
            )
        )


def render_audit_json(audit: AuditResult, console: Console | None = None) -> None:
    """Render the audit report as JSON.

    Args:
        audit: The audit result to render.
        console: Rich console for output (created if not provided).
    """
    import json

    from rich.console import Console as RichConsole

    if console is None:
        console = RichConsole(force_terminal=False, no_color=True)
    assert console is not None

    console.print(json.dumps(audit.to_dict(), indent=2))
