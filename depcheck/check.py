"""Comprehensive health check for Python project dependencies.

Runs all depcheck analysis modules in one pass — vulnerabilities, outdated
packages, license compliance, dependency freshness, maintainer activity,
and transitive dependency depth — then produces an aggregated HealthReport
with an overall score (0–100) and per-category grades.

This is the single-command entry point for CI pipelines and quick
project audits.
"""

from __future__ import annotations

import enum
import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.version import Version

from depcheck.audit import RiskLevel, run_audit
from depcheck.models import HealthStatus, ScanResult
from depcheck.scanner import scan_project

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class Grade(enum.Enum):
    """Letter grade for a health category."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @classmethod
    def from_score(cls, score: float) -> Grade:
        """Convert a 0–100 numeric score to a letter grade."""
        if score >= 90:
            return cls.A
        if score >= 75:
            return cls.B
        if score >= 55:
            return cls.C
        if score >= 35:
            return cls.D
        return cls.F


@dataclass
class CategoryScore:
    """Score for a single health category."""

    name: str
    score: float  # 0–100
    grade: Grade
    weight: float  # relative weight in overall score
    details: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 1),
            "grade": self.grade.value,
            "weight": self.weight,
            "details": self.details,
            "recommendations": self.recommendations,
        }


@dataclass
class DependencyFreshness:
    """Freshness analysis for a single package."""

    name: str
    installed_version: str
    latest_version: str | None
    days_behind: int | None = None
    releases_behind: int | None = None
    freshness_ratio: float | None = None  # 0.0–1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "days_behind": self.days_behind,
            "releases_behind": self.releases_behind,
            "freshness_ratio": round(self.freshness_ratio, 3) if self.freshness_ratio else None,
        }


@dataclass
class MaintainerSignal:
    """Maintainer activity signal for a package."""

    name: str
    signal: str  # "active", "slow", "inactive", "unknown"
    days_since_release: int | None = None
    total_releases: int | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "signal": self.signal,
            "days_since_release": self.days_since_release,
            "total_releases": self.total_releases,
            "note": self.note,
        }


@dataclass
class TransitiveDepth:
    """Transitive dependency depth info for a package."""

    name: str
    max_depth: int
    transitive_count: int
    deepest_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "max_depth": self.max_depth,
            "transitive_count": self.transitive_count,
            "deepest_path": self.deepest_path,
        }


@dataclass
class HealthReport:
    """Aggregated health report for a project."""

    project_path: str
    overall_score: float = 0.0
    overall_grade: Grade = Grade.F
    categories: list[CategoryScore] = field(default_factory=list)
    freshness: list[DependencyFreshness] = field(default_factory=list)
    maintainer_signals: list[MaintainerSignal] = field(default_factory=list)
    transitive_depths: list[TransitiveDepth] = field(default_factory=list)
    scan_result: ScanResult | None = None
    audit_risk_level: RiskLevel = RiskLevel.NONE
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "overall_score": round(self.overall_score, 1),
            "overall_grade": self.overall_grade.value,
            "categories": [c.to_dict() for c in self.categories],
            "freshness": [f.to_dict() for f in self.freshness],
            "maintainer_signals": [m.to_dict() for m in self.maintainer_signals],
            "transitive_depths": [t.to_dict() for t in self.transitive_depths],
            "audit_risk_level": self.audit_risk_level.value,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

# Weights for each category (must sum to 1.0)
DEFAULT_WEIGHTS: dict[str, float] = {
    "vulnerability": 0.30,
    "freshness": 0.20,
    "license": 0.15,
    "maintenance": 0.15,
    "transitive_depth": 0.10,
    "outdated": 0.10,
}


def _score_vulnerability(scan_result: ScanResult) -> CategoryScore:
    """Score the vulnerability health of the project.

    Starting score is 100. Each vulnerability deducts points based on
    severity: CRITICAL -30, HIGH -15, MEDIUM -8, LOW -3.
    """
    vuln_packages = [p for p in scan_result.packages if p.status == HealthStatus.VULNERABLE]
    all_vulns: list[Any] = []
    for pkg in vuln_packages:
        all_vulns.extend(pkg.vulnerabilities)

    deductions = 0.0
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in all_vulns:
        sev = v.severity.lower() if v.severity else "unknown"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if sev == "critical":
            deductions += 30
        elif sev == "high":
            deductions += 15
        elif sev == "medium":
            deductions += 8
        elif sev == "low":
            deductions += 3
        else:
            deductions += 5

    score = max(0.0, 100.0 - deductions)
    grade = Grade.from_score(score)

    recs: list[str] = []
    if sev_counts.get("critical", 0) > 0:
        recs.append(
            f"CRITICAL: {sev_counts['critical']} critical vulnerabilit"
            f"{'y' if sev_counts['critical'] == 1 else 'ies'} found — upgrade immediately"
        )
    if sev_counts.get("high", 0) > 0:
        recs.append(
            f"HIGH: {sev_counts['high']} high-severity vulnerabilit"
            f"{'y' if sev_counts['high'] == 1 else 'ies'} need attention"
        )
    if not vuln_packages:
        recs.append("No known vulnerabilities detected")

    return CategoryScore(
        name="vulnerability",
        score=score,
        grade=grade,
        weight=DEFAULT_WEIGHTS["vulnerability"],
        details={
            "vulnerable_packages": len(vuln_packages),
            "total_vulnerabilities": len(all_vulns),
            "severity_counts": sev_counts,
        },
        recommendations=recs,
    )


def _score_freshness(
    scan_result: ScanResult,
    freshness_data: list[DependencyFreshness],
) -> CategoryScore:
    """Score the dependency freshness of the project.

    Measures how close installed versions are to latest releases.
    A package that is at the latest version gets 100; one that is
    365+ days behind gets 0. The project score is the average.
    """
    if not freshness_data:
        return CategoryScore(
            name="freshness",
            score=100.0,
            grade=Grade.A,
            weight=DEFAULT_WEIGHTS["freshness"],
            details={"message": "No freshness data available"},
            recommendations=["Unable to determine freshness — check PyPI connectivity"],
        )

    scores: list[float] = []
    stale_count = 0
    very_stale_count = 0

    for f in freshness_data:
        if f.freshness_ratio is not None:
            # freshness_ratio is 0–1; convert to 0–100
            pkg_score = f.freshness_ratio * 100.0
        elif f.days_behind is not None:
            if f.days_behind == 0:
                pkg_score = 100.0
            else:
                # Exponential decay: half-life of 90 days
                pkg_score = 100.0 * math.exp(-0.0077 * f.days_behind)
        else:
            pkg_score = 50.0  # unknown

        scores.append(pkg_score)
        if f.days_behind is not None:
            if f.days_behind > 365:
                very_stale_count += 1
            elif f.days_behind > 180:
                stale_count += 1

    avg_score = sum(scores) / len(scores) if scores else 0.0
    grade = Grade.from_score(avg_score)

    recs: list[str] = []
    if very_stale_count > 0:
        recs.append(
            f"{very_stale_count} package{'s' if very_stale_count != 1 else ''} "
            "more than 365 days behind latest release"
        )
    if stale_count > 0:
        recs.append(
            f"{stale_count} package{'s' if stale_count != 1 else ''} "
            "more than 180 days behind latest release"
        )
    if not recs:
        recs.append("All dependencies are reasonably up to date")

    return CategoryScore(
        name="freshness",
        score=avg_score,
        grade=grade,
        weight=DEFAULT_WEIGHTS["freshness"],
        details={
            "average_days_behind": (
                round(
                    sum(f.days_behind for f in freshness_data if f.days_behind is not None)
                    / max(1, sum(1 for f in freshness_data if f.days_behind is not None)),
                    1,
                )
            ),
            "stale_count": stale_count,
            "very_stale_count": very_stale_count,
        },
        recommendations=recs,
    )


def _score_license(scan_result: ScanResult) -> CategoryScore:
    """Score the license compliance health.

    100 if all packages are compliant; deductions for each
    non-compliant package (-15 per violation).
    """
    total = len(scan_result.packages)
    if total == 0:
        return CategoryScore(
            name="license",
            score=100.0,
            grade=Grade.A,
            weight=DEFAULT_WEIGHTS["license"],
            details={"message": "No packages to check"},
            recommendations=[],
        )

    non_compliant = sum(1 for p in scan_result.packages if p.has_license_issue)
    unknown = sum(
        1 for p in scan_result.packages if p.license_info and p.license_info.category == "unknown"
    )
    compliant = total - non_compliant

    deduction = non_compliant * 15
    score = max(0.0, 100.0 - deduction)
    grade = Grade.from_score(score)

    recs: list[str] = []
    if non_compliant > 0:
        recs.append(
            f"{non_compliant} package{'s' if non_compliant != 1 else ''} "
            "with license compliance violations"
        )
    if unknown > 0:
        recs.append(
            f"{unknown} package{'s' if unknown != 1 else ''} with unknown/unclassified licenses"
        )
    if not recs:
        recs.append("All licenses are compliant")

    return CategoryScore(
        name="license",
        score=score,
        grade=grade,
        weight=DEFAULT_WEIGHTS["license"],
        details={
            "total_packages": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "unknown_licenses": unknown,
        },
        recommendations=recs,
    )


def _score_maintenance(
    signals: list[MaintainerSignal],
) -> CategoryScore:
    """Score the maintainer activity health.

    Active packages get 100, slow get 60, inactive get 20, unknown get 50.
    Project score is the average.
    """
    if not signals:
        return CategoryScore(
            name="maintenance",
            score=50.0,
            grade=Grade.C,
            weight=DEFAULT_WEIGHTS["maintenance"],
            details={"message": "No maintainer data available"},
            recommendations=["Could not determine maintainer activity"],
        )

    signal_scores = {"active": 100.0, "slow": 60.0, "inactive": 20.0, "unknown": 50.0}
    scores = [signal_scores.get(s.signal, 50.0) for s in signals]
    avg = sum(scores) / len(scores)
    grade = Grade.from_score(avg)

    inactive_count = sum(1 for s in signals if s.signal == "inactive")
    slow_count = sum(1 for s in signals if s.signal == "slow")

    recs: list[str] = []
    if inactive_count > 0:
        recs.append(
            f"{inactive_count} package{'s' if inactive_count != 1 else ''} "
            "appear inactive — consider alternatives"
        )
    if slow_count > 0:
        recs.append(
            f"{slow_count} package{'s' if slow_count != 1 else ''} have slow release cadence"
        )
    if not recs:
        recs.append("All dependencies appear actively maintained")

    return CategoryScore(
        name="maintenance",
        score=avg,
        grade=grade,
        weight=DEFAULT_WEIGHTS["maintenance"],
        details={
            "active": sum(1 for s in signals if s.signal == "active"),
            "slow": slow_count,
            "inactive": inactive_count,
            "unknown": sum(1 for s in signals if s.signal == "unknown"),
        },
        recommendations=recs,
    )


def _score_transitive_depth(
    depths: list[TransitiveDepth],
) -> CategoryScore:
    """Score transitive dependency depth health.

    Deeper dependency chains are riskier. Score per package:
    depth 0-1 → 100, depth 2 → 90, depth 3 → 70, depth 4+ → 50 - (depth-4)*5.
    """
    if not depths:
        return CategoryScore(
            name="transitive_depth",
            score=100.0,
            grade=Grade.A,
            weight=DEFAULT_WEIGHTS["transitive_depth"],
            details={"message": "No transitive depth data available"},
            recommendations=[],
        )

    def _pkg_score(d: int) -> float:
        if d <= 1:
            return 100.0
        if d == 2:
            return 90.0
        if d == 3:
            return 70.0
        return max(10.0, 50.0 - (d - 4) * 5)

    scores = [_pkg_score(t.max_depth) for t in depths]
    avg = sum(scores) / len(scores)
    grade = Grade.from_score(avg)

    deep_count = sum(1 for t in depths if t.max_depth >= 4)
    very_deep = sum(1 for t in depths if t.max_depth >= 6)

    recs: list[str] = []
    if very_deep > 0:
        recs.append(
            f"{very_deep} package{'s' if very_deep != 1 else ''} with depth ≥ 6 "
            "— significant transitive dependency risk"
        )
    if deep_count > 0:
        recs.append(
            f"{deep_count} package{'s' if deep_count != 1 else ''} with depth ≥ 4 "
            "— review transitive dependencies"
        )
    if not recs:
        recs.append("Dependency depth is within healthy limits")

    return CategoryScore(
        name="transitive_depth",
        score=avg,
        grade=grade,
        weight=DEFAULT_WEIGHTS["transitive_depth"],
        details={
            "max_depth_found": max(t.max_depth for t in depths),
            "average_depth": round(sum(t.max_depth for t in depths) / len(depths), 1),
            "deep_count": deep_count,
            "very_deep_count": very_deep,
        },
        recommendations=recs,
    )


def _score_outdated(scan_result: ScanResult) -> CategoryScore:
    """Score the outdated-package health.

    Outdated packages get 0 score, current packages get 100.
    Major-version-behind: additional penalty multiplier.
    """
    total = len(scan_result.packages)
    if total == 0:
        return CategoryScore(
            name="outdated",
            score=100.0,
            grade=Grade.A,
            weight=DEFAULT_WEIGHTS["outdated"],
            details={"message": "No packages to check"},
            recommendations=[],
        )

    outdated_pkgs = [p for p in scan_result.packages if p.is_outdated]
    current_pkgs = total - len(outdated_pkgs)

    # Classify how far behind
    major_behind = 0
    minor_behind = 0
    patch_behind = 0

    for pkg in outdated_pkgs:
        if pkg.latest_version:
            try:
                inst = Version(pkg.installed_version)
                lat = Version(pkg.latest_version)
                if inst.major < lat.major:
                    major_behind += 1
                elif inst.minor < lat.minor:
                    minor_behind += 1
                else:
                    patch_behind += 1
            except Exception:
                major_behind += 1  # assume worst

    # Weighted score: major behind is worse than minor behind
    score = max(
        0.0,
        100.0 - (major_behind * 20 + minor_behind * 8 + patch_behind * 3),
    )
    grade = Grade.from_score(score)

    recs: list[str] = []
    if major_behind > 0:
        recs.append(
            f"{major_behind} package{'s' if major_behind != 1 else ''} "
            "with major version updates available"
        )
    if minor_behind > 0:
        recs.append(
            f"{minor_behind} package{'s' if minor_behind != 1 else ''} "
            "with minor version updates available"
        )
    if not recs:
        recs.append("All packages are at their latest versions")

    return CategoryScore(
        name="outdated",
        score=score,
        grade=grade,
        weight=DEFAULT_WEIGHTS["outdated"],
        details={
            "total": total,
            "current": current_pkgs,
            "outdated": len(outdated_pkgs),
            "major_behind": major_behind,
            "minor_behind": minor_behind,
            "patch_behind": patch_behind,
        },
        recommendations=recs,
    )


# ---------------------------------------------------------------------------
# Freshness analysis
# ---------------------------------------------------------------------------


def analyze_freshness(scan_result: ScanResult) -> list[DependencyFreshness]:
    """Compute freshness data for each package in a scan result.

    Uses last_release_date from PackageReport when available.
    Estimates days_behind based on release cadence.
    """
    results: list[DependencyFreshness] = []

    for pkg in scan_result.packages:
        days_behind: int | None = None
        freshness_ratio: float | None = None

        if pkg.last_release_date:
            try:
                # Parse ISO date
                release_dt = datetime.fromisoformat(pkg.last_release_date.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                delta = now - release_dt
                days_behind = max(0, delta.days)
            except Exception:
                pass

        if pkg.is_outdated and pkg.latest_version and days_behind is not None:
            # freshness ratio: 1.0 = current, decays to 0 over time
            freshness_ratio = max(0.0, 1.0 - (days_behind / 365.0))
        elif not pkg.is_outdated:
            freshness_ratio = 1.0
            days_behind = 0

        results.append(
            DependencyFreshness(
                name=pkg.name,
                installed_version=pkg.installed_version,
                latest_version=pkg.latest_version,
                days_behind=days_behind,
                freshness_ratio=freshness_ratio,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Maintainer signal analysis
# ---------------------------------------------------------------------------


def analyze_maintainer_signals(scan_result: ScanResult) -> list[MaintainerSignal]:
    """Analyze maintainer activity signals for each package.

    Uses last_release_date and health status to estimate activity level.
    """
    results: list[MaintainerSignal] = []

    for pkg in scan_result.packages:
        signal = "unknown"
        days_since: int | None = None
        note = ""

        if pkg.last_release_date:
            try:
                release_dt = datetime.fromisoformat(pkg.last_release_date.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                days_since = max(0, (now - release_dt).days)
            except Exception:
                pass

        if pkg.status == HealthStatus.UNMAINTAINED:
            signal = "inactive"
            note = "Flagged as unmaintained"
        elif days_since is not None:
            if days_since > 365:
                signal = "inactive"
                note = f"No release in {days_since} days"
            elif days_since > 180:
                signal = "slow"
                note = f"Last release {days_since} days ago"
            else:
                signal = "active"
                note = f"Last release {days_since} days ago"
        elif pkg.status == HealthStatus.YANKED:
            signal = "inactive"
            note = "Latest version was yanked"
        elif pkg.status == HealthStatus.REMOVED:
            signal = "inactive"
            note = "Package removed from PyPI"

        results.append(
            MaintainerSignal(
                name=pkg.name,
                signal=signal,
                days_since_release=days_since,
                note=note,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Transitive depth analysis (lightweight — from scan result metadata)
# ---------------------------------------------------------------------------


def analyze_transitive_depth(scan_result: ScanResult) -> list[TransitiveDepth]:
    """Estimate transitive dependency depth from scan result data.

    This is a lightweight estimation that doesn't do full tree resolution.
    It uses package metadata and dependency hints where available.
    For full tree analysis, use `depcheck tree`.
    """
    results: list[TransitiveDepth] = []

    for pkg in scan_result.packages:
        # Estimate depth based on common patterns
        # Heuristic: packages with many reverse deps tend to be deeper
        depth = 1  # default: direct dependency
        transitive = 0

        # Use status signals to estimate depth indirectly
        if pkg.status == HealthStatus.UNKNOWN and pkg.error:
            # Failed to resolve — likely a transitive dep
            depth = 2
            transitive = 1

        results.append(
            TransitiveDepth(
                name=pkg.name,
                max_depth=depth,
                transitive_count=transitive,
                deepest_path=[pkg.name],
            )
        )

    return results


# ---------------------------------------------------------------------------
# Main check runner
# ---------------------------------------------------------------------------


def run_check(
    project_path: str = ".",
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
    weights: dict[str, float] | None = None,
) -> HealthReport:
    """Run a comprehensive health check on a project.

    This orchestrates all sub-analyses and produces an aggregated
    HealthReport with an overall score and per-category grades.
    """
    start = time.monotonic()

    _ = weights or DEFAULT_WEIGHTS

    # Run the full scan
    scan_result = scan_project(
        project_path=project_path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )

    # Run audit for risk level
    try:
        audit_result = run_audit(
            project_path=project_path,
            check_vulnerabilities=check_vulnerabilities,
            check_licenses=check_licenses,
        )
        audit_risk = audit_result.risk_level
    except Exception:
        audit_risk = RiskLevel.NONE

    # Compute sub-analyses
    freshness_data = analyze_freshness(scan_result)
    maintainer_signals = analyze_maintainer_signals(scan_result)
    transitive_depths = analyze_transitive_depth(scan_result)

    # Score each category
    categories: list[CategoryScore] = [
        _score_vulnerability(scan_result),
        _score_freshness(scan_result, freshness_data),
        _score_license(scan_result),
        _score_maintenance(maintainer_signals),
        _score_transitive_depth(transitive_depths),
        _score_outdated(scan_result),
    ]

    # Normalize weights to sum to 1.0
    total_weight = sum(c.weight for c in categories)
    if total_weight > 0:
        for c in categories:
            c.weight = c.weight / total_weight

    # Compute overall weighted score
    overall = sum(c.score * c.weight for c in categories)
    overall_grade = Grade.from_score(overall)

    elapsed = time.monotonic() - start

    return HealthReport(
        project_path=str(Path(project_path).resolve()),
        overall_score=overall,
        overall_grade=overall_grade,
        categories=categories,
        freshness=freshness_data,
        maintainer_signals=maintainer_signals,
        transitive_depths=transitive_depths,
        scan_result=scan_result,
        audit_risk_level=audit_risk,
        duration_seconds=elapsed,
        errors=scan_result.errors,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_check_table(report: HealthReport, *, console: Any = None) -> None:
    """Render a Rich table health check report."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    if console is None:
        console = Console()

    # Header with overall score
    grade_colors = {
        Grade.A: "green",
        Grade.B: "bright_green",
        Grade.C: "yellow",
        Grade.D: "red",
        Grade.F: "bright_red",
    }
    grade_color = grade_colors.get(report.overall_grade, "white")

    header = Text()
    header.append("Overall Health: ", style="bold")
    header.append(
        f"{report.overall_grade.value} ({report.overall_score:.0f}/100)",
        style=f"bold {grade_color}",
    )
    header.append(f"\nProject: {report.project_path}", style="dim")
    header.append(f"\nDuration: {report.duration_seconds:.1f}s", style="dim")

    console.print(Panel(header, title="depcheck health", border_style=grade_color))

    # Category scores table
    cat_table = Table(title="Category Scores", show_lines=True)
    cat_table.add_column("Category", style="bold")
    cat_table.add_column("Score", justify="right")
    cat_table.add_column("Grade", justify="center")
    cat_table.add_column("Weight", justify="right", style="dim")
    cat_table.add_column("Key Findings")

    for cat in report.categories:
        cat_grade_color = grade_colors.get(cat.grade, "white")
        findings = "; ".join(cat.recommendations[:2]) if cat.recommendations else "—"
        cat_table.add_row(
            cat.name.title(),
            f"{cat.score:.0f}",
            f"[{cat_grade_color}]{cat.grade.value}[/{cat_grade_color}]",
            f"{cat.weight:.0%}",
            findings,
        )

    console.print(cat_table)

    # Vulnerability summary (if any)
    vuln_cat = next((c for c in report.categories if c.name == "vulnerability"), None)
    if vuln_cat and vuln_cat.details.get("total_vulnerabilities", 0) > 0:
        sev = vuln_cat.details.get("severity_counts", {})
        console.print(
            f"\n[red]⚠ {vuln_cat.details['total_vulnerabilities']} vulnerabilit"
            f"{'y' if vuln_cat.details['total_vulnerabilities'] == 1 else 'ies'}[/red] "
            f"(Critical: {sev.get('critical', 0)}, High: {sev.get('high', 0)}, "
            f"Medium: {sev.get('medium', 0)}, Low: {sev.get('low', 0)})"
        )

    # Stale packages (if any)
    fresh_cat = next((c for c in report.categories if c.name == "freshness"), None)
    if fresh_cat and fresh_cat.details.get("very_stale_count", 0) > 0:
        console.print(
            f"[yellow]⚠ {fresh_cat.details['very_stale_count']} package(s) "
            "more than 1 year behind latest release[/yellow]"
        )

    # Inactive packages (if any)
    maint_cat = next((c for c in report.categories if c.name == "maintenance"), None)
    if maint_cat and maint_cat.details.get("inactive", 0) > 0:
        console.print(
            f"[yellow]⚠ {maint_cat.details['inactive']} package(s) appear inactive[/yellow]"
        )

    # Recommendations
    all_recs: list[str] = []
    for cat in report.categories:
        all_recs.extend(cat.recommendations)

    if all_recs:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in all_recs[:8]:  # cap at 8 to avoid wall of text
            if rec.startswith("CRITICAL") or rec.startswith("HIGH"):
                console.print(f"  [red]• {rec}[/red]")
            elif "inactive" in rec.lower() or "stale" in rec.lower():
                console.print(f"  [yellow]• {rec}[/yellow]")
            else:
                console.print(f"  [green]• {rec}[/green]")

    console.print()


def render_check_json(report: HealthReport, *, console: Any = None) -> None:
    """Render the health report as JSON."""
    from rich.console import Console

    if console is None:
        console = Console(force_terminal=False, no_color=True)

    console.print(json.dumps(report.to_dict(), indent=2))
