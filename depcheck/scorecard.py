"""Dependency health scorecard for depcheck.

Generates a comprehensive health scorecard combining multiple analysis
dimensions: security, freshness, pinning quality, license compliance,
size efficiency, and maintenance status. Produces an overall project
health grade from A+ to F.

Features:
- Multi-dimensional health scoring (security, freshness, pinning, licenses, size, maintenance)
- Overall project health grade (A+ through F)
- Category-level scores with detailed breakdowns
- Trend comparison: compare scores between two scan points
- Actionable improvement suggestions ranked by impact
- Score weighting: configurable importance per category
- Markdown report generation for CI/CD integration
- Badge URL generation for README shields
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.depsize import build_size_report
from depcheck.models import ScanResult
from depcheck.pinpoint import build_pin_report
from depcheck.scanner import scan_project

# ── Enums & Constants ────────────────────────────────────────────────────


class Grade(enum.Enum):
    """Overall health grade."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class ScoreCategory(enum.Enum):
    """Categories of health scoring."""

    SECURITY = "security"
    FRESHNESS = "freshness"
    PINNING = "pinning"
    LICENSES = "licenses"
    SIZE = "size"
    MAINTENANCE = "maintenance"


# Grade thresholds (numeric score -> grade)
_GRADE_THRESHOLDS: list[tuple[float, Grade]] = [
    (95, Grade.A_PLUS),
    (85, Grade.A),
    (70, Grade.B),
    (55, Grade.C),
    (40, Grade.D),
    (0, Grade.F),
]

# Default category weights (sum to 1.0)
DEFAULT_WEIGHTS: dict[str, float] = {
    "security": 0.30,
    "freshness": 0.20,
    "pinning": 0.15,
    "licenses": 0.15,
    "size": 0.10,
    "maintenance": 0.10,
}


# ── Data Models ──────────────────────────────────────────────────────────


@dataclass
class CategoryScore:
    """Score for a single health category."""

    category: str
    score: float = 0.0  # 0-100
    weight: float = 0.0  # 0-1
    weighted_score: float = 0.0  # score * weight
    details: str = ""
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "category": self.category,
            "score": round(self.score, 1),
            "weight": self.weight,
            "weighted_score": round(self.weighted_score, 2),
            "details": self.details,
            "suggestions": self.suggestions,
        }


@dataclass
class ScorecardResult:
    """Complete health scorecard for a project."""

    project_path: str
    overall_score: float = 0.0
    grade: Grade = Grade.F
    category_scores: list[CategoryScore] = field(default_factory=list)
    top_suggestions: list[str] = field(default_factory=list)
    scan_result: ScanResult | None = None
    weights: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "overall_score": round(self.overall_score, 1),
            "grade": self.grade.value,
            "categories": [c.to_dict() for c in self.category_scores],
            "top_suggestions": self.top_suggestions,
            "weights": self.weights,
        }


# ── Scoring Functions ────────────────────────────────────────────────────


def _score_security(result: ScanResult) -> CategoryScore:
    """Score the security health of a project.

    Factors:
    - Vulnerable packages (major penalty)
    - Yanked packages (moderate penalty)
    - Removed packages (major penalty)
    """
    score = CategoryScore(category="security", weight=DEFAULT_WEIGHTS["security"])

    if result.total == 0:
        score.score = 100.0
        score.details = "No dependencies to analyze"
        return score

    vuln_penalty = result.vulnerable_count * 25  # -25 per vulnerable package
    yanked_penalty = result.yanked_count * 15
    removed_penalty = result.removed_count * 20

    raw_score = 100 - vuln_penalty - yanked_penalty - removed_penalty
    score.score = max(0, min(100, raw_score))

    # Details
    parts = []
    if result.vulnerable_count > 0:
        parts.append(f"{result.vulnerable_count} vulnerable")
        score.suggestions.append(
            "Fix vulnerable packages immediately — check 'depcheck audit' for details"
        )
    if result.yanked_count > 0:
        parts.append(f"{result.yanked_count} yanked")
        score.suggestions.append("Update yanked packages to non-yanked versions")
    if result.removed_count > 0:
        parts.append(f"{result.removed_count} removed")
        score.suggestions.append("Replace removed packages with maintained alternatives")
    if not parts:
        parts.append("No security issues found")

    score.details = ", ".join(parts)
    return score


def _score_freshness(result: ScanResult) -> CategoryScore:
    """Score how up-to-date the dependencies are.

    Factors:
    - Outdated packages (penalty based on how outdated)
    - Major versions behind (bigger penalty)
    """
    score = CategoryScore(category="freshness", weight=DEFAULT_WEIGHTS["freshness"])

    if result.total == 0:
        score.score = 100.0
        score.details = "No dependencies to analyze"
        return score

    healthy_ratio = result.healthy_count / result.total
    outdated_ratio = result.outdated_count / result.total

    # Start at 100, penalize for outdated
    raw_score = 100 * healthy_ratio - outdated_ratio * 20
    score.score = max(0, min(100, raw_score))

    if result.outdated_count > 0:
        score.details = f"{result.outdated_count}/{result.total} outdated"
        score.suggestions.append(
            "Run 'depcheck outdated' to see which packages have updates available"
        )
    else:
        score.details = "All packages are up to date"

    return score


def _score_pinning(project_path: str) -> CategoryScore:
    """Score the quality of version pinning.

    Uses the pinpoint module for detailed analysis.
    """
    score = CategoryScore(category="pinning", weight=DEFAULT_WEIGHTS["pinning"])

    try:
        pin_report = build_pin_report(project_path)
        score.score = pin_report.health_score
        score.details = (
            f"{pin_report.pinned_count}/{pin_report.total_dependencies} pinned "
            f"(score: {pin_report.health_score:.0f})"
        )
        if pin_report.unpinned_count > 0:
            score.suggestions.append(
                f"Pin {pin_report.unpinned_count} unpinned dependencies for reproducible builds"
            )
        if pin_report.recommendations:
            top_rec = pin_report.recommendations[0]
            score.suggestions.append(f"Pinning: {top_rec.rationale}")
    except Exception as e:
        score.score = 50.0
        score.details = f"Could not analyze pinning: {e}"

    return score


def _score_licenses(result: ScanResult) -> CategoryScore:
    """Score license compliance.

    Factors:
    - Packages with license issues
    - Packages with unknown licenses
    """
    score = CategoryScore(category="licenses", weight=DEFAULT_WEIGHTS["licenses"])

    if result.total == 0:
        score.score = 100.0
        score.details = "No dependencies to analyze"
        return score

    license_issue_count = result.license_issues_count
    unknown_count = sum(
        1 for p in result.packages if p.license_info is None or p.license_info.spdx_id == ""
    )

    raw_score = 100 - (license_issue_count * 20) - (unknown_count * 5)
    score.score = max(0, min(100, raw_score))

    parts = []
    if license_issue_count > 0:
        parts.append(f"{license_issue_count} violations")
        score.suggestions.append(
            "Run 'depcheck license' to identify and fix license compliance issues"
        )
    if unknown_count > 0:
        parts.append(f"{unknown_count} unknown")
        score.suggestions.append(
            f"Identify licenses for {unknown_count} packages with unknown licensing"
        )
    if not parts:
        parts.append("All licenses compliant")

    score.details = ", ".join(parts)
    return score


def _score_size(project_path: str, result: ScanResult) -> CategoryScore:
    """Score dependency size efficiency.

    Factors:
    - Number of bloated packages
    - Number of large packages
    - Total dependency footprint
    """
    score = CategoryScore(category="size", weight=DEFAULT_WEIGHTS["size"])

    if result.total == 0:
        score.score = 100.0
        score.details = "No dependencies to analyze"
        return score

    try:
        size_report = build_size_report(project_path)

        raw_score = 100.0
        raw_score -= len(size_report.bloated_packages) * 15
        raw_score -= len(size_report.large_packages) * 5

        # Penalty for very large total footprint
        if size_report.total_install_mb > 500:
            raw_score -= 10
        elif size_report.total_install_mb > 200:
            raw_score -= 5

        score.score = max(0, min(100, raw_score))

        parts = [f"Total: {size_report.total_install_mb:.0f}MB"]
        if size_report.bloated_packages:
            parts.append(f"{len(size_report.bloated_packages)} bloated")
            score.suggestions.append(
                "Consider alternatives for bloated packages: "
                + ", ".join(size_report.bloated_packages[:3])
            )
        if size_report.large_packages:
            parts.append(f"{len(size_report.large_packages)} large")
        if not size_report.bloated_packages and not size_report.large_packages:
            parts.append("No oversized packages")

        score.details = ", ".join(parts)
    except Exception:
        score.score = 70.0
        score.details = "Size analysis unavailable"

    return score


def _score_maintenance(result: ScanResult) -> CategoryScore:
    """Score the maintenance status of dependencies.

    Factors:
    - Unmaintained packages (no release in 1+ year)
    - Packages with no recent activity
    """
    score = CategoryScore(category="maintenance", weight=DEFAULT_WEIGHTS["maintenance"])

    if result.total == 0:
        score.score = 100.0
        score.details = "No dependencies to analyze"
        return score

    unmaintained_penalty = result.unmaintained_count * 15
    healthy_ratio = result.healthy_count / result.total

    raw_score = 100 * healthy_ratio - unmaintained_penalty
    score.score = max(0, min(100, raw_score))

    if result.unmaintained_count > 0:
        score.details = f"{result.unmaintained_count}/{result.total} unmaintained"
        score.suggestions.append(
            f"Replace {result.unmaintained_count} unmaintained packages"
            " with actively maintained alternatives"
        )
    else:
        score.details = "All packages actively maintained"

    return score


def _calculate_grade(score: float) -> Grade:
    """Convert a numeric score to a letter grade.

    Args:
        score: Numeric score (0-100).

    Returns:
        The corresponding Grade.
    """
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return Grade.F


# ── Main Scorecard Builder ───────────────────────────────────────────────


def build_scorecard(
    project_path: str,
    weights: dict[str, float] | None = None,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
) -> ScorecardResult:
    """Build a comprehensive health scorecard for a project.

    Args:
        project_path: Path to the project directory.
        weights: Optional custom weights for each category.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.

    Returns:
        ScorecardResult with the complete scorecard.
    """
    result = ScorecardResult(
        project_path=project_path,
        weights=weights or DEFAULT_WEIGHTS,
    )

    # Run the base scan
    scan = scan_project(
        project_path=project_path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )
    result.scan_result = scan

    w = weights or DEFAULT_WEIGHTS

    # Score each category
    security = _score_security(scan)
    security.weight = w.get("security", DEFAULT_WEIGHTS["security"])

    freshness = _score_freshness(scan)
    freshness.weight = w.get("freshness", DEFAULT_WEIGHTS["freshness"])

    pinning = _score_pinning(project_path)
    pinning.weight = w.get("pinning", DEFAULT_WEIGHTS["pinning"])

    licenses = _score_licenses(scan)
    licenses.weight = w.get("licenses", DEFAULT_WEIGHTS["licenses"])

    size = _score_size(project_path, scan)
    size.weight = w.get("size", DEFAULT_WEIGHTS["size"])

    maintenance = _score_maintenance(scan)
    maintenance.weight = w.get("maintenance", DEFAULT_WEIGHTS["maintenance"])

    # Calculate weighted scores
    for cat in [security, freshness, pinning, licenses, size, maintenance]:
        cat.weighted_score = cat.score * cat.weight

    result.category_scores = [security, freshness, pinning, licenses, size, maintenance]

    # Overall score
    result.overall_score = sum(c.weighted_score for c in result.category_scores)
    result.grade = _calculate_grade(result.overall_score)

    # Collect top suggestions (sorted by category weight * impact)
    all_suggestions: list[tuple[float, str]] = []
    for cat in result.category_scores:
        for suggestion in cat.suggestions:
            impact = (100 - cat.score) * cat.weight
            all_suggestions.append((impact, suggestion))

    all_suggestions.sort(key=lambda x: -x[0])
    result.top_suggestions = [s for _, s in all_suggestions[:5]]

    return result


# ── Badge Generation ─────────────────────────────────────────────────────


def generate_badge_url(scorecard: ScorecardResult) -> str:
    """Generate a shields.io badge URL for the scorecard grade.

    Args:
        scorecard: The scorecard result.

    Returns:
        shields.io badge URL.
    """
    grade = scorecard.grade.value
    score = round(scorecard.overall_score)

    color_map = {
        Grade.A_PLUS: "brightgreen",
        Grade.A: "green",
        Grade.B: "yellowgreen",
        Grade.C: "yellow",
        Grade.D: "orange",
        Grade.F: "red",
    }
    color = color_map.get(scorecard.grade, "lightgray")

    return f"https://img.shields.io/badge/depcheck-{grade}+({score})-{color}"


def generate_markdown_report(scorecard: ScorecardResult) -> str:
    """Generate a Markdown report for the scorecard.

    Args:
        scorecard: The scorecard result.

    Returns:
        Markdown string.
    """
    lines = [
        "# Depcheck Health Scorecard",
        "",
        f"**Project:** `{scorecard.project_path}`  ",
        f"**Overall Grade:** {scorecard.grade.value} ({scorecard.overall_score:.0f}/100)  ",
        "",
        f"![Score]({generate_badge_url(scorecard)})",
        "",
        "## Category Scores",
        "",
        "| Category | Score | Weight | Weighted | Details |",
        "|----------|-------|--------|----------|---------|",
    ]

    for cat in scorecard.category_scores:
        lines.append(
            f"| {cat.category} | {cat.score:.0f}/100 | {cat.weight:.0%} | "
            f"{cat.weighted_score:.1f} | {cat.details} |"
        )

    lines.append(
        f"| **Overall** | **{scorecard.overall_score:.0f}/100** | | **{scorecard.grade.value}** | |"
    )

    if scorecard.top_suggestions:
        lines.append("")
        lines.append("## Top Suggestions")
        lines.append("")
        for i, suggestion in enumerate(scorecard.top_suggestions, 1):
            lines.append(f"{i}. {suggestion}")

    lines.append("")
    lines.append("*Generated by [depcheck](https://github.com/jlaportebot/depcheck)*")

    return "\n".join(lines)


# ── Rendering ────────────────────────────────────────────────────────────


_GRADE_COLORS: dict[Grade, str] = {
    Grade.A_PLUS: "bright_green",
    Grade.A: "green",
    Grade.B: "yellow",
    Grade.C: "yellow",
    Grade.D: "orange1",
    Grade.F: "red",
}


def render_scorecard(scorecard: ScorecardResult, console: Console | None = None) -> None:
    """Render the scorecard as a Rich panel with category breakdowns.

    Args:
        scorecard: The scorecard result to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    grade_color = _GRADE_COLORS.get(scorecard.grade, "white")

    # Main grade panel
    console.print(
        Panel(
            f"[bold {grade_color}]{scorecard.grade.value}[/] ({scorecard.overall_score:.0f}/100)",
            title="Dependency Health Scorecard",
            border_style=grade_color,
        )
    )

    # Category scores table
    table = Table(title="Category Breakdown", show_lines=True)
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Score", justify="right", style="bold")
    table.add_column("Bar", no_wrap=True)
    table.add_column("Weight", justify="right")
    table.add_column("Weighted", justify="right", style="magenta")
    table.add_column("Details", style="dim", max_width=40)

    for cat in scorecard.category_scores:
        score_color = "green" if cat.score >= 80 else "yellow" if cat.score >= 60 else "red"
        bar_len = int(cat.score / 5)  # 0-20 chars
        bar = "█" * bar_len + "░" * (20 - bar_len)

        table.add_row(
            cat.category,
            f"[{score_color}]{cat.score:.0f}[/]",
            f"[{score_color}]{bar}[/]",
            f"{cat.weight:.0%}",
            f"{cat.weighted_score:.1f}",
            cat.details,
        )

    # Total row
    table.add_row(
        "[bold]OVERALL[/bold]",
        f"[bold {grade_color}]{scorecard.overall_score:.0f}[/]",
        "",
        "",
        f"[bold {grade_color}]{scorecard.grade.value}[/]",
        "",
    )

    console.print(table)

    # Top suggestions
    if scorecard.top_suggestions:
        console.print("\n[bold]🎯 Top Improvement Suggestions:[/bold]")
        for i, suggestion in enumerate(scorecard.top_suggestions, 1):
            console.print(f"  {i}. {suggestion}")


def render_scorecard_json(scorecard: ScorecardResult) -> str:
    """Render the scorecard as JSON.

    Args:
        scorecard: The scorecard result to render.

    Returns:
        JSON string of the scorecard.
    """
    return json.dumps(scorecard.to_dict(), indent=2)
