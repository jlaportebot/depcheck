"""Dependency history and version timeline tracking for depcheck.

Provides historical version analysis for each dependency — version age,
release frequency, maintenance trends, and deprecation warnings. Helps
you understand the maintenance health and release cadence of your
dependencies over time.

Supports:
- Per-package version timeline (release dates, age of current version)
- Release cadence analysis (releases/year, average gap between releases)
- Maintenance trend detection (accelerating, steady, slowing, abandoned)
- Project-wide maintenance summary
- JSON and table output
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class MaintenanceTrend(enum.Enum):
    """Maintenance trend for a package."""

    ACCELERATING = "accelerating"
    STEADY = "steady"
    SLOWING = "slowing"
    ABANDONED = "abandoned"
    NEW = "new"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class VersionRelease:
    """A single version release entry."""

    version: str
    release_date: str  # ISO format: YYYY-MM-DD
    is_current: bool = False
    is_latest: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "release_date": self.release_date,
            "is_current": self.is_current,
            "is_latest": self.is_latest,
        }


@dataclass
class PackageHistory:
    """History analysis for a single package."""

    name: str
    installed_version: str
    latest_version: str | None = None
    version_releases: list[VersionRelease] = field(default_factory=list)
    current_version_age_days: int | None = None
    latest_version_age_days: int | None = None
    releases_per_year: float | None = None
    avg_days_between_releases: float | None = None
    maintenance_trend: MaintenanceTrend = MaintenanceTrend.UNKNOWN
    first_release_date: str | None = None
    total_releases: int = 0
    years_active: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "current_version_age_days": self.current_version_age_days,
            "latest_version_age_days": self.latest_version_age_days,
            "releases_per_year": (
                round(self.releases_per_year, 1) if self.releases_per_year is not None else None
            ),
            "avg_days_between_releases": (
                round(self.avg_days_between_releases, 1)
                if self.avg_days_between_releases is not None
                else None
            ),
            "maintenance_trend": self.maintenance_trend.value,
            "first_release_date": self.first_release_date,
            "total_releases": self.total_releases,
            "years_active": (
                round(self.years_active, 1) if self.years_active is not None else None
            ),
            "version_releases": [v.to_dict() for v in self.version_releases],
            "error": self.error,
        }


@dataclass
class HistoryReport:
    """Aggregated history report for all project dependencies."""

    project_path: str
    packages: list[PackageHistory] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)

    @property
    def package_count(self) -> int:
        return len(self.packages)

    @property
    def accelerating_count(self) -> int:
        return sum(1 for p in self.packages if p.maintenance_trend == MaintenanceTrend.ACCELERATING)

    @property
    def steady_count(self) -> int:
        return sum(1 for p in self.packages if p.maintenance_trend == MaintenanceTrend.STEADY)

    @property
    def slowing_count(self) -> int:
        return sum(1 for p in self.packages if p.maintenance_trend == MaintenanceTrend.SLOWING)

    @property
    def abandoned_count(self) -> int:
        return sum(1 for p in self.packages if p.maintenance_trend == MaintenanceTrend.ABANDONED)

    @property
    def new_count(self) -> int:
        return sum(1 for p in self.packages if p.maintenance_trend == MaintenanceTrend.NEW)

    @property
    def unknown_count(self) -> int:
        return sum(1 for p in self.packages if p.maintenance_trend == MaintenanceTrend.UNKNOWN)

    @property
    def avg_current_version_age(self) -> float | None:
        ages = [
            p.current_version_age_days
            for p in self.packages
            if p.current_version_age_days is not None
        ]
        return sum(ages) / len(ages) if ages else None

    @property
    def oldest_current_version(self) -> PackageHistory | None:
        with_ages = [p for p in self.packages if p.current_version_age_days is not None]
        if not with_ages:
            return None
        return max(with_ages, key=lambda p: p.current_version_age_days or 0)

    @property
    def newest_current_version(self) -> PackageHistory | None:
        with_ages = [p for p in self.packages if p.current_version_age_days is not None]
        if not with_ages:
            return None
        return min(with_ages, key=lambda p: p.current_version_age_days or 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "summary": {
                "package_count": self.package_count,
                "avg_current_version_age_days": (
                    round(self.avg_current_version_age, 1)
                    if self.avg_current_version_age is not None
                    else None
                ),
                "trends": {
                    "accelerating": self.accelerating_count,
                    "steady": self.steady_count,
                    "slowing": self.slowing_count,
                    "abandoned": self.abandoned_count,
                    "new": self.new_count,
                    "unknown": self.unknown_count,
                },
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Analysis logic
# ---------------------------------------------------------------------------


def _compute_trend(
    release_dates: list[datetime],
) -> MaintenanceTrend:
    """Compute maintenance trend from release date intervals.

    Compares the average gap in the first half of releases vs the second
    half to determine if development is accelerating, steady, or slowing.
    """
    if len(release_dates) < 2:
        return MaintenanceTrend.NEW

    now = datetime.now(tz=timezone.utc)
    days_since_last = (now - release_dates[-1]).days

    # Abandoned: no release in 18+ months
    if days_since_last > 540:
        return MaintenanceTrend.ABANDONED

    # Need at least 4 releases to compute a meaningful trend
    if len(release_dates) < 4:
        return MaintenanceTrend.STEADY

    # Split into first half and second half
    mid = len(release_dates) // 2
    first_half = release_dates[:mid]
    second_half = release_dates[mid:]

    # Compute average gap (in days) for each half
    def avg_gap(dates: list[datetime]) -> float:
        if len(dates) < 2:
            return 0.0
        gaps = []
        for i in range(1, len(dates)):
            gap = (dates[i] - dates[i - 1]).days
            gaps.append(gap)
        return sum(gaps) / len(gaps) if gaps else 0.0

    first_avg = avg_gap(first_half)
    second_avg = avg_gap(second_half)

    if first_avg == 0 and second_avg == 0:
        return MaintenanceTrend.STEADY

    if first_avg == 0:
        return MaintenanceTrend.ACCELERATING

    ratio = second_avg / first_avg

    if ratio > 1.5:
        return MaintenanceTrend.SLOWING
    if ratio < 0.67:
        return MaintenanceTrend.ACCELERATING
    return MaintenanceTrend.STEADY


def analyze_package_history(
    dep: ParsedDependency,
    pypi_client: PyPIClient,
    max_versions: int = 20,
) -> PackageHistory:
    """Analyze the release history of a single package.

    Args:
        dep: The parsed dependency.
        pypi_client: PyPI API client.
        max_versions: Maximum number of historical versions to retrieve.

    Returns:
        A PackageHistory with release timeline and trend data.
    """
    history = PackageHistory(
        name=dep.name,
        installed_version=dep.version or "unknown",
    )

    try:
        info = pypi_client.get_package_info(dep.name)
        if info is None:
            history.error = "Package not found on PyPI"
            return history

        # Get latest version
        history.latest_version = info.get("info", {}).get("version")

        # Get release data
        releases = info.get("releases", {})
        if not releases:
            history.error = "No release data available"
            return history

        # Parse release dates
        now = datetime.now(tz=timezone.utc)
        version_releases: list[VersionRelease] = []
        release_dates: list[datetime] = []

        for ver_str, files in releases.items():
            if not files:
                continue
            # Use the first file's upload time as the release date
            upload_time = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
            if not upload_time:
                continue

            try:
                if upload_time.endswith("Z"):
                    dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                else:
                    dt = datetime.fromisoformat(upload_time)
                # Ensure timezone-aware
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue

            is_current = ver_str == history.installed_version
            is_latest = ver_str == history.latest_version
            version_releases.append(
                VersionRelease(
                    version=ver_str,
                    release_date=dt.strftime("%Y-%m-%d"),
                    is_current=is_current,
                    is_latest=is_latest,
                )
            )
            release_dates.append(dt)

        # Sort by date
        version_releases.sort(key=lambda v: v.release_date)
        release_dates.sort()

        # Trim to max_versions (keep the most recent)
        if len(version_releases) > max_versions:
            version_releases = version_releases[-max_versions:]
        if len(release_dates) > max_versions:
            release_dates = release_dates[-max_versions:]

        history.version_releases = version_releases
        history.total_releases = len(releases)

        # First release date
        if release_dates:
            history.first_release_date = release_dates[0].strftime("%Y-%m-%d")

        # Years active
        if release_dates:
            days_active = (now - release_dates[0]).days
            history.years_active = days_active / 365.25

        # Current version age
        current_release = next((v for v in version_releases if v.is_current), None)
        if current_release:
            try:
                current_dt = datetime.fromisoformat(current_release.release_date).replace(
                    tzinfo=timezone.utc
                )
                history.current_version_age_days = (now - current_dt).days
            except (ValueError, TypeError):
                pass

        # Latest version age
        latest_release = next((v for v in version_releases if v.is_latest), None)
        if latest_release:
            try:
                latest_dt = datetime.fromisoformat(latest_release.release_date).replace(
                    tzinfo=timezone.utc
                )
                history.latest_version_age_days = (now - latest_dt).days
            except (ValueError, TypeError):
                pass

        # Release cadence
        if len(release_dates) >= 2 and history.years_active and history.years_active > 0:
            total_days = (release_dates[-1] - release_dates[0]).days
            if total_days > 0:
                history.releases_per_year = ((len(release_dates) - 1) / total_days) * 365.25

                # Average days between releases
            gaps = []
            for i in range(1, len(release_dates)):
                gap = (release_dates[i] - release_dates[i - 1]).days
                gaps.append(gap)
            if gaps:
                history.avg_days_between_releases = sum(gaps) / len(gaps)

        # Maintenance trend
        history.maintenance_trend = _compute_trend(release_dates)

    except Exception as exc:
        history.error = str(exc)

    return history


def analyze_history(
    project_path: str,
    max_versions: int = 20,
) -> HistoryReport:
    """Analyze the release history of all project dependencies.

    Args:
        project_path: Path to the project directory.
        max_versions: Maximum number of historical versions to retrieve per package.

    Returns:
        A HistoryReport with per-package and aggregate history data.
    """
    project_path_obj = Path(project_path).resolve()

    if not project_path_obj.is_dir():
        return HistoryReport(
            project_path=str(project_path_obj),
            errors=[f"Path is not a directory: {project_path_obj}"],
        )

    # Discover dependencies
    dependencies, files_scanned = discover_dependencies(project_path_obj)

    if not dependencies:
        return HistoryReport(
            project_path=str(project_path_obj),
            files_scanned=files_scanned,
            errors=["No dependencies found in the project."],
        )

    # Analyze each package
    packages: list[PackageHistory] = []
    with PyPIClient() as pypi_client:
        for dep in dependencies:
            history = analyze_package_history(dep, pypi_client, max_versions)
            packages.append(history)

    return HistoryReport(
        project_path=str(project_path_obj),
        packages=packages,
        files_scanned=files_scanned,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _trend_style(trend: MaintenanceTrend) -> str:
    """Return Rich style string for a maintenance trend."""
    styles = {
        MaintenanceTrend.ACCELERATING: "[green]↑ accelerating[/green]",
        MaintenanceTrend.STEADY: "[cyan]→ steady[/cyan]",
        MaintenanceTrend.SLOWING: "[yellow]↓ slowing[/yellow]",
        MaintenanceTrend.ABANDONED: "[red]✗ abandoned[/red]",
        MaintenanceTrend.NEW: "[blue]✦ new[/blue]",
        MaintenanceTrend.UNKNOWN: "[dim]? unknown[/dim]",
    }
    return styles.get(trend, "[dim]? unknown[/dim]")


def render_history_table(report: HistoryReport, console: Console | None = None) -> None:
    """Render history report as a Rich table."""
    if console is None:
        console = Console()

    console.print()
    console.print(f"[bold]Dependency History Report: {report.project_path}[/bold]")
    console.print()

    # Summary table
    summary = Table(title="Summary", show_header=True, header_style="bold cyan")
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", justify="right")

    summary.add_row("Total Packages", str(report.package_count))
    if report.avg_current_version_age is not None:
        avg_years = report.avg_current_version_age / 365.25
        summary.add_row(
            "Avg Current Version Age",
            f"{report.avg_current_version_age:.0f} days ({avg_years:.1f} yrs)",
        )
    if report.oldest_current_version:
        p = report.oldest_current_version
        summary.add_row(
            "Oldest Current Version",
            f"{p.name} {p.installed_version} ({p.current_version_age_days}d)",
        )
    if report.newest_current_version and report.package_count > 1:
        p = report.newest_current_version
        summary.add_row(
            "Newest Current Version",
            f"{p.name} {p.installed_version} ({p.current_version_age_days}d)",
        )

    console.print(summary)
    console.print()

    # Trend breakdown
    trend_table = Table(
        title="Maintenance Trends",
        show_header=True,
        header_style="bold cyan",
    )
    trend_table.add_column("Trend", style="bold")
    trend_table.add_column("Count", justify="right")
    trend_table.add_column("Packages")

    trend_groups: dict[MaintenanceTrend, list[str]] = {}
    for pkg in report.packages:
        trend_groups.setdefault(pkg.maintenance_trend, []).append(pkg.name)

    for trend in MaintenanceTrend:
        pkgs = trend_groups.get(trend, [])
        if not pkgs:
            continue
        pkg_str = ", ".join(pkgs[:5])
        if len(pkgs) > 5:
            pkg_str += f", ... (+{len(pkgs) - 5} more)"
        trend_table.add_row(
            _trend_style(trend),
            str(len(pkgs)),
            pkg_str,
        )

    console.print(trend_table)
    console.print()

    # Per-package detail table
    pkg_table = Table(
        title="Per-Package History",
        show_header=True,
        header_style="bold cyan",
    )
    pkg_table.add_column("Package", style="bold")
    pkg_table.add_column("Installed", justify="right")
    pkg_table.add_column("Latest", justify="right")
    pkg_table.add_column("Age (days)", justify="right")
    pkg_table.add_column("Releases/Yr", justify="right")
    pkg_table.add_column("Avg Gap (d)", justify="right")
    pkg_table.add_column("Trend")
    pkg_table.add_column("Years Active", justify="right")

    for pkg in sorted(report.packages, key=lambda p: p.name):
        if pkg.error:
            pkg_table.add_row(
                pkg.name,
                pkg.installed_version,
                "-",
                "-",
                "-",
                "-",
                "[dim]error[/dim]",
                "-",
            )
        else:
            age = (
                str(pkg.current_version_age_days)
                if pkg.current_version_age_days is not None
                else "-"
            )
            rpy = f"{pkg.releases_per_year:.1f}" if pkg.releases_per_year is not None else "-"
            avg_gap = (
                f"{pkg.avg_days_between_releases:.0f}"
                if pkg.avg_days_between_releases is not None
                else "-"
            )
            yrs = f"{pkg.years_active:.1f}" if pkg.years_active is not None else "-"
            pkg_table.add_row(
                pkg.name,
                pkg.installed_version,
                pkg.latest_version or "-",
                age,
                rpy,
                avg_gap,
                _trend_style(pkg.maintenance_trend),
                yrs,
            )

    console.print(pkg_table)
    console.print()


def render_history_json(report: HistoryReport, console: Console | None = None) -> None:
    """Render history report as JSON."""
    data = report.to_dict()
    output = json.dumps(data, indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
