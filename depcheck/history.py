"""Release timeline analysis for depcheck.

Analyzes release patterns for project dependencies including:
- Release frequency and cadence
- Time between releases (development velocity)
- Version gap analysis (how far behind each dependency is)
- Project health indicators based on release patterns
- Lifecycle classification (active, maintenance, declining, abandoned)

Helps identify dependencies that may need attention based on their
release history and development patterns.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from depcheck.models import HealthStatus, PackageReport, ScanResult
from depcheck.scanner import discover_dependencies, normalize_package_name


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LifecycleStage(Enum):
    """Lifecycle stage of a package based on release patterns."""

    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DECLINING = "declining"
    ABANDONED = "abandoned"
    NEW = "new"
    UNKNOWN = "unknown"


class ReleaseCadence(Enum):
    """How frequently a package releases."""

    RAPID = "rapid"       # Multiple releases per month
    REGULAR = "regular"   # Monthly to quarterly
    SLOW = "slow"         # Quarterly to yearly
    INFREQUENT = "infrequent"  # Less than yearly
    DORMANT = "dormant"    # No releases in 2+ years
    UNKNOWN = "unknown"


class VersionGap(Enum):
    """How far behind the installed version is from latest."""

    CURRENT = "current"       # On latest version
    PATCH_BEHIND = "patch_behind"   # 1-2 patch versions behind
    MINOR_BEHIND = "minor_behind"   # 1+ minor versions behind
    MAJOR_BEHIND = "major_behind"   # 1+ major versions behind
    VERY_BEHIND = "very_behind"    # 2+ major versions behind
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ReleaseEvent:
    """A single release event."""

    version: str
    date: datetime
    is_prerelease: bool = False
    is_yanked: bool = False

    @property
    def is_stable(self) -> bool:
        """Whether this is a stable (non-prerelease, non-yanked) release."""
        return not self.is_prerelease and not self.is_yanked

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "date": self.date.isoformat(),
            "is_prerelease": self.is_prerelease,
            "is_yanked": self.is_yanked,
        }


@dataclass
class PackageTimeline:
    """Release timeline analysis for a single package."""

    package: str
    installed_version: str = ""
    latest_version: str = ""
    releases: list[ReleaseEvent] = field(default_factory=list)
    lifecycle: LifecycleStage = LifecycleStage.UNKNOWN
    cadence: ReleaseCadence = ReleaseCadence.UNKNOWN
    version_gap: VersionGap = VersionGap.UNKNOWN

    # Computed metrics
    total_releases: int = 0
    stable_releases: int = 0
    first_release_date: datetime | None = None
    last_release_date: datetime | None = None
    avg_days_between_releases: float = 0.0
    median_days_between_releases: float = 0.0
    days_since_last_release: int = 0
    versions_behind: int = 0
    yanked_releases_count: int = 0
    prerelease_ratio: float = 0.0

    # Derived insights
    health_trend: str = "stable"  # "improving", "stable", "declining", "unknown"
    risk_level: str = "low"       # "low", "medium", "high", "critical"
    insights: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "lifecycle": self.lifecycle.value,
            "cadence": self.cadence.value,
            "version_gap": self.version_gap.value,
            "metrics": {
                "total_releases": self.total_releases,
                "stable_releases": self.stable_releases,
                "first_release_date": (
                    self.first_release_date.isoformat() if self.first_release_date else None
                ),
                "last_release_date": (
                    self.last_release_date.isoformat() if self.last_release_date else None
                ),
                "avg_days_between_releases": round(self.avg_days_between_releases, 1),
                "median_days_between_releases": round(self.median_days_between_releases, 1),
                "days_since_last_release": self.days_since_last_release,
                "versions_behind": self.versions_behind,
                "yanked_releases_count": self.yanked_releases_count,
                "prerelease_ratio": round(self.prerelease_ratio, 3),
            },
            "health_trend": self.health_trend,
            "risk_level": self.risk_level,
            "insights": self.insights,
            "releases": [r.to_dict() for r in self.releases[:20]],  # Last 20 releases
        }


@dataclass
class HistoryResult:
    """Complete release timeline analysis for a project."""

    project_path: str = ""
    timelines: list[PackageTimeline] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.timelines)

    @property
    def active_count(self) -> int:
        return sum(1 for t in self.timelines if t.lifecycle == LifecycleStage.ACTIVE)

    @property
    def maintenance_count(self) -> int:
        return sum(1 for t in self.timelines if t.lifecycle == LifecycleStage.MAINTENANCE)

    @property
    def declining_count(self) -> int:
        return sum(1 for t in self.timelines if t.lifecycle == LifecycleStage.DECLINING)

    @property
    def abandoned_count(self) -> int:
        return sum(1 for t in self.timelines if t.lifecycle == LifecycleStage.ABANDONED)

    @property
    def high_risk_count(self) -> int:
        return sum(1 for t in self.timelines if t.risk_level in ("high", "critical"))

    @property
    def current_count(self) -> int:
        return sum(1 for t in self.timelines if t.version_gap == VersionGap.CURRENT)

    @property
    def behind_count(self) -> int:
        return sum(
            1
            for t in self.timelines
            if t.version_gap not in (VersionGap.CURRENT, VersionGap.UNKNOWN)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "summary": {
                "total": self.total,
                "active": self.active_count,
                "maintenance": self.maintenance_count,
                "declining": self.declining_count,
                "abandoned": self.abandoned_count,
                "high_risk": self.high_risk_count,
                "current": self.current_count,
                "behind": self.behind_count,
            },
            "timelines": [t.to_dict() for t in self.timelines],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _parse_releases(releases_data: dict[str, list[dict[str, Any]]]) -> list[ReleaseEvent]:
    """Parse PyPI releases data into ReleaseEvent objects.

    Args:
        releases_data: Dictionary from PyPI API mapping version strings to file lists.

    Returns:
        Sorted list of ReleaseEvent objects (oldest first).
    """
    events: list[ReleaseEvent] = []

    for version_str, files in releases_data.items():
        if not files:
            continue

        # Find the earliest upload time for this version
        upload_times: list[datetime] = []
        is_yanked = all(f.get("yanked", False) for f in files)

        for file_info in files:
            upload_time = file_info.get("upload_time_iso_8601")
            if upload_time:
                try:
                    dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                    upload_times.append(dt)
                except (ValueError, TypeError):
                    continue

        if not upload_times:
            continue

        release_date = min(upload_times)

        # Determine if prerelease
        is_prerelease = False
        try:
            ver = Version(version_str)
            is_prerelease = ver.is_prerelease or ver.is_devrelease
        except InvalidVersion:
            # Fallback heuristic
            is_prerelease = any(
                marker in version_str.lower()
                for marker in ("alpha", "beta", "rc", "dev", "a", "b", "c")
            )

        events.append(
            ReleaseEvent(
                version=version_str,
                date=release_date,
                is_prerelease=is_prerelease,
                is_yanked=is_yanked,
            )
        )

    # Sort by date (oldest first)
    events.sort(key=lambda e: e.date)
    return events


def _compute_cadence(stable_releases: list[ReleaseEvent]) -> ReleaseCadence:
    """Compute the release cadence from stable release events.

    Args:
        stable_releases: List of stable release events sorted by date.

    Returns:
        The release cadence classification.
    """
    if len(stable_releases) < 2:
        if len(stable_releases) == 1:
            days_since = (datetime.now(tz=timezone.utc) - stable_releases[0].date).days
            if days_since > 730:  # 2 years
                return ReleaseCadence.DORMANT
        return ReleaseCadence.UNKNOWN

    # Compute intervals between consecutive releases
    intervals: list[float] = []
    for i in range(1, len(stable_releases)):
        delta = (stable_releases[i].date - stable_releases[i - 1].date).total_seconds()
        days = delta / 86400.0
        if days > 0:
            intervals.append(days)

    if not intervals:
        return ReleaseCadence.UNKNOWN

    avg_interval = sum(intervals) / len(intervals)

    # Use recent releases (last 4) for more accurate cadence
    recent_intervals = intervals[-4:] if len(intervals) >= 4 else intervals
    recent_avg = sum(recent_intervals) / len(recent_intervals)

    if recent_avg <= 14:      # ~2 weeks
        return ReleaseCadence.RAPID
    elif recent_avg <= 90:    # ~3 months
        return ReleaseCadence.REGULAR
    elif recent_avg <= 365:   # ~1 year
        return ReleaseCadence.SLOW
    elif recent_avg <= 730:   # ~2 years
        return ReleaseCadence.INFREQUENT
    else:
        return ReleaseCadence.DORMANT


def _compute_lifecycle(
    cadence: ReleaseCadence,
    days_since_last_release: int,
    total_releases: int,
    stable_releases: int,
) -> LifecycleStage:
    """Determine the lifecycle stage of a package.

    Args:
        cadence: The release cadence.
        days_since_last_release: Days since the last stable release.
        total_releases: Total number of releases.
        stable_releases: Number of stable releases.

    Returns:
        The lifecycle stage.
    """
    if total_releases == 0:
        return LifecycleStage.UNKNOWN

    if stable_releases <= 1 and days_since_last_release < 90:
        return LifecycleStage.NEW

    if days_since_last_release > 730:  # 2+ years
        return LifecycleStage.ABANDONED

    if days_since_last_release > 540:  # 18+ months
        if cadence in (ReleaseCadence.RAPID, ReleaseCadence.REGULAR):
            return LifecycleStage.DECLINING
        return LifecycleStage.ABANDONED

    if days_since_last_release > 365:  # 1+ year
        if cadence in (ReleaseCadence.RAPID, ReleaseCadence.REGULAR):
            return LifecycleStage.DECLINING
        return LifecycleStage.MAINTENANCE

    if cadence in (ReleaseCadence.DORMANT, ReleaseCadence.INFREQUENT):
        if days_since_last_release > 180:
            return LifecycleStage.DECLINING
        return LifecycleStage.MAINTENANCE

    if cadence in (ReleaseCadence.RAPID, ReleaseCadence.REGULAR):
        return LifecycleStage.ACTIVE

    if cadence == ReleaseCadence.SLOW:
        if days_since_last_release < 365:
            return LifecycleStage.MAINTENANCE
        return LifecycleStage.DECLINING

    return LifecycleStage.MAINTENANCE


def _compute_version_gap(
    installed_version: str,
    latest_version: str,
    releases: list[ReleaseEvent],
) -> tuple[VersionGap, int]:
    """Compute how far behind the installed version is.

    Args:
        installed_version: The currently installed version string.
        latest_version: The latest available version string.
        releases: List of all release events.

    Returns:
        Tuple of (VersionGap classification, number of versions behind).
    """
    if not installed_version or not latest_version:
        return VersionGap.UNKNOWN, 0

    if installed_version == latest_version:
        return VersionGap.CURRENT, 0

    try:
        installed = Version(installed_version)
        latest = Version(latest_version)
    except InvalidVersion:
        return VersionGap.UNKNOWN, 0

    # Count how many stable releases are between installed and latest
    versions_behind = 0
    for release in releases:
        if release.is_prerelease:
            continue
        try:
            rv = Version(release.version)
            if installed < rv <= latest:
                versions_behind += 1
        except InvalidVersion:
            continue

    # Classify the gap
    if latest.major > installed.major:
        if latest.major - installed.major >= 2:
            return VersionGap.VERY_BEHIND, versions_behind
        return VersionGap.MAJOR_BEHIND, versions_behind

    if latest.minor > installed.minor:
        return VersionGap.MINOR_BEHIND, versions_behind

    if latest.micro > installed.micro:
        if versions_behind <= 2:
            return VersionGap.PATCH_BEHIND, versions_behind
        return VersionGap.MINOR_BEHIND, versions_behind

    return VersionGap.CURRENT, 0


def _compute_health_trend(stable_releases: list[ReleaseEvent]) -> str:
    """Compute the health trend based on release frequency changes.

    Args:
        stable_releases: List of stable release events sorted by date.

    Returns:
        "improving", "stable", "declining", or "unknown".
    """
    if len(stable_releases) < 4:
        return "unknown"

    # Compare intervals in first half vs second half of releases
    mid = len(stable_releases) // 2
    first_half = stable_releases[:mid]
    second_half = stable_releases[mid:]

    def avg_interval(releases: list[ReleaseEvent]) -> float:
        intervals = []
        for i in range(1, len(releases)):
            delta = (releases[i].date - releases[i - 1].date).total_seconds()
            days = delta / 86400.0
            if days > 0:
                intervals.append(days)
        return sum(intervals) / len(intervals) if intervals else 0.0

    first_avg = avg_interval(first_half)
    second_avg = avg_interval(second_half)

    if first_avg == 0 or second_avg == 0:
        return "unknown"

    ratio = second_avg / first_avg

    if ratio > 2.0:     # Releases slowed to less than half the frequency
        return "declining"
    elif ratio < 0.5:   # Releases more than doubled in frequency
        return "improving"
    else:
        return "stable"


def _compute_risk_level(timeline: PackageTimeline) -> str:
    """Compute overall risk level based on timeline analysis.

    Args:
        timeline: The package timeline with computed metrics.

    Returns:
        Risk level: "low", "medium", "high", or "critical".
    """
    risk_score = 0

    # Lifecycle risk
    lifecycle_risk = {
        LifecycleStage.ACTIVE: 0,
        LifecycleStage.NEW: 1,
        LifecycleStage.MAINTENANCE: 2,
        LifecycleStage.DECLINING: 3,
        LifecycleStage.ABANDONED: 4,
        LifecycleStage.UNKNOWN: 2,
    }
    risk_score += lifecycle_risk.get(timeline.lifecycle, 2)

    # Version gap risk
    gap_risk = {
        VersionGap.CURRENT: 0,
        VersionGap.PATCH_BEHIND: 1,
        VersionGap.MINOR_BEHIND: 2,
        VersionGap.MAJOR_BEHIND: 3,
        VersionGap.VERY_BEHIND: 4,
        VersionGap.UNKNOWN: 1,
    }
    risk_score += gap_risk.get(timeline.version_gap, 1)

    # Days since last release risk
    if timeline.days_since_last_release > 730:
        risk_score += 3
    elif timeline.days_since_last_release > 365:
        risk_score += 2
    elif timeline.days_since_last_release > 180:
        risk_score += 1

    # Yanked releases risk
    if timeline.yanked_releases_count > 2:
        risk_score += 2
    elif timeline.yanked_releases_count > 0:
        risk_score += 1

    # Health trend risk
    if timeline.health_trend == "declining":
        risk_score += 1

    if risk_score >= 8:
        return "critical"
    elif risk_score >= 5:
        return "high"
    elif risk_score >= 3:
        return "medium"
    else:
        return "low"


def _generate_insights(timeline: PackageTimeline) -> list[str]:
    """Generate human-readable insights about a package's release timeline.

    Args:
        timeline: The package timeline with computed metrics.

    Returns:
        List of insight strings.
    """
    insights: list[str] = []

    # Lifecycle insights
    lifecycle_messages = {
        LifecycleStage.ACTIVE: "Package is actively maintained with regular releases.",
        LifecycleStage.MAINTENANCE: "Package is in maintenance mode - bug fixes only expected.",
        LifecycleStage.DECLINING: "Release frequency is declining - monitor for abandonment.",
        LifecycleStage.ABANDONED: "Package appears abandoned - consider alternatives.",
        LifecycleStage.NEW: "Package is relatively new with few releases.",
    }
    msg = lifecycle_messages.get(timeline.lifecycle)
    if msg:
        insights.append(msg)

    # Cadence insights
    cadence_messages = {
        ReleaseCadence.RAPID: "Very frequent releases (multiple per month).",
        ReleaseCadence.REGULAR: "Regular release cadence (monthly to quarterly).",
        ReleaseCadence.SLOW: "Slow release cadence (quarterly to yearly).",
        ReleaseCadence.INFREQUENT: "Infrequent releases (less than yearly).",
        ReleaseCadence.DORMANT: "No releases in over 2 years.",
    }
    msg = cadence_messages.get(timeline.cadence)
    if msg:
        insights.append(msg)

    # Version gap insights
    if timeline.version_gap == VersionGap.CURRENT:
        insights.append("You are on the latest version.")
    elif timeline.version_gap == VersionGap.PATCH_BEHIND:
        insights.append(
            f"Minor patch updates available ({timeline.versions_behind} version(s) behind)."
        )
    elif timeline.version_gap == VersionGap.MINOR_BEHIND:
        insights.append(
            f"Minor version updates available ({timeline.versions_behind} version(s) behind)."
        )
    elif timeline.version_gap == VersionGap.MAJOR_BEHIND:
        insights.append(
            f"Major version update available ({timeline.versions_behind} version(s) behind). "
            f"Review changelog for breaking changes."
        )
    elif timeline.version_gap == VersionGap.VERY_BEHIND:
        insights.append(
            f"Significantly behind latest ({timeline.versions_behind} version(s) behind). "
            f"Strongly consider upgrading."
        )

    # Time-based insights
    if timeline.days_since_last_release > 365:
        years = timeline.days_since_last_release / 365.25
        insights.append(
            f"Last release was {timeline.days_since_last_release} days ago "
            f"({years:.1f} years)."
        )

    # Yanked releases insights
    if timeline.yanked_releases_count > 0:
        insights.append(
            f"{timeline.yanked_releases_count} yanked release(s) detected - "
            f"verify your version is not affected."
        )

    # High prerelease ratio
    if timeline.prerelease_ratio > 0.5 and timeline.total_releases > 5:
        insights.append(
            f"High prerelease ratio ({timeline.prerelease_ratio:.0%}) - "
            f"package may be in active development/unstable."
        )

    # Health trend insights
    if timeline.health_trend == "improving":
        insights.append("Release frequency is increasing - project is becoming more active.")
    elif timeline.health_trend == "declining":
        insights.append("Release frequency is declining - project may be winding down.")

    return insights


def _compute_intervals(releases: list[ReleaseEvent]) -> tuple[float, float]:
    """Compute average and median days between stable releases.

    Args:
        releases: List of stable release events sorted by date.

    Returns:
        Tuple of (average_days, median_days).
    """
    if len(releases) < 2:
        return 0.0, 0.0

    intervals: list[float] = []
    for i in range(1, len(releases)):
        delta = (releases[i].date - releases[i - 1].date).total_seconds()
        days = delta / 86400.0
        if days > 0:
            intervals.append(days)

    if not intervals:
        return 0.0, 0.0

    avg = sum(intervals) / len(intervals)
    sorted_intervals = sorted(intervals)
    n = len(sorted_intervals)
    if n % 2 == 0:
        median = (sorted_intervals[n // 2 - 1] + sorted_intervals[n // 2]) / 2.0
    else:
        median = sorted_intervals[n // 2]

    return avg, median


def build_timeline(
    package_name: str,
    releases_data: dict[str, list[dict[str, Any]]],
    installed_version: str = "",
    latest_version: str = "",
) -> PackageTimeline:
    """Build a release timeline for a single package.

    Args:
        package_name: The package name.
        releases_data: Raw PyPI releases data (version -> file list).
        installed_version: The installed version string.
        latest_version: The latest version string.

    Returns:
        A PackageTimeline with computed metrics and insights.
    """
    timeline = PackageTimeline(
        package=package_name,
        installed_version=installed_version,
        latest_version=latest_version,
    )

    # Parse all releases
    all_releases = _parse_releases(releases_data)
    timeline.releases = all_releases
    timeline.total_releases = len(all_releases)

    # Filter to stable releases
    stable_releases = [r for r in all_releases if r.is_stable]
    timeline.stable_releases = len(stable_releases)

    # Count yanked
    timeline.yanked_releases_count = sum(1 for r in all_releases if r.is_yanked)

    # Prerelease ratio
    if timeline.total_releases > 0:
        prerelease_count = sum(1 for r in all_releases if r.is_prerelease)
        timeline.prerelease_ratio = prerelease_count / timeline.total_releases

    # Date range
    if stable_releases:
        timeline.first_release_date = stable_releases[0].date
        timeline.last_release_date = stable_releases[-1].date

        # Days since last release
        now = datetime.now(tz=timezone.utc)
        timeline.days_since_last_release = (now - stable_releases[-1].date).days

        # Compute intervals
        avg, median = _compute_intervals(stable_releases)
        timeline.avg_days_between_releases = avg
        timeline.median_days_between_releases = median

    # Compute cadence
    timeline.cadence = _compute_cadence(stable_releases)

    # Compute lifecycle
    timeline.lifecycle = _compute_lifecycle(
        timeline.cadence,
        timeline.days_since_last_release,
        timeline.total_releases,
        timeline.stable_releases,
    )

    # Compute version gap
    timeline.version_gap, timeline.versions_behind = _compute_version_gap(
        installed_version, latest_version, all_releases
    )

    # Compute health trend
    timeline.health_trend = _compute_health_trend(stable_releases)

    # Compute risk level
    timeline.risk_level = _compute_risk_level(timeline)

    # Generate insights
    timeline.insights = _generate_insights(timeline)

    return timeline


def analyze_history(
    project_path: str | Path,
    scan_result: ScanResult | None = None,
    check_vulnerabilities: bool = False,
    check_licenses: bool = False,
) -> HistoryResult:
    """Analyze release timeline for all project dependencies.

    Args:
        project_path: Path to the project directory.
        scan_result: Pre-existing scan result (optional).
        check_vulnerabilities: Whether to include vulnerability data in scan.
        check_licenses: Whether to include license data in scan.

    Returns:
        HistoryResult with timeline analysis for each dependency.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return HistoryResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    if scan_result is None:
        from depcheck.scanner import scan_project

        scan_result = scan_project(
            project_path=str(project_path),
            check_vulnerabilities=check_vulnerabilities,
            check_licenses=check_licenses,
        )

    result = HistoryResult(project_path=str(project_path))
    result.errors.extend(scan_result.errors)

    # We need PyPI data for release timelines
    from depcheck.pypi import PyPIClient

    with PyPIClient() as pypi_client:
        for pkg in scan_result.packages:
            info = pypi_client.get_package_info(pkg.name)
            if info is None:
                result.errors.append(f"Could not fetch PyPI data for {pkg.name}")
                continue

            releases_data = info.get("releases", {})
            latest_version = info.get("info", {}).get("version", "")

            timeline = build_timeline(
                package_name=pkg.name,
                releases_data=releases_data,
                installed_version=pkg.installed_version,
                latest_version=latest_version or pkg.latest_version or "",
            )
            result.timelines.append(timeline)

    # Sort by risk level (highest first), then by name
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.timelines.sort(
        key=lambda t: (risk_order.get(t.risk_level, 3), t.package)
    )

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_history_table(result: HistoryResult, *, console: Any = None) -> None:
    """Render the release timeline analysis as Rich tables.

    Args:
        result: The history analysis result.
        console: Rich console instance.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    if console is None:
        console = Console()

    console.print()
    console.print(
        Panel(
            "[bold]depcheck history[/bold] - Release Timeline Analysis\n"
            f"[dim]Project: {result.project_path}[/dim]",
            border_style="blue",
        )
    )

    if result.errors and not result.timelines:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    # Summary
    summary_parts: list[str] = []
    summary_parts.append(f"[bold]Total:[/bold] {result.total} packages")
    if result.active_count:
        summary_parts.append(f"[green]Active: {result.active_count}[/green]")
    if result.maintenance_count:
        summary_parts.append(f"[yellow]Maintenance: {result.maintenance_count}[/yellow]")
    if result.declining_count:
        summary_parts.append(f"[orange1]Declining: {result.declining_count}[/orange1]")
    if result.abandoned_count:
        summary_parts.append(f"[red]Abandoned: {result.abandoned_count}[/red]")
    if result.high_risk_count:
        summary_parts.append(f"[red bold]High risk: {result.high_risk_count}[/red bold]")
    if result.current_count:
        summary_parts.append(f"[green]Current: {result.current_count}[/green]")
    if result.behind_count:
        summary_parts.append(f"[yellow]Behind: {result.behind_count}[/yellow]")

    console.print(Panel("\n".join(summary_parts), title="Summary", border_style="blue"))

    # Lifecycle overview table
    lifecycle_styles: dict[str, tuple[str, str]] = {
        "active": ("OK", "green"),
        "maintenance": ("MT", "yellow"),
        "declining": ("DC", "orange1"),
        "abandoned": ("AB", "red bold"),
        "new": ("NW", "cyan"),
        "unknown": ("??", "dim"),
    }

    risk_styles: dict[str, str] = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "red bold",
    }

    table = Table(
        title="Dependency Release Timelines",
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
        pad_edge=False,
        expand=True,
    )
    table.add_column("Package", style="bold", min_width=18)
    table.add_column("Installed", min_width=12)
    table.add_column("Latest", min_width=12)
    table.add_column("Lifecycle", justify="center", min_width=10)
    table.add_column("Cadence", justify="center", min_width=10)
    table.add_column("Gap", justify="center", min_width=8)
    table.add_column("Days Since", justify="right", min_width=10)
    table.add_column("Risk", justify="center", min_width=8)

    for t in result.timelines:
        lc_label, lc_color = lifecycle_styles.get(t.lifecycle.value, ("??", "white"))
        risk_color = risk_styles.get(t.risk_level, "white")

        table.add_row(
            f"[cyan]{t.package}[/cyan]",
            t.installed_version or "-",
            t.latest_version or "-",
            f"[{lc_color}]{lc_label} {t.lifecycle.value}[/{lc_color}]",
            t.cadence.value,
            t.version_gap.value.replace("_", " "),
            str(t.days_since_last_release),
            f"[{risk_color}]{t.risk_level.upper()}[/{risk_color}]",
        )

    console.print(table)

    # Insights for high-risk packages
    high_risk = [t for t in result.timelines if t.risk_level in ("high", "critical")]
    if high_risk:
        console.print()
        console.print("[bold red]High Risk Dependencies:[/bold red]")
        for t in high_risk:
            console.print(f"\n  [cyan]{t.package}[/cyan] [dim]({t.installed_version})[/dim]")
            for insight in t.insights[:3]:
                console.print(f"    [dim]- {insight}[/dim]")

    console.print()


def render_history_json(result: HistoryResult) -> str:
    """Render the release timeline analysis as JSON.

    Args:
        result: The history analysis result.

    Returns:
        JSON string.
    """
    return json.dumps(result.to_dict(), indent=2)
