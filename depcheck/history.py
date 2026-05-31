"""Release timeline analysis for depcheck.

Analyzes release patterns for project dependencies including:
- Release frequency and cadence
- Time between releases (development velocity)
- Version gap analysis (how far behind is installed)
- Maintenance health indicators
- Risk scoring based on release patterns

Public API:
    build_history_report: Main entry point for CLI
    render_history_table: Rich table output
    render_history_json: JSON output
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from depcheck.pypi import PyPIClient
from depcheck.scanner import scan_project

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class MaintenanceLevel(str, Enum):
    """Maintenance health classification."""

    ACTIVE = "active"
    STABLE = "stable"
    SLOW = "slow"
    STALE = "stale"
    ABANDONED = "abandoned"


class RiskLevel(str, Enum):
    """Risk level based on release timeline."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CadenceTrend(str, Enum):
    """Trend in release cadence."""

    IMPROVING = "improving"
    STEADY = "steady"
    DECLINING = "declining"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass
class Release:
    """A single release event."""

    version: str
    release_date: datetime
    is_prerelease: bool = False
    is_yanked: bool = False

    @property
    def is_stable(self) -> bool:
        """Whether this is a stable (non-prerelease, non-yanked) release."""
        return not self.is_prerelease and not self.is_yanked


@dataclass
class Timeline:
    """Release timeline analysis for a single package."""

    package_name: str
    installed_version: str | None = None
    latest_version: str | None = None
    releases: list[Release] = field(default_factory=list)

    # Computed metrics
    total_releases: int = 0
    stable_releases: int = 0
    yanked_releases_count: int = 0
    prerelease_count: int = 0
    first_release_date: datetime | None = None
    latest_release_date: datetime | None = None
    avg_days_between_releases: float = 0.0
    median_days_between_releases: float = 0.0
    days_since_last_release: int = 0
    maintenance_level: MaintenanceLevel = MaintenanceLevel.ACTIVE
    risk_level: RiskLevel = RiskLevel.LOW
    cadence_trend: CadenceTrend = CadenceTrend.INSUFFICIENT_DATA
    version_gap: int = 0
    patch_behind_count: int = 0
    minor_behind_count: int = 0
    major_behind_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "total_releases": self.total_releases,
            "stable_releases": self.stable_releases,
            "yanked_releases_count": self.yanked_releases_count,
            "prerelease_count": self.prerelease_count,
            "first_release_date": (
                self.first_release_date.isoformat() if self.first_release_date else None
            ),
            "latest_release_date": (
                self.latest_release_date.isoformat() if self.latest_release_date else None
            ),
            "avg_days_between_releases": round(self.avg_days_between_releases, 1),
            "median_days_between_releases": round(self.median_days_between_releases, 1),
            "days_since_last_release": self.days_since_last_release,
            "maintenance_level": self.maintenance_level.value,
            "risk_level": self.risk_level.value,
            "cadence_trend": self.cadence_trend.value,
            "version_gap": self.version_gap,
            "patch_behind_count": self.patch_behind_count,
            "minor_behind_count": self.minor_behind_count,
            "major_behind_count": self.major_behind_count,
        }


@dataclass
class HistoryResult:
    """Result of history analysis across all project dependencies."""

    project_path: str
    timelines: list[Timeline] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def active_count(self) -> int:
        """Count of actively maintained packages."""
        return sum(1 for t in self.timelines if t.maintenance_level == MaintenanceLevel.ACTIVE)

    @property
    def stale_count(self) -> int:
        """Count of stale or abandoned packages."""
        return sum(
            1
            for t in self.timelines
            if t.maintenance_level in (MaintenanceLevel.STALE, MaintenanceLevel.ABANDONED)
        )

    @property
    def high_risk_count(self) -> int:
        """Count of high or critical risk packages."""
        return sum(
            1
            for t in self.timelines
            if t.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "summary": {
                "total": len(self.timelines),
                "active": self.active_count,
                "stale": self.stale_count,
                "high_risk": self.high_risk_count,
            },
            "timelines": [t.to_dict() for t in self.timelines],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Core analysis functions
# ---------------------------------------------------------------------------


def _is_prerelease(version: str) -> bool:
    """Check if a version string looks like a prerelease."""
    version_lower = version.lower()
    pre_tags = ("a", "b", "rc", "alpha", "beta", "dev", "pre")
    for tag in pre_tags:
        if tag in version_lower:
            return True
    return False


def _parse_version_parts(version: str) -> tuple[int, ...]:
    """Parse version string into integer tuple for comparison.

    Only considers numeric components.
    """
    parts: list[int] = []
    for segment in version.split("."):
        # Extract leading numeric portion
        num_str = ""
        for ch in segment:
            if ch.isdigit():
                num_str += ch
            else:
                break
        if num_str:
            parts.append(int(num_str))
    return tuple(parts) if parts else (0,)


def compute_version_gap(installed: str, latest: str) -> tuple[int, int, int, int]:
    """Compute the version gap between installed and latest.

    Returns (total_gap, major_behind, minor_behind, patch_behind).
    """
    inst_parts = _parse_version_parts(installed)
    latest_parts = _parse_version_parts(latest)

    # Pad to same length
    max_len = max(len(inst_parts), len(latest_parts))
    inst_padded = inst_parts + (0,) * (max_len - len(inst_parts))
    latest_padded = latest_parts + (0,) * (max_len - len(latest_parts))

    major_behind = max(0, latest_padded[0] - inst_padded[0]) if max_len > 0 else 0
    minor_behind = max(0, latest_padded[1] - inst_padded[1]) if max_len > 1 else 0
    patch_behind = max(0, latest_padded[2] - inst_padded[2]) if max_len > 2 else 0

    total_gap = major_behind + minor_behind + patch_behind
    return total_gap, major_behind, minor_behind, patch_behind


def compute_release_intervals(releases: list[Release]) -> list[float]:
    """Compute days between consecutive releases (stable only)."""
    stable = sorted(
        [r for r in releases if r.is_stable],
        key=lambda r: r.release_date,
    )
    if len(stable) < 2:
        return []

    intervals: list[float] = []
    for i in range(1, len(stable)):
        delta = (stable[i].release_date - stable[i - 1].release_date).days
        intervals.append(float(delta))
    return intervals


def compute_avg_interval(intervals: list[float]) -> float:
    """Compute average interval in days."""
    if not intervals:
        return 0.0
    return sum(intervals) / len(intervals)


def compute_median_interval(intervals: list[float]) -> float:
    """Compute median interval in days."""
    if not intervals:
        return 0.0
    sorted_intervals = sorted(intervals)
    n = len(sorted_intervals)
    mid = n // 2
    if n % 2 == 0:
        return (sorted_intervals[mid - 1] + sorted_intervals[mid]) / 2
    return sorted_intervals[mid]


def classify_maintenance(days_since_last: int, avg_interval: float) -> MaintenanceLevel:
    """Classify maintenance level based on release recency and frequency.

    Parameters
    ----------
    days_since_last
        Days since the most recent release.
    avg_interval
        Average days between releases.
    """
    if days_since_last <= 0:
        return MaintenanceLevel.ACTIVE

    # Very active: recent release and frequent releases
    if days_since_last <= 90 and avg_interval <= 60:
        return MaintenanceLevel.ACTIVE

    if days_since_last <= 180:
        if avg_interval <= 90:
            return MaintenanceLevel.ACTIVE
        return MaintenanceLevel.STABLE

    if days_since_last <= 365:
        if avg_interval <= 180:
            return MaintenanceLevel.SLOW
        return MaintenanceLevel.STALE

    if days_since_last <= 730:
        return MaintenanceLevel.STALE

    return MaintenanceLevel.ABANDONED


def classify_risk(
    days_since_last: int, version_gap: int, maintenance: MaintenanceLevel
) -> RiskLevel:
    """Classify risk level based on multiple factors."""
    if maintenance == MaintenanceLevel.ABANDONED:
        return RiskLevel.CRITICAL
    if maintenance == MaintenanceLevel.STALE:
        if version_gap >= 3:
            return RiskLevel.CRITICAL
        return RiskLevel.HIGH
    if maintenance == MaintenanceLevel.SLOW:
        if version_gap >= 5:
            return RiskLevel.HIGH
        if version_gap >= 2:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    # ACTIVE or STABLE
    if version_gap >= 10:
        return RiskLevel.MEDIUM
    if version_gap >= 3:
        return RiskLevel.LOW
    return RiskLevel.LOW


def classify_cadence_trend(intervals: list[float]) -> CadenceTrend:
    """Classify the trend in release cadence.

    Compares the average interval of the first half of releases
    to the second half.
    """
    if len(intervals) < 3:
        return CadenceTrend.INSUFFICIENT_DATA

    mid = len(intervals) // 2
    first_half_avg = sum(intervals[:mid]) / mid if mid > 0 else 0
    second_half_avg = (
        sum(intervals[mid:]) / (len(intervals) - mid) if (len(intervals) - mid) > 0 else 0
    )

    if first_half_avg == 0 and second_half_avg == 0:
        return CadenceTrend.INSUFFICIENT_DATA

    # If second half is faster (shorter intervals), cadence is improving
    ratio = second_half_avg / first_half_avg if first_half_avg > 0 else 1.0

    if ratio < 0.7:
        return CadenceTrend.IMPROVING
    if ratio > 1.4:
        return CadenceTrend.DECLINING
    return CadenceTrend.STEADY


def build_timeline(
    package_name: str,
    installed_version: str | None = None,
    latest_version: str | None = None,
    releases_data: list[dict[str, Any]] | None = None,
) -> Timeline:
    """Build a Timeline from package data.

    Parameters
    ----------
    package_name
        Name of the package.
    installed_version
        Currently installed version string.
    latest_version
        Latest available version string.
    releases_data
        List of release dicts with keys: version, release_date (ISO str or datetime),
        is_prerelease, is_yanked.
    """
    releases: list[Release] = []
    if releases_data:
        for rd in releases_data:
            date_val = rd.get("release_date")
            if isinstance(date_val, str):
                release_date = datetime.fromisoformat(date_val)
            elif isinstance(date_val, datetime):
                release_date = date_val
            else:
                continue

            version_str = rd.get("version", "0.0.0")
            is_pre = rd.get("is_prerelease", _is_prerelease(version_str))
            is_yanked = rd.get("is_yanked", False)

            releases.append(
                Release(
                    version=version_str,
                    release_date=release_date,
                    is_prerelease=is_pre,
                    is_yanked=is_yanked,
                )
            )

    # Sort releases by date
    releases.sort(key=lambda r: r.release_date)

    # Compute metrics
    stable_releases_list = [r for r in releases if r.is_stable]
    prereleases = [r for r in releases if r.is_prerelease]
    yanked = [r for r in releases if r.is_yanked]

    intervals = compute_release_intervals(releases)
    avg_interval = compute_avg_interval(intervals)
    median_interval = compute_median_interval(intervals)

    now = datetime.now(tz=timezone.utc)
    latest_stable = stable_releases_list[-1] if stable_releases_list else None
    first_stable = stable_releases_list[0] if stable_releases_list else None

    days_since_last = 0
    if latest_stable:
        latest_date = latest_stable.release_date
        if latest_date.tzinfo is None:
            latest_date = latest_date.replace(tzinfo=timezone.utc)
        days_since_last = max(0, (now - latest_date).days)

    # Version gap
    version_gap = 0
    major_behind = 0
    minor_behind = 0
    patch_behind = 0
    if installed_version and latest_version:
        version_gap, major_behind, minor_behind, patch_behind = compute_version_gap(
            installed_version, latest_version
        )

    # Classifications
    maintenance = classify_maintenance(days_since_last, avg_interval)
    risk = classify_risk(days_since_last, version_gap, maintenance)
    cadence = classify_cadence_trend(intervals)

    return Timeline(
        package_name=package_name,
        installed_version=installed_version,
        latest_version=latest_version,
        releases=releases,
        total_releases=len(releases),
        stable_releases=len(stable_releases_list),
        yanked_releases_count=len(yanked),
        prerelease_count=len(prereleases),
        first_release_date=first_stable.release_date if first_stable else None,
        latest_release_date=latest_stable.release_date if latest_stable else None,
        avg_days_between_releases=avg_interval,
        median_days_between_releases=median_interval,
        days_since_last_release=days_since_last,
        maintenance_level=maintenance,
        risk_level=risk,
        cadence_trend=cadence,
        version_gap=version_gap,
        patch_behind_count=patch_behind,
        minor_behind_count=minor_behind,
        major_behind_count=major_behind,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_history_table(result: HistoryResult, *, console: Any = None) -> None:
    """Render history analysis as a Rich table."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    if console is None:
        console = Console()

    # Summary panel
    summary_parts: list[str] = []
    summary_parts.append(f"Total packages: {len(result.timelines)}")
    summary_parts.append(f"Active: {result.active_count}")
    if result.stale_count:
        summary_parts.append(f"Stale/Abandoned: {result.stale_count}")
    if result.high_risk_count:
        summary_parts.append(f"High risk: {result.high_risk_count}")

    console.print(Panel("\n".join(summary_parts), title="History Summary", border_style="blue"))

    if not result.timelines:
        console.print("[dim]No packages to analyze.[/dim]")
        return

    # Timeline table
    table = Table(title="Release Timeline Analysis", show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Installed", style="white")
    table.add_column("Latest", style="white")
    table.add_column("Releases", justify="right", style="white")
    table.add_column("Avg Days", justify="right", style="white")
    table.add_column("Since Last", justify="right", style="white")
    table.add_column("Maintenance", style="white")
    table.add_column("Risk", style="white")
    table.add_column("Trend", style="white")

    for tl in result.timelines:
        # Color-code maintenance
        maint_colors = {
            MaintenanceLevel.ACTIVE: "green",
            MaintenanceLevel.STABLE: "blue",
            MaintenanceLevel.SLOW: "yellow",
            MaintenanceLevel.STALE: "red",
            MaintenanceLevel.ABANDONED: "bold red",
        }
        maint_style = maint_colors.get(tl.maintenance_level, "white")

        # Color-code risk
        risk_colors = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red",
        }
        risk_style = risk_colors.get(tl.risk_level, "white")

        table.add_row(
            tl.package_name,
            tl.installed_version or "-",
            tl.latest_version or "-",
            str(tl.total_releases),
            f"{tl.avg_days_between_releases:.0f}" if tl.avg_days_between_releases else "-",
            str(tl.days_since_last_release) if tl.days_since_last_release else "-",
            f"[{maint_style}]{tl.maintenance_level.value}[/{maint_style}]",
            f"[{risk_style}]{tl.risk_level.value}[/{risk_style}]",
            tl.cadence_trend.value.replace("_", " "),
        )

    console.print(table)

    if result.errors:
        console.print("\n[red]Errors:[/red]")
        for err in result.errors:
            console.print(f"  [red]- {err}[/red]")


def render_history_json(result: HistoryResult) -> str:
    """Render history analysis as JSON."""
    return json.dumps(result.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Report builder (main entry point for CLI)
# ---------------------------------------------------------------------------


def build_history_report(
    project_path: str | Path,
    packages: list[str] | None = None,
    risk_threshold: str | None = None,
) -> HistoryResult:
    """Build a history report for all project dependencies.

    Parameters
    ----------
    project_path
        Path to the project directory.
    packages
        Optional list of specific packages to analyze.
    risk_threshold
        Optional risk level threshold filter ('low', 'medium', 'high', 'critical').
        Only packages at or above this level will be included.
    """
    path = Path(project_path)

    if not path.is_dir():
        return HistoryResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Scan project
    try:
        scan_result = scan_project(str(path))
    except Exception as exc:
        return HistoryResult(
            project_path=str(project_path),
            errors=[f"Failed to scan project: {exc}"],
        )

    if scan_result.errors:
        return HistoryResult(
            project_path=str(project_path),
            errors=scan_result.errors,
        )

    # Filter packages
    pkg_list = scan_result.packages
    if packages:
        pkg_set = set(p.lower() for p in packages)
        pkg_list = [p for p in pkg_list if p.name.lower() in pkg_set]

    timelines: list[Timeline] = []
    errors: list[str] = []

    client = PyPIClient()
    for pkg in pkg_list:
        try:
            # Get release data from PyPI
            all_releases = client.get_all_releases(pkg.name)
            releases_data: list[dict[str, Any]] = []
            for ver, files in all_releases.items():
                if not files:
                    continue
                # Get the upload time from the first file
                upload_time_str = files[0].get("upload_time_iso") or files[0].get("upload_time")
                if upload_time_str:
                    try:
                        release_date = datetime.fromisoformat(
                    upload_time_str.replace("Z", "+00:00")
                )
                    except (ValueError, AttributeError):
                        continue
                else:
                    continue

                is_yanked = any(f.get("yanked", False) for f in files)
                releases_data.append({
                    "version": ver,
                    "release_date": release_date.isoformat(),
                    "is_prerelease": _is_prerelease(ver),
                    "is_yanked": is_yanked,
                })

            tl = build_timeline(
                package_name=pkg.name,
                installed_version=pkg.installed_version,
                latest_version=pkg.latest_version,
                releases_data=releases_data,
            )
            timelines.append(tl)
        except Exception as exc:
            errors.append(f"Failed to get history for {pkg.name}: {exc}")

    # Apply risk threshold filter
    if risk_threshold:
        threshold_order = {
            "low": RiskLevel.LOW,
            "medium": RiskLevel.MEDIUM,
            "high": RiskLevel.HIGH,
            "critical": RiskLevel.CRITICAL,
        }
        threshold_level = threshold_order.get(risk_threshold.lower())
        if threshold_level:
            risk_order = list(RiskLevel)
            threshold_idx = risk_order.index(threshold_level)
            timelines = [
                t for t in timelines if risk_order.index(t.risk_level) >= threshold_idx
            ]

    return HistoryResult(
        project_path=str(project_path),
        timelines=timelines,
        errors=errors,
    )
