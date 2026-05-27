"""Outdated dependency analysis with upgrade path tracking and risk assessment."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus, ScanResult


class UpgradeLevel:
    """Classification of upgrade severity based on semver."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    PRERELEASE = "prerelease"
    UNKNOWN = "unknown"


class RiskLevel:
    """Risk level for upgrading a dependency."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


@dataclass
class UpgradeInfo:
    """Detailed upgrade information for a single package."""

    name: str
    installed_version: str
    latest_version: str
    upgrade_level: str = UpgradeLevel.UNKNOWN
    risk: str = RiskLevel.UNKNOWN
    days_behind: int | None = None
    installed_release_date: str | None = None
    latest_release_date: str | None = None
    changelog_url: str | None = None
    is_prerelease: bool = False
    deprecation_warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "upgrade_level": self.upgrade_level,
            "risk": self.risk,
            "days_behind": self.days_behind,
            "installed_release_date": self.installed_release_date,
            "latest_release_date": self.latest_release_date,
            "changelog_url": self.changelog_url,
            "is_prerelease": self.is_prerelease,
            "deprecation_warning": self.deprecation_warning,
        }


@dataclass
class OutdatedReport:
    """Aggregated outdated dependency report."""

    packages: list[UpgradeInfo] = field(default_factory=list)
    total_packages: int = 0
    up_to_date_count: int = 0
    outdated_count: int = 0
    major_count: int = 0
    minor_count: int = 0
    patch_count: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "total_packages": self.total_packages,
                "up_to_date": self.up_to_date_count,
                "outdated": self.outdated_count,
                "major_upgrades": self.major_count,
                "minor_upgrades": self.minor_count,
                "patch_upgrades": self.patch_count,
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


def classify_upgrade_level(installed: str, latest: str) -> str:
    """Classify the upgrade level (major/minor/patch) based on semver.

    Args:
        installed: The currently installed version string.
        latest: The latest available version string.

    Returns:
        One of UpgradeLevel constants.
    """
    try:
        from packaging.version import Version

        inst_ver = Version(installed)
        lat_ver = Version(latest)

        # Check for prerelease
        if lat_ver.is_prerelease or lat_ver.is_devrelease:
            return UpgradeLevel.PRERELEASE

        if inst_ver.epoch != lat_ver.epoch:
            return UpgradeLevel.MAJOR

        if lat_ver.major > inst_ver.major:
            return UpgradeLevel.MAJOR
        elif lat_ver.major == inst_ver.major:
            if lat_ver.minor > inst_ver.minor:
                return UpgradeLevel.MINOR
            elif lat_ver.minor == inst_ver.minor:
                if lat_ver.micro > inst_ver.micro:
                    return UpgradeLevel.PATCH
                else:
                    # Same major.minor.micro but different post/dev
                    return UpgradeLevel.PATCH
        return UpgradeLevel.PATCH
    except Exception:
        return UpgradeLevel.UNKNOWN


def assess_risk(upgrade_level: str, days_behind: int | None) -> str:
    """Assess the risk of upgrading based on upgrade level and age.

    Args:
        upgrade_level: The semver classification of the upgrade.
        days_behind: Number of days between installed and latest release.

    Returns:
        One of RiskLevel constants.
    """
    if upgrade_level == UpgradeLevel.MAJOR:
        return RiskLevel.HIGH
    elif upgrade_level == UpgradeLevel.MINOR:
        if days_behind is not None and days_behind > 365:
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM
    elif upgrade_level == UpgradeLevel.PATCH:
        return RiskLevel.LOW
    elif upgrade_level == UpgradeLevel.PRERELEASE:
        return RiskLevel.HIGH
    return RiskLevel.UNKNOWN


def guess_changelog_url(package_name: str, pypi_info: dict[str, Any] | None = None) -> str | None:
    """Guess the changelog URL for a package.

    Tries project_urls from PyPI data first, then falls back to
    common patterns.

    Args:
        package_name: The normalized package name.
        pypi_info: Pre-fetched PyPI info dict (optional).

    Returns:
        A URL string or None.
    """
    # Try project_urls from PyPI metadata
    if pypi_info:
        info = pypi_info.get("info", {})
        project_urls = info.get("project_urls") or {}
        for key in ("Changelog", "Changes", "Change Log", "History", "Release Notes", "What's New"):
            if key in project_urls:
                return project_urls[key]
        # Try homepage as fallback
        home = info.get("home_page") or project_urls.get("Homepage")
        if home and "github.com" in home:
            base = home.rstrip("/")
            return f"{base}/releases"

    # Common GitHub pattern
    return f"https://github.com/{package_name}/{package_name}/releases"


def compute_days_behind(
    installed_date: str | None, latest_date: str | None
) -> int | None:
    """Compute the number of days between two release dates.

    Args:
        installed_date: ISO date string for the installed version.
        latest_date: ISO date string for the latest version.

    Returns:
        Number of days behind, or None if dates can't be parsed.
    """
    if not installed_date or not latest_date:
        return None
    try:
        inst = datetime.date.fromisoformat(installed_date)
        lat = datetime.date.fromisoformat(latest_date)
        return (lat - inst).days
    except (ValueError, TypeError):
        return None


def build_outdated_report(
    scan_result: ScanResult,
    pypi_infos: dict[str, dict[str, Any]] | None = None,
) -> OutdatedReport:
    """Build an OutdatedReport from a ScanResult.

    Args:
        scan_result: The raw scan result from scan_project().
        pypi_infos: Optional pre-fetched PyPI info for changelog URLs.

    Returns:
        An OutdatedReport with upgrade path details.
    """
    report = OutdatedReport(
        total_packages=len(scan_result.packages),
        errors=list(scan_result.errors),
    )

    for pkg in scan_result.packages:
        if pkg.status == HealthStatus.HEALTHY:
            report.up_to_date_count += 1
            continue

        if pkg.status not in (HealthStatus.OUTDATED, HealthStatus.UNMAINTAINED):
            # Skip vulnerable/yanked/removed — those need different actions
            report.up_to_date_count += 1
            continue

        if not pkg.latest_version or not pkg.installed_version:
            continue

        if pkg.installed_version == "unknown":
            continue

        level = classify_upgrade_level(pkg.installed_version, pkg.latest_version)
        days = compute_days_behind(pkg.last_release_date, None)
        # We'll use the last_release_date as the latest release date
        # since that's what the scanner provides

        risk = assess_risk(level, days)

        # Try to get changelog URL
        changelog = None
        if pypi_infos and pkg.name in pypi_infos:
            changelog = guess_changelog_url(pkg.name, pypi_infos[pkg.name])
        else:
            changelog = guess_changelog_url(pkg.name)

        info = UpgradeInfo(
            name=pkg.name,
            installed_version=pkg.installed_version,
            latest_version=pkg.latest_version,
            upgrade_level=level,
            risk=risk,
            days_behind=days,
            latest_release_date=pkg.last_release_date,
            changelog_url=changelog,
            is_prerelease=level == UpgradeLevel.PRERELEASE,
        )
        report.packages.append(info)
        report.outdated_count += 1

        if level == UpgradeLevel.MAJOR:
            report.major_count += 1
        elif level == UpgradeLevel.MINOR:
            report.minor_count += 1
        elif level == UpgradeLevel.PATCH:
            report.patch_count += 1

    # Sort: major first, then minor, then patch
    level_order = {
        UpgradeLevel.MAJOR: 0,
        UpgradeLevel.MINOR: 1,
        UpgradeLevel.PATCH: 2,
        UpgradeLevel.PRERELEASE: 3,
        UpgradeLevel.UNKNOWN: 4,
    }
    report.packages.sort(key=lambda p: (level_order.get(p.upgrade_level, 4), p.name))

    return report


def render_outdated_table(report: OutdatedReport, console: Console | None = None) -> None:
    """Render the outdated report as a Rich table.

    Args:
        report: The OutdatedReport to render.
        console: Optional Rich console (created if not provided).
    """
    if console is None:
        console = Console()

    if not report.packages:
        console.print("[green]✓ All dependencies are up to date![/green]")
        return

    # Summary panel
    summary_parts = []
    if report.major_count:
        summary_parts.append(f"[red]{report.major_count} major[/red]")
    if report.minor_count:
        summary_parts.append(f"[yellow]{report.minor_count} minor[/yellow]")
    if report.patch_count:
        summary_parts.append(f"[green]{report.patch_count} patch[/green]")

    summary_text = "Outdated: " + ", ".join(summary_parts)
    summary_text += f"  •  {report.up_to_date_count} up to date  •  {report.total_packages} total"

    console.print()
    console.print(Panel(summary_text, title="Outdated Dependencies", border_style="blue"))

    # Main table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Package", style="cyan", min_width=20)
    table.add_column("Installed", justify="right", min_width=12)
    table.add_column("Latest", justify="right", min_width=12)
    table.add_column("Level", justify="center", min_width=8)
    table.add_column("Risk", justify="center", min_width=8)
    table.add_column("Days Behind", justify="right", min_width=12)
    table.add_column("Changelog", min_width=20, no_wrap=True)

    risk_colors = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.UNKNOWN: "dim",
    }

    level_colors = {
        UpgradeLevel.MAJOR: "red bold",
        UpgradeLevel.MINOR: "yellow",
        UpgradeLevel.PATCH: "green",
        UpgradeLevel.PRERELEASE: "magenta",
        UpgradeLevel.UNKNOWN: "dim",
    }

    level_icons = {
        UpgradeLevel.MAJOR: "⬆ MAJOR",
        UpgradeLevel.MINOR: "↗ minor",
        UpgradeLevel.PATCH: "· patch",
        UpgradeLevel.PRERELEASE: "⚠ pre",
        UpgradeLevel.UNKNOWN: "?",
    }

    for pkg in report.packages:
        risk_color = risk_colors.get(pkg.risk, "dim")
        level_color = level_colors.get(pkg.upgrade_level, "dim")
        level_text = level_icons.get(pkg.upgrade_level, "?")

        days_str = str(pkg.days_behind) if pkg.days_behind is not None else "-"
        if pkg.days_behind is not None and pkg.days_behind > 365:
            days_str = f"{pkg.days_behind}d ⚠"

        changelog_str = pkg.changelog_url or "-"
        # Truncate long URLs for display
        if len(changelog_str) > 50:
            changelog_str = changelog_str[:47] + "..."

        table.add_row(
            pkg.name,
            pkg.installed_version,
            f"[bold]{pkg.latest_version}[/bold]",
            f"[{level_color}]{level_text}[/{level_color}]",
            f"[{risk_color}]{pkg.risk.upper()}[/{risk_color}]",
            days_str,
            changelog_str,
        )

    console.print(table)

    # Upgrade hints
    console.print()
    if report.major_count:
        console.print(
            f"[red]⚠ {report.major_count} major upgrade(s) available — "
            f"review changelogs for breaking changes before upgrading.[/red]"
        )
    if report.minor_count:
        console.print(
            f"[yellow]💡 {report.minor_count} minor upgrade(s) — "
            f"usually safe but check for deprecations.[/yellow]"
        )
    if report.patch_count:
        console.print(
            f"[green]✓ {report.patch_count} patch upgrade(s) — "
            f"generally safe, often includes bug fixes.[/green]"
        )


def render_outdated_json(report: OutdatedReport) -> str:
    """Render the outdated report as JSON string.

    Args:
        report: The OutdatedReport to render.

    Returns:
        JSON string of the report.
    """
    import json

    return json.dumps(report.to_dict(), indent=2)


def render_upgrade_commands(report: OutdatedReport, console: Console | None = None) -> None:
    """Render pip upgrade commands for all outdated packages.

    Args:
        report: The OutdatedReport to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    if not report.packages:
        return

    console.print()
    console.print("[bold]Upgrade commands:[/bold]")
    console.print()

    # Group by risk level
    low_pkgs = [p for p in report.packages if p.risk == RiskLevel.LOW]
    med_pkgs = [p for p in report.packages if p.risk == RiskLevel.MEDIUM]
    high_pkgs = [p for p in report.packages if p.risk == RiskLevel.HIGH]

    if low_pkgs:
        console.print("[green]# Low risk (patch upgrades):[/green]")
        names = " ".join(f"{p.name}=={p.latest_version}" for p in low_pkgs)
        console.print(f"[dim]$[/dim] pip install --upgrade {names}")
        console.print()

    if med_pkgs:
        console.print("[yellow]# Medium risk (minor upgrades):[/yellow]")
        for p in med_pkgs:
            console.print(f"[dim]$[/dim] pip install --upgrade {p.name}=={p.latest_version}")
        console.print()

    if high_pkgs:
        console.print("[red]# High risk (major upgrades — review changelogs first!):[/red]")
        for p in high_pkgs:
            url = p.changelog_url or "N/A"
            console.print(
                f"[dim]$[/dim] pip install --upgrade {p.name}=={p.latest_version}"
                f"  [dim]# {url}[/dim]"
            )
