"""Dependency size estimation for depcheck.

Estimates the download and install size of dependencies by analyzing
PyPI package metadata (wheel/sdist file sizes). Provides aggregated
reports showing which dependencies are heaviest and where bloat lives.

Features:
- Per-package download size from PyPI wheel metadata
- Install size estimation (typically 2-3x download size for Python packages)
- Cumulative size analysis for project dependency footprint
- Bloat detection: large packages that could be replaced
- Size-by-category breakdown (direct vs transitive)
- Comparison between download and estimated install size
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.pypi import PyPIClient
from depcheck.scanner import normalize_package_name, scan_project

# ── Constants ────────────────────────────────────────────────────────────

# Install size multiplier: Python packages typically expand 2-3x
# (bytecode, .pyc files, .dist-info, extracted C extensions)
INSTALL_SIZE_MULTIPLIER = 2.5

# Threshold for "large" package in MB
LARGE_PACKAGE_THRESHOLD_MB = 10.0

# Threshold for "bloated" package in MB (consider replacing)
BLOAT_THRESHOLD_MB = 50.0


# ── Data Models ──────────────────────────────────────────────────────────


@dataclass
class PackageSize:
    """Size information for a single package."""

    name: str
    version: str | None = None
    download_size_bytes: int = 0
    install_size_bytes: int = 0
    file_type: str = "unknown"  # "wheel", "sdist", "unknown"
    is_large: bool = False
    is_bloated: bool = False
    error: str | None = None

    @property
    def download_size_mb(self) -> float:
        """Download size in megabytes."""
        return self.download_size_bytes / (1024 * 1024)

    @property
    def install_size_mb(self) -> float:
        """Estimated install size in megabytes."""
        return self.install_size_bytes / (1024 * 1024)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "download_size_bytes": self.download_size_bytes,
            "download_size_mb": round(self.download_size_mb, 2),
            "install_size_bytes": self.install_size_bytes,
            "install_size_mb": round(self.install_size_mb, 2),
            "file_type": self.file_type,
            "is_large": self.is_large,
            "is_bloated": self.is_bloated,
            "error": self.error,
        }


@dataclass
class SizeReport:
    """Aggregated size report for all project dependencies."""

    project_path: str
    packages: list[PackageSize] = field(default_factory=list)
    total_download_bytes: int = 0
    total_install_bytes: int = 0
    large_packages: list[str] = field(default_factory=list)
    bloated_packages: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_download_mb(self) -> float:
        """Total download size in megabytes."""
        return self.total_download_bytes / (1024 * 1024)

    @property
    def total_install_mb(self) -> float:
        """Total estimated install size in megabytes."""
        return self.total_install_bytes / (1024 * 1024)

    @property
    def packages_with_sizes(self) -> int:
        """Number of packages for which we successfully got size data."""
        return sum(1 for p in self.packages if p.error is None)

    @property
    def packages_with_errors(self) -> int:
        """Number of packages for which size lookup failed."""
        return sum(1 for p in self.packages if p.error is not None)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "summary": {
                "total_packages": len(self.packages),
                "packages_with_sizes": self.packages_with_sizes,
                "packages_with_errors": self.packages_with_errors,
                "total_download_mb": round(self.total_download_mb, 2),
                "total_install_mb": round(self.total_install_mb, 2),
                "large_packages": self.large_packages,
                "bloated_packages": self.bloated_packages,
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


# ── Size Estimation ──────────────────────────────────────────────────────


def _get_package_download_size(
    package_name: str,
    version: str | None = None,
    pypi: PyPIClient | None = None,
) -> PackageSize:
    """Get the download size of a package from PyPI metadata.

    Prefers wheel files (they're what pip installs), falls back to sdist.
    Picks the smallest wheel for the current platform or "any" platform.

    Args:
        package_name: Normalized package name.
        version: Optional version string.
        pypi: Optional PyPI client (created if not provided).

    Returns:
        PackageSize with size information.
    """
    should_close = pypi is None
    if pypi is None:
        pypi = PyPIClient()

    try:
        info = pypi.get_package_info(package_name)
        if info is None:
            return PackageSize(
                name=package_name,
                version=version,
                error="Package not found on PyPI",
            )

        latest_version = info.get("info", {}).get("version", "")
        target_version = version or latest_version
        releases = info.get("releases", {})

        # Find the best file for this version
        version_files = releases.get(target_version, [])
        if not version_files:
            # Try latest version if specified version not found
            version_files = releases.get(latest_version, [])

        if not version_files:
            return PackageSize(
                name=package_name,
                version=target_version,
                error="No release files found",
            )

        # Prefer wheels (especially "none any" universal wheels)
        wheels = [f for f in version_files if f.get("packagetype") == "bdist_wheel"]
        sdists = [f for f in version_files if f.get("packagetype") == "sdist"]

        best_file = None
        file_type = "unknown"

        if wheels:
            # Prefer pure-python wheels (any platform), then any wheel
            pure_wheels = [w for w in wheels if "none" in w.get("filename", "")]
            if pure_wheels:
                best_file = min(pure_wheels, key=lambda f: f.get("size", float("inf")))
            else:
                best_file = min(wheels, key=lambda f: f.get("size", float("inf")))
            file_type = "wheel"
        elif sdists:
            best_file = min(sdists, key=lambda f: f.get("size", float("inf")))
            file_type = "sdist"

        if best_file is None:
            return PackageSize(
                name=package_name,
                version=target_version,
                error="No suitable download file found",
            )

        download_bytes = best_file.get("size", 0) or 0
        install_bytes = int(download_bytes * INSTALL_SIZE_MULTIPLIER)

        return PackageSize(
            name=package_name,
            version=target_version,
            download_size_bytes=download_bytes,
            install_size_bytes=install_bytes,
            file_type=file_type,
            is_large=download_bytes >= LARGE_PACKAGE_THRESHOLD_MB * 1024 * 1024,
            is_bloated=download_bytes >= BLOAT_THRESHOLD_MB * 1024 * 1024,
        )

    except Exception as exc:
        return PackageSize(
            name=package_name,
            version=version,
            error=str(exc),
        )
    finally:
        if should_close:
            pypi.close()


def build_size_report(
    project_path: str,
    check_vulnerabilities: bool = False,
    check_licenses: bool = False,
) -> SizeReport:
    """Build a complete size report for a project's dependencies.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to include vulnerability data.
        check_licenses: Whether to include license data.

    Returns:
        SizeReport with size information for all dependencies.
    """
    # Use scan_project to get the full list of packages
    result = scan_project(
        project_path=project_path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )

    report = SizeReport(project_path=project_path)

    with PyPIClient() as pypi:
        for pkg in result.packages:
            pkg_size = _get_package_download_size(
                package_name=normalize_package_name(pkg.name),
                version=pkg.installed_version,
                pypi=pypi,
            )
            report.packages.append(pkg_size)

    # Calculate totals
    report.total_download_bytes = sum(
        p.download_size_bytes for p in report.packages if p.error is None
    )
    report.total_install_bytes = sum(
        p.install_size_bytes for p in report.packages if p.error is None
    )

    # Identify large and bloated packages
    for pkg in report.packages:
        if pkg.is_bloated:
            report.bloated_packages.append(pkg.name)
        elif pkg.is_large:
            report.large_packages.append(pkg.name)

    # Collect errors
    for pkg in report.packages:
        if pkg.error:
            report.errors.append(f"{pkg.name}: {pkg.error}")

    return report


# ── Rendering ────────────────────────────────────────────────────────────


def _format_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable size string.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Human-readable size string (e.g., "1.5 MB", "256 KB").
    """
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def render_size_table(report: SizeReport, console: Console | None = None) -> None:
    """Render the size report as a Rich table.

    Args:
        report: The size report to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    # Summary panel
    summary_text = (
        f"[bold]Total Download:[/bold] {_format_size(report.total_download_bytes)}  "
        f"[bold]Total Install:[/bold] {_format_size(report.total_install_bytes)}  "
        f"[bold]Packages:[/bold] {report.packages_with_sizes}/{len(report.packages)}  "
        f"[bold]Large:[/bold] {len(report.large_packages)}  "
        f"[bold]Bloated:[/bold] {len(report.bloated_packages)}"
    )
    console.print(Panel(summary_text, title="Dependency Size Report", border_style="blue"))

    # Sort by download size descending
    sorted_packages = sorted(
        [p for p in report.packages if p.error is None],
        key=lambda p: p.download_size_bytes,
        reverse=True,
    )

    table = Table(title="Package Sizes (sorted by download size)", show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="magenta")
    table.add_column("Type", style="dim")
    table.add_column("Download", justify="right", style="green")
    table.add_column("Install (est.)", justify="right", style="yellow")
    table.add_column("% of Total", justify="right")
    table.add_column("Status", style="bold")

    for pkg in sorted_packages:
        pct = (
            (pkg.download_size_bytes / report.total_download_bytes * 100)
            if report.total_download_bytes > 0
            else 0
        )

        status = ""
        if pkg.is_bloated:
            status = "🔴 BLOAT"
        elif pkg.is_large:
            status = "🟡 LARGE"
        else:
            status = "🟢 OK"

        table.add_row(
            pkg.name,
            pkg.version or "—",
            pkg.file_type,
            _format_size(pkg.download_size_bytes),
            _format_size(pkg.install_size_bytes),
            f"{pct:.1f}%",
            status,
        )

    console.print(table)

    # Bloat warnings
    if report.bloated_packages:
        console.print(
            f"\n[bold red]🔴 Bloated packages (>{BLOAT_THRESHOLD_MB:.0f}MB download):[/bold red] "
            + ", ".join(report.bloated_packages)
        )
        console.print("[dim]  Consider lighter alternatives for these packages.[/dim]")

    if report.large_packages:
        console.print(
            f"\n[yellow]🟡 Large packages (>{LARGE_PACKAGE_THRESHOLD_MB:.0f}MB download):[/yellow] "
            + ", ".join(report.large_packages)
        )

    # Packages with errors
    error_pkgs = [p for p in report.packages if p.error is not None]
    if error_pkgs:
        console.print(f"\n[dim]⚠ Could not determine size for {len(error_pkgs)} packages[/dim]")


def render_size_json(report: SizeReport) -> str:
    """Render the size report as JSON.

    Args:
        report: The size report to render.

    Returns:
        JSON string of the size report.
    """
    return json.dumps(report.to_dict(), indent=2)


def render_size_bar_chart(report: SizeReport, console: Console | None = None) -> None:
    """Render a text-based bar chart of package sizes.

    Args:
        report: The size report to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    sorted_packages = sorted(
        [p for p in report.packages if p.error is None and p.download_size_bytes > 0],
        key=lambda p: p.download_size_bytes,
        reverse=True,
    )

    if not sorted_packages:
        console.print("[dim]No size data available for bar chart.[/dim]")
        return

    max_size = max(p.download_size_mb for p in sorted_packages)
    bar_width = 40

    console.print("\n[bold]Download Size Distribution[/bold]")
    for pkg in sorted_packages[:20]:  # Top 20
        size_mb = pkg.download_size_mb
        bar_len = int((size_mb / max_size) * bar_width) if max_size > 0 else 0

        color = "red" if pkg.is_bloated else "yellow" if pkg.is_large else "green"
        bar = "█" * bar_len

        console.print(f"  {pkg.name:<20} [{color}]{bar}[/{color}] {size_mb:.1f} MB")
