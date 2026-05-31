"""Package size analysis for depcheck.

Analyzes the download size, install size, and disk footprint of Python
dependencies. Helps identify bloated packages, compare alternatives by
size, and estimate the total dependency footprint of a project.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies, normalize_package_name

# ── Constants ────────────────────────────────────────────────────────────

# Average install-to-download size ratio (empirical: ~2.5x)
INSTALL_SIZE_MULTIPLIER = 2.5

# Size thresholds for categorization
LARGE_PKG_THRESHOLD_KB = 1_000  # 1 MB
VERY_LARGE_PKG_THRESHOLD_KB = 10_000  # 10 MB
HUGE_PKG_THRESHOLD_KB = 100_000  # 100 MB


# ── Data models ──────────────────────────────────────────────────────────


@dataclass
class PackageSize:
    """Size information for a single package.

    Attributes:
        name: Normalized package name.
        version: Resolved version string.
        wheel_size_kb: Size of the wheel file in kilobytes.
        source_size_kb: Size of the source distribution in kilobytes.
        estimated_install_kb: Estimated installed size in kilobytes.
        file_count: Number of files in the distribution.
        has_wheel: Whether a wheel distribution is available.
        has_sdist: Whether a source distribution is available.
        category: Size category (tiny, small, medium, large, very_large, huge).
        status: Health status of the package.
        alternatives: List of alternative package names with smaller sizes.
    """

    name: str = ""
    version: str = ""
    wheel_size_kb: float = 0.0
    source_size_kb: float = 0.0
    estimated_install_kb: float = 0.0
    file_count: int = 0
    has_wheel: bool = False
    has_sdist: bool = False
    category: str = "unknown"
    status: HealthStatus = HealthStatus.UNKNOWN
    alternatives: list[str] = field(default_factory=list)

    @property
    def download_size_kb(self) -> float:
        """Prefer wheel size, fall back to source size."""
        return self.wheel_size_kb if self.wheel_size_kb > 0 else self.source_size_kb

    @property
    def human_download_size(self) -> str:
        """Human-readable download size."""
        return _human_size(self.download_size_kb)

    @property
    def human_install_size(self) -> str:
        """Human-readable estimated install size."""
        return _human_size(self.estimated_install_kb)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "wheel_size_kb": round(self.wheel_size_kb, 1),
            "source_size_kb": round(self.source_size_kb, 1),
            "download_size_kb": round(self.download_size_kb, 1),
            "estimated_install_kb": round(self.estimated_install_kb, 1),
            "human_download_size": self.human_download_size,
            "human_install_size": self.human_install_size,
            "file_count": self.file_count,
            "has_wheel": self.has_wheel,
            "has_sdist": self.has_sdist,
            "category": self.category,
            "status": self.status.value,
            "alternatives": self.alternatives,
        }


@dataclass
class SizeReport:
    """Aggregated size report for a project's dependencies.

    Attributes:
        project_path: Path to the analyzed project.
        packages: Size info for each package.
        total_download_kb: Total download size of all packages.
        total_install_kb: Total estimated install size.
        total_file_count: Total file count across all packages.
        largest_packages: Top 5 largest packages by download size.
        category_breakdown: Count of packages by size category.
        errors: Any errors encountered.
    """

    project_path: str = ""
    packages: list[PackageSize] = field(default_factory=list)
    total_download_kb: float = 0.0
    total_install_kb: float = 0.0
    total_file_count: int = 0
    largest_packages: list[str] = field(default_factory=list)
    category_breakdown: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def human_total_download(self) -> str:
        return _human_size(self.total_download_kb)

    @property
    def human_total_install(self) -> str:
        return _human_size(self.total_install_kb)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "packages": [p.to_dict() for p in self.packages],
            "total_download_kb": round(self.total_download_kb, 1),
            "total_install_kb": round(self.total_install_kb, 1),
            "human_total_download": self.human_total_download,
            "human_total_install": self.human_total_install,
            "total_file_count": self.total_file_count,
            "largest_packages": self.largest_packages,
            "category_breakdown": self.category_breakdown,
            "errors": self.errors,
        }


# ── Well-known lightweight alternatives ──────────────────────────────────


_LIGHTWEIGHT_ALTERNATIVES: dict[str, list[str]] = {
    "requests": ["httpx", "urllib3", "aiohttp"],
    "numpy": ["array", "tinyndarray"],
    "pandas": ["polars", "duckdb", "datatable"],
    "flask": ["starlette", "fastapi", "bottle"],
    "django": ["flask", "starlette", "fastapi"],
    "sqlalchemy": ["peewee", "sqlite-utils", "dataset"],
    "pillow": ["pgmagick", "pyvips"],
    "matplotlib": ["plotly", "altair", "seaborn"],
    "scipy": ["numpy"],
    "tensorflow": ["onnxruntime", "tinygrad"],
    "torch": ["onnxruntime", "tinygrad", "sklearn"],
    "click": ["argparse", "docopt"],
    "rich": ["click", "colorama"],
    "pyyaml": ["tomli", "tomllib"],
    "lxml": ["xml.etree", "defusedxml"],
    "beautifulsoup4": ["lxml", "selectolax"],
    "selenium": ["playwright"],
    "pytest": ["unittest"],
    "boto3": ["moto"],
}


# ── Helpers ──────────────────────────────────────────────────────────────


def _human_size(size_kb: float) -> str:
    """Convert kilobytes to human-readable string.

    Args:
        size_kb: Size in kilobytes.

    Returns:
        Human-readable size string (e.g., "1.5 MB").
    """
    if size_kb <= 0:
        return "0 KB"
    if size_kb < 1:
        return f"{size_kb * 1024:.0f} B"
    if size_kb < LARGE_PKG_THRESHOLD_KB:
        return f"{size_kb:.1f} KB"
    if size_kb < VERY_LARGE_PKG_THRESHOLD_KB:
        return f"{size_kb / LARGE_PKG_THRESHOLD_KB:.1f} MB"
    return f"{size_kb / VERY_LARGE_PKG_THRESHOLD_KB:.1f} MB"


def _categorize_size(size_kb: float) -> str:
    """Categorize a package by its download size.

    Args:
        size_kb: Download size in kilobytes.

    Returns:
        Size category string.
    """
    if size_kb <= 0:
        return "unknown"
    if size_kb < 50:
        return "tiny"
    if size_kb < LARGE_PKG_THRESHOLD_KB:
        return "small"
    if size_kb < VERY_LARGE_PKG_THRESHOLD_KB:
        return "medium"
    if size_kb < HUGE_PKG_THRESHOLD_KB:
        return "large"
    return "very_large"


# ── Size analysis implementation ────────────────────────────────────────


def _fetch_package_size(
    pypi_client: PyPIClient,
    package_name: str,
    version: str | None = None,
) -> PackageSize:
    """Fetch size information for a single package.

    Args:
        pypi_client: PyPI API client.
        package_name: Package name to analyze.
        version: Optional version to check (defaults to latest).

    Returns:
        PackageSize with size metadata.
    """
    result = PackageSize(name=normalize_package_name(package_name))

    info = pypi_client.get_package_info(package_name)
    if info is None:
        result.status = HealthStatus.REMOVED
        return result

    # Get version
    pkg_info = info.get("info", {})
    result.version = version or pkg_info.get("version", "unknown")
    result.status = HealthStatus.HEALTHY

    # Parse releases to find file sizes
    releases = info.get("releases", {})
    version_files = releases.get(result.version, [])

    if not version_files:
        # Try latest version
        result.version = pkg_info.get("version", "unknown")
        version_files = releases.get(result.version, [])

    wheel_size = 0.0
    source_size = 0.0
    file_count = 0

    for file_info in version_files:
        packagetype = file_info.get("packagetype", "")
        size_bytes = file_info.get("size", 0) or 0
        size_kb = size_bytes / 1024.0

        if packagetype == "bdist_wheel":
            wheel_size = max(wheel_size, size_kb)
            result.has_wheel = True
            # Count files in wheel (approximate from size)
            file_count += max(1, int(size_kb / 5))  # ~5KB per file avg
        elif packagetype == "sdist":
            source_size = max(source_size, size_kb)
            result.has_sdist = True
            file_count += max(1, int(size_kb / 8))  # ~8KB per file avg

    result.wheel_size_kb = wheel_size
    result.source_size_kb = source_size
    result.file_count = file_count

    # Estimate install size
    download_size = result.download_size_kb
    result.estimated_install_kb = download_size * INSTALL_SIZE_MULTIPLIER

    # Categorize
    result.category = _categorize_size(download_size)

    # Suggest alternatives for large packages
    if download_size > LARGE_PKG_THRESHOLD_KB:
        alts = _LIGHTWEIGHT_ALTERNATIVES.get(package_name.lower(), [])
        if alts:
            result.alternatives = alts

    return result


def analyze_project_sizes(
    project_path: str | Path,
    check_vulnerabilities: bool = False,
) -> SizeReport:
    """Analyze the size footprint of all project dependencies.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to include health status.

    Returns:
        SizeReport with size info for each dependency.
    """
    project_path = Path(project_path).resolve()

    report = SizeReport(project_path=str(project_path))

    if not project_path.is_dir():
        report.errors.append(f"Path is not a directory: {project_path}")
        return report

    # Discover dependencies
    dependencies, _ = discover_dependencies(project_path)
    if not dependencies:
        report.errors.append("No dependencies found in the project.")
        return report

    # Fetch sizes for each dependency
    with PyPIClient() as pypi_client:
        for dep in dependencies:
            try:
                size = _fetch_package_size(pypi_client, dep.name, dep.version)
                report.packages.append(size)
            except Exception as exc:
                report.errors.append(f"Error analyzing {dep.name}: {exc}")
                report.packages.append(
                    PackageSize(
                        name=dep.name,
                        version=dep.version or "unknown",
                        status=HealthStatus.UNKNOWN,
                    )
                )

    # Compute aggregates
    report.total_download_kb = sum(p.download_size_kb for p in report.packages)
    report.total_install_kb = sum(p.estimated_install_kb for p in report.packages)
    report.total_file_count = sum(p.file_count for p in report.packages)

    # Find largest packages
    sorted_pkgs = sorted(report.packages, key=lambda p: p.download_size_kb, reverse=True)
    report.largest_packages = [p.name for p in sorted_pkgs[:5]]

    # Category breakdown
    categories: dict[str, int] = {}
    for p in report.packages:
        categories[p.category] = categories.get(p.category, 0) + 1
    report.category_breakdown = categories

    return report


def compare_package_sizes(
    package_names: list[str],
) -> list[PackageSize]:
    """Compare sizes of multiple packages.

    Args:
        package_names: List of package names to compare.

    Returns:
        List of PackageSize objects sorted by download size (ascending).
    """
    results: list[PackageSize] = []
    with PyPIClient() as pypi_client:
        for name in package_names:
            try:
                size = _fetch_package_size(pypi_client, name)
                results.append(size)
            except Exception:
                results.append(
                    PackageSize(
                        name=normalize_package_name(name),
                        status=HealthStatus.UNKNOWN,
                    )
                )

    results.sort(key=lambda p: p.download_size_kb)
    return results


# ── Rendering ────────────────────────────────────────────────────────────


def render_size_table(report: SizeReport, console: Console | None = None) -> None:
    """Render a size report as a Rich table.

    Args:
        report: The size report to render.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    console.print()
    console.print(
        Panel(
            f"[bold]depcheck size[/bold] — Dependency Size Report\n"
            f"[dim]Project: {report.project_path}[/dim]",
            border_style="blue",
        )
    )

    if not report.packages:
        console.print("[dim]No packages to analyze.[/dim]")
        return

    # Size table
    table = Table(
        title="Package Sizes",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        expand=True,
    )

    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Version", min_width=10)
    table.add_column("Download", min_width=12, justify="right")
    table.add_column("Install (est.)", min_width=12, justify="right")
    table.add_column("Category", min_width=10, justify="center")
    table.add_column("Type", min_width=8, justify="center")
    table.add_column("Alternatives", min_width=20)

    category_colors = {
        "tiny": "green",
        "small": "green",
        "medium": "yellow",
        "large": "red",
        "very_large": "red bold",
        "unknown": "dim",
    }

    for pkg in sorted(report.packages, key=lambda p: p.download_size_kb, reverse=True):
        color = category_colors.get(pkg.category, "white")
        dist_type = "wheel" if pkg.has_wheel else ("sdist" if pkg.has_sdist else "—")
        alts = ", ".join(pkg.alternatives[:3]) if pkg.alternatives else "—"

        table.add_row(
            f"[cyan]{pkg.name}[/cyan]",
            pkg.version,
            pkg.human_download_size,
            pkg.human_install_size,
            f"[{color}]{pkg.category}[/{color}]",
            dist_type,
            f"[dim]{alts}[/dim]" if alts != "—" else "—",
        )

    console.print(table)

    # Summary
    console.print()
    summary_parts = [
        f"[bold]Total dependencies:[/bold] {len(report.packages)}",
        f"[bold]Download size:[/bold] {report.human_total_download}",
        f"[bold]Install size (est.):[/bold] {report.human_total_install}",
        f"[bold]Total files (est.):[/bold] {report.total_file_count:,}",
    ]

    if report.category_breakdown:
        breakdown = "  ".join(
            f"[{category_colors.get(cat, 'white')}]{cat}: {count}"
f"[/{category_colors.get(cat, 'white')}]"
            for cat, count in sorted(report.category_breakdown.items())
        )
        summary_parts.append(f"[bold]Size breakdown:[/bold] {breakdown}")

    if report.largest_packages:
        summary_parts.append(
            f"[bold]Largest:[/bold] {', '.join(report.largest_packages[:3])}"
        )

    console.print(Panel("\n".join(summary_parts), title="Size Summary", border_style="blue"))
    console.print()


def render_size_comparison(
    packages: list[PackageSize],
    console: Console | None = None,
) -> None:
    """Render a size comparison table for multiple packages.

    Args:
        packages: List of PackageSize objects to compare.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    if not packages:
        console.print("[dim]No packages to compare.[/dim]")
        return

    console.print()
    console.print(
    Panel("[bold]depcheck size[/bold] — Package Size Comparison", border_style="blue")
)

    table = Table(
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        expand=True,
    )

    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Version", min_width=10)
    table.add_column("Download", min_width=12, justify="right")
    table.add_column("Install (est.)", min_width=12, justify="right")
    table.add_column("Category", min_width=10, justify="center")
    table.add_column("Winner", width=8, justify="center")

    smallest = min(packages, key=lambda p: p.download_size_kb) if packages else None

    for pkg in packages:
        is_smallest = smallest and pkg.name == smallest.name and pkg.download_size_kb > 0
        winner = "[green]✓ smallest[/green]" if is_smallest else ""
        cat_colors = {
            "tiny": "green", "small": "green", "medium": "yellow",
            "large": "red", "very_large": "red bold", "unknown": "dim",
        }
        color = cat_colors.get(pkg.category, "white")

        table.add_row(
            f"[cyan]{pkg.name}[/cyan]",
            pkg.version,
            pkg.human_download_size,
            pkg.human_install_size,
            f"[{color}]{pkg.category}[/{color}]",
            winner,
        )

    console.print(table)
    console.print()


def render_size_json(report: SizeReport) -> str:
    """Render size report as JSON string.

    Args:
        report: The size report to render.

    Returns:
        JSON string.
    """
    return json.dumps(report.to_dict(), indent=2)


def render_comparison_json(packages: list[PackageSize]) -> str:
    """Render size comparison as JSON string.

    Args:
        packages: List of PackageSize objects.

    Returns:
        JSON string.
    """
    return json.dumps([p.to_dict() for p in packages], indent=2)
