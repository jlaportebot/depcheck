"""Package size impact analysis for Python dependencies.

Analyzes the download/install size of dependencies and their impact:
- Download size per package from PyPI metadata
- Cumulative size impact on project
- Size trend across versions (bloat detection)
- Size categories (tiny/small/medium/large/huge)
- Size efficiency score (features per KB)
- Suggests lighter alternatives for heavy packages
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies

# Size categories in KB
SIZE_CATEGORIES = {
    "tiny": 50,       # < 50 KB
    "small": 500,     # < 500 KB
    "medium": 5000,   # < 5 MB
    "large": 50000,   # < 50 MB
    "huge": float("inf"),  # >= 50 MB
}


@dataclass
class SizeInfo:
    """Size information for a single package."""

    name: str
    version: str
    download_size_kb: float = 0.0
    install_size_kb: float = 0.0
    size_category: str = "unknown"
    file_count: int = 0
    has_wheel: bool = False
    has_sdist: bool = False
    wheel_size_kb: float = 0.0
    sdist_size_kb: float = 0.0
    size_trend: str = "stable"  # growing, shrinking, stable, unknown
    lighter_alternatives: list[str] = field(default_factory=list)
    size_score: float = 0.0

    @property
    def total_size_kb(self) -> float:
        """Total estimated size (wheel preferred, sdist fallback)."""
        if self.has_wheel:
            return self.wheel_size_kb
        return self.sdist_size_kb if self.has_sdist else self.download_size_kb

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "download_size_kb": round(self.download_size_kb, 1),
            "install_size_kb": round(self.install_size_kb, 1),
            "size_category": self.size_category,
            "file_count": self.file_count,
            "has_wheel": self.has_wheel,
            "has_sdist": self.has_sdist,
            "wheel_size_kb": round(self.wheel_size_kb, 1),
            "sdist_size_kb": round(self.sdist_size_kb, 1),
            "size_trend": self.size_trend,
            "lighter_alternatives": self.lighter_alternatives,
            "size_score": round(self.size_score, 2),
        }


@dataclass
class SizeReport:
    """Aggregated size impact report."""

    packages: list[SizeInfo] = field(default_factory=list)
    total_packages: int = 0
    total_download_size_kb: float = 0.0
    total_install_size_kb: float = 0.0
    total_file_count: int = 0
    huge_count: int = 0
    large_count: int = 0
    medium_count: int = 0
    small_count: int = 0
    tiny_count: int = 0
    bloat_count: int = 0  # packages with growing size trend
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "total_packages": self.total_packages,
                "total_download_size_kb": round(self.total_download_size_kb, 1),
                "total_install_size_kb": round(self.total_install_size_kb, 1),
                "total_file_count": self.total_file_count,
                "huge": self.huge_count,
                "large": self.large_count,
                "medium": self.medium_count,
                "small": self.small_count,
                "tiny": self.tiny_count,
                "bloat_count": self.bloat_count,
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


# Known lighter alternatives for heavy packages
LIGHTER_ALTERNATIVES: dict[str, list[str]] = {
    "pandas": ["polars", "duckdb"],
    "numpy": ["tinyndarray"],
    "scipy": ["numpy"],  # partial coverage
    "matplotlib": ["plotly", "bokeh", "seaborn"],
    "tensorflow": ["onnxruntime", "tflite-runtime"],
    "torch": ["torchvision-only", "onnxruntime"],
    "pillow": ["pyheif", "python-magic"],
    "requests": ["httpx", "aiohttp", "urllib3"],
    "sqlalchemy": ["peewee", "tortoise-orm"],
    "django": ["flask", "fastapi", "starlette"],
    "sphinx": ["mkdocs", "mdbook"],
    "jupyter": ["jupyter-lite"],
    "boto3": ["boto3-lightspeed"],
    "pydantic": ["msgspec", "attrs"],
    "scikit-learn": ["lightgbm", "xgboost"],
}


def classify_size(size_kb: float) -> str:
    """Classify a package size into a category.

    Args:
        size_kb: Size in kilobytes.

    Returns:
        Size category string.
    """
    for category, threshold in SIZE_CATEGORIES.items():
        if size_kb < threshold:
            return category
    return "huge"


def compute_size_score(size_kb: float, file_count: int, has_wheel: bool) -> float:
    """Compute a size efficiency score.

    Higher is better (0-1). Penalizes large packages without wheels.

    Args:
        size_kb: Download size in KB.
        file_count: Number of files in the distribution.
        has_wheel: Whether a wheel is available.

    Returns:
        Score between 0.0 and 1.0.
    """
    if size_kb <= 0:
        return 1.0

    # Base score from size (log scale)
    import math
    score = max(0.0, 1.0 - math.log10(max(size_kb, 1)) / 5.0)

    # Bonus for having wheels (faster install, smaller footprint)
    if has_wheel:
        score = min(1.0, score + 0.1)

    # Penalty for excessive file count
    if file_count > 1000:
        score -= 0.1
    elif file_count > 500:
        score -= 0.05

    return max(0.0, min(1.0, score))


def analyze_size_trend(
    releases: dict[str, list[dict[str, Any]]],
    current_version: str,
) -> str:
    """Analyze the size trend across recent versions.

    Compares the size of the current version against the 3 previous
    stable releases to detect growing (bloat) or shrinking trends.

    Args:
        releases: PyPI releases dict.
        current_version: The current version string.

    Returns:
        "growing", "shrinking", "stable", or "unknown".
    """
    from packaging.version import Version

    versions: list[tuple[Version, float]] = []
    for ver_str, files in releases.items():
        try:
            ver = Version(ver_str)
            if ver.is_prerelease or ver.is_devrelease:
                continue
            # Get wheel size if available, else sdist
            size = 0.0
            for f in files:
                if f.get("packagetype") == "bdist_wheel":
                    size = max(size, f.get("size", 0))
            if size == 0:
                for f in files:
                    if f.get("packagetype") == "sdist":
                        size = max(size, f.get("size", 0))
            if size > 0:
                versions.append((ver, size))
        except Exception:
            continue

    if len(versions) < 3:
        return "unknown"

    # Sort by version descending and take recent ones
    versions.sort(key=lambda x: x[0], reverse=True)
    recent = versions[:4]

    if len(recent) < 3:
        return "unknown"

    # Compare first (newest) vs last (oldest) in recent
    newest_size = recent[0][1]
    oldest_size = recent[-1][1]

    if oldest_size == 0:
        return "unknown"

    ratio = newest_size / oldest_size
    if ratio > 1.2:
        return "growing"
    elif ratio < 0.8:
        return "shrinking"
    return "stable"


def fetch_package_size_info(
    package_name: str,
    version: str | None = None,
    pypi_client: PyPIClient | None = None,
) -> SizeInfo:
    """Fetch size information for a single package from PyPI.

    Args:
        package_name: The normalized package name.
        version: Optional version (uses latest if None).
        pypi_client: Optional PyPIClient (created if None).

    Returns:
        SizeInfo with size data.
    """
    client = pypi_client or PyPIClient()
    should_close = pypi_client is None

    try:
        info = client.get_package_info(package_name)
        if info is None:
            return SizeInfo(
                name=package_name,
                version=version or "unknown",
                size_category="unknown",
            )

        pkg_info = info.get("info", {})
        latest_version = pkg_info.get("version", "unknown")
        target_version = version or latest_version

        releases = info.get("releases", {})
        version_files = releases.get(target_version, [])

        wheel_size = 0.0
        sdist_size = 0.0
        file_count = 0
        has_wheel = False
        has_sdist = False

        for f in version_files:
            pkg_type = f.get("packagetype", "")
            size = f.get("size", 0)
            file_count += 1

            if pkg_type == "bdist_wheel":
                has_wheel = True
                wheel_size = max(wheel_size, size / 1024.0)
            elif pkg_type == "sdist":
                has_sdist = True
                sdist_size = max(sdist_size, size / 1024.0)

        download_size = wheel_size if has_wheel else sdist_size
        install_size = download_size * 2.5  # Rough estimate: install is ~2.5x download

        # Size trend
        trend = analyze_size_trend(releases, target_version)

        # Lighter alternatives
        alternatives = LIGHTER_ALTERNATIVES.get(package_name, [])

        size_cat = classify_size(download_size)
        score = compute_size_score(download_size, file_count, has_wheel)

        return SizeInfo(
            name=package_name,
            version=target_version,
            download_size_kb=download_size,
            install_size_kb=install_size,
            size_category=size_cat,
            file_count=file_count,
            has_wheel=has_wheel,
            has_sdist=has_sdist,
            wheel_size_kb=wheel_size,
            sdist_size_kb=sdist_size,
            size_trend=trend,
            lighter_alternatives=alternatives,
            size_score=score,
        )
    finally:
        if should_close:
            client.close()


def build_size_report(
    project_path: str | Path,
    dependencies: list[ParsedDependency] | None = None,
) -> SizeReport:
    """Build a comprehensive size report for a project's dependencies.

    Args:
        project_path: Path to the project directory.
        dependencies: Pre-parsed dependencies (discovered if None).

    Returns:
        A SizeReport with size analysis for each package.
    """
    project_path = Path(str(project_path)).resolve()

    if not project_path.is_dir():
        return SizeReport(errors=[f"Path is not a directory: {project_path}"])

    if dependencies is None:
        dependencies, _ = discover_dependencies(project_path)

    if not dependencies:
        return SizeReport(errors=["No dependencies found in the project."])

    report = SizeReport(total_packages=len(dependencies))

    with PyPIClient() as client:
        for dep in dependencies:
            try:
                size_info = fetch_package_size_info(dep.name, dep.version, client)
                report.packages.append(size_info)

                size = size_info.total_size_kb
                report.total_download_size_kb += size
                report.total_install_size_kb += size * 2.5
                report.total_file_count += size_info.file_count

                cat = size_info.size_category
                if cat == "huge":
                    report.huge_count += 1
                elif cat == "large":
                    report.large_count += 1
                elif cat == "medium":
                    report.medium_count += 1
                elif cat == "small":
                    report.small_count += 1
                elif cat == "tiny":
                    report.tiny_count += 1

                if size_info.size_trend == "growing":
                    report.bloat_count += 1

            except Exception as exc:
                report.errors.append(f"{dep.name}: {exc}")

    # Sort by size descending
    report.packages.sort(key=lambda p: p.total_size_kb, reverse=True)

    return report


def format_size(size_kb: float) -> str:
    """Format a size in KB to human-readable string.

    Args:
        size_kb: Size in kilobytes.

    Returns:
        Human-readable size string.
    """
    if size_kb >= 1048576:  # >= 1 GB
        return f"{size_kb / 1048576:.1f} GB"
    elif size_kb >= 1024:  # >= 1 MB
        return f"{size_kb / 1024:.1f} MB"
    elif size_kb >= 1:
        return f"{size_kb:.0f} KB"
    else:
        return f"{size_kb * 1024:.0f} B"


def render_size_table(report: SizeReport, console: Console | None = None) -> None:
    """Render the size report as a Rich table.

    Args:
        report: The SizeReport to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    if not report.packages:
        console.print("[yellow]No package size data available.[/yellow]")
        return

    # Summary
    cat_parts: list[str] = []
    if report.huge_count:
        cat_parts.append(f"[red bold]{report.huge_count} huge[/red bold]")
    if report.large_count:
        cat_parts.append(f"[red]{report.large_count} large[/red]")
    if report.medium_count:
        cat_parts.append(f"[yellow]{report.medium_count} medium[/yellow]")
    if report.small_count:
        cat_parts.append(f"[green]{report.small_count} small[/green]")
    if report.tiny_count:
        cat_parts.append(f"[dim]{report.tiny_count} tiny[/dim]")

    summary = "Sizes: " + ", ".join(cat_parts)
    summary += f" • Total: {format_size(report.total_download_size_kb)}"
    summary += f" • {report.total_packages} packages"
    if report.bloat_count:
        summary += f" • [red]{report.bloat_count} growing (bloat)[/red]"

    console.print()
    console.print(Panel(summary, title="Package Size Analysis", border_style="blue"))

    # Main table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Package", style="cyan", min_width=20)
    table.add_column("Version", justify="right", min_width=12)
    table.add_column("Size", justify="right", min_width=10)
    table.add_column("Category", justify="center", min_width=10)
    table.add_column("Trend", justify="center", min_width=8)
    table.add_column("Score", justify="right", min_width=8)
    table.add_column("Alternatives", min_width=25)

    cat_styles = {
        "huge": "red bold",
        "large": "red",
        "medium": "yellow",
        "small": "green",
        "tiny": "dim",
        "unknown": "dim",
    }

    trend_styles = {
        "growing": "red ↑",
        "shrinking": "green ↓",
        "stable": "blue =",
        "unknown": "dim ?",
    }

    for pkg in report.packages:
        cat_style = cat_styles.get(pkg.size_category, "dim")
        trend_icon = trend_styles.get(pkg.size_trend, "dim ?")
        alts = ", ".join(pkg.lighter_alternatives) if pkg.lighter_alternatives else "-"

        table.add_row(
            pkg.name,
            pkg.version,
            format_size(pkg.total_size_kb),
            f"[{cat_style}]{pkg.size_category.upper()}[/{cat_style}]",
            trend_icon,
            f"{pkg.size_score:.2f}",
            alts,
        )

    console.print(table)

    # Show bloat warning
    bloated = [p for p in report.packages if p.size_trend == "growing"]
    if bloated:
        console.print()
        console.print(f"[red]⚠ {len(bloated)} package(s) show growing size trends (bloat):[/red]")
        for p in bloated:
            alts = (
    f" — alternatives: {', '.join(p.lighter_alternatives)}"
    if p.lighter_alternatives
    else ""
)
            console.print(f"  • {p.name} ({format_size(p.total_size_kb)}){alts}")


def render_size_json(report: SizeReport) -> str:
    """Render the size report as JSON string.

    Args:
        report: The SizeReport to render.

    Returns:
        JSON string of the report.
    """
    import json

    return json.dumps(report.to_dict(), indent=2)
