"""Dependency size and install footprint analysis for depcheck.

Analyzes the installed size of each dependency by inspecting the local
site-packages directory. Reports disk usage, file counts, and per-package
breakdowns so you can identify bloated dependencies and prune your
dependency tree.

Supports:
- Per-package installed size (disk bytes, file count, directory count)
- Total project dependency footprint
- Largest-N and smallest-N ranking
- JSON and table output
- --fail-on-threshold for CI (exit 1 if any dep exceeds a size limit)
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from depcheck.scanner import discover_dependencies

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PackageSize:
    """Size information for a single installed package."""

    name: str
    version: str
    total_bytes: int = 0
    file_count: int = 0
    dir_count: int = 0
    top_files: list[tuple[str, int]] = field(default_factory=list)
    install_path: str = ""
    error: str | None = None

    @property
    def total_kb(self) -> float:
        return self.total_bytes / 1024

    @property
    def total_mb(self) -> float:
        return self.total_bytes / (1024 * 1024)

    def human_size(self) -> str:
        """Return human-readable size string."""
        if self.total_bytes >= 1024 * 1024 * 1024:
            return f"{self.total_bytes / (1024 * 1024 * 1024):.1f} GB"
        if self.total_bytes >= 1024 * 1024:
            return f"{self.total_mb:.1f} MB"
        if self.total_bytes >= 1024:
            return f"{self.total_kb:.1f} KB"
        return f"{self.total_bytes} B"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "total_bytes": self.total_bytes,
            "total_kb": round(self.total_kb, 1),
            "total_mb": round(self.total_mb, 2),
            "file_count": self.file_count,
            "dir_count": self.dir_count,
            "top_files": [(p, s) for p, s in self.top_files],
            "install_path": self.install_path,
            "error": self.error,
        }


@dataclass
class SizeReport:
    """Aggregated size report for all project dependencies."""

    project_path: str
    packages: list[PackageSize] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(p.total_bytes for p in self.packages)

    @property
    def total_file_count(self) -> int:
        return sum(p.file_count for p in self.packages)

    @property
    def total_dir_count(self) -> int:
        return sum(p.dir_count for p in self.packages)

    @property
    def total_kb(self) -> float:
        return self.total_bytes / 1024

    @property
    def total_mb(self) -> float:
        return self.total_bytes / (1024 * 1024)

    @property
    def package_count(self) -> int:
        return len(self.packages)

    @property
    def largest(self) -> PackageSize | None:
        if not self.packages:
            return None
        return max(self.packages, key=lambda p: p.total_bytes)

    @property
    def smallest(self) -> PackageSize | None:
        if not self.packages:
            return None
        return min(self.packages, key=lambda p: p.total_bytes)

    @property
    def median_bytes(self) -> float:
        if not self.packages:
            return 0.0
        sorted_sizes = sorted(p.total_bytes for p in self.packages)
        n = len(sorted_sizes)
        mid = n // 2
        if n % 2 == 0:
            return (sorted_sizes[mid - 1] + sorted_sizes[mid]) / 2
        return float(sorted_sizes[mid])

    def top_n(self, n: int = 10) -> list[PackageSize]:
        """Return the N largest packages."""
        return sorted(self.packages, key=lambda p: p.total_bytes, reverse=True)[:n]

    def bottom_n(self, n: int = 10) -> list[PackageSize]:
        """Return the N smallest packages."""
        return sorted(self.packages, key=lambda p: p.total_bytes)[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "summary": {
                "total_bytes": self.total_bytes,
                "total_kb": round(self.total_kb, 1),
                "total_mb": round(self.total_mb, 2),
                "total_file_count": self.total_file_count,
                "total_dir_count": self.total_dir_count,
                "package_count": self.package_count,
                "median_bytes": round(self.median_bytes, 1),
            },
            "packages": [
                p.to_dict()
                for p in sorted(self.packages, key=lambda p: p.total_bytes, reverse=True)
            ],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Site-packages discovery
# ---------------------------------------------------------------------------


def find_site_packages() -> Path | None:
    """Find the site-packages directory for the current Python interpreter.

    Checks multiple strategies:
    1. distutils.sysconfig (most reliable)
    2. sys.path inspection
    3. Standard lib/pythonX.Y/site-packages relative to sys.prefix
    """
    # Strategy 1: distutils.sysconfig
    try:
        import distutils.sysconfig as sc  # type: ignore[import]

        pure = sc.get_python_lib(plat_specific=False)
        plat = sc.get_python_lib(plat_specific=True)
        for candidate in [pure, plat]:
            p = Path(candidate)
            if p.is_dir():
                return p
    except (ImportError, AttributeError):
        pass

    # Strategy 2: sys.path
    for entry in sys.path:
        p = Path(entry)
        if p.is_dir() and p.name == "site-packages":
            return p

    # Strategy 3: standard layout
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidate = Path(sys.prefix) / "lib" / version / "site-packages"
    if candidate.is_dir():
        return candidate

    return None


def resolve_package_dir(package_name: str, site_packages: Path) -> Path | None:
    """Resolve the on-disk directory for an installed package.

    Handles PEP 503 normalization: looks for both the original name
    and the normalized form (hyphens → underscores).
    """
    normalized = package_name.replace("-", "_").lower()

    candidates = [
        site_packages / package_name,
        site_packages / package_name.replace("-", "_"),
        site_packages / normalized,
        site_packages / normalized.replace("-", "_"),
    ]

    # Also check .dist-info directories for metadata
    for item in site_packages.iterdir():
        if not item.is_dir():
            continue
        item_name_lower = item.name.lower()
        if item_name_lower.startswith(normalized) or item_name_lower.startswith(
            package_name.lower()
        ):
            if item_name_lower.endswith(".dist-info") or item_name_lower.endswith(".egg-info"):
                # The actual package dir might differ from the dist-info name
                pkg_name_part = item.name.split("-")[0].lower().replace("_", "-")
                if pkg_name_part == package_name.lower() or pkg_name_part == normalized:
                    # Try to find the actual package dir
                    actual_name = item.name.split("-")[0]
                    pkg_dir = site_packages / actual_name
                    if pkg_dir.is_dir():
                        candidates.insert(0, pkg_dir)

    for candidate in candidates:
        if candidate.is_dir():
            return candidate

    return None


def resolve_package_version(package_name: str, site_packages: Path) -> str:
    """Resolve the installed version of a package from .dist-info metadata.

    Falls back to 'unknown' if metadata is unavailable.
    """
    normalized = package_name.replace("-", "_").lower()

    # Look for .dist-info directory
    for item in site_packages.iterdir():
        if not item.is_dir():
            continue
        item_name_lower = item.name.lower()
        if item_name_lower.startswith(normalized) and item_name_lower.endswith(".dist-info"):
            # Parse version from directory name: {name}-{version}.dist-info
            # Strip the .dist-info suffix first, then split on last hyphen
            base = item.name[: -len(".dist-info")]
            parts = base.rsplit("-", 1)
            if len(parts) == 2:
                return parts[1]

    # Try METADATA file
    for item in site_packages.iterdir():
        if not item.is_dir():
            continue
        item_name_lower = item.name.lower()
        if item_name_lower.startswith(normalized) and item_name_lower.endswith(".dist-info"):
            metadata_file = item / "METADATA"
            if metadata_file.is_file():
                try:
                    for line in metadata_file.read_text(encoding="utf-8").splitlines():
                        if line.lower().startswith("version:"):
                            return line.split(":", 1)[1].strip()
                except (OSError, UnicodeDecodeError):
                    pass

    return "unknown"


def measure_package_size(package_dir: Path) -> tuple[int, int, int, list[tuple[str, int]]]:
    """Walk a package directory and measure its total size.

    Returns:
        Tuple of (total_bytes, file_count, dir_count, top_5_largest_files)
    """
    total_bytes = 0
    file_count = 0
    dir_count = 0
    file_sizes: list[tuple[str, int]] = []

    for root, dirs, files in os.walk(package_dir):
        dir_count += len(dirs)
        for fname in files:
            fpath = Path(root) / fname
            try:
                size = fpath.stat().st_size
                total_bytes += size
                file_count += 1
                rel = str(fpath.relative_to(package_dir))
                file_sizes.append((rel, size))
            except OSError:
                # Permission denied or file gone
                pass

    # Sort by size descending and keep top 5
    file_sizes.sort(key=lambda x: x[1], reverse=True)
    top_files = file_sizes[:5]

    return total_bytes, file_count, dir_count, top_files


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_sizes(
    project_path: str,
    top_n: int = 20,
    include_top_files: bool = True,
) -> SizeReport:
    """Analyze the installed size of all project dependencies.

    Args:
        project_path: Path to the project directory.
        top_n: Number of largest packages to highlight.
        include_top_files: Whether to include top-5 largest files per package.

    Returns:
        A SizeReport with per-package and aggregate size data.
    """
    project_path_obj = Path(project_path).resolve()

    if not project_path_obj.is_dir():
        return SizeReport(
            project_path=str(project_path_obj),
            errors=[f"Path is not a directory: {project_path_obj}"],
        )

    # Discover dependencies
    dependencies, files_scanned = discover_dependencies(project_path_obj)

    if not dependencies:
        return SizeReport(
            project_path=str(project_path_obj),
            files_scanned=files_scanned,
            errors=["No dependencies found in the project."],
        )

    # Find site-packages
    site_packages = find_site_packages()
    if site_packages is None:
        return SizeReport(
            project_path=str(project_path_obj),
            files_scanned=files_scanned,
            errors=["Could not locate site-packages directory."],
        )

    # Measure each dependency
    packages: list[PackageSize] = []
    for dep in dependencies:
        pkg_dir = resolve_package_dir(dep.name, site_packages)
        if pkg_dir is None:
            # Package not installed locally
            version = dep.version or "unknown"
            packages.append(
                PackageSize(
                    name=dep.name,
                    version=version,
                    error="Package not found in site-packages (not installed?)",
                )
            )
            continue

        version = dep.version or resolve_package_version(dep.name, site_packages)
        total_bytes, file_count, dir_count, top_files = measure_package_size(pkg_dir)

        packages.append(
            PackageSize(
                name=dep.name,
                version=version,
                total_bytes=total_bytes,
                file_count=file_count,
                dir_count=dir_count,
                top_files=top_files if include_top_files else [],
                install_path=str(pkg_dir),
            )
        )

    report = SizeReport(
        project_path=str(project_path_obj),
        packages=packages,
        files_scanned=files_scanned,
    )

    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_size_table(report: SizeReport, console: Console | None = None) -> None:
    """Render size report as a Rich table."""
    if console is None:
        console = Console()

    # Summary
    console.print()
    console.print(f"[bold]Dependency Size Report: {report.project_path}[/bold]")
    console.print()

    summary_table = Table(title="Summary", show_header=True, header_style="bold cyan")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Total Footprint", _human_size(report.total_bytes))
    summary_table.add_row("Total Files", f"{report.total_file_count:,}")
    summary_table.add_row("Total Directories", f"{report.total_dir_count:,}")
    summary_table.add_row("Packages Measured", str(report.package_count))
    summary_table.add_row("Median Package Size", _human_size(int(report.median_bytes)))

    if report.largest:
        summary_table.add_row(
            "Largest Package",
            f"{report.largest.name} ({report.largest.human_size()})",
        )
    if report.smallest and report.package_count > 1:
        summary_table.add_row(
            "Smallest Package",
            f"{report.smallest.name} ({report.smallest.human_size()})",
        )

    console.print(summary_table)
    console.print()

    # Per-package table sorted by size descending
    pkg_table = Table(
        title="Packages by Size (largest first)",
        show_header=True,
        header_style="bold cyan",
    )
    pkg_table.add_column("Package", style="bold")
    pkg_table.add_column("Version")
    pkg_table.add_column("Size", justify="right")
    pkg_table.add_column("Files", justify="right")
    pkg_table.add_column("Dirs", justify="right")
    pkg_table.add_column("Install Path", max_width=50, overflow="ellipsis")

    sorted_pkgs = sorted(report.packages, key=lambda p: p.total_bytes, reverse=True)
    for pkg in sorted_pkgs:
        if pkg.error:
            pkg_table.add_row(
                pkg.name, pkg.version, "[dim]N/A[/dim]", "-", "-", f"[dim]{pkg.error}[/dim]"
            )
        else:
            size_style = (
                "red" if pkg.total_mb >= 50 else "yellow" if pkg.total_mb >= 10 else "green"
            )
            pkg_table.add_row(
                pkg.name,
                pkg.version,
                f"[{size_style}]{pkg.human_size()}[/{size_style}]",
                f"{pkg.file_count:,}",
                f"{pkg.dir_count:,}",
                pkg.install_path,
            )

    console.print(pkg_table)
    console.print()

    # Top files section (for the largest 5 packages)
    large_pkgs = report.top_n(5)
    has_top_files = any(pkg.top_files for pkg in large_pkgs if not pkg.error)
    if has_top_files:
        console.print("[bold]Largest Files in Top Packages:[/bold]")
        console.print()
        for pkg in large_pkgs:
            if pkg.error or not pkg.top_files:
                continue
            console.print(f"  [bold]{pkg.name}[/bold] ({pkg.human_size()}):")
            for filepath, size in pkg.top_files:
                console.print(f"    {_human_size(size):>10s}  {filepath}")
            console.print()


def render_size_json(report: SizeReport, console: Console | None = None) -> None:
    """Render size report as JSON."""
    data = report.to_dict()
    output = json.dumps(data, indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)


def _human_size(num_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f} GB"
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes} B"
