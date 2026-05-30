"""Bundle size analysis and dependency optimization for depcheck.

Analyzes the install size of dependencies, detects bloat, identifies
redundant packages, suggests lighter alternatives, and provides
optimization recommendations for reducing dependency footprint.
"""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    discover_dependencies,
    normalize_package_name,
)

# Known lightweight alternatives for common heavy packages
_LIGHTWEIGHT_ALTERNATIVES: dict[str, list[dict[str, str]]] = {
    "requests": [
        {"alternative": "httpx",
         "reason": "Lighter HTTP client with async support",
         "savings": "~30%"},
        {"alternative": "urllib3",
         "reason": "Lower-level, requests depends on it",
         "savings": "~60%"},
    ],
    "pandas": [
        {"alternative": "polars",
         "reason": "Faster, lower memory DataFrame library",
         "savings": "~50%"},
        {"alternative": "duckdb",
         "reason": "In-process SQL analytics, smaller footprint",
         "savings": "~70%"},
    ],
    "numpy": [
        {"alternative": "array",
         "reason": "Built-in Python array module for simple cases",
         "savings": "~95%"},
    ],
    "scipy": [
        {"alternative": "numpy",
         "reason": "If only basic numerical functions needed",
         "savings": "~80%"},
    ],
    "sqlalchemy": [
        {"alternative": "sqlite3",
         "reason": "Built-in for simple SQLite usage",
         "savings": "~90%"},
        {"alternative": "peewee",
         "reason": "Lighter ORM with smaller footprint",
         "savings": "~60%"},
    ],
    "django": [
        {"alternative": "flask",
         "reason": "Micro-framework if full Django not needed",
         "savings": "~70%"},
        {"alternative": "fastapi",
         "reason": "Async-first, lighter for API-only projects",
         "savings": "~65%"},
    ],
    "pillow": [
        {"alternative": "pypng",
         "reason": "PNG-only, much smaller footprint",
         "savings": "~80%"},
    ],
    "matplotlib": [
        {"alternative": "plotly",
         "reason": "Interactive plots, smaller base install",
         "savings": "~30%"},
        {"alternative": "asciiplotlib",
         "reason": "ASCII plots for CLI-only output",
         "savings": "~98%"},
    ],
    "pyyaml": [
        {"alternative": "tomli",
         "reason": "If YAML not strictly required, TOML is lighter",
         "savings": "~40%"},
    ],
    "lxml": [
        {"alternative": "xml.etree.ElementTree",
         "reason": "Built-in XML parser, no C deps",
         "savings": "~95%"},
    ],
    "boto3": [
        {"alternative": "httpx + sigv4",
         "reason": "Direct API calls for limited AWS usage",
         "savings": "~80%"},
    ],
}

# Packages commonly used together where one can replace the other
_REDUNDANCY_GROUPS: list[dict[str, Any]] = [
    {
        "name": "HTTP Clients",
        "packages": ["requests", "httpx", "aiohttp", "urllib3"],
        "message": "Multiple HTTP clients found; consider standardizing on one",
    },
    {
        "name": "YAML Parsers",
        "packages": ["pyyaml", "ruamel-yaml", "strictyaml"],
        "message": "Multiple YAML parsers found; pick one based on your needs",
    },
    {
        "name": "CLI Frameworks",
        "packages": ["click", "argparse", "typer"],
        "message": "Multiple CLI frameworks; typer wraps click, so you may not need both",
    },
    {
        "name": "Data Validation",
        "packages": ["pydantic", "marshmallow", "attrs", "voluptuous"],
        "message": "Multiple validation libraries detected; consolidate if possible",
    },
    {
        "name": "Template Engines",
        "packages": ["jinja2", "mako", "cheetah3"],
        "message": "Multiple template engines; most projects need only one",
    },
    {
        "name": "Async Frameworks",
        "packages": ["aiohttp", "httpx", "asks"],
        "message": "Multiple async HTTP libraries; consider using one consistently",
    },
    {
        "name": "Logging",
        "packages": ["loguru", "structlog", "python-json-logger"],
        "message": "Multiple logging enhancements; standardize on one approach",
    },
    {
        "name": "Testing",
        "packages": ["pytest", "unittest"],
        "message": "Both pytest and unittest found; pytest can run unittest tests",
    },
    {
        "name": "Linting",
        "packages": ["ruff", "flake8", "pylint"],
        "message": "Multiple linters; ruff can replace both flake8 and many pylint checks",
    },
    {
        "name": "Type Checking",
        "packages": ["mypy", "pyright"],
        "message": "Multiple type checkers; standardize on one for consistency",
    },
]


class SizeCategory(enum.Enum):
    """Size category for a package's install footprint."""

    TINY = "tiny"        # < 100 KB
    SMALL = "small"      # 100 KB - 1 MB
    MEDIUM = "medium"    # 1 MB - 10 MB
    LARGE = "large"      # 10 MB - 50 MB
    VERY_LARGE = "very_large"  # 50 MB - 200 MB
    HUGE = "huge"        # > 200 MB


class OptimizationType(enum.Enum):
    """Type of optimization recommendation."""

    REPLACE = "replace"
    REMOVE = "remove"
    CONSOLIDATE = "consolidate"
    PIN_MORE = "pin_more"
    SPLIT_EXTRAS = "split_extras"


@dataclass
class PackageSizeInfo:
    """Size information for a single package."""

    package_name: str
    version: str | None = None
    wheel_size_bytes: int | None = None
    wheel_size_human: str = "unknown"
    size_category: SizeCategory = SizeCategory.TINY
    has_c_extensions: bool = False
    num_files: int | None = None
    dependency_count: int = 0
    is_optional: bool = False
    extras: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "wheel_size_bytes": self.wheel_size_bytes,
            "wheel_size_human": self.wheel_size_human,
            "size_category": self.size_category.value,
            "has_c_extensions": self.has_c_extensions,
            "num_files": self.num_files,
            "dependency_count": self.dependency_count,
            "is_optional": self.is_optional,
            "extras": self.extras,
        }


@dataclass
class RedundancyGroup:
    """A group of packages that may be redundant with each other."""

    group_name: str
    packages_found: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_name": self.group_name,
            "packages_found": self.packages_found,
            "message": self.message,
        }


@dataclass
class OptimizationRecommendation:
    """A single optimization recommendation."""

    optimization_type: OptimizationType
    package_name: str
    description: str
    estimated_savings: str = ""
    priority: str = "medium"  # low, medium, high
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "optimization_type": self.optimization_type.value,
            "package_name": self.package_name,
            "description": self.description,
            "estimated_savings": self.estimated_savings,
            "priority": self.priority,
            "details": self.details,
        }


@dataclass
class BundleResult:
    """Result of bundle size analysis."""

    project_path: str = ""
    packages: list[PackageSizeInfo] = field(default_factory=list)
    total_size_bytes: int = 0
    total_size_human: str = ""
    redundancy_groups: list[RedundancyGroup] = field(default_factory=list)
    recommendations: list[OptimizationRecommendation] = field(default_factory=list)
    size_by_category: dict[str, int] = field(default_factory=dict)
    top_heavy_packages: list[PackageSizeInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "total_size_bytes": self.total_size_bytes,
            "total_size_human": self.total_size_human,
            "packages": [p.to_dict() for p in self.packages],
            "redundancy_groups": [g.to_dict() for g in self.redundancy_groups],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "size_by_category": self.size_by_category,
            "top_heavy_packages": [p.to_dict() for p in self.top_heavy_packages],
            "errors": self.errors,
        }


def _human_readable_size(size_bytes: int | None) -> str:
    """Convert bytes to human-readable size string.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Human-readable string like '1.2 MB' or '350 KB'.
    """
    if size_bytes is None:
        return "unknown"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def _classify_size(size_bytes: int | None) -> SizeCategory:
    """Classify a package size into a category.

    Args:
        size_bytes: Size in bytes.

    Returns:
        The appropriate SizeCategory.
    """
    if size_bytes is None:
        return SizeCategory.TINY
    if size_bytes < 100 * 1024:
        return SizeCategory.TINY
    if size_bytes < 1024 * 1024:
        return SizeCategory.SMALL
    if size_bytes < 10 * 1024 * 1024:
        return SizeCategory.MEDIUM
    if size_bytes < 50 * 1024 * 1024:
        return SizeCategory.LARGE
    if size_bytes < 200 * 1024 * 1024:
        return SizeCategory.VERY_LARGE
    return SizeCategory.HUGE


def _detect_c_extensions(pypi_info: dict[str, Any], version: str | None) -> bool:
    """Detect if a package has C extensions from PyPI release files.

    Args:
        pypi_info: PyPI package info dictionary.
        version: The version to check.

    Returns:
        True if C extensions are detected.
    """
    releases = pypi_info.get("releases", {})
    target_ver = version

    # If no version specified, use latest
    if target_ver is None:
        target_ver = pypi_info.get("info", {}).get("version")

    if target_ver and target_ver in releases:
        files = releases[target_ver]
        for f in files:
            filename = f.get("filename", "")
            # C extensions typically have platform-specific wheels
            # Check for CPython ABI tag (cp3XX) and platform tags
            parts = filename.replace(".whl", "").split("-")
            # Wheel filename parts: {name}-{version}-{python}-{abi}-{platform}
            has_c_abi = False
            has_platform_tag = False
            if len(parts) >= 5:
                # parts[2] is python tag, parts[3] is abi tag, parts[4] is platform
                abi_tag = parts[3]
                platform_tag = parts[4] if len(parts) > 4 else ""
                # CPython ABI like cp311, cp312
                if abi_tag.startswith("cp"):
                    has_c_abi = True
                # Non-pure platform tags (not "any")
                if platform_tag != "any":
                    has_platform_tag = True
            # If ABI is CPython and platform is specific -> C extension
            if has_c_abi and has_platform_tag:
                return True
            # Source distributions with .c files
            if filename.endswith(".tar.gz") or filename.endswith(".zip"):
                packagetype = f.get("packagetype", "")
                if packagetype == "sdist":
                    # Heuristic: platform-specific files suggest C extensions
                    pass

    # Also check for trove classifiers
    info_section = pypi_info.get("info", {})
    classifiers = info_section.get("classifiers", []) or []
    for classifier in classifiers:
        if "Implementation :: C" in classifier:
            return True
        if "Programming Language :: C" in classifier:
            return True
        if "Programming Language :: C++" in classifier:
            return True
        if "Programming Language :: Rust" in classifier:
            return True

    return False


def _count_dependencies_from_info(pypi_info: dict[str, Any]) -> int:
    """Count the number of dependencies declared by a package.

    Args:
        pypi_info: PyPI package info dictionary.

    Returns:
        Number of declared dependencies (excluding extras).
    """
    requires_dist = pypi_info.get("info", {}).get("requires_dist", []) or []
    count = 0
    for req in requires_dist:
        req = req.strip()
        if not req:
            continue
        # Skip extras
        if "; extra ==" in req.lower() or "; extra ==" in req:
            continue
        count += 1
    return count


def _extract_extras(pypi_info: dict[str, Any]) -> list[str]:
    """Extract available extras from package info.

    Args:
        pypi_info: PyPI package info dictionary.

    Returns:
        List of extra names.
    """
    requires_dist = pypi_info.get("info", {}).get("requires_dist", []) or []
    extras: set[str] = set()

    for req in requires_dist:
        req = req.strip()
        match = re.search(r'extra\s*==\s*["\']?(\w+)["\']?', req, re.IGNORECASE)
        if match:
            extras.add(match.group(1))

    return sorted(extras)


def _get_wheel_size(pypi_info: dict[str, Any], version: str | None) -> int | None:
    """Get the size of the wheel for a specific version.

    Args:
        pypi_info: PyPI package info dictionary.
        version: Version to check.

    Returns:
        Size in bytes, or None.
    """
    releases = pypi_info.get("releases", {})
    target_ver = version

    if target_ver is None:
        target_ver = pypi_info.get("info", {}).get("version")

    if not target_ver or target_ver not in releases:
        return None

    files = releases[target_ver]

    # Prefer universal/pure Python wheel
    best_size = None
    for f in files:
        if f.get("packagetype") == "bdist_wheel":
            filename = f.get("filename", "")
            size = f.get("size")
            if size is None:
                continue

            # Prefer "none-any" wheel (universal)
            if "none" in filename and "any" in filename:
                return size

            # Otherwise take the smallest wheel
            if best_size is None or size < best_size:
                best_size = size

    # If no wheel, try sdist
    if best_size is None:
        for f in files:
            if f.get("packagetype") == "sdist":
                size = f.get("size")
                if size is not None:
                    return size

    return best_size


def analyze_package_size(
    dep: ParsedDependency,
    pypi_info: dict[str, Any] | None,
) -> PackageSizeInfo:
    """Analyze the size of a single package.

    Args:
        dep: The parsed dependency.
        pypi_info: PyPI package info (or None if not found).

    Returns:
        PackageSizeInfo with size analysis.
    """
    info = PackageSizeInfo(
        package_name=dep.name,
        version=dep.version,
    )

    if pypi_info is None:
        return info

    # Resolve version
    resolved_version = dep.version
    if not resolved_version:
        resolved_version = pypi_info.get("info", {}).get("version")

    info.version = resolved_version

    # Get wheel size
    size_bytes = _get_wheel_size(pypi_info, resolved_version)
    info.wheel_size_bytes = size_bytes
    info.wheel_size_human = _human_readable_size(size_bytes)
    info.size_category = _classify_size(size_bytes)

    # Detect C extensions
    info.has_c_extensions = _detect_c_extensions(pypi_info, resolved_version)

    # Count dependencies
    info.dependency_count = _count_dependencies_from_info(pypi_info)

    # Extract extras
    info.extras = _extract_extras(pypi_info)

    return info


def detect_redundancies(package_names: list[str]) -> list[RedundancyGroup]:
    """Detect redundancy groups among installed packages.

    Args:
        package_names: List of normalized package names.

    Returns:
        List of RedundancyGroup instances for groups where multiple members are found.
    """
    normalized = {normalize_package_name(n) for n in package_names}
    groups: list[RedundancyGroup] = []

    for group_def in _REDUNDANCY_GROUPS:
        found = [pkg for pkg in group_def["packages"] if normalize_package_name(pkg) in normalized]
        if len(found) >= 2:
            groups.append(
                RedundancyGroup(
                    group_name=group_def["name"],
                    packages_found=found,
                    message=group_def["message"],
                )
            )

    return groups


def generate_recommendations(
    packages: list[PackageSizeInfo],
    redundancy_groups: list[RedundancyGroup],
) -> list[OptimizationRecommendation]:
    """Generate optimization recommendations based on bundle analysis.

    Args:
        packages: List of package size info.
        redundancy_groups: Detected redundancy groups.

    Returns:
        List of OptimizationRecommendation instances.
    """
    recommendations: list[OptimizationRecommendation] = []

    # Recommendations for large/very_large/huge packages with alternatives
    for pkg in packages:
        alternatives = _LIGHTWEIGHT_ALTERNATIVES.get(pkg.package_name, [])
        if alternatives and pkg.size_category in (
            SizeCategory.LARGE,
            SizeCategory.VERY_LARGE,
            SizeCategory.HUGE,
        ):
            for alt in alternatives:
                recommendations.append(
                    OptimizationRecommendation(
                        optimization_type=OptimizationType.REPLACE,
                        package_name=pkg.package_name,
                        description=(
                            f"Consider replacing {pkg.package_name} with {alt['alternative']}: "
                            f"{alt['reason']}"
                        ),
                        estimated_savings=alt["savings"],
                        priority="high",
                        details={
                            "alternative": alt["alternative"],
                            "reason": alt["reason"],
                            "current_size": pkg.wheel_size_human,
                        },
                    )
                )
        elif alternatives and pkg.size_category == SizeCategory.MEDIUM:
            # Medium packages: lower priority
            alt = alternatives[0]
            recommendations.append(
                OptimizationRecommendation(
                    optimization_type=OptimizationType.REPLACE,
                    package_name=pkg.package_name,
                    description=(
                        f"Consider {alt['alternative']} instead of {pkg.package_name}: "
                        f"{alt['reason']}"
                    ),
                    estimated_savings=alt["savings"],
                    priority="medium",
                    details={
                        "alternative": alt["alternative"],
                        "reason": alt["reason"],
                        "current_size": pkg.wheel_size_human,
                    },
                )
            )

    # Recommendations for packages with extras that could reduce install size
    for pkg in packages:
        if (
        pkg.extras
        and pkg.size_category
        in (SizeCategory.LARGE, SizeCategory.VERY_LARGE, SizeCategory.HUGE)
    ):
            recommendations.append(
                OptimizationRecommendation(
                    optimization_type=OptimizationType.SPLIT_EXTRAS,
                    package_name=pkg.package_name,
                    description=(
                        f"{pkg.package_name} has extras: {', '.join(pkg.extras[:5])}. "
                        f"Install only the extras you need to reduce footprint."
                    ),
                    estimated_savings="varies",
                    priority="medium",
                    details={"available_extras": pkg.extras},
                )
            )

    # Recommendations for redundancy groups
    for group in redundancy_groups:
        recommendations.append(
            OptimizationRecommendation(
                optimization_type=OptimizationType.CONSOLIDATE,
                package_name=", ".join(group.packages_found),
                description=group.message,
                estimated_savings="varies",
                priority="medium",
                details={"group": group.group_name, "packages": group.packages_found},
            )
        )

    # Recommendations for unpinned large packages
    for pkg in packages:
        if pkg.size_category in (SizeCategory.LARGE, SizeCategory.VERY_LARGE, SizeCategory.HUGE):
            # Heuristic: if version looks like it might not be pinned
            recommendations.append(
                OptimizationRecommendation(
                    optimization_type=OptimizationType.PIN_MORE,
                    package_name=pkg.package_name,
                    description=(
                        f"Pin {pkg.package_name} to exact version to avoid unexpected "
                        f"size increases from upgrades ({pkg.wheel_size_human})"
                    ),
                    estimated_savings="0 (risk reduction)",
                    priority="low",
                    details={"current_size": pkg.wheel_size_human},
                )
            )

    # Sort by priority
    priority_order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda r: priority_order.get(r.priority, 3))

    return recommendations


def run_bundle(
    project_path: str | Path,
) -> BundleResult:
    """Run bundle size analysis on all project dependencies.

    Args:
        project_path: Path to the project directory.

    Returns:
        BundleResult with analysis for all dependencies.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return BundleResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    dependencies, _ = discover_dependencies(project_path)

    if not dependencies:
        return BundleResult(
            project_path=str(project_path),
            errors=["No dependencies found in the project."],
        )

    package_sizes: list[PackageSizeInfo] = []

    with PyPIClient() as pypi_client:
        for dep in dependencies:
            try:
                info = pypi_client.get_package_info(dep.name)
                size_info = analyze_package_size(dep, info)
                package_sizes.append(size_info)
            except Exception:
                package_sizes.append(
                    PackageSizeInfo(
                        package_name=dep.name,
                        version=dep.version,
                    )
                )

    # Build result
    result = BundleResult(
        project_path=str(project_path),
        packages=package_sizes,
    )

    # Calculate total size
    total_bytes = sum(p.wheel_size_bytes or 0 for p in package_sizes)
    result.total_size_bytes = total_bytes
    result.total_size_human = _human_readable_size(total_bytes)

    # Count by category
    category_counts: dict[str, int] = {}
    for pkg in package_sizes:
        cat = pkg.size_category.value
        category_counts[cat] = category_counts.get(cat, 0) + 1
    result.size_by_category = category_counts

    # Top heavy packages (sorted by size descending)
    sized = [p for p in package_sizes if p.wheel_size_bytes is not None]
    sized.sort(key=lambda p: p.wheel_size_bytes or 0, reverse=True)
    result.top_heavy_packages = sized[:10]

    # Detect redundancies
    pkg_names = [p.package_name for p in package_sizes]
    result.redundancy_groups = detect_redundancies(pkg_names)

    # Generate recommendations
    result.recommendations = generate_recommendations(package_sizes, result.redundancy_groups)

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SIZE_CATEGORY_STYLES: dict[SizeCategory, str] = {
    SizeCategory.TINY: "green",
    SizeCategory.SMALL: "green",
    SizeCategory.MEDIUM: "cyan",
    SizeCategory.LARGE: "yellow",
    SizeCategory.VERY_LARGE: "red",
    SizeCategory.HUGE: "red bold",
}

_PRIORITY_STYLES: dict[str, tuple[str, str]] = {
    "high": ("▲", "red"),
    "medium": ("●", "yellow"),
    "low": ("○", "dim"),
}


def render_bundle_table(result: BundleResult, console: Console | None = None) -> None:
    """Render bundle analysis results as Rich tables.

    Args:
        result: The bundle analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    console.print()
    console.print(
        f"[bold]depcheck bundle[/bold] — Dependency Bundle Analysis for "
        f"[cyan]{result.project_path}[/cyan]"
    )
    console.print(f" Total install size: [bold]{result.total_size_human}[/bold]")
    console.print()

    # Size by category
    cat_table = Table(title="Size Distribution", show_lines=False, pad_edge=False)
    cat_table.add_column("Category", style="bold")
    cat_table.add_column("Count", justify="right")
    cat_table.add_column("Bar", min_width=30)

    max_count = max(result.size_by_category.values()) if result.size_by_category else 1
    for cat in SizeCategory:
        count = result.size_by_category.get(cat.value, 0)
        if count == 0:
            continue
        color = _SIZE_CATEGORY_STYLES.get(cat, "white")
        bar_len = int(count / max_count * 25)
        bar = "█" * bar_len
        cat_table.add_row(
            f"[{color}]{cat.value}[/{color}]",
            str(count),
            f"[{color}]{bar}[/{color}] {count}",
        )

    console.print(cat_table)
    console.print()

    # Package size table
    pkg_table = Table(title="Package Sizes", show_lines=True, pad_edge=False)
    pkg_table.add_column("Package", style="bold", max_width=25)
    pkg_table.add_column("Version", max_width=14)
    pkg_table.add_column("Wheel Size", justify="right")
    pkg_table.add_column("Category", justify="center")
    pkg_table.add_column("C Ext", justify="center")
    pkg_table.add_column("Deps", justify="right", max_width=5)
    pkg_table.add_column("Extras", max_width=20)

    for pkg in sorted(result.packages, key=lambda p: p.wheel_size_bytes or 0, reverse=True):
        cat_color = _SIZE_CATEGORY_STYLES.get(pkg.size_category, "white")
        cat_str = f"[{cat_color}]{pkg.size_category.value}[/{cat_color}]"
        c_ext_str = "[red]✓[/red]" if pkg.has_c_extensions else "[dim]—[/dim]"
        extras_str = ", ".join(pkg.extras[:3]) if pkg.extras else "—"
        if len(pkg.extras) > 3:
            extras_str += f" (+{len(pkg.extras) - 3})"

        pkg_table.add_row(
            pkg.package_name,
            pkg.version or "—",
            pkg.wheel_size_human,
            cat_str,
            c_ext_str,
            str(pkg.dependency_count),
            extras_str,
        )

    console.print(pkg_table)

    # Top heaviest packages
    if result.top_heavy_packages:
        console.print()
        console.print("[bold]Top Heaviest Packages[/bold]")
        for i, pkg in enumerate(result.top_heavy_packages[:5], 1):
            cat_color = _SIZE_CATEGORY_STYLES.get(pkg.size_category, "white")
            pct = (
                f" ({pkg.wheel_size_bytes / result.total_size_bytes * 100:.0f}%)"
                if result.total_size_bytes > 0 and pkg.wheel_size_bytes
                else ""
            )
            console.print(
                f"  {i}. [{cat_color}]{pkg.package_name}[/{cat_color}] "
                f"— {pkg.wheel_size_human}{pct}"
            )

    # Redundancy groups
    if result.redundancy_groups:
        console.print()
        console.print("[bold yellow]⚠ Potential Redundancies[/bold yellow]")
        for group in result.redundancy_groups:
            console.print(
                f"  [bold]{group.group_name}[/bold]: {', '.join(group.packages_found)}"
            )
            console.print(f"    [dim]{group.message}[/dim]")

    # Recommendations
    if result.recommendations:
        console.print()
        rec_table = Table(title="Optimization Recommendations", show_lines=True, pad_edge=False)
        rec_table.add_column("Priority", justify="center", max_width=8)
        rec_table.add_column("Type", max_width=12)
        rec_table.add_column("Package", style="bold", max_width=25)
        rec_table.add_column("Recommendation", max_width=60)
        rec_table.add_column("Savings", justify="right", max_width=10)

        for rec in result.recommendations[:15]:  # Show top 15
            icon, color = _PRIORITY_STYLES.get(rec.priority, ("?", "white"))
            priority_str = f"[{color}]{icon} {rec.priority}[/{color}]"
            rec_table.add_row(
                priority_str,
                rec.optimization_type.value,
                rec.package_name,
                rec.description[:60],
                rec.estimated_savings,
            )

        console.print(rec_table)


def render_bundle_json(result: BundleResult, console: Console | None = None) -> None:
    """Render bundle analysis results as JSON.

    Args:
        result: The bundle analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console(force_terminal=False, no_color=True)

    console.print(json.dumps(result.to_dict(), indent=2))
