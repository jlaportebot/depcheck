"""Python version compatibility checker for dependencies.

Checks each dependency against a target Python version to determine:
- Minimum required Python version per package
- Compatibility with specified Python version(s)
- Version ranges supported
- Packages that will break on upgrade
- Python version upgrade readiness score
- Classifiers-based compatibility from PyPI metadata
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies


@dataclass
class CompatInfo:
    """Compatibility information for a single package."""

    name: str
    version: str | None = None
    min_python: str | None = None
    max_python: str | None = None
    supported_versions: list[str] = field(default_factory=list)
    classifiers: list[str] = field(default_factory=list)
    requires_python: str | None = None
    is_compatible: bool = True
    compatibility_detail: str = ""
    breaking_on_upgrade: bool = False
    upgrade_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "min_python": self.min_python,
            "max_python": self.max_python,
            "supported_versions": self.supported_versions,
            "classifiers": self.classifiers,
            "requires_python": self.requires_python,
            "is_compatible": self.is_compatible,
            "compatibility_detail": self.compatibility_detail,
            "breaking_on_upgrade": self.breaking_on_upgrade,
            "upgrade_note": self.upgrade_note,
        }


@dataclass
class CompatReport:
    """Aggregated compatibility report."""

    packages: list[CompatInfo] = field(default_factory=list)
    target_python: str = ""
    current_python: str = f"{sys.version_info.major}.{sys.version_info.minor}"
    total_packages: int = 0
    compatible_count: int = 0
    incompatible_count: int = 0
    unknown_count: int = 0
    breaking_on_upgrade_count: int = 0
    readiness_score: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "target_python": self.target_python,
                "current_python": self.current_python,
                "total_packages": self.total_packages,
                "compatible": self.compatible_count,
                "incompatible": self.incompatible_count,
                "unknown": self.unknown_count,
                "breaking_on_upgrade": self.breaking_on_upgrade_count,
                "readiness_score": round(self.readiness_score, 2),
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


def parse_requires_python(specifier: str) -> tuple[str | None, str | None]:
    """Parse a Requires-Python specifier into min and max versions.

    Handles common patterns:
    - ">=3.8" → (3.8, None)
    - ">=3.8,<3.13" → (3.8, 3.13)
    - ">=3.8,<4" → (3.8, None)
    - "==3.8.*" → (3.8, 3.8)
    - ">=3.10" → (3.10, None)

    Args:
        specifier: The Requires-Python specifier string.

    Returns:
        Tuple of (min_version, max_version) strings.
    """
    if not specifier:
        return None, None

    min_ver: str | None = None
    max_ver: str | None = None

    parts = [p.strip() for p in specifier.split(",")]

    for part in parts:
        # >=3.x
        match = re.match(r">=\s*(\d+\.\d+)", part)
        if match:
            min_ver = match.group(1)
            continue

        # >3.x
        match = re.match(r">\s*(\d+\.\d+)", part)
        if match:
            ver = match.group(1)
            # >3.11 means >=3.12
            major, minor = ver.split(".")
            min_ver = f"{major}.{int(minor) + 1}"
            continue

        # <3.x
        match = re.match(r"<\s*(\d+\.\d+)", part)
        if match:
            ver = match.group(1)
            # <3.13 means max is 3.12
            major, minor = ver.split(".")
            max_ver = f"{major}.{int(minor) - 1}"
            continue

        # <=3.x
        match = re.match(r"<=\s*(\d+\.\d+)", part)
        if match:
            max_ver = match.group(1)
            continue

        # ==3.x.*
        match = re.match(r"==\s*(\d+)\.\*", part)
        if match:
            min_ver = f"{match.group(1)}.0"
            max_ver = f"{match.group(1)}.99"
            continue

        # ~=3.x
        match = re.match(r"~=\s*(\d+\.\d+)", part)
        if match:
            min_ver = match.group(1)
            major, minor = match.group(1).split(".")
            max_ver = f"{major}.{int(minor)}"
            continue

    return min_ver, max_ver


def extract_python_classifiers(classifiers: list[str]) -> list[str]:
    """Extract Python version classifiers from PyPI metadata.

    Args:
        classifiers: List of classifier strings.

    Returns:
        List of Python version strings (e.g., ["3.8", "3.9", "3.10"]).
    """
    versions: list[str] = []
    for classifier in classifiers:
        if classifier.startswith("Programming Language :: Python ::"):
            ver_str = classifier.replace("Programming Language :: Python ::", "").strip()
            # Only keep major.minor patterns
            if re.match(r"^\d+\.\d+$", ver_str):
                versions.append(ver_str)
    return sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".")))


def check_version_compatibility(
    target_version: str,
    requires_python: str | None = None,
    classifiers: list[str] | None = None,
) -> tuple[bool, str]:
    """Check if a package is compatible with a target Python version.

    Uses both Requires-Python specifier and classifiers to determine
    compatibility.

    Args:
        target_version: The Python version to check (e.g., "3.12").
        requires_python: The Requires-Python specifier string.
        classifiers: List of PyPI classifiers.

    Returns:
        Tuple of (is_compatible, detail_message).
    """
    if not requires_python and not classifiers:
        return True, "No version constraint specified"

    target_parts = target_version.split(".")
    tuple(int(x) for x in target_parts)

    # Check Requires-Python specifier
    if requires_python:
        try:
            from packaging.specifiers import SpecifierSet

            spec = SpecifierSet(requires_python)
            if target_version not in spec:
                # Try with micro version
                target_with_micro = f"{target_version}.0"
                if target_with_micro not in spec:
                    min_ver, max_ver = parse_requires_python(requires_python)
                    detail_parts: list[str] = []
                    if min_ver:
                        detail_parts.append(f"requires >={min_ver}")
                    if max_ver:
                        detail_parts.append(f"requires <{max_ver}")
                    return False, f"Incompatible: {', '.join(detail_parts)}"
        except Exception:
            pass  # Fall through to classifier check

    # Check classifiers
    if classifiers:
        supported = extract_python_classifiers(classifiers)
        if supported:
            if target_version in supported:
                return True, f"Explicitly supports Python {target_version}"
            # Check if target is within the range
            try:
                target_ver = tuple(int(x) for x in target_version.split("."))
                min_supported = tuple(int(x) for x in supported[0].split("."))
                max_supported = tuple(int(x) for x in supported[-1].split("."))
                if target_ver > max_supported:
                    return False, f"Only supports Python {supported[0]}-{supported[-1]}"
                if target_ver < min_supported:
                    return False, f"Requires Python >={supported[0]}"
            except (ValueError, IndexError):
                pass

    return True, "Compatible (within supported range)"


def check_breaking_on_upgrade(
    current_version: str,
    target_version: str,
    requires_python: str | None,
) -> tuple[bool, str]:
    """Check if upgrading Python would break a package.

    Args:
        current_version: Current Python version (e.g., "3.11").
        target_version: Target Python version (e.g., "3.12").
        requires_python: The Requires-Python specifier.

    Returns:
        Tuple of (will_break, note).
    """
    if not requires_python:
        return False, ""

    try:
        from packaging.specifiers import SpecifierSet

        spec = SpecifierSet(requires_python)

        current_ok = current_version in spec or f"{current_version}.0" in spec
        target_ok = target_version in spec or f"{target_version}.0" in spec

        if current_ok and not target_ok:
            min_ver, max_ver = parse_requires_python(requires_python)
            note_parts = []
            if max_ver:
                note_parts.append(f"max supported: {max_ver}")
            return True, f"Will break on Python {target_version} ({', '.join(note_parts)})"
    except Exception:
        pass

    return False, ""


def fetch_compat_info(
    package_name: str,
    version: str | None,
    target_python: str,
    current_python: str,
    pypi_client: PyPIClient | None = None,
) -> CompatInfo:
    """Fetch compatibility info for a single package.

    Args:
        package_name: The normalized package name.
        version: The installed version (optional).
        target_python: The Python version to check against.
        current_python: The current Python version.
        pypi_client: Optional PyPIClient.

    Returns:
        CompatInfo with compatibility data.
    """
    client = pypi_client or PyPIClient()
    should_close = pypi_client is None

    try:
        info = client.get_package_info(package_name)
        if info is None:
            return CompatInfo(
                name=package_name,
                version=version or "unknown",
                is_compatible=True,
                compatibility_detail="Package not found on PyPI",
            )

        pkg_info = info.get("info", {})
        latest_version = pkg_info.get("version", "unknown")
        requires_python = pkg_info.get("requires_python") or pkg_info.get("requires_python", "")
        classifiers = pkg_info.get("classifiers", [])

        # Check compatibility
        is_compatible, detail = check_version_compatibility(
            target_python, requires_python, classifiers
        )

        # Check breaking on upgrade
        breaking, upgrade_note = check_breaking_on_upgrade(
            current_python, target_python, requires_python
        )

        # Parse min/max from requires_python
        min_py, max_py = parse_requires_python(requires_python)

        # Get supported versions from classifiers
        supported_versions = extract_python_classifiers(classifiers)

        return CompatInfo(
            name=package_name,
            version=version or latest_version,
            min_python=min_py,
            max_python=max_py,
            supported_versions=supported_versions,
            classifiers=[c for c in classifiers if "Python ::" in c][:10],
            requires_python=requires_python,
            is_compatible=is_compatible,
            compatibility_detail=detail,
            breaking_on_upgrade=breaking,
            upgrade_note=upgrade_note,
        )
    finally:
        if should_close:
            client.close()


def build_compat_report(
    project_path: str | Path,
    target_python: str = "3.12",
    dependencies: list[ParsedDependency] | None = None,
) -> CompatReport:
    """Build a compatibility report for a project's dependencies.

    Args:
        project_path: Path to the project directory.
        target_python: The Python version to check compatibility against.
        dependencies: Pre-parsed dependencies (discovered if None).

    Returns:
        A CompatReport with compatibility analysis.
    """
    project_path = Path(str(project_path)).resolve()

    if not project_path.is_dir():
        return CompatReport(errors=[f"Path is not a directory: {project_path}"])

    if dependencies is None:
        dependencies, _ = discover_dependencies(project_path)

    if not dependencies:
        return CompatReport(errors=["No dependencies found in the project."])

    current_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    report = CompatReport(
        target_python=target_python,
        current_python=current_python,
        total_packages=len(dependencies),
    )

    with PyPIClient() as client:
        for dep in dependencies:
            try:
                compat = fetch_compat_info(
                    dep.name, dep.version, target_python, current_python, client
                )
                report.packages.append(compat)

                if not compat.is_compatible:
                    report.incompatible_count += 1
                elif compat.compatibility_detail == "No version constraint specified":
                    report.unknown_count += 1
                else:
                    report.compatible_count += 1

                if compat.breaking_on_upgrade:
                    report.breaking_on_upgrade_count += 1

            except Exception as exc:
                report.errors.append(f"{dep.name}: {exc}")
                report.unknown_count += 1

    # Compute readiness score
    if report.total_packages > 0:
        report.readiness_score = report.compatible_count / report.total_packages

    # Sort: incompatible first, then breaking, then by name
    report.packages.sort(key=lambda p: (not p.is_compatible, p.breaking_on_upgrade, p.name))

    return report


def render_compat_table(report: CompatReport, console: Console | None = None) -> None:
    """Render the compatibility report as a Rich table.

    Args:
        report: The CompatReport to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    if not report.packages:
        console.print("[yellow]No compatibility data available.[/yellow]")
        return

    # Summary
    py_str = f"Python {report.current_python} → {report.target_python}"
    parts: list[str] = []
    if report.compatible_count:
        parts.append(f"[green]{report.compatible_count} compatible[/green]")
    if report.incompatible_count:
        parts.append(f"[red]{report.incompatible_count} incompatible[/red]")
    if report.unknown_count:
        parts.append(f"[dim]{report.unknown_count} unknown[/dim]")
    if report.breaking_on_upgrade_count:
        parts.append(f"[red bold]{report.breaking_on_upgrade_count} will break[/red bold]")

    summary = f"{py_str}: " + ", ".join(parts)
    score_pct = f"{report.readiness_score * 100:.0f}%"
    score_color = (
        "green"
        if report.readiness_score >= 0.9
        else "yellow"
        if report.readiness_score >= 0.7
        else "red"
    )
    summary += f" • Readiness: [{score_color}]{score_pct}[/{score_color}]"

    console.print()
    console.print(Panel(summary, title="Python Compatibility Check", border_style="blue"))

    # Main table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Package", style="cyan", min_width=20)
    table.add_column("Version", justify="right", min_width=12)
    table.add_column("Requires Python", min_width=18)
    table.add_column("Compatible", justify="center", min_width=12)
    table.add_column("Breaks on Upgrade", justify="center", min_width=16)
    table.add_column("Detail", min_width=30)

    for pkg in report.packages:
        compat_str = "[green]✓ yes[/green]" if pkg.is_compatible else "[red]✗ no[/red]"
        breaks_str = "[red]⚠ YES[/red]" if pkg.breaking_on_upgrade else "[dim]no[/dim]"
        req_py = pkg.requires_python or "-"

        table.add_row(
            pkg.name,
            pkg.version or "-",
            req_py,
            compat_str,
            breaks_str,
            pkg.compatibility_detail,
        )

    console.print(table)

    # Show breaking packages warning
    breaking = [p for p in report.packages if p.breaking_on_upgrade]
    if breaking:
        console.print()
        console.print(
            f"[red bold]⚠ {len(breaking)} package(s) will break"
            f" on Python {report.target_python}:[/red bold]"
        )
        for p in breaking:
            console.print(f"  • {p.name}: {p.upgrade_note}")


def render_compat_json(report: CompatReport) -> str:
    """Render the compatibility report as JSON string.

    Args:
        report: The CompatReport to render.

    Returns:
        JSON string of the report.
    """
    import json

    return json.dumps(report.to_dict(), indent=2)
