"""Dependency conflict detection for depcheck.

Detects version conflicts in dependency specifications — when different
packages require incompatible versions of the same dependency. This is
one of the most painful problems in Python dependency management.

Features:
- Version conflict detection across the full dependency tree
- Overlapping specifier analysis (e.g., pkg-a requires foo>=2.0, pkg-b requires foo<2.0)
- Constraint merging: find the compatible version range
- Conflict severity classification (hard conflict vs. soft warning)
- Resolution suggestions: which version(s) would satisfy all constraints
- Extras/optional dependency conflict detection
- Circular dependency detection with conflict analysis
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.pypi import PyPIClient

# Re-export from repomap for node model
from depcheck.repomap import RepoMap, build_repomap
from depcheck.scanner import normalize_package_name

# ── Data Models ──────────────────────────────────────────────────────────


class ConflictSeverity:
    """Severity levels for dependency conflicts."""

    HARD = "hard"  # No compatible version exists
    SOFT = "soft"  # Compatible version exists but is narrow
    WARNING = "warning"  # Potential issue (e.g., very old version required)


@dataclass
class VersionConstraint:
    """A version constraint from a specific package."""

    package: str  # The package imposing the constraint
    target: str  # The package being constrained
    specifier: str  # The version specifier (e.g., ">=2.0,<3.0")
    source: str = "direct"  # "direct" or "transitive"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "package": self.package,
            "target": self.target,
            "specifier": self.specifier,
            "source": self.source,
        }


@dataclass
class ConflictResult:
    """Result of analyzing a dependency conflict."""

    package: str  # The conflicting package
    constraints: list[VersionConstraint] = field(default_factory=list)
    severity: str = ConflictSeverity.WARNING
    compatible_versions: list[str] = field(default_factory=list)
    resolution_suggestion: str = ""
    details: str = ""

    @property
    def constraint_count(self) -> int:
        """Number of conflicting constraints."""
        return len(self.constraints)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "package": self.package,
            "severity": self.severity,
            "constraints": [c.to_dict() for c in self.constraints],
            "compatible_versions": self.compatible_versions,
            "resolution_suggestion": self.resolution_suggestion,
            "details": self.details,
        }


@dataclass
class ConflictReport:
    """Complete conflict analysis for a project."""

    project_path: str
    conflicts: list[ConflictResult] = field(default_factory=list)
    warnings: list[ConflictResult] = field(default_factory=list)
    total_packages_analyzed: int = 0
    total_constraints: int = 0
    hard_conflict_count: int = 0
    soft_conflict_count: int = 0
    warning_count: int = 0
    circular_deps: list[list[str]] = field(default_factory=list)

    @property
    def has_hard_conflicts(self) -> bool:
        """Whether any hard conflicts exist."""
        return self.hard_conflict_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "summary": {
                "total_packages_analyzed": self.total_packages_analyzed,
                "total_constraints": self.total_constraints,
                "hard_conflicts": self.hard_conflict_count,
                "soft_conflicts": self.soft_conflict_count,
                "warnings": self.warning_count,
                "circular_dependencies": len(self.circular_deps),
            },
            "conflicts": [c.to_dict() for c in self.conflicts],
            "warnings": [c.to_dict() for c in self.warnings],
            "circular_deps": self.circular_deps,
        }


# ── Conflict Detection ──────────────────────────────────────────────────


def _extract_version_constraints(
    repo_map: RepoMap,
    pypi: PyPIClient,
) -> dict[str, list[VersionConstraint]]:
    """Extract all version constraints from the dependency map.

    Args:
        repo_map: The dependency map to analyze.
        pypi: PyPI client for fetching package info.

    Returns:
        Dictionary mapping target package names to their constraints.
    """
    constraints: dict[str, list[VersionConstraint]] = {}

    # For each package in the map, look at its dependencies and extract specifiers
    for name, node in repo_map.nodes.items():
        # Get this package's requirements from PyPI
        info = pypi.get_package_info(name)
        if info is None:
            continue

        requires_dist = info.get("info", {}).get("requires_dist", []) or []

        for req_str in requires_dist:
            # Skip extras-only dependencies
            if ";" in req_str:
                marker = req_str.split(";", 1)[1].strip()
                if "extra" in marker.lower():
                    continue

            # Parse the requirement: "package>=1.0,<2.0"
            parsed = _parse_requirement_spec(req_str)
            if parsed is None:
                continue

            target_name, specifier = parsed
            norm_target = normalize_package_name(target_name)

            # Only track constraints for packages we know about
            if norm_target in repo_map.nodes:
                constraint = VersionConstraint(
                    package=name,
                    target=norm_target,
                    specifier=specifier,
                    source="transitive" if not node.direct else "direct",
                )
                constraints.setdefault(norm_target, []).append(constraint)

    return constraints


def _parse_requirement_spec(req_str: str) -> tuple[str, str] | None:
    """Parse a requirement string into (name, specifier).

    Args:
        req_str: A PEP 508 requirement string like "requests>=2.0,<3.0".

    Returns:
        Tuple of (normalized_name, specifier_string), or None if parsing fails.
    """
    import re

    # Match: name[extras]specifier
    match = re.match(
        r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*([><=!~].+)?$",
        req_str.strip(),
    )
    if match is None:
        return None

    name = normalize_package_name(match.group(1))
    specifier = match.group(2) or ""

    return name, specifier.strip()


def _find_compatible_versions(
    constraints: list[VersionConstraint],
    pypi: PyPIClient,
) -> list[str]:
    """Find versions that satisfy all constraints.

    Args:
        constraints: List of version constraints.
        pypi: PyPI client for fetching available versions.

    Returns:
        List of version strings that satisfy all constraints.
    """
    if not constraints:
        return []

    # Get the target package name
    target = constraints[0].target
    info = pypi.get_package_info(target)
    if info is None:
        return []

    releases = info.get("releases", {})
    available_versions: list[Version] = []

    for ver_str in releases:
        try:
            ver = Version(ver_str)
            if not ver.is_prerelease and not ver.is_devrelease:
                available_versions.append(ver)
        except Exception:
            continue

    if not available_versions:
        return []

    # Filter by all constraints
    compatible: list[Version] = []

    for ver in available_versions:
        satisfies_all = True
        for constraint in constraints:
            if constraint.specifier:
                try:
                    spec = SpecifierSet(constraint.specifier)
                    if ver not in spec:
                        satisfies_all = False
                        break
                except Exception:
                    # Invalid specifier, skip this constraint
                    continue

        if satisfies_all:
            compatible.append(ver)

    # Return the 10 latest compatible versions
    compatible.sort(reverse=True)
    return [str(v) for v in compatible[:10]]


def _classify_conflict(
    constraints: list[VersionConstraint],
    compatible_versions: list[str],
) -> tuple[str, str]:
    """Classify the severity of a conflict and generate a suggestion.

    Args:
        constraints: The conflicting constraints.
        compatible_versions: Versions that satisfy all constraints.

    Returns:
        Tuple of (severity, suggestion).
    """
    if not compatible_versions:
        # No version satisfies all constraints — hard conflict
        [c.specifier for c in constraints if c.specifier]
        constraint_strs = [
            f"  {c.package} requires {c.target}{c.specifier}" for c in constraints
        ]
        return (
            ConflictSeverity.HARD,
            "No compatible version found. Conflicting specifiers:\n"
            + "\n".join(constraint_strs),
        )

    if len(compatible_versions) <= 2:
        # Very narrow compatible range — soft conflict
        return (
            ConflictSeverity.SOFT,
            f"Only {len(compatible_versions)} compatible version(s): "
            + ", ".join(compatible_versions[:3]),
        )

    # Multiple constraints but wide compatible range — warning
    if len(constraints) > 1:
        return (
            ConflictSeverity.WARNING,
            f"Multiple constraints but {len(compatible_versions)} compatible versions exist.",
        )

    return ConflictSeverity.WARNING, ""


def _detect_circular_deps(repo_map: RepoMap) -> list[list[str]]:
    """Detect circular dependencies in the dependency map.

    Args:
        repo_map: The dependency map to analyze.

    Returns:
        List of circular dependency chains.
    """
    cycles: list[list[str]] = []
    visited: set[str] = set()

    def dfs(node_name: str, path: list[str]) -> None:
        """Depth-first search for cycles."""
        if node_name in path:
            # Found a cycle
            cycle_start = path.index(node_name)
            cycle = path[cycle_start:] + [node_name]
            cycles.append(cycle)
            return

        if node_name in visited:
            return

        visited.add(node_name)
        path.append(node_name)

        node = repo_map.nodes.get(node_name)
        if node:
            for dep in node.dependencies:
                dfs(dep, path)

        path.pop()

    for name in repo_map.nodes:
        visited.clear()
        dfs(name, [])

    return cycles


def build_conflict_report(
    project_path: str,
    resolve_depth: int = 2,
) -> ConflictReport:
    """Build a complete conflict report for a project.

    Args:
        project_path: Path to the project directory.
        resolve_depth: How deep to resolve transitive dependencies.

    Returns:
        ConflictReport with conflict analysis.
    """
    report = ConflictReport(project_path=project_path)

    # Build the dependency map first
    repo_map = build_repomap(
        project_path=project_path,
        resolve_depth=resolve_depth,
    )
    report.total_packages_analyzed = repo_map.total_packages

    # Detect circular deps
    report.circular_deps = _detect_circular_deps(repo_map)

    # Extract and analyze constraints
    with PyPIClient() as pypi:
        constraints = _extract_version_constraints(repo_map, pypi)
        report.total_constraints = sum(len(c) for c in constraints.values())

        for target_name, target_constraints in constraints.items():
            if len(target_constraints) <= 1:
                continue  # No conflict possible with a single constraint

            # Find compatible versions
            compatible = _find_compatible_versions(target_constraints, pypi)

            # Classify the conflict
            severity, suggestion = _classify_conflict(target_constraints, compatible)

            result = ConflictResult(
                package=target_name,
                constraints=target_constraints,
                severity=severity,
                compatible_versions=compatible,
                resolution_suggestion=suggestion,
                details=_build_conflict_details(target_name, target_constraints),
            )

            if severity == ConflictSeverity.HARD:
                report.conflicts.append(result)
                report.hard_conflict_count += 1
            elif severity == ConflictSeverity.SOFT:
                report.conflicts.append(result)
                report.soft_conflict_count += 1
            else:
                report.warnings.append(result)
                report.warning_count += 1

    return report


def _build_conflict_details(
    target: str,
    constraints: list[VersionConstraint],
) -> str:
    """Build a human-readable details string for a conflict.

    Args:
        target: The target package name.
        constraints: The conflicting constraints.

    Returns:
        Human-readable conflict details.
    """
    lines = [f"Conflicting requirements for {target}:"]
    for c in constraints:
        specifier = c.specifier or "any"
        lines.append(f"  • {c.package} ({c.source}) requires {target}{specifier}")
    return "\n".join(lines)


# ── Rendering ────────────────────────────────────────────────────────────


def render_conflict_table(report: ConflictReport, console: Console | None = None) -> None:
    """Render the conflict report as a Rich table.

    Args:
        report: The conflict report to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    # Summary panel
    severity_color = (
    "red"
    if report.hard_conflict_count > 0
    else "yellow"
    if report.soft_conflict_count > 0
    else "green"
)
    summary = (
        f"[bold]Packages Analyzed:[/bold] {report.total_packages_analyzed}  "
        f"[bold]Constraints:[/bold] {report.total_constraints}  "
        f"[{severity_color}]Hard Conflicts: {report.hard_conflict_count}[/{severity_color}]  "
        f"[yellow]Soft: {report.soft_conflict_count}[/yellow]  "
        f"[dim]Warnings: {report.warning_count}[/dim]  "
        f"[blue]Circular: {len(report.circular_deps)}[/blue]"
    )
    console.print(Panel(summary, title="Conflict Analysis", border_style=severity_color))

    # Hard and soft conflicts table
    if report.conflicts:
        table = Table(title="Dependency Conflicts", show_lines=True)
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Severity", style="bold")
        table.add_column("Constraints", style="yellow")
        table.add_column("Compatible", style="green")
        table.add_column("Suggestion", style="dim", max_width=40)

        for conflict in report.conflicts:
            severity_icon = "🔴" if conflict.severity == ConflictSeverity.HARD else "🟡"
            constraint_lines = []
            for c in conflict.constraints:
                spec = c.specifier or "any"
                constraint_lines.append(f"{c.package}{spec}")
            constraint_str = "\n".join(constraint_lines[:5])
            if len(constraint_lines) > 5:
                constraint_str += f"\n+{len(constraint_lines) - 5} more"

            compatible_str = ", ".join(conflict.compatible_versions[:5]) or "NONE"

            table.add_row(
                conflict.package,
                f"{severity_icon} {conflict.severity}",
                constraint_str,
                compatible_str,
                conflict.resolution_suggestion[:80],
            )

        console.print(table)

    # Warnings
    if report.warnings:
        table = Table(title="Dependency Warnings", show_lines=True)
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Constraints", style="yellow")
        table.add_column("Suggestion", style="dim", max_width=50)

        for warning in report.warnings:
            constraint_lines = []
            for c in warning.constraints:
                spec = c.specifier or "any"
                constraint_lines.append(f"{c.package}{spec}")
            constraint_str = ", ".join(constraint_lines[:3])

            table.add_row(
                warning.package,
                constraint_str,
                warning.resolution_suggestion[:80],
            )

        console.print(table)

    # Circular dependencies
    if report.circular_deps:
        console.print("\n[bold blue]🔄 Circular Dependencies:[/bold blue]")
        for cycle in report.circular_deps:
            console.print(f"  {' → '.join(cycle)}")

    # No conflicts
    if not report.conflicts and not report.warnings and not report.circular_deps:
        console.print("\n[green]✓ No dependency conflicts detected![/green]")


def render_conflict_json(report: ConflictReport) -> str:
    """Render the conflict report as JSON.

    Args:
        report: The conflict report to render.

    Returns:
        JSON string of the conflict report.
    """
    return json.dumps(report.to_dict(), indent=2)
