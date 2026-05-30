"""Dependency repomap for depcheck.

Maps which packages in your project depend on which other packages,
building a reverse dependency map and a usage impact analysis.

Features:
- Reverse dependency map: which packages depend on each package
- Forward dependency map: what each package depends on
- Impact analysis: what breaks if a package is removed/updated
- Dependency depth analysis: how deep each dependency chain goes
- Orphan detection: packages not depended upon by anything
- Critical path identification: most-depended-upon packages
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    normalize_package_name,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
)

# ── Data Models ──────────────────────────────────────────────────────────


@dataclass
class DependencyNode:
    """A node in the dependency map."""

    name: str
    version: str | None = None
    direct: bool = False  # True if this is a direct (declared) dependency
    depth: int = 0
    dependents: list[str] = field(default_factory=list)  # packages that depend on this
    dependencies: list[str] = field(default_factory=list)  # packages this depends on

    @property
    def is_orphan(self) -> bool:
        """True if no other package depends on this (except as a direct dep)."""
        return len(self.dependents) == 0

    @property
    def dependents_count(self) -> int:
        """Number of packages that depend on this one."""
        return len(self.dependents)

    @property
    def dependencies_count(self) -> int:
        """Number of packages this one depends on."""
        return len(self.dependencies)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "direct": self.direct,
            "depth": self.depth,
            "dependents": self.dependents,
            "dependencies": self.dependencies,
            "is_orphan": self.is_orphan,
        }


@dataclass
class ImpactReport:
    """Impact analysis for removing/updating a package."""

    package: str
    removed_directly: list[str] = field(default_factory=list)
    removed_transitively: list[str] = field(default_factory=list)
    affected_packages: list[str] = field(default_factory=list)

    @property
    def total_impact(self) -> int:
        """Total number of packages affected."""
        return (
            len(self.removed_directly)
            + len(self.removed_transitively)
            + len(self.affected_packages)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "package": self.package,
            "removed_directly": self.removed_directly,
            "removed_transitively": self.removed_transitively,
            "affected_packages": self.affected_packages,
            "total_impact": self.total_impact,
        }


@dataclass
class RepoMap:
    """Complete dependency map of a project."""

    project_path: str
    nodes: dict[str, DependencyNode] = field(default_factory=dict)
    direct_dependencies: list[str] = field(default_factory=list)
    max_depth: int = 0
    total_packages: int = 0
    orphan_packages: list[str] = field(default_factory=list)
    critical_packages: list[str] = field(default_factory=list)

    def get_node(self, name: str) -> DependencyNode | None:
        """Get a dependency node by name."""
        return self.nodes.get(normalize_package_name(name))

    def impact_analysis(self, package_name: str) -> ImpactReport:
        """Analyze the impact of removing a package.

        Args:
            package_name: The package to analyze removal impact for.

        Returns:
            ImpactReport showing what would break.
        """
        normalized = normalize_package_name(package_name)
        report = ImpactReport(package=normalized)

        if normalized not in self.nodes:
            return report

        node = self.nodes[normalized]

        # Packages that directly depend on this one would break
        report.removed_directly = list(node.dependents)

        # Find transitive impact: packages that depend on dependents
        visited: set[str] = {normalized}
        queue: list[str] = list(node.dependents)

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            current_node = self.nodes.get(current)
            if current_node is None:
                continue

            # Packages that depend on a now-removed package
            for dependent in current_node.dependents:
                if dependent not in visited:
                    report.removed_transitively.append(dependent)
                    queue.append(dependent)

        # Packages that would lose functionality (depend on it but won't break)
        for dep in node.dependencies:
            dep_node = self.nodes.get(dep)
            if dep_node and dep_node.dependents_count <= 1:
                # This was the only user; it becomes orphaned
                report.affected_packages.append(dep)

        return report

    def top_dependents(self, limit: int = 10) -> list[tuple[str, int]]:
        """Get packages ranked by how many packages depend on them.

        Args:
            limit: Maximum number of packages to return.

        Returns:
            List of (package_name, dependents_count) sorted by count descending.
        """
        ranked = sorted(
            [(name, node.dependents_count) for name, node in self.nodes.items()],
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked[:limit]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "total_packages": self.total_packages,
            "max_depth": self.max_depth,
            "direct_dependencies": self.direct_dependencies,
            "orphan_packages": self.orphan_packages,
            "critical_packages": self.critical_packages,
            "nodes": {name: node.to_dict() for name, node in self.nodes.items()},
        }


# ── Map Building ─────────────────────────────────────────────────────────


def _parse_project_deps(project_path: str) -> list[ParsedDependency]:
    """Parse all dependency files in a project.

    Args:
        project_path: Path to the project directory.

    Returns:
        List of parsed dependencies from all found dep files.
    """
    path = Path(project_path)
    all_deps: list[ParsedDependency] = []
    seen: set[str] = set()

    # requirements.txt
    req_file = path / "requirements.txt"
    if req_file.exists():
        for dep in parse_requirements_txt(req_file):
            norm = normalize_package_name(dep.name)
            if norm not in seen:
                seen.add(norm)
                all_deps.append(dep)

    # pyproject.toml
    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        for dep in parse_pyproject_toml(pyproject):
            norm = normalize_package_name(dep.name)
            if norm not in seen:
                seen.add(norm)
                all_deps.append(dep)

    # Pipfile
    pipfile = path / "Pipfile"
    if pipfile.exists():
        for dep in parse_pipfile(pipfile):
            norm = normalize_package_name(dep.name)
            if norm not in seen:
                seen.add(norm)
                all_deps.append(dep)

    # Also check requirements/ directory
    req_dir = path / "requirements"
    if req_dir.exists() and req_dir.is_dir():
        for req in sorted(req_dir.glob("*.txt")):
            for dep in parse_requirements_txt(req):
                norm = normalize_package_name(dep.name)
                if norm not in seen:
                    seen.add(norm)
                    all_deps.append(dep)

    return all_deps


def build_repomap(
    project_path: str,
    resolve_depth: int = 2,
    check_vulnerabilities: bool = False,
) -> RepoMap:
    """Build a complete dependency map for a project.

    Args:
        project_path: Path to the project directory.
        resolve_depth: How deep to resolve transitive dependencies.
        check_vulnerabilities: Whether to check for vulnerabilities.

    Returns:
        A RepoMap object with the complete dependency map.
    """
    repo_map = RepoMap(project_path=project_path)

    # Parse direct dependencies
    direct_deps = _parse_project_deps(project_path)
    repo_map.direct_dependencies = [normalize_package_name(d.name) for d in direct_deps]

    # Build initial nodes for direct dependencies
    with PyPIClient() as pypi:
        for dep in direct_deps:
            norm_name = normalize_package_name(dep.name)
            version = dep.version or pypi.resolve_version(dep)

            node = DependencyNode(
                name=norm_name,
                version=version,
                direct=True,
                depth=0,
            )
            repo_map.nodes[norm_name] = node

        # Resolve transitive dependencies
        if resolve_depth > 0:
            _resolve_transitive_deps(repo_map, pypi, resolve_depth)

    # Calculate derived metrics
    _calculate_metrics(repo_map)

    return repo_map


def _resolve_transitive_deps(
    repo_map: RepoMap,
    pypi: PyPIClient,
    max_depth: int,
) -> None:
    """Resolve transitive dependencies up to max_depth.

    Args:
        repo_map: The repo map to populate.
        pypi: PyPI client for fetching package info.
        max_depth: Maximum depth to resolve.
    """
    # BFS through dependency tree
    queue: list[tuple[str, int]] = [
        (name, 0) for name in repo_map.direct_dependencies
    ]
    visited: set[str] = set(repo_map.direct_dependencies)

    while queue:
        current_name, current_depth = queue.pop(0)

        if current_depth >= max_depth:
            continue

        node = repo_map.nodes.get(current_name)
        if node is None:
            continue

        # Fetch package info from PyPI to get dependencies
        info = pypi.get_package_info(current_name)
        if info is None:
            continue

        # Extract requires_dist from PyPI metadata
        requires_dist = info.get("info", {}).get("requires_dist", []) or []

        for req_str in requires_dist:
            # Parse "package>=1.0; extra == ..." — skip extras
            if ";" in req_str:
                marker = req_str.split(";", 1)[1].strip()
                # Skip conditional dependencies (extras, platform-specific)
                if "extra" in marker.lower():
                    continue

            # Extract package name
            req_name = _extract_package_name(req_str)
            if req_name is None:
                continue

            norm_name = normalize_package_name(req_name)

            # Add as a dependency of current node
            if norm_name not in node.dependencies:
                node.dependencies.append(norm_name)

            # Create or update the transitive dep node
            if norm_name not in visited:
                visited.add(norm_name)
                trans_node = DependencyNode(
                    name=norm_name,
                    direct=False,
                    depth=current_depth + 1,
                )
                repo_map.nodes[norm_name] = trans_node
                queue.append((norm_name, current_depth + 1))

            # Add reverse dependency
            trans_node = repo_map.nodes.get(norm_name)
            if trans_node and current_name not in trans_node.dependents:
                trans_node.dependents.append(current_name)


def _extract_package_name(requirement_string: str) -> str | None:
    """Extract just the package name from a requirement string.

    Handles formats like:
    - "requests>=2.0"
    - "package[extra]>=1.0"
    - "my-package~=1.0"

    Args:
        requirement_string: A PEP 508 requirement string.

    Returns:
        The package name, or None if parsing fails.
    """
    import re

    match = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(\[.*?\])?", requirement_string.strip())
    if match:
        return match.group(1)
    return None


def _calculate_metrics(repo_map: RepoMap) -> None:
    """Calculate derived metrics for the repo map.

    Args:
        repo_map: The repo map to calculate metrics for.
    """
    repo_map.total_packages = len(repo_map.nodes)
    repo_map.max_depth = max((n.depth for n in repo_map.nodes.values()), default=0)

    # Orphan packages: transitive deps not depended upon by any other transitive dep
    for name, node in repo_map.nodes.items():
        if node.is_orphan and not node.direct:
            repo_map.orphan_packages.append(name)

    # Critical packages: top 5 by dependents count
    top = repo_map.top_dependents(limit=5)
    repo_map.critical_packages = [name for name, _ in top if _ > 0]


# ── Rendering ────────────────────────────────────────────────────────────


def render_repomap_table(repo_map: RepoMap, console: Console | None = None) -> None:
    """Render the dependency map as a Rich table.

    Args:
        repo_map: The repo map to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    # Summary panel
    summary = (
        f"[bold]Total Packages:[/bold] {repo_map.total_packages}  "
        f"[bold]Direct:[/bold] {len(repo_map.direct_dependencies)}  "
        f"[bold]Transitive:[/bold] {repo_map.total_packages - len(repo_map.direct_dependencies)}  "
        f"[bold]Max Depth:[/bold] {repo_map.max_depth}  "
        f"[bold]Orphans:[/bold] {len(repo_map.orphan_packages)}  "
        f"[bold]Critical:[/bold] {len(repo_map.critical_packages)}"
    )
    console.print(Panel(summary, title="Dependency Map Summary", border_style="blue"))

    # Dependencies table
    table = Table(title="Dependency Map", show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="magenta")
    table.add_column("Direct", style="green")
    table.add_column("Depth", justify="right")
    table.add_column("Dependents", style="yellow")
    table.add_column("Dependencies", style="blue")
    table.add_column("Status", style="bold")

    # Sort: direct deps first, then by dependents count
    sorted_nodes = sorted(
        repo_map.nodes.items(),
        key=lambda x: (not x[1].direct, -x[1].dependents_count),
    )

    for name, node in sorted_nodes:
        direct_str = "✓" if node.direct else ""
        status = "🔴 critical" if name in repo_map.critical_packages else ""
        if not status and node.is_orphan and not node.direct:
            status = "⚪ orphan"
        if not status and node.direct:
            status = "🟢 direct"

        dependents_str = ", ".join(node.dependents[:5])
        if len(node.dependents) > 5:
            dependents_str += f" (+{len(node.dependents) - 5})"

        dependencies_str = ", ".join(node.dependencies[:5])
        if len(node.dependencies) > 5:
            dependencies_str += f" (+{len(node.dependencies) - 5})"

        table.add_row(
            name,
            node.version or "—",
            direct_str,
            str(node.depth),
            dependents_str or "—",
            dependencies_str or "—",
            status,
        )

    console.print(table)

    # Critical packages
    if repo_map.critical_packages:
        console.print(
            "\n[bold red]⚠ Critical packages (most depended-upon):[/bold red] "
            + ", ".join(repo_map.critical_packages)
        )

    # Orphan packages
    if repo_map.orphan_packages:
        console.print(
            "[dim]⚪ Orphan packages (no reverse deps):[/dim] "
            + ", ".join(repo_map.orphan_packages[:20])
        )


def render_repomap_tree(repo_map: RepoMap, console: Console | None = None) -> None:
    """Render the dependency map as a Rich tree.

    Args:
        repo_map: The repo map to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    tree = Tree("📦 [bold]Dependency Map[/bold]")

    # Show direct dependencies as top-level, with their transitive deps as children
    direct_tree = tree.add("🔹 [cyan]Direct Dependencies[/cyan]")
    for name in sorted(repo_map.direct_dependencies):
        node = repo_map.nodes.get(name)
        if node is None:
            continue
        label = f"[green]{name}[/green]"
        if node.version:
            label += f" [dim]v{node.version}[/dim]"
        branch = direct_tree.add(label)
        _add_transitive_branch(branch, node, repo_map, visited=set())

    # Show transitive-only deps
    transitive = [
        name
        for name in repo_map.nodes
        if name not in repo_map.direct_dependencies
    ]
    if transitive:
        trans_tree = tree.add("🔸 [yellow]Transitive Dependencies[/yellow]")
        for name in sorted(transitive):
            node = repo_map.nodes.get(name)
            if node is None:
                continue
            label = f"[yellow]{name}[/yellow]"
            if node.version:
                label += f" [dim]v{node.version}[/dim]"
            if node.dependents:
                label += f" [dim]← {', '.join(node.dependents[:3])}[/dim]"
            trans_tree.add(label)

    console.print(tree)


def _add_transitive_branch(
    branch: Tree,
    node: DependencyNode,
    repo_map: RepoMap,
    visited: set[str],
    depth: int = 0,
) -> None:
    """Recursively add transitive dependencies to a tree branch.

    Args:
        branch: The Rich tree branch to add to.
        node: The current dependency node.
        repo_map: The complete repo map.
        visited: Set of already-visited package names (cycle detection).
        depth: Current depth in the tree.
    """
    if depth > 5:  # Limit tree depth for readability
        return

    for dep_name in sorted(node.dependencies):
        norm_name = normalize_package_name(dep_name)
        if norm_name in visited:
            branch.add(f"[dim]{norm_name} ↻[/dim]")
            continue

        visited.add(norm_name)
        dep_node = repo_map.nodes.get(norm_name)
        if dep_node is None:
            branch.add(f"[dim]{norm_name}[/dim]")
            continue

        label = f"{norm_name}"
        if dep_node.version:
            label += f" [dim]v{dep_node.version}[/dim]"

        child = branch.add(label)
        _add_transitive_branch(child, dep_node, repo_map, visited, depth + 1)
        visited.discard(norm_name)


def render_repomap_json(repo_map: RepoMap) -> str:
    """Render the dependency map as JSON.

    Args:
        repo_map: The repo map to render.

    Returns:
        JSON string of the repo map.
    """
    return json.dumps(repo_map.to_dict(), indent=2)


def render_impact_table(impact: ImpactReport, console: Console | None = None) -> None:
    """Render an impact analysis report as a Rich table.

    Args:
        impact: The impact report to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    console.print(
        Panel(
            f"[bold]Impact of removing '{impact.package}':[/bold] "
            f"{impact.total_impact} packages affected",
            border_style="red",
        )
    )

    if impact.removed_directly:
        console.print(
            "  [red]✗ Directly removed:[/red] "
            + ", ".join(impact.removed_directly)
        )

    if impact.removed_transitively:
        console.print(
            "  [red]✗ Transitively removed:[/red] "
            + ", ".join(impact.removed_transitively)
        )

    if impact.affected_packages:
        console.print(
            "  [yellow]⚠ Affected (orphaned):[/yellow] "
            + ", ".join(impact.affected_packages)
        )

    if impact.total_impact == 0:
        console.print("  [green]✓ No packages would be affected[/green]")


def render_impact_json(impact: ImpactReport) -> str:
    """Render an impact analysis report as JSON.

    Args:
        impact: The impact report to render.

    Returns:
        JSON string of the impact report.
    """
    return json.dumps(impact.to_dict(), indent=2)
