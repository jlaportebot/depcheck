"""Dependency chain analysis for depcheck.

Traces why a transitive dependency exists in a project by resolving the
full dependency graph and finding all paths from direct dependencies
to the target package. Shows health status at each link in the chain.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from depcheck.models import HealthStatus, ParsedDependency
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    check_package_health,
    discover_dependencies,
    normalize_package_name,
)

# Reuse status styles from tree module
_STATUS_STYLES: dict[HealthStatus, tuple[str, str]] = {
    HealthStatus.HEALTHY: ("✓", "green"),
    HealthStatus.OUTDATED: ("↑", "yellow"),
    HealthStatus.VULNERABLE: ("!", "red bold"),
    HealthStatus.UNMAINTAINED: ("⚠", "yellow"),
    HealthStatus.YANKED: ("✗", "red"),
    HealthStatus.REMOVED: ("✗", "red"),
    HealthStatus.UNKNOWN: ("?", "dim"),
}


@dataclass
class DependencyChain:
    """A single path from a direct dependency to a target package.

    Attributes:
        path: Ordered list of (name, version, status) tuples from root to target.
        is_direct: True if the target is a direct dependency.
        total_links: Number of hops in the chain.
    """

    path: list[tuple[str, str | None, HealthStatus]] = field(default_factory=list)
    is_direct: bool = False

    @property
    def total_links(self) -> int:
        return len(self.path) - 1

    @property
    def target(self) -> tuple[str, str | None, HealthStatus] | None:
        return self.path[-1] if self.path else None

    @property
    def root(self) -> tuple[str, str | None, HealthStatus] | None:
        return self.path[0] if self.path else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_direct": self.is_direct,
            "total_links": self.total_links,
            "path": [
                {"name": n, "version": v, "status": s.value}
                for n, v, s in self.path
            ],
        }


@dataclass
class WhyResult:
    """Result of dependency chain analysis.

    Attributes:
        target: The package name that was searched for.
        found: Whether the target package was found in the dependency graph.
        is_direct: Whether the target is a direct (top-level) dependency.
        chains: All dependency chains leading to the target.
        direct_deps: List of direct dependencies of the project.
        errors: Any errors encountered during resolution.
        project_path: Path to the scanned project.
    """

    target: str = ""
    found: bool = False
    is_direct: bool = False
    chains: list[DependencyChain] = field(default_factory=list)
    direct_deps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    project_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "found": self.found,
            "is_direct": self.is_direct,
            "project_path": self.project_path,
            "direct_dependencies": self.direct_deps,
            "chains": [c.to_dict() for c in self.chains],
            "errors": self.errors,
        }


def _build_adjacency_map(
    dependencies: list[ParsedDependency],
    pypi_client: PyPIClient,
    osv_client: OSVClient,
    max_depth: int = 4,
    check_vulnerabilities: bool = True,
) -> tuple[
    dict[str, list[str]],
    dict[str, str | None],
    dict[str, HealthStatus],
    list[str],
]:
    """Build an adjacency map of the dependency graph via BFS.

    Args:
        dependencies: List of direct dependencies.
        pypi_client: PyPI API client.
        osv_client: OSV API client.
        max_depth: Maximum depth to resolve.
        check_vulnerabilities: Whether to check for vulnerabilities.

    Returns:
        Tuple of (adjacency_map, version_map, status_map, errors).
        adjacency_map: package_name -> list of dependency names.
        version_map: package_name -> resolved version.
        status_map: package_name -> health status.
        errors: list of error messages.
    """
    import re

    adj: dict[str, list[str]] = {}
    versions: dict[str, str | None] = {}
    statuses: dict[str, HealthStatus] = {}
    errors: list[str] = []

    visited: set[str] = set()
    queue: list[tuple[str, str | None, str | None, int]] = []

    # Seed with direct dependencies
    for dep in dependencies:
        queue.append((dep.name, dep.version, dep.specifier, 0))

    while queue:
        name, version, specifier, depth = queue.pop(0)

        if name in visited:
            continue
        visited.add(name)

        # Fetch package info
        info = pypi_client.get_package_info(name)
        if info is None:
            statuses[name] = HealthStatus.REMOVED
            versions[name] = version or "unknown"
            adj[name] = []
            continue

        # Resolve version
        dep = ParsedDependency(name=name, version=version, specifier=specifier)
        resolved_version = pypi_client.resolve_version(dep, info)
        versions[name] = resolved_version or version

        # Check health (only at first two levels for speed)
        if depth <= 1 and check_vulnerabilities:
            report = check_package_health(dep, pypi_client, osv_client)
            statuses[name] = report.status
        else:
            # Fast health check without vulnerability scan
            latest = info.get("info", {}).get("version")
            if resolved_version and latest and resolved_version != latest:
                try:
                    from packaging.version import Version

                    if Version(resolved_version) < Version(latest):
                        statuses[name] = HealthStatus.OUTDATED
                    else:
                        statuses[name] = HealthStatus.HEALTHY
                except Exception:
                    statuses[name] = HealthStatus.HEALTHY
            else:
                statuses[name] = HealthStatus.HEALTHY

        # Parse sub-dependencies
        requires_dist = info.get("info", {}).get("requires_dist", []) or []
        children: list[str] = []

        for req_str in requires_dist:
            req_str = req_str.strip()
            if not req_str:
                continue

            # Skip extras and platform markers
            if ";" in req_str:
                _, marker = req_str.split(";", 1)
                marker = marker.strip().lower()
                if any(
                    kw in marker
                    for kw in (
                        "sys_platform",
                        "platform_system",
                        "platform_machine",
                        "python_version",
                        "implementation_name",
                        "extra ==",
                        'extra ==',
                    )
                ):
                    continue

            match = re.match(
                r"^(?P<nm>[a-zA-Z0-9][a-zA-Z0-9._-]*)"
                r"(\[(?P<extras>[^\]]+)\])?"
                r"(?P<spec>[><=!~].+)?$",
                req_str,
            )
            if match:
                child_name = normalize_package_name(match.group("nm"))
                children.append(child_name)
                if child_name not in visited and depth < max_depth:
                    child_spec = match.group("spec")
                    queue.append((child_name, None, child_spec, depth + 1))

        adj[name] = children

    return adj, versions, statuses, errors


def _find_all_paths(
    adj: dict[str, list[str]],
    start: str,
    target: str,
    visited: set[str] | None = None,
    path: list[str] | None = None,
    max_paths: int = 20,
    max_depth: int = 10,
) -> list[list[str]]:
    """DFS to find all paths from start to target in the dependency graph.

    Args:
        adj: Adjacency map of the dependency graph.
        start: Starting node.
        target: Target node.
        visited: Set of visited nodes (for cycle detection).
        path: Current path being built.
        max_paths: Maximum number of paths to return.
        max_depth: Maximum path length.

    Returns:
        List of paths, each path being a list of package names.
    """
    if visited is None:
        visited = set()
    if path is None:
        path = []

    results: list[list[str]] = []

    if len(results) >= max_paths:
        return results

    visited = visited | {start}
    path = path + [start]

    if start == target:
        return [path]

    if len(path) > max_depth:
        return []

    for neighbor in adj.get(start, []):
        if neighbor not in visited:
            paths = _find_all_paths(
                adj, neighbor, target, visited, path, max_paths - len(results), max_depth
            )
            results.extend(paths)
            if len(results) >= max_paths:
                break

    return results


def resolve_why(
    project_path: str | Path,
    target_package: str,
    max_depth: int = 4,
    check_vulnerabilities: bool = True,
) -> WhyResult:
    """Resolve why a package exists in a project's dependency tree.

    Args:
        project_path: Path to the project directory.
        target_package: The package to trace dependency chains for.
        max_depth: Maximum resolution depth for the dependency graph.
        check_vulnerabilities: Whether to check for vulnerabilities.

    Returns:
        WhyResult with all dependency chains leading to the target.
    """
    project_path = Path(project_path).resolve()
    target_package = normalize_package_name(target_package)

    if not project_path.is_dir():
        return WhyResult(
            target=target_package,
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Discover direct dependencies
    dependencies, _ = discover_dependencies(project_path)
    if not dependencies:
        return WhyResult(
            target=target_package,
            project_path=str(project_path),
            direct_deps=[],
            errors=["No dependencies found in the project."],
        )

    direct_names = [d.name for d in dependencies]

    result = WhyResult(
        target=target_package,
        project_path=str(project_path),
        direct_deps=direct_names,
    )

    # Check if target is a direct dependency
    if target_package in direct_names:
        result.is_direct = True
        result.found = True
        # We still resolve the full graph to show all chains

    # Build adjacency map
    with PyPIClient() as pypi_client, OSVClient() as osv_client:
        adj, versions, statuses, errors = _build_adjacency_map(
            dependencies,
            pypi_client,
            osv_client,
            max_depth=max_depth,
            check_vulnerabilities=check_vulnerabilities,
        )

    result.errors.extend(errors)

    # Check if target exists in the resolved graph
    if target_package not in adj:
        # Try case-insensitive search
        for pkg_name in adj:
            if pkg_name.lower() == target_package.lower():
                target_package = pkg_name
                break
        else:
            result.found = False
            return result

    result.found = True
    result.target = target_package

    # If direct dependency, create a single-hop chain
    if result.is_direct:
        chain = DependencyChain(
            path=[(target_package, versions.get(target_package), statuses.get(target_package, HealthStatus.UNKNOWN))],
            is_direct=True,
        )
        result.chains.append(chain)

    # Find all paths from each direct dependency to the target
    all_paths: list[list[str]] = []
    for dep_name in direct_names:
        if dep_name == target_package:
            continue  # Already handled above
        if dep_name not in adj:
            continue
        paths = _find_all_paths(adj, dep_name, target_package, max_paths=10, max_depth=max_depth)
        all_paths.extend(paths)

    # Sort paths by length (shortest first)
    all_paths.sort(key=len)

    # Convert paths to DependencyChain objects
    for path in all_paths:
        chain_path: list[tuple[str, str | None, HealthStatus]] = []
        for pkg_name in path:
            ver = versions.get(pkg_name)
            status = statuses.get(pkg_name, HealthStatus.UNKNOWN)
            chain_path.append((pkg_name, ver, status))
        chain = DependencyChain(path=chain_path, is_direct=False)
        result.chains.append(chain)

    return result


def render_why_table(result: WhyResult, console: Console | None = None) -> None:
    """Render the 'why' analysis as a Rich table with chain visualization.

    Args:
        result: The why analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    if not result.found:
        console.print()
        console.print(
            Panel(
                f"[red]Package '{result.target}' not found[/red] in the dependency "
                f"tree of {result.project_path}",
                title="[bold]depcheck why[/bold]",
                border_style="red",
            )
        )
        console.print()
        console.print("[dim]Possible reasons:[/dim]")
        console.print("[dim]  • The package is not a dependency (direct or transitive)[/dim]")
        console.print("[dim]  • The package name may be misspelled[/dim]")
        console.print("[dim]  • The dependency tree was not fully resolved (try increasing --max-depth)[/dim]")
        return

    console.print()
    title_text = f"[bold]depcheck why[/bold] — Why is [cyan]{result.target}[/cyan] in your project?"
    console.print(title_text)
    console.print()

    if result.is_direct:
        console.print(
            f"  [green]▸[/green] [cyan]{result.target}[/cyan] is a "
            f"[bold green]direct dependency[/bold green]"
        )
        if result.chains:
            ver = result.chains[0].path[0][1] or "?"
            status = result.chains[0].path[0][2]
            icon, color = _STATUS_STYLES.get(status, ("?", "white"))
            console.print(
                f"    Version: {ver}  [{color}]{icon} {status.value}[/{color}]"
            )
        console.print()

    # Render each chain
    for i, chain in enumerate(result.chains, 1):
        if chain.is_direct:
            continue  # Already shown above

        console.print(f"  [bold]Chain {i}[/bold] ({chain.total_links} link{'s' if chain.total_links != 1 else ''})")
        console.print()

        for j, (name, ver, status) in enumerate(chain.path):
            icon, color = _STATUS_STYLES.get(status, ("?", "white"))
            version_str = f" [dim]{ver}[/dim]" if ver else ""
            status_str = f" [{color}]{icon}[/{color}]"

            if j == 0:
                prefix = "  ┌─ "
            elif j == len(chain.path) - 1:
                prefix = "  └─ "
            else:
                prefix = "  ├─ "

            # Highlight the target
            if name == result.target and j == len(chain.path) - 1:
                console.print(f"{prefix}[bold cyan]{name}[/bold cyan]{version_str}{status_str}")
            elif j == 0:
                console.print(f"{prefix}[bold]{name}[/bold]{version_str}{status_str}")
            else:
                connector = "│" if j < len(chain.path) - 1 else " "
                console.print(f"  {connector}  {prefix.strip()}{name}{version_str}{status_str}")

        console.print()

    # Summary
    if not result.is_direct and result.chains:
        total_chains = len([c for c in result.chains if not c.is_direct])
        shortest = min(c.total_links for c in result.chains if not c.is_direct)
        direct_root_names = set()
        for c in result.chains:
            if c.path and not c.is_direct:
                direct_root_names.add(c.path[0][0])

        console.print(f"  [bold]Summary:[/bold] {total_chains} chain{'s' if total_chains != 1 else ''} found")
        console.print(
            f"  Shortest path: {shortest} link{'s' if shortest != 1 else ''} "
            f"from {', '.join(direct_root_names)}"
        )

        # Health status of the target
        target_status = None
        for c in result.chains:
            if c.target:
                target_status = c.target[2]
                break
        if target_status:
            icon, color = _STATUS_STYLES.get(target_status, ("?", "white"))
            console.print(f"  Target health: [{color}]{icon} {target_status.value}[/{color}]")

    # Show direct dependencies
    console.print()
    table = Table(title="Direct Dependencies", show_lines=False, pad_edge=False)
    table.add_column("Package", style="bold")
    table.add_column("Status", justify="center")

    for dep_name in result.direct_deps:
        # Find status from any chain
        status = HealthStatus.UNKNOWN
        for c in result.chains:
            for n, v, s in c.path:
                if n == dep_name:
                    status = s
                    break
        icon, color = _STATUS_STYLES.get(status, ("?", "white"))
        table.add_row(dep_name, f"[{color}]{icon} {status.value}[/{color}]")

    console.print(table)


def render_why_json(result: WhyResult, console: Console | None = None) -> None:
    """Render the 'why' analysis as JSON.

    Args:
        result: The why analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console(force_terminal=False, no_color=True)

    output = result.to_dict()
    console.print(json.dumps(output, indent=2))
