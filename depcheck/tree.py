"""Dependency tree resolution and visualization for depcheck.

Resolves the full dependency tree of a Python project by querying PyPI
for each package's declared dependencies, then renders the tree with
health status indicators using Rich.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.tree import Tree

from depcheck.models import HealthStatus
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    check_package_health,
    discover_dependencies,
)

# License support is optional — available when the license-compliance feature is merged
try:
    from depcheck.licenses import LicenseCategory
except ImportError:
    LicenseCategory = None  # type: ignore[assignment,misc]


@dataclass
class TreeNode:
    """A node in the dependency tree.

    Attributes:
        name: Normalized package name.
        version: Resolved version string (or None).
        status: Health status of this package.
        license_id: SPDX license ID (or empty string).
        license_category: License category string.
        is_compliant: Whether the license is compliant.
        children: Sub-dependencies of this package.
        depth: Depth in the tree (0 for root-level deps).
        parent_chain: Set of package names from root to this node (for cycle detection).
    """

    name: str
    version: str | None = None
    status: HealthStatus = HealthStatus.UNKNOWN
    license_id: str = ""
    license_category: str = ""
    is_compliant: bool = True
    children: list[TreeNode] = field(default_factory=list)
    depth: int = 0
    parent_chain: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "license": self.license_id or None,
            "license_category": self.license_category or None,
            "license_compliant": self.is_compliant if self.license_id else None,
            "children": [c.to_dict() for c in self.children],
        }

    @property
    def is_circular(self) -> bool:
        """Check if this node would create a circular dependency."""
        return self.name in self.parent_chain


@dataclass
class DependencyTreeResult:
    """Result of dependency tree resolution.

    Attributes:
        project_path: Path to the scanned project.
        roots: Top-level dependency tree nodes.
        files_scanned: List of files that were scanned for dependencies.
        circular_deps: List of circular dependency paths found.
        errors: List of error messages encountered.
        stats: Resolution statistics.
    """

    project_path: str
    roots: list[TreeNode] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    circular_deps: list[list[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "files_scanned": self.files_scanned,
            "circular_dependencies": self.circular_deps,
            "errors": self.errors,
            "stats": self.stats,
            "tree": [r.to_dict() for r in self.roots],
        }

    @property
    def total_packages(self) -> int:
        """Count all unique packages in the tree."""

        def _count(nodes: list[TreeNode], seen: set[str] | None = None) -> int:
            if seen is None:
                seen = set()
            count = 0
            for node in nodes:
                if node.name not in seen:
                    seen.add(node.name)
                    count += 1
                    count += _count(node.children, seen)
            return count

        return _count(self.roots)

    @property
    def max_depth(self) -> int:
        """Get the maximum depth of the tree (number of levels from root to deepest leaf)."""

        def _depth(node: TreeNode) -> int:
            if not node.children:
                return 1
            return 1 + max(_depth(c) for c in node.children)

        if not self.roots:
            return 0
        return max(_depth(r) for r in self.roots)


# Status styles for tree rendering
_STATUS_STYLES: dict[HealthStatus, tuple[str, str]] = {
    HealthStatus.HEALTHY: ("✓", "green"),
    HealthStatus.OUTDATED: ("↑", "yellow"),
    HealthStatus.VULNERABLE: ("!", "red bold"),
    HealthStatus.UNMAINTAINED: ("⚠", "yellow"),
    HealthStatus.YANKED: ("✗", "red"),
    HealthStatus.REMOVED: ("✗", "red"),
    HealthStatus.UNKNOWN: ("?", "dim"),
}


def resolve_dependency_tree(
    project_path: str | Path,
    max_depth: int = 3,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list[Any] | None = None,
    denied_licenses: list[str] | None = None,
) -> DependencyTreeResult:
    """Resolve the full dependency tree for a Python project.

    Args:
        project_path: Path to the project directory.
        max_depth: Maximum depth to resolve (prevents infinite recursion).
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: Allowed license categories.
        denied_licenses: Denied SPDX license IDs.

    Returns:
        DependencyTreeResult with the resolved tree and metadata.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return DependencyTreeResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Discover top-level dependencies
    dependencies, files_scanned = discover_dependencies(project_path)

    if not dependencies:
        return DependencyTreeResult(
            project_path=str(project_path),
            files_scanned=files_scanned,
            errors=["No dependencies found in the project."],
        )

    result = DependencyTreeResult(
        project_path=str(project_path),
        files_scanned=files_scanned,
    )

    # Resolve the tree
    total_resolved = 0
    total_skipped = 0

    with PyPIClient() as pypi_client, OSVClient() as osv_client:
        for dep in dependencies:
            try:
                tree_node = _resolve_node(
                    name=dep.name,
                    version=dep.version,
                    specifier=dep.specifier,
                    pypi_client=pypi_client,
                    osv_client=osv_client,
                    depth=0,
                    max_depth=max_depth,
                    parent_chain=frozenset(),
                    result=result,
                    check_vulnerabilities=check_vulnerabilities,
                    check_licenses=check_licenses,
                    allowed_license_categories=allowed_license_categories,
                    denied_licenses=denied_licenses,
                )
                if tree_node is not None:
                    result.roots.append(tree_node)
                    total_resolved += 1
            except Exception as exc:
                result.errors.append(f"Failed to resolve {dep.name}: {exc}")
                # Still add a stub node
                result.roots.append(
                    TreeNode(name=dep.name, version=dep.version, status=HealthStatus.UNKNOWN)
                )
                total_skipped += 1

    result.stats = {
        "total_packages": total_resolved,
        "skipped": total_skipped,
        "circular_deps_found": len(result.circular_deps),
        "max_depth_reached": (
        max(n.depth for n in _flatten_tree(result.roots)) if result.roots else 0
    ),
    }

    return result


def _resolve_node(
    name: str,
    version: str | None,
    specifier: str | None,
    pypi_client: PyPIClient,
    osv_client: OSVClient,
    depth: int,
    max_depth: int,
    parent_chain: frozenset[str],
    result: DependencyTreeResult,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list[Any] | None = None,
    denied_licenses: list[str] | None = None,
) -> TreeNode | None:
    """Recursively resolve a single dependency node and its children.

    Args:
        name: Package name.
        version: Known version (from requirements.txt).
        specifier: Version specifier.
        pypi_client: PyPI API client.
        osv_client: OSV API client.
        depth: Current depth in the tree.
        max_depth: Maximum resolution depth.
        parent_chain: Set of ancestor package names (for cycle detection).
        result: Tree result to record circular deps.
        check_vulnerabilities: Whether to check vulnerabilities.
        check_licenses: Whether to check licenses.
        allowed_license_categories: Allowed license categories.
        denied_licenses: Denied SPDX IDs.

    Returns:
        A TreeNode, or None if the package couldn't be found.
    """
    # Circular dependency detection
    if name in parent_chain:
        cycle_path = sorted(parent_chain | {name})
        if cycle_path not in [sorted(c) for c in result.circular_deps]:
            result.circular_deps.append(list(parent_chain | {name}))
        return TreeNode(
            name=name,
            version=version,
            status=HealthStatus.UNKNOWN,
            depth=depth,
            parent_chain=parent_chain | {name},
        )

    # Fetch package info from PyPI
    info = pypi_client.get_package_info(name)
    if info is None:
        return TreeNode(
            name=name,
            version=version or "unknown",
            status=HealthStatus.REMOVED,
            depth=depth,
            parent_chain=parent_chain | {name},
        )

    # Resolve version
    from depcheck.models import ParsedDependency

    dep = ParsedDependency(name=name, version=version, specifier=specifier)
    resolved_version = pypi_client.resolve_version(dep, info)

    # Check health status
    report = check_package_health(
        dep,
        pypi_client,
        osv_client,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
        allowed_license_categories=allowed_license_categories,
        denied_licenses=denied_licenses,
    )

    # Build the node
    node = TreeNode(
        name=name,
        version=resolved_version or version,
        status=report.status,
        depth=depth,
        parent_chain=parent_chain | {name},
    )

    # Extract license info
    if report.license_info:
        node.license_id = report.license_info.spdx_id
        node.license_category = report.license_info.category
        node.is_compliant = report.license_info.is_compliant

    # Resolve children if not at max depth
    if depth < max_depth:
        requires_dist = info.get("info", {}).get("requires_dist", []) or []
        child_deps = _parse_requires_dist(requires_dist)

        new_chain = parent_chain | {name}
        for child_name, child_spec in child_deps:
            try:
                child_node = _resolve_node(
                    name=child_name,
                    version=None,
                    specifier=child_spec,
                    pypi_client=pypi_client,
                    osv_client=osv_client,
                    depth=depth + 1,
                    max_depth=max_depth,
                    parent_chain=new_chain,
                    result=result,
                    check_vulnerabilities=False,  # Only check vulns at top level for speed
                    check_licenses=False,
                )
                if child_node is not None:
                    node.children.append(child_node)
            except Exception:
                # Silently skip children that can't be resolved
                pass

    return node


def _parse_requires_dist(requires_dist: list[str]) -> list[tuple[str, str | None]]:
    """Parse Python package requires_dist into (name, specifier) pairs.

    Handles:
    - Simple requirements: "requests"
    - Version specifiers: "requests>=2.28"
    - Extras markers: "requests[security]>=2.28"
    - Environment markers: 'pywin32; sys_platform == "win32"' (skipped)
    - Extra requirements: 'requests[security]; extra == "security"' (skipped unless base)

    Args:
        requires_dist: List of requirement strings from PyPI metadata.

    Returns:
        List of (normalized_name, version_specifier) tuples.
    """
    import re

    from depcheck.scanner import normalize_package_name

    dependencies: list[tuple[str, str | None]] = []

    for req_str in requires_dist:
        req_str = req_str.strip()
        if not req_str:
            continue

        # Skip requirements with environment markers (conditional deps)
        # e.g., 'pywin32; sys_platform == "win32"'
        # e.g., 'requests[security]; extra == "security"'
        if ";" in req_str:
            _, marker = req_str.split(";", 1)
            marker = marker.strip().lower()
            # Skip platform-specific, python-version-specific, and extra deps
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

        # Extract package name and specifier
        # Match: name[extras]specifier
        match = re.match(
            r"^(?P<name>[a-zA-Z0-9][a-zA-Z0-9._-]*)"
            r"(\[(?P<extras>[^\]]+)\])?"
            r"(?P<specifier>[><=!~].+)?$",
            req_str,
        )
        if not match:
            continue

        name = normalize_package_name(match.group("name"))
        specifier = match.group("specifier")
        if specifier:
            specifier = specifier.strip()

        dependencies.append((name, specifier))

    return dependencies


def _flatten_tree(nodes: list[TreeNode]) -> list[TreeNode]:
    """Flatten a tree into a list of all nodes."""

    def _walk(nodes: list[TreeNode], acc: list[TreeNode]) -> None:
        for node in nodes:
            acc.append(node)
            _walk(node.children, acc)

    result: list[TreeNode] = []
    _walk(nodes, result)
    return result


def render_tree(
    result: DependencyTreeResult,
    max_depth: int | None = None,
    highlight_issues: bool = True,
    console: Console | None = None,
) -> None:
    """Render the dependency tree using Rich.

    Args:
        result: The dependency tree result.
        max_depth: Maximum depth to display (None for all).
        highlight_issues: Whether to color-code health issues.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    if result.errors and not result.roots:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    console.print()
    console.print(f"[bold]depcheck tree[/bold] — Dependency Tree for {result.project_path}")
    console.print()

    for root_node in result.roots:
        _render_node(
            root_node,
            console=console,
            highlight_issues=highlight_issues,
            max_depth=max_depth,
        )

    # Summary
    console.print()
    all_nodes = _flatten_tree(result.roots)
    unique_names = {n.name for n in all_nodes}

    summary_parts: list[str] = []
    summary_parts.append(f"[bold]Total:[/bold] {len(unique_names)} unique packages")

    status_counts: dict[HealthStatus, int] = {}
    for node in all_nodes:
        # Count each unique package only once
        if node.name not in {n.name for n in all_nodes[: all_nodes.index(node)]}:
            status_counts[node.status] = status_counts.get(node.status, 0) + 1

    for status, count in sorted(status_counts.items(), key=lambda x: x[0].value):
        icon, color = _STATUS_STYLES.get(status, ("?", "white"))
        if count > 0:
            summary_parts.append(f"[{color}]{icon} {status.value}: {count}[/{color}]")

    if result.circular_deps:
        summary_parts.append(f"[red]🔄 Circular deps: {len(result.circular_deps)}[/red]")

    if result.stats:
            depth_val = result.stats.get("max_depth_reached", 0)
            summary_parts.append(
                f"[dim]Max depth resolved: {depth_val}[/dim]"
            )

    from rich.panel import Panel

    console.print(Panel("\n".join(summary_parts), title="Tree Summary", border_style="blue"))
    console.print()


def _render_node(
    node: TreeNode,
    console: Console,
    tree: Tree | None = None,
    highlight_issues: bool = True,
    max_depth: int | None = None,
    depth: int = 0,
) -> None:
    """Render a single tree node and its children.

    Args:
        node: The tree node to render.
        console: Rich console.
        tree: Parent Rich Tree object (None for root nodes).
        highlight_issues: Whether to color-code issues.
        max_depth: Maximum display depth.
        depth: Current display depth.
    """
    if max_depth is not None and depth > max_depth:
        return

    icon, color = _STATUS_STYLES.get(node.status, ("?", "dim"))

    # Build label
    version_str = f" [dim]{node.version}[/dim]" if node.version else ""
    status_str = f" [{color}]{icon}[/{color}]" if highlight_issues else ""
    license_str = ""
    if node.license_id and highlight_issues:
        lic_color = "green" if node.is_compliant else "red"
        license_str = f" [{lic_color}]⚖ {node.license_id}[/{lic_color}]"

    circular_str = " [red bold]↻ circular[/red bold]" if node.is_circular else ""

    label = f"{status_str} {node.name}{version_str}{license_str}{circular_str}"

    if tree is None:
        parent = Tree(label)
    else:
        parent = tree.add(label)

    # Render children
    for child in node.children:
        _render_node(
            child,
            console=console,
            tree=parent,
            highlight_issues=highlight_issues,
            max_depth=max_depth,
            depth=depth + 1,
        )

    # If this is a root node, print the tree
    if tree is None:
        console.print(parent)


def render_tree_json(result: DependencyTreeResult, console: Console | None = None) -> None:
    """Render the dependency tree as JSON.

    Args:
        result: The dependency tree result.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    data = result.to_dict()
    json_str = json.dumps(data, indent=2)
    # Use no_color to ensure clean JSON output without ANSI escape codes
    clean_console = Console(
        file=console.file,
        force_terminal=False,
        no_color=True,
        legacy_windows=False,
    )
    clean_console.print(json_str)
