"""Dependency graph visualization for depcheck.

Builds and analyzes the full dependency graph, detecting cycles,
computing centrality metrics, finding diamond dependencies, and
rendering the graph in multiple formats (ASCII, DOT/Graphviz, Mermaid,
JSON). Supports interactive exploration with path finding and
subgraph extraction.
"""

from __future__ import annotations

import enum
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from depcheck.models import HealthStatus
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies

# ─── Package Name Regex ────────────────────────────────────────────────────

_PKG_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)")


# ─── Data Models ───────────────────────────────────────────────────────────


class GraphFormat(enum.Enum):
    """Output format for the dependency graph."""

    ASCII = "ascii"
    DOT = "dot"
    MERMAID = "mermaid"
    JSON = "json"


@dataclass
class GraphNode:
    """A node in the dependency graph."""

    name: str
    version: str | None = None
    is_direct: bool = False
    is_dev: bool = False
    is_optional: bool = False
    health_status: HealthStatus = HealthStatus.UNKNOWN
    depth: int = 0

    @property
    def label(self) -> str:
        """Display label for the node."""
        if self.version:
            return f"{self.name}=={self.version}"
        return self.name

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "is_optional": self.is_optional,
            "health_status": self.health_status.value,
            "depth": self.depth,
        }


@dataclass
class GraphEdge:
    """An edge in the dependency graph."""

    source: str
    target: str
    label: str = ""  # Version specifier, e.g., ">=2.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
        }


@dataclass
class CycleInfo:
    """Information about a dependency cycle."""

    nodes: list[str]
    length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": self.nodes,
            "length": self.length,
        }


@dataclass
class DiamondDependency:
    """A diamond dependency (same package required via different paths)."""

    package: str
    paths: list[list[str]]
    version_conflict: bool = False
    conflicting_versions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "paths": self.paths,
            "version_conflict": self.version_conflict,
            "conflicting_versions": self.conflicting_versions,
        }


@dataclass
class CentralityMetrics:
    """Centrality metrics for a node."""

    name: str
    in_degree: int = 0  # How many packages depend on this
    out_degree: int = 0  # How many packages this depends on
    betweenness: float = 0.0  # Approximate betweenness centrality
    is_bottleneck: bool = False  # High betweenness + high in-degree

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "betweenness": round(self.betweenness, 4),
            "is_bottleneck": self.is_bottleneck,
        }


@dataclass
class DependencyGraph:
    """Complete dependency graph for a project."""

    project_path: str
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    adjacency: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    reverse_adjacency: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    cycles: list[CycleInfo] = field(default_factory=list)
    diamonds: list[DiamondDependency] = field(default_factory=list)
    centrality: list[CentralityMetrics] = field(default_factory=list)
    direct_packages: list[str] = field(default_factory=list)
    max_depth: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "adjacency": dict(self.adjacency),
            "reverse_adjacency": dict(self.reverse_adjacency),
            "cycles": [c.to_dict() for c in self.cycles],
            "diamonds": [d.to_dict() for d in self.diamonds],
            "centrality": [c.to_dict() for c in self.centrality],
            "direct_packages": self.direct_packages,
            "max_depth": self.max_depth,
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "errors": self.errors,
        }


# ─── Graph Building ────────────────────────────────────────────────────────


def _resolve_sub_dependencies(pkg_name: str, pypi_client: PyPIClient) -> list[tuple[str, str]]:
    """Resolve the sub-dependencies of a package via PyPI.

    Returns:
        List of (dep_name, version_specifier) tuples.
    """
    info = pypi_client.get_package_info(pkg_name)
    if info is None:
        return []

    requires_dist = info.get("info", {}).get("requires_dist", []) or []
    deps: list[tuple[str, str]] = []

    for req_str in requires_dist:
        # Skip extras-only dependencies (conditional)
        if ";" in req_str and "extra" in req_str:
            continue

        match = _PKG_RE.match(req_str.strip())
        if match:
            dep_name = match.group(1).lower().replace("_", "-")
            dep_name = re.sub(r"[-_.]+", "-", dep_name)
            # Extract version specifier
            specifier = req_str.strip()[len(match.group(1)) :]
            # Clean up extras notation
            if specifier.startswith("["):
                bracket_end = specifier.find("]")
                if bracket_end != -1:
                    specifier = specifier[bracket_end + 1 :].strip()
            deps.append((dep_name, specifier.strip()))

    return deps


def build_dependency_graph(
    project_path: str | Path,
    max_depth: int = 4,
    check_vulnerabilities: bool = False,
) -> DependencyGraph:
    """Build the full dependency graph for a project.

    Args:
        project_path: Path to the project directory.
        max_depth: Maximum resolution depth.
        check_vulnerabilities: Whether to check vulnerability status.

    Returns:
        A DependencyGraph with all nodes, edges, and analysis.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return DependencyGraph(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    graph = DependencyGraph(project_path=str(project_path))

    # Discover direct dependencies
    direct_deps, _ = discover_dependencies(project_path)
    direct_names: set[str] = set()

    for dep in direct_deps:
        node = GraphNode(
            name=dep.name,
            version=dep.version,
            is_direct=True,
            depth=0,
        )
        graph.nodes[dep.name] = node
        graph.direct_packages.append(dep.name)
        direct_names.add(dep.name)

    if not direct_deps:
        graph.errors.append("No dependencies found in the project.")
        return graph

    # Resolve the full graph via BFS
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    for dep in direct_deps:
        queue.append((dep.name, 0))

    with PyPIClient() as client:
        while queue:
            pkg_name, depth = queue.popleft()

            if pkg_name in visited or depth >= max_depth:
                continue
            visited.add(pkg_name)

            # Resolve sub-dependencies
            sub_deps = _resolve_sub_dependencies(pkg_name, client)

            for dep_name, specifier in sub_deps:
                # Add edge
                edge = GraphEdge(source=pkg_name, target=dep_name, label=specifier)
                graph.edges.append(edge)
                graph.adjacency[pkg_name].append(dep_name)
                graph.reverse_adjacency[dep_name].append(pkg_name)

                # Add node if not present
                if dep_name not in graph.nodes:
                    node = GraphNode(
                        name=dep_name,
                        is_direct=dep_name in direct_names,
                        depth=depth + 1,
                    )
                    graph.nodes[dep_name] = node
                    if depth + 1 > graph.max_depth:
                        graph.max_depth = depth + 1

                # Enqueue for further resolution
                if dep_name not in visited:
                    queue.append((dep_name, depth + 1))

    graph.total_nodes = len(graph.nodes)
    graph.total_edges = len(graph.edges)

    # Run graph analyses
    graph.cycles = _detect_cycles(graph)
    graph.diamonds = _detect_diamonds(graph)
    graph.centrality = _compute_centrality(graph)

    return graph


# ─── Graph Analysis ────────────────────────────────────────────────────────


def _detect_cycles(graph: DependencyGraph) -> list[CycleInfo]:
    """Detect all dependency cycles using DFS.

    Returns cycles as lists of node names forming the cycle.
    """
    cycles: list[CycleInfo] = []
    visited: set[str] = set()
    rec_stack: list[str] = []

    def dfs(node: str) -> None:
        if node in visited:
            return
        visited.add(node)
        rec_stack.append(node)

        for neighbor in graph.adjacency.get(node, []):
            if neighbor in rec_stack:
                # Found a cycle
                cycle_start = rec_stack.index(neighbor)
                cycle_nodes = rec_stack[cycle_start:]
                cycles.append(
                    CycleInfo(
                        nodes=cycle_nodes,
                        length=len(cycle_nodes),
                    )
                )
            elif neighbor not in visited:
                dfs(neighbor)

        rec_stack.pop()

    for node_name in graph.nodes:
        if node_name not in visited:
            dfs(node_name)

    return cycles


def _detect_diamonds(graph: DependencyGraph) -> list[DiamondDependency]:
    """Detect diamond dependencies.

    A diamond dependency occurs when the same package is reachable
    via multiple paths from a root node.
    """
    diamonds: list[DiamondDependency] = []
    checked: set[str] = set()

    # For each node with in-degree >= 2, find all paths from direct deps
    for node_name in graph.nodes:
        if node_name in checked:
            continue
        checked.add(node_name)

        in_degree = len(graph.reverse_adjacency.get(node_name, []))
        if in_degree < 2:
            continue

        # Find all paths from direct dependencies to this node
        paths = _find_all_paths_to(graph, node_name, max_paths=5)

        if len(paths) >= 2:
            # Check for version conflicts
            version_specs: set[str] = set()
            for path in paths:
                # The last edge in each path has the version specifier
                for edge in graph.edges:
                    if edge.target == node_name and edge.source in path:
                        if edge.label:
                            version_specs.add(edge.label)

            diamonds.append(
                DiamondDependency(
                    package=node_name,
                    paths=paths[:5],  # Limit to 5 paths
                    version_conflict=len(version_specs) > 1,
                    conflicting_versions=list(version_specs),
                )
            )

    return diamonds


def _find_all_paths_to(graph: DependencyGraph, target: str, max_paths: int = 5) -> list[list[str]]:
    """Find all paths from direct dependencies to a target node.

    Uses BFS to find paths, limited to max_paths.
    """
    paths: list[list[str]] = []
    queue: deque[list[str]] = deque()

    # Start from each direct dependency
    for direct in graph.direct_packages:
        queue.append([direct])

    while queue and len(paths) < max_paths:
        path = queue.popleft()
        current = path[-1]

        if current == target and len(path) > 1:
            paths.append(path)
            continue

        for neighbor in graph.adjacency.get(current, []):
            if neighbor not in path:  # Avoid cycles in paths
                queue.append(path + [neighbor])

    return paths


def _compute_centrality(graph: DependencyGraph) -> list[CentralityMetrics]:
    """Compute centrality metrics for all nodes.

    Uses in-degree and out-degree, plus approximate betweenness
    centrality based on shortest path counts.
    """
    metrics: list[CentralityMetrics] = []

    # Compute degrees
    for node_name in graph.nodes:
        in_deg = len(graph.reverse_adjacency.get(node_name, []))
        out_deg = len(graph.adjacency.get(node_name, []))
        metrics.append(
            CentralityMetrics(
                name=node_name,
                in_degree=in_deg,
                out_degree=out_deg,
            )
        )

    # Approximate betweenness using sampling (BFS from each direct dep)
    betweenness: dict[str, float] = defaultdict(float)
    for source in graph.direct_packages:
        # BFS to find shortest paths
        dist: dict[str, int] = {source: 0}
        pred: dict[str, list[str]] = defaultdict(list)
        sigma: dict[str, int] = defaultdict(int)
        sigma[source] = 1

        queue_bfs: deque[str] = deque([source])
        while queue_bfs:
            v = queue_bfs.popleft()
            for w in graph.adjacency.get(v, []):
                if w not in dist:
                    dist[w] = dist[v] + 1
                    queue_bfs.append(w)
                if dist.get(w) == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        # Accumulate betweenness
        delta: dict[str, float] = defaultdict(float)
        # Process in reverse BFS order
        sorted_nodes = sorted(dist.keys(), key=lambda x: dist.get(x, 0), reverse=True)
        for w in sorted_nodes:
            for v in pred.get(w, []):
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != source:
                betweenness[w] += delta[w]

    # Normalize betweenness
    n = len(graph.nodes)
    if n > 2:
        norm_factor = (n - 1) * (n - 2)  # For directed graph
        for m in metrics:
            m.betweenness = betweenness.get(m.name, 0) / max(norm_factor, 1)
            # A bottleneck is a node with high betweenness and high in-degree
            m.is_bottleneck = m.betweenness > 0.1 and m.in_degree >= 3

    # Sort by betweenness descending
    metrics.sort(key=lambda m: m.betweenness, reverse=True)
    return metrics


# ─── Path Finding ──────────────────────────────────────────────────────────


def find_shortest_path(graph: DependencyGraph, source: str, target: str) -> list[str] | None:
    """Find the shortest path between two nodes in the graph.

    Args:
        graph: The dependency graph.
        source: Source node name.
        target: Target node name.

    Returns:
        List of node names forming the shortest path, or None.
    """
    if source not in graph.nodes or target not in graph.nodes:
        return None

    # BFS from source
    visited: set[str] = {source}
    pred: dict[str, str] = {}
    queue: deque[str] = deque([source])

    while queue:
        current = queue.popleft()
        if current == target:
            # Reconstruct path
            path = [target]
            while path[-1] in pred:
                path.append(pred[path[-1]])
            path.reverse()
            return path

        for neighbor in graph.adjacency.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                pred[neighbor] = current
                queue.append(neighbor)

    return None


def extract_subgraph(graph: DependencyGraph, root: str, max_depth: int = 3) -> DependencyGraph:
    """Extract a subgraph rooted at a specific node.

    Args:
        graph: The full dependency graph.
        root: Root node for the subgraph.
        max_depth: Maximum depth to include.

    Returns:
        A new DependencyGraph containing only the subgraph.
    """
    subgraph = DependencyGraph(project_path=graph.project_path)

    if root not in graph.nodes:
        subgraph.errors.append(f"Node not found: {root}")
        return subgraph

    # BFS from root
    visited: set[str] = {root}
    queue: deque[tuple[str, int]] = deque([(root, 0)])

    while queue:
        node_name, depth = queue.popleft()

        # Add node
        if node_name in graph.nodes:
            subgraph.nodes[node_name] = graph.nodes[node_name]

        if depth >= max_depth:
            continue

        for neighbor in graph.adjacency.get(node_name, []):
            # Add edge
            for edge in graph.edges:
                if edge.source == node_name and edge.target == neighbor:
                    subgraph.edges.append(edge)
                    subgraph.adjacency[node_name].append(neighbor)
                    subgraph.reverse_adjacency[neighbor].append(node_name)
                    break

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))

    subgraph.total_nodes = len(subgraph.nodes)
    subgraph.total_edges = len(subgraph.edges)
    subgraph.max_depth = max_depth
    subgraph.direct_packages = [root]

    return subgraph


# ─── Rendering ─────────────────────────────────────────────────────────────


def render_graph_ascii(graph: DependencyGraph, console: Console | None = None) -> None:
    """Render the dependency graph as an ASCII tree."""
    if console is None:
        console = Console()

    console.print(f"\n[bold]Dependency Graph: {graph.project_path}[/bold]\n")

    # Build tree from direct dependencies
    for direct_name in graph.direct_packages:
        if direct_name not in graph.nodes:
            continue

        node = graph.nodes[direct_name]
        status_icon = _health_icon(node.health_status)
        root_label = f"{status_icon} {node.label}"

        tree = Tree(root_label)
        _build_tree_recursive(graph, direct_name, tree, visited=set(), depth=0, max_depth=6)
        console.print(tree)

    # Print analysis summary
    console.print("\n[bold]Graph Analysis:[/bold]")
    console.print(f"  Nodes: {graph.total_nodes}")
    console.print(f"  Edges: {graph.total_edges}")
    console.print(f"  Max depth: {graph.max_depth}")
    console.print(f"  Cycles: {len(graph.cycles)}")
    console.print(f"  Diamond dependencies: {len(graph.diamonds)}")

    if graph.cycles:
        console.print("\n[red]⚠ Dependency cycles detected:[/red]")
        for cycle in graph.cycles:
            console.print(f"  ↻ {' → '.join(cycle.nodes)} → {cycle.nodes[0]}")

    if graph.diamonds:
        console.print("\n[yellow]⚠ Diamond dependencies detected:[/yellow]")
        for diamond in graph.diamonds[:5]:
            conflict = " [red](version conflict)[/red]" if diamond.version_conflict else ""
            console.print(
                f"  ◇ {diamond.package} reachable via {len(diamond.paths)} paths{conflict}"
            )


def _build_tree_recursive(
    graph: DependencyGraph,
    node_name: str,
    tree: Tree,
    visited: set[str],
    depth: int,
    max_depth: int,
) -> None:
    """Recursively build a Rich Tree from the graph."""
    if depth >= max_depth:
        return

    for neighbor in graph.adjacency.get(node_name, []):
        if neighbor in visited:
            # Circular reference
            tree.add(f"[dim]↻ {neighbor} (circular)[/dim]")
            continue

        if neighbor in graph.nodes:
            node = graph.nodes[neighbor]
            icon = _health_icon(node.health_status)
            label = f"{icon} {node.label}"
            branch = tree.add(label)
            visited.add(neighbor)
            _build_tree_recursive(graph, neighbor, branch, visited, depth + 1, max_depth)
            visited.discard(neighbor)
        else:
            tree.add(f"[dim]? {neighbor}[/dim]")


def _health_icon(status: HealthStatus) -> str:
    """Get an icon for a health status."""
    icons = {
        HealthStatus.HEALTHY: "[green]✓[/green]",
        HealthStatus.OUTDATED: "[yellow]↑[/yellow]",
        HealthStatus.VULNERABLE: "[red]![/red]",
        HealthStatus.UNMAINTAINED: "[yellow]⚠[/yellow]",
        HealthStatus.YANKED: "[red]✗[/red]",
        HealthStatus.REMOVED: "[red]✗[/red]",
        HealthStatus.UNKNOWN: "[dim]?[/dim]",
    }
    return icons.get(status, "[dim]?[/dim]")


def render_graph_dot(graph: DependencyGraph, console: Console | None = None) -> None:
    """Render the dependency graph in DOT/Graphviz format."""
    if console is None:
        console = Console(force_terminal=False, no_color=True)

    lines = [
        'digraph "dependency_graph" {',
        "  rankdir=LR;",
        '  node [shape=box, style=rounded, fontname="sans-serif"];',
        "",
    ]

    # Node definitions
    for name, node in graph.nodes.items():
        attrs: list[str] = [f'label="{node.label}"']

        if node.is_direct:
            attrs.append("shape=box")
            attrs.append("style=bold,rounded")
        else:
            attrs.append("shape=ellipse")

        # Color by health status
        color_map = {
            HealthStatus.HEALTHY: "green",
            HealthStatus.OUTDATED: "yellow",
            HealthStatus.VULNERABLE: "red",
            HealthStatus.UNMAINTAINED: "orange",
            HealthStatus.YANKED: "red",
            HealthStatus.REMOVED: "red",
        }
        color = color_map.get(node.health_status, "gray")
        attrs.append(f"color={color}")
        if node.health_status in (
            HealthStatus.VULNERABLE,
            HealthStatus.YANKED,
            HealthStatus.REMOVED,
        ):
            attrs.append("penwidth=2")

        safe_name = name.replace("-", "_").replace(".", "_")
        lines.append(f"  {safe_name} [{', '.join(attrs)}];")

    lines.append("")

    # Edge definitions
    for edge in graph.edges:
        safe_source = edge.source.replace("-", "_").replace(".", "_")
        safe_target = edge.target.replace("-", "_").replace(".", "_")
        attrs = []
        if edge.label:
            label = edge.label.replace('"', '\\"')
            attrs.append(f'label="{label}"')
        lines.append(f"  {safe_source} -> {safe_target} [{', '.join(attrs)}];")

    lines.append("}")
    console.print("\n".join(lines))


def render_graph_mermaid(graph: DependencyGraph, console: Console | None = None) -> None:
    """Render the dependency graph in Mermaid format."""
    if console is None:
        console = Console(force_terminal=False, no_color=True)

    lines = ["graph LR"]

    # Edges
    for edge in graph.edges:
        safe_source = edge.source.replace("-", "_").replace(".", "_")
        safe_target = edge.target.replace("-", "_").replace(".", "_")
        label = f"|{edge.label}|" if edge.label else ""
        lines.append(f"  {safe_source} -->{label} {safe_target}")

    # Node styles
    for name, node in graph.nodes.items():
        safe_name = name.replace("-", "_").replace(".", "_")
        if node.health_status == HealthStatus.VULNERABLE:
            lines.append(f"  style {safe_name} fill:#ff6b6b,stroke:#c0392b")
        elif node.health_status == HealthStatus.UNMAINTAINED:
            lines.append(f"  style {safe_name} fill:#f39c12,stroke:#d68910")
        elif node.health_status == HealthStatus.OUTDATED:
            lines.append(f"  style {safe_name} fill:#f1c40f,stroke:#d4ac0d")
        elif node.is_direct:
            lines.append(f"  style {safe_name} fill:#2ecc71,stroke:#27ae60")

    console.print("\n".join(lines))


def render_graph_json(graph: DependencyGraph, console: Console | None = None) -> None:
    """Render the dependency graph as JSON."""
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(json.dumps(graph.to_dict(), indent=2))


def render_centrality_table(graph: DependencyGraph, console: Console | None = None) -> None:
    """Render centrality metrics as a Rich table."""
    if console is None:
        console = Console()

    if not graph.centrality:
        return

    console.print("\n[bold]Centrality Analysis[/bold]\n")

    table = Table(title="Most Central Dependencies", show_lines=True)
    table.add_column("Package", style="bold")
    table.add_column("In-Degree", justify="right")
    table.add_column("Out-Degree", justify="right")
    table.add_column("Betweenness", justify="right")
    table.add_column("Bottleneck", justify="center")

    for metric in graph.centrality[:20]:  # Top 20
        bottleneck = "[red]⚠ YES[/red]" if metric.is_bottleneck else "—"
        table.add_row(
            metric.name,
            str(metric.in_degree),
            str(metric.out_degree),
            f"{metric.betweenness:.4f}",
            bottleneck,
        )

    console.print(table)


def render_graph(
    graph: DependencyGraph,
    fmt: GraphFormat = GraphFormat.ASCII,
    console: Console | None = None,
) -> None:
    """Render the dependency graph in the specified format.

    Args:
        graph: The dependency graph to render.
        fmt: Output format.
        console: Rich console for output.
    """
    renderers = {
        GraphFormat.ASCII: render_graph_ascii,
        GraphFormat.DOT: render_graph_dot,
        GraphFormat.MERMAID: render_graph_mermaid,
        GraphFormat.JSON: render_graph_json,
    }

    renderer = renderers.get(fmt, render_graph_ascii)
    renderer(graph, console=console)

    # Always show centrality for ASCII format
    if fmt == GraphFormat.ASCII:
        render_centrality_table(graph, console=console)
