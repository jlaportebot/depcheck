"""Build an interactive dependency graph."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="graph")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["ascii", "dot", "mermaid", "json"]),
    default="ascii",
    help="Output format for the dependency graph.",
)
@click.option(
    "--max-depth",
    type=int,
    default=4,
    help="Maximum depth for transitive dependency resolution.",
)
@click.option(
    "--subgraph",
    default=None,
    help="Extract subgraph rooted at this package name.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    path: str,
    fmt: str,
    max_depth: int,
    subgraph: str | None,
    quiet: bool,
) -> None:
    """Visualise the dependency graph.

    Builds and analyses the full dependency graph, detecting cycles,
    diamond dependencies, and computing centrality metrics. Supports
    multiple output formats for integration with visualisation tools.

    PATH is the project directory to analyse (defaults to current directory).

    Examples:

    \b
    depcheck graph
    depcheck graph --format dot > deps.dot
    depcheck graph --format mermaid > deps.mmd
    depcheck graph --subgraph requests
    depcheck graph --max-depth 2 --format json
    """
    from depcheck.graph import (
        GraphFormat,
        build_dependency_graph,
        extract_subgraph,
        render_graph,
    )

    console = Console(quiet=quiet)

    full_graph = build_dependency_graph(
        project_path=path,
        max_depth=max_depth,
    )

    if full_graph.errors and not full_graph.nodes:
        for error in full_graph.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Extract subgraph if requested
    target_graph = full_graph
    if subgraph:
        target_graph = extract_subgraph(full_graph, root=subgraph, max_depth=max_depth)
        if target_graph.errors:
            for error in target_graph.errors:
                console.print(f"[red]Error:[/red] {error}")
            sys.exit(2)

    fmt_map = {
        "ascii": GraphFormat.ASCII,
        "dot": GraphFormat.DOT,
        "mermaid": GraphFormat.MERMAID,
        "json": GraphFormat.JSON,
    }
    graph_fmt = fmt_map.get(fmt, GraphFormat.ASCII)

    if not quiet:
        render_graph(target_graph, fmt=graph_fmt, console=console)

    if len(full_graph.cycles) > 0:
        if not quiet and graph_fmt == GraphFormat.JSON:
            pass  # Cycles shown in JSON output
        elif not quiet:
            console.print(
                f"\n[yellow]⚠ {len(full_graph.cycles)} dependency cycle(s) detected[/yellow]"
            )
