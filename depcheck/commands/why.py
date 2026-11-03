"""Explain why a dependency is present."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="why")
@click.argument(
    "target_package",
)
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output the dependency chains as JSON.",
)
@click.option(
    "--max-depth",
    type=int,
    default=4,
    help="Maximum depth to resolve in the dependency graph (default: 4).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster graph resolution).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    target_package: str,
    path: str,
    output_json: bool,
    max_depth: int,
    no_vuln_check: bool,
    quiet: bool,
) -> None:
    """Trace why a package is in your dependency tree.

    Finds all dependency chains from your direct dependencies down to
    the target package, showing the exact path that pulls it in.
    Useful for understanding transitive dependencies, debugging bloat,
    or deciding if a deep dependency is worth the risk.

    TARGET_PACKAGE is the name of the package to trace.

    PATH is the project directory to scan (defaults to current directory).

    Examples:

    \b
    depcheck why requests
    depcheck why urllib3 .
    depcheck why setuptools /path/to/project
    depcheck why numpy --json
    depcheck why pillow --max-depth 6
    depcheck why certifi --no-vuln-check
    """
    from depcheck.why import render_why_json, render_why_table, resolve_why

    console = Console(quiet=quiet)

    result = resolve_why(
        project_path=path,
        target_package=target_package,
        max_depth=max_depth,
        check_vulnerabilities=not no_vuln_check,
    )

    if result.errors and not result.found:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_why_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        render_why_table(result, console=console)

    # Exit with code 1 if package not found
    if not result.found:
        sys.exit(1)
