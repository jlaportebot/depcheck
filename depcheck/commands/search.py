"""PyPI package search for depcheck.

Wraps depcheck.search.search_packages and search_by_category with CLI access.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.search import (
    render_search_table,
    search_by_category,
    search_packages,
)


@click.command(name="search")
@click.argument(
    "query",
    required=False,
    default=None,
)
@click.option(
    "--category",
    "category",
    default=None,
    help="Search by category: web, data, testing, cli, database, security, ml, devtools.",
)
@click.option(
    "--limit",
    "limit",
    type=int,
    default=10,
    help="Maximum number of results to return.",
)
@click.option(
    "--license",
    "license_filter",
    default=None,
    help="Filter by license category (permissive, copyleft, public_domain, proprietary).",
)
@click.option(
    "--python",
    "python_version",
    default=None,
    help="Filter by Python version compatibility (e.g., '3.11').",
)
@click.option(
    "--min-score",
    "min_score",
    type=float,
    default=0.0,
    help="Minimum health score (0-100) to include.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    query: str | None,
    category: str | None,
    limit: int,
    license_filter: str | None,
    python_version: str | None,
    min_score: float,
    output_json: bool,
    quiet: bool,
) -> None:
    """Search PyPI for packages by query or category.

    QUERY is the package name or keyword to search for.
    Use --category to browse popular packages in a category instead.
    """
    console = Console(quiet=quiet)

    if category:
        if query:
            console.print("[red]Error:[/red] Cannot use both QUERY and --category")
            sys.exit(2)
        results = search_by_category(
            category=category,
            limit=limit,
            min_score=min_score,
        )
    else:
        if not query:
            console.print("[red]Error:[/red] QUERY is required when not using --category")
            sys.exit(2)
        results = search_packages(
            query=query,
            limit=limit,
            license_filter=license_filter,
            python_version=python_version,
            min_score=min_score,
        )

    if results.errors and not results.results:
        for error in results.errors:
            console.print(f"[red]Error:[/red] {error}")
        if output_json:
            jsonout.write_text(jsonout.to_json(results.to_dict()))
        sys.exit(2)

    if output_json:
        jsonout.write_text(jsonout.to_json(results.to_dict()))
    elif not quiet:
        render_search_table(results, console=console)

    sys.exit(0)
