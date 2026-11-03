"""Suggest healthier alternative dependencies."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="suggest")
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
    help="Output suggestions as JSON.",
)
@click.option(
    "--policy",
    type=click.Choice(["relaxed", "standard", "strict"]),
    default="standard",
    help="Health policy threshold for recommendations (default: standard).",
)
@click.option(
    "--min-score",
    type=int,
    default=0,
    help="Minimum recommendation score (0-100) to include.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    path: str,
    output_json: bool,
    policy: str,
    min_score: int,
    quiet: bool,
) -> None:
    """Suggest healthier alternative dependencies.

    Analyzes your project dependencies and recommends alternatives based on
    maintenance health, popularity, and compatibility.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck suggest
    depcheck suggest /path/to/project --policy strict
    depcheck suggest . --json > suggestions.json
    depcheck suggest . --min-score 60
    """
    from depcheck.suggest import render_suggest_json, render_suggest_table, suggest_alternatives

    console = Console(quiet=quiet)
    result = suggest_alternatives(
        project_path=path,
    )

    if output_json:
        jsonout.write_text(render_suggest_json(result))
    elif not quiet:
        render_suggest_table(result, console=console)

    if result.errors:
        sys.exit(2)
