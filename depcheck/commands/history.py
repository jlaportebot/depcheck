"""Report dependency changes across git history."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="history")
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
    help="Output history report as JSON.",
)
@click.option(
    "--max-versions",
    type=int,
    default=20,
    help="Maximum historical versions to retrieve per package (default: 20).",
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
    max_versions: int,
    quiet: bool,
) -> None:
    """Analyze the release history and maintenance trends of dependencies.

    Shows version timelines, release cadence, maintenance trends
    (accelerating, steady, slowing, abandoned), and version age for
    each dependency.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck history
    depcheck history --json
    depcheck history --max-versions 10
    depcheck history /path/to/project
    """
    from depcheck.history import analyze_history, render_history_json, render_history_table

    console = Console(quiet=quiet)

    report = analyze_history(
        project_path=path,
        max_versions=max_versions,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_history_json(report)
    elif not quiet:
        render_history_table(report, console=console)
