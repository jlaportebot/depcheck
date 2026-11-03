"""Measure installed dependency sizes."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="size")
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
    help="Output size report as JSON.",
)
@click.option(
    "--top-n",
    type=int,
    default=20,
    help="Number of largest packages to highlight (default: 20).",
)
@click.option(
    "--no-top-files",
    is_flag=True,
    default=False,
    help="Don't show largest files per package.",
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
    top_n: int,
    no_top_files: bool,
    quiet: bool,
) -> None:
    """Analyze the installed size of each dependency.

    Measures the disk footprint of every dependency in your project by
    inspecting the local site-packages directory. Reports total bytes,
    file counts, and identifies the largest packages and files.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck size
    depcheck size --json
    depcheck size --top-n 10
    depcheck size --no-top-files
    depcheck size /path/to/project
    """
    from depcheck.size import analyze_sizes, render_size_json, render_size_table

    console = Console(quiet=quiet)

    report = analyze_sizes(
        project_path=path,
        top_n=top_n,
        include_top_files=not no_top_files,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_size_json(report)
    elif not quiet:
        render_size_table(report, console=console)
