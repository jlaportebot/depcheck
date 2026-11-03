"""Score dependencies by install footprint."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="sizescore")
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
    help="Output size score report as JSON.",
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
    quiet: bool,
) -> None:
    """Analyze dependency sizes and bloat.

    Checks download/install sizes of your dependencies, detects
    size trends (bloat vs. lean), suggests lighter alternatives
    for heavy packages, and computes a size efficiency score.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck sizescore
    depcheck sizescore --json
    depcheck sizescore /path/to/project
    """
    from depcheck.sizescore import (
        build_size_report,
        render_size_json,
        render_size_table,
    )

    console = Console(quiet=quiet)

    report = build_size_report(project_path=path)

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_size_json(report)
        jsonout.write_text(content)
    elif not quiet:
        render_size_table(report, console=console)
