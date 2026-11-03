"""Analyze dependency isolation boundaries."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="isolate")
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
    help="Output isolation report as JSON.",
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
    """Analyze which dependencies can be safely removed.

    Scans your project's source code for import statements and
    cross-references them with declared dependencies to find packages
    that are unused, transitive-only, or safely removable.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck isolate
    depcheck isolate --json
    depcheck isolate /path/to/project
    """
    from pathlib import Path

    from depcheck.isolate import (
        analyze_isolation,
        render_isolation_json,
        render_isolation_table,
    )

    console = Console(quiet=quiet)

    report = analyze_isolation(project_path=Path(path))

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_isolation_json(report)
        jsonout.write_text(content)
    elif not quiet:
        render_isolation_table(report, console=console)
