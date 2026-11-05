"""Tech stack analysis and conflict detection for depcheck.

Wraps depcheck.stack.run_stack and provides CLI access with table/JSON output.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.stack import render_stack_table, run_stack


@click.command(name="stack")
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
    help="Output results as JSON.",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Check license chain compatibility across dependencies.",
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
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Analyze the technology stack of a Python project.

    Detects frameworks, databases, ORMs, and other categories.
    Identifies conflicts, version incompatibilities, and license issues.

    PATH is the project directory to scan (defaults to current directory).
    """
    console = Console(quiet=quiet)

    # Run stack analysis
    result = run_stack(
        project_path=path,
        check_licenses=check_licenses,
    )

    if result.errors and not result.components:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        if output_json:
            jsonout.write_text(jsonout.to_json(result.to_dict()))
        sys.exit(2)

    # Render output
    if output_json:
        jsonout.write_text(jsonout.to_json(result.to_dict()))
    elif not quiet:
        render_stack_table(result, console=console)

    sys.exit(0)
