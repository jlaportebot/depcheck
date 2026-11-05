"""Deprecation and release prediction for depcheck.

Wraps depcheck.predict.run_predict and provides CLI access with table/JSON output.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.predict import render_predict_table, run_predict


@click.command(name="predict")
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
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
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
    no_vuln_check: bool,
    quiet: bool,
) -> None:
    """Predict deprecation timelines and release schedules for dependencies.

    PATH is the project directory to scan (defaults to current directory).
    """
    console = Console(quiet=quiet)

    # Run prediction
    result = run_predict(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        if output_json:
            jsonout.write_text(jsonout.to_json(result.to_dict()))
        sys.exit(2)

    # Render output
    if output_json:
        jsonout.write_text(jsonout.to_json(result.to_dict()))
    elif not quiet:
        render_predict_table(result, console=console)

    sys.exit(0)
