"""Check Python version compatibility."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="compat")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--target",
    "target_python",
    default="3.12",
    help="Target Python version to check (default: 3.12).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output compatibility report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    path: str,
    target_python: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Check Python version compatibility of dependencies.

    Analyzes your project's dependencies for compatibility with a
    target Python version using PyPI metadata (Requires-Python and
    classifiers). Identifies packages that will break on upgrade
    and computes an upgrade readiness score.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck compat
    depcheck compat --target 3.13
    depcheck compat --target 3.11 --json
    depcheck compat /path/to/project
    """
    from depcheck.compat import (
        build_compat_report,
        render_compat_json,
        render_compat_table,
    )

    console = Console(quiet=quiet)

    report = build_compat_report(
        project_path=path,
        target_python=target_python,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_compat_json(report)
        jsonout.write_text(content)
    elif not quiet:
        render_compat_table(report, console=console)

    # Exit with error if any packages are incompatible
    if report.incompatible_count > 0:
        sys.exit(1)
