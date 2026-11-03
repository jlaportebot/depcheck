"""Track dependency drift across git history."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="depdrift")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--from-commit",
    "from_commit",
    default=None,
    help="Starting git commit (uses oldest if not set).",
)
@click.option(
    "--to-commit",
    "to_commit",
    default=None,
    help="Ending git commit (uses HEAD if not set).",
)
@click.option(
    "--max-commits",
    type=int,
    default=20,
    help="Max commits to scan for dependency changes (default: 20).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output drift report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    path: str,
    from_commit: str | None,
    to_commit: str | None,
    max_commits: int,
    output_json: bool,
    quiet: bool,
) -> None:
    """Track dependency drift over time via git history.

    Compares your project's dependency files across git commits to
    detect version drift, package additions/removals, and pin erosion.
    Computes drift velocity and identifies high-drift packages.

    PATH is the project directory (defaults to current directory).
    Must be a git repository.

    Examples:

    \b
    depcheck depdrift
    depcheck depdrift --json
    depcheck depdrift --from-commit abc123 --to-commit def456
    depcheck depdrift --max-commits 50
    """
    from depcheck.depdrift import (
        build_drift_report,
        render_drift_json,
        render_drift_table,
    )

    console = Console(quiet=quiet)

    report = build_drift_report(
        project_path=path,
        from_commit=from_commit,
        to_commit=to_commit,
        max_commits=max_commits,
    )

    if report.errors and not report.entries:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_drift_json(report)
        jsonout.write_text(content)
    elif not quiet:
        render_drift_table(report, console=console)
