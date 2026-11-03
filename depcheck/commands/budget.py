"""Enforce dependency budgets."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="budget")
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
    help="Output budget report as JSON.",
)
@click.option(
    "--per-dep-limit",
    type=int,
    default=None,
    help="Maximum allowed dependencies per single dependency.",
)
@click.option(
    "--transitive-limit",
    type=int,
    default=None,
    help="Maximum allowed total transitive dependencies.",
)
@click.option(
    "--depth-limit",
    type=int,
    default=None,
    help="Maximum allowed dependency depth.",
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
    per_dep_limit: int | None,
    transitive_limit: int | None,
    depth_limit: int | None,
    quiet: bool,
) -> None:
    """Analyse dependency budget and cost metrics.

    Shows per-dependency transitive counts, depth, and estimated risk
    for every direct dependency. Use limits to fail CI when budgets
    are exceeded.

    PATH is the project directory to analyse (defaults to current directory).

    Examples:

    \b
    depcheck budget
    depcheck budget --per-dep-limit 20
    depcheck budget --transitive-limit 200 --depth-limit 5
    depcheck budget --json
    """
    from depcheck.budget import (
        BudgetConfig,
        check_budget,
        render_budget_json,
        render_budget_table,
    )

    console = Console(quiet=quiet)

    config = BudgetConfig(
        total=transitive_limit,
        direct=per_dep_limit,
        transitive=transitive_limit,
        dev=None,
        optional=None,
    )

    report = check_budget(project_path=path, config=config)

    if report.errors and not report.categories:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_budget_json(report)
    elif not quiet:
        render_budget_table(report, console=console)

    if not report.is_within_budget:
        if not quiet:
            console.print(
                f"[red]✗ Budget exceeded: {len(report.over_budget_categories)} "
                f"limit(s) violated[/red]"
            )
        sys.exit(1)
