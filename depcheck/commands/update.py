"""Generate a prioritized dependency update plan."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.commands import _common


@click.command(name="update")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--pinned",
    is_flag=True,
    default=False,
    help="Treat all exact-version deps as pinned (affects strategy).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    path: str,
    pinned: bool,
    no_vuln_check: bool,
    quiet: bool,
) -> None:
    """Generate a safe, prioritized update plan for dependencies.

    Analyzes your project's dependencies and produces a step-by-step
    update plan ordered by priority (security fixes first, then
    major → minor → patch). Each step includes pip commands, risk
    assessment, and strategy recommendations.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck update
    depcheck update --json
    depcheck update --pinned
    depcheck update /path/to/project
    """
    from depcheck.update import (
        build_update_plan,
        render_update_plan_json,
        render_update_plan_table,
    )

    console = Console(quiet=quiet)

    result = _common.scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Determine pinned packages
    pinned_set: set[str] | None = None
    if pinned:
        pinned_set = {
            pkg.name
            for pkg in result.packages
            if pkg.installed_version and pkg.installed_version != "unknown"
        }

    plan = build_update_plan(result, pinned_packages=pinned_set)

    output_json = False  # update command doesn't have --json flag
    if output_json:
        content = render_update_plan_json(plan)
        jsonout.write_text(content)
    elif not quiet:
        render_update_plan_table(plan, console=console)
