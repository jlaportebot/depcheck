"""Check a project against dependency best practices."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="check")
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
    help="Output health report as JSON.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance in the health check.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["critical", "high", "medium", "low", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if overall grade meets or falls below threshold.",
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
    check_licenses: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Run a comprehensive health check with overall score and grades.

    Combines vulnerability, freshness, license, maintenance, transitive
    depth, and outdated analysis into a single 0–100 health score with
    per-category letter grades (A–F).

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck check
    depcheck check --json
    depcheck check --fail-on high
    depcheck check /path/to/project
    """
    from depcheck.check import Grade, render_check_json, render_check_table, run_check

    console = Console(quiet=quiet)

    report = run_check(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if report.errors and not report.categories:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_check_json(report)
    elif not quiet:
        render_check_table(report, console=console)

    # Exit code based on grade threshold
    if fail_on:
        grade_order = {
            Grade.A: 0,
            Grade.B: 1,
            Grade.C: 2,
            Grade.D: 3,
            Grade.F: 4,
        }
        threshold_map = {
            "critical": Grade.F,
            "high": Grade.D,
            "medium": Grade.C,
            "low": Grade.B,
            "any": Grade.A,
        }
        threshold = threshold_map.get(fail_on.lower(), Grade.F)
        if grade_order.get(report.overall_grade, 4) >= grade_order.get(threshold, 4):
            if not quiet:
                console.print(
                    f"[red]✗ Health check failed: grade {report.overall_grade.value} "
                    f"meets or exceeds --fail-on {fail_on} threshold[/red]"
                )
            sys.exit(1)
