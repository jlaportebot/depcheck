"""Assess dependency risk levels."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="risks")
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
    help="Output risk report as JSON.",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity to include in output.",
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
    severity_threshold: str,
    quiet: bool,
) -> None:
    """Assess multi-dimensional risk scores for dependencies.

    Evaluates each dependency across vulnerability, maintenance, age,
    popularity, and license risk dimensions. Produces a composite
    risk score and remediation priority list.

    PATH is the project directory to analyse (defaults to current directory).

    Examples:

    \b
    depcheck risks
    depcheck risks --severity-threshold high
    depcheck risks --json
    """
    from depcheck.risks import (
        RiskSeverity,
        assess_risks,
        render_risks_json,
        render_risks_table,
    )

    console = Console(quiet=quiet)

    severity_map = {
        "low": RiskSeverity.LOW,
        "medium": RiskSeverity.MEDIUM,
        "high": RiskSeverity.HIGH,
        "critical": RiskSeverity.CRITICAL,
    }
    threshold = severity_map.get(severity_threshold, RiskSeverity.MEDIUM)

    report = assess_risks(project_path=path, min_severity=threshold)

    if report.errors and not report.entries:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_risks_json(report)
    elif not quiet:
        render_risks_table(report, console=console)

    if report.critical_count > 0:
        if not quiet:
            console.print(f"[red]✗ {report.critical_count} critical-risk dependencies found[/red]")
        sys.exit(1)
