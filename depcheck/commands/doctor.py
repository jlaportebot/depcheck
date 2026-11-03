"""Diagnose dependency tooling and CI setup."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="doctor")
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
    help="Output diagnostic report as JSON.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["critical", "warning", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if findings meet the severity threshold.",
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
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Diagnose dependency configuration and environment issues.

    Runs a comprehensive diagnostic on your project's dependency setup,
    checking for unpinned versions, missing lockfiles, venv issues,
    Python compatibility, import consistency, and formatting problems.

    PATH is the project directory to diagnose (defaults to current directory).

    Examples:

    \b
    depcheck doctor
    depcheck doctor --json
    depcheck doctor --fail-on critical
    depcheck doctor --fail-on warning
    depcheck doctor /path/to/project
    """
    from depcheck.doctor import Severity, render_doctor_json, render_doctor_table, run_doctor

    console = Console(quiet=quiet)

    report = run_doctor(project_path=path)

    if report.errors and not report.findings:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_doctor_json(report)
    elif not quiet:
        render_doctor_table(report, console=console)

    # Exit code based on fail-on
    if fail_on:
        severity_threshold = {
            "critical": Severity.CRITICAL,
            "warning": Severity.WARNING,
            "any": Severity.INFO,
        }
        threshold = severity_threshold.get(fail_on.lower(), Severity.CRITICAL)

        level_order = {
            Severity.INFO: 0,
            Severity.WARNING: 1,
            Severity.CRITICAL: 2,
        }
        _ = level_order.get(threshold, 2)

        if fail_on.lower() == "critical" and report.critical_count > 0:
            if not quiet:
                console.print(
                    f"[red]✗ Doctor found {report.critical_count} critical issue(s)[/red]"
                )
            sys.exit(1)
        elif fail_on.lower() == "warning" and (
            report.critical_count > 0 or report.warning_count > 0
        ):
            if not quiet:
                console.print(
                    f"[red]✗ Doctor found {report.critical_count} critical "
                    f"and {report.warning_count} warning(s)[/red]"
                )
            sys.exit(1)
        elif fail_on.lower() == "any" and not report.is_healthy:
            if not quiet:
                console.print(
                    f"[red]✗ Doctor found {report.critical_count} critical, "
                    f"{report.warning_count} warnings, "
                    f"{report.info_count} info[/red]"
                )
            sys.exit(1)
