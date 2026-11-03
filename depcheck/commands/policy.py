"""Evaluate a project against a dependency policy."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="policy")
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
    help="Output policy report as JSON.",
)
@click.option(
    "--no-vulns",
    is_flag=True,
    default=False,
    help="Skip vulnerability checks during policy evaluation.",
)
@click.option(
    "--no-licenses",
    is_flag=True,
    default=False,
    help="Skip license checks during policy evaluation.",
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
    no_vulns: bool,
    no_licenses: bool,
    quiet: bool,
) -> None:
    """Evaluate dependency policies and check compliance.

    Loads policy rules from [tool.depcheck.policy] in pyproject.toml
    and evaluates them against your project's dependencies. Reports
    violations by severity (error, warning, info) with remediation
    guidance. Exits with code 1 if any error-severity rules are
    violated.

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck policy
    depcheck policy --json
    depcheck policy --no-vulns
    """
    from depcheck.policy import (
        evaluate_policy,
        render_policy_json,
        render_policy_table,
    )

    console = Console(quiet=quiet)

    report = evaluate_policy(
        project_path=path,
        check_vulnerabilities=not no_vulns,
        check_licenses=not no_licenses,
    )

    if report.errors and not report.violations and report.total_packages == 0:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_policy_json(report)
    elif not quiet:
        render_policy_table(report, console=console)

    if not report.is_compliant:
        if not quiet:
            console.print(
                f"[red]✗ Policy non-compliant: {report.error_count} "
                f"error(s), compliance score {report.compliance_score}%[/red]"
            )
        sys.exit(1)
