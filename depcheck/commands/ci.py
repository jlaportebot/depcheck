"""One-shot CI gate for depcheck.

Runs a scan and evaluates the configured budget and policy in a single pass,
then exits with a code a CI runner can act on directly.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.cigate import determine_gate_exit_code, run_ci_gate

#: Conditions the gate can fail on.
_FAIL_ON_CHOICES = ("vulnerable", "outdated", "license", "any")


@click.command(name="ci")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--fail-on",
    type=click.Choice(list(_FAIL_ON_CHOICES), case_sensitive=False),
    default="vulnerable",
    help="Which condition fails the gate (default: vulnerable).",
)
@click.option(
    "--check-vulnerabilities/--no-check-vulnerabilities",
    default=True,
    help="Check for known vulnerabilities.",
)
@click.option(
    "--check-licenses/--no-check-licenses",
    default=True,
    help="Check license compliance.",
)
@click.option(
    "--enforce-budget",
    is_flag=True,
    default=False,
    help="Enforce the dependency budget configured in pyproject.toml.",
)
@click.option(
    "--enforce-policy",
    is_flag=True,
    default=False,
    help="Enforce the policy rules configured in pyproject.toml.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output the gate result as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def command(
    path: str,
    fail_on: str,
    check_vulnerabilities: bool,
    check_licenses: bool,
    enforce_budget: bool,
    enforce_policy: bool,
    output_json: bool,
    quiet: bool,
) -> None:
    """Run the full CI gate: scan, licenses, budget and policy in one shot.

    Exit code 0 means every enabled check passed, 1 means a check failed and
    2 means the gate itself could not run.
    """
    console = Console(quiet=quiet)

    result = run_ci_gate(
        path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
        fail_on=fail_on.lower(),
        enforce_budget=enforce_budget,
        enforce_policy=enforce_policy,
    )

    if output_json:
        jsonout.write_text(jsonout.to_json(result.to_dict()))
    elif not quiet:
        _render_gate(result, console)

    sys.exit(determine_gate_exit_code(result))


def _render_gate(result, console: Console) -> None:
    """Render a CI gate result as a short human-readable report.

    Args:
        result: The gate result to render.
        console: Console to write to.
    """
    verdict_style = {
        "pass": "green",
        "fail": "red",
        "error": "yellow",
    }.get(result.verdict, "white")

    console.print(f"[bold]{result.verdict.upper()}[/bold] [{verdict_style}]{result.summary}[/]")

    for check in result.passed_checks:
        console.print(f"  [green]✓[/green] {check}")
    for check in result.failed_checks:
        console.print(f"  [red]✗[/red] {check}")
    for error in result.errors:
        console.print(f"  [yellow]![/yellow] {error}")
