"""Audit dependencies for supply-chain risk."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="audit")
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
    help="Output audit report as JSON (useful for CI/CD pipelines).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
)
@click.option(
    "--no-license-check",
    is_flag=True,
    default=False,
    help="Skip license compliance checking.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["critical", "high", "medium", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if a package meets the risk threshold.",
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
    no_license_check: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Run a comprehensive security audit on your dependencies.

    Performs deep vulnerability analysis with severity breakdowns,
    per-package risk scoring, and actionable remediation advice.

    PATH is the project directory to audit (defaults to current directory).

    Examples:

    \b
    depcheck audit
    depcheck audit --json
    depcheck audit --fail-on high
    depcheck audit --fail-on critical
    depcheck audit /path/to/project
    """
    from depcheck.audit import RiskLevel, render_audit_json, render_audit_table, run_audit

    console = Console(quiet=quiet)

    result = run_audit(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=not no_license_check,
    )

    if result.errors and not result.all_risks:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Render output
    if output_json:
        render_audit_json(result)
    elif not quiet:
        render_audit_table(result, console=console)

    # Exit code based on risk threshold
    if fail_on:
        threshold_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "any": RiskLevel.LOW,
        }
        threshold = threshold_map.get(fail_on.lower(), RiskLevel.CRITICAL)
        level_order = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        if level_order.get(result.risk_level, 0) >= level_order.get(threshold, 4):
            if not quiet:
                console.print(
                    f"[red]✗ Audit failed: risk level {result.risk_level.value} "
                    f"meets or exceeds --fail-on {fail_on} threshold[/red]"
                )
            sys.exit(1)
