"""Explain the dependencies of a project."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="explain")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(
        ["plain", "markdown", "json", "ai"],
        case_sensitive=False,
    ),
    default="plain",
    help="Output format (default: plain). 'ai' is compact for LLM context windows.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster explanations).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info in explanations.",
)
@click.option(
    "--filter",
    "filter_status",
    type=click.Choice(
        ["vulnerable", "outdated", "unmaintained", "at-risk", "all"],
        case_sensitive=False,
    ),
    default="all",
    help="Filter to only show packages with the specified status.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    path: str,
    fmt: str,
    no_vuln_check: bool,
    check_licenses: bool,
    filter_status: str,
    quiet: bool,
) -> None:
    """Explain what each dependency does and its health status.

    Generates human-readable explanations for every dependency in
    your project, including what the package provides, its ecosystem
    role, alternatives, and actionable risk items.

    PATH is the project directory to explain (defaults to current directory).

    Examples:

    \b
    depcheck explain
    depcheck explain --format markdown
    depcheck explain --format json
    depcheck explain --format ai
    depcheck explain --filter at-risk
    depcheck explain --filter vulnerable
    depcheck explain --check-licenses
    """
    from depcheck.explain import (
        explain_project,
        render_explain_ai,
        render_explain_json,
        render_explain_markdown,
        render_explain_plain,
    )
    from depcheck.models import HealthStatus

    console = Console(quiet=quiet)

    report = explain_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Apply filter
    if filter_status != "all":
        if filter_status == "at-risk":
            report.packages = [
                p for p in report.packages if p.is_vulnerable or p.is_outdated or p.is_unmaintained
            ]
        else:
            status_map = {
                "vulnerable": HealthStatus.VULNERABLE,
                "outdated": HealthStatus.OUTDATED,
                "unmaintained": HealthStatus.UNMAINTAINED,
            }
            target_status = status_map.get(filter_status)
            if target_status:
                report.packages = [p for p in report.packages if p.status == target_status]

    fmt_lower = fmt.lower()
    if fmt_lower == "json":
        render_explain_json(report)
    elif fmt_lower == "markdown":
        render_explain_markdown(report, console=console)
    elif fmt_lower == "ai":
        render_explain_ai(report)
    else:
        render_explain_plain(report, console=console)
