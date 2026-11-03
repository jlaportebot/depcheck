"""List security advisories affecting dependencies."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="advisories")
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
    help="Output advisory report as JSON.",
)
@click.option(
    "--source",
    type=click.Choice(["osv", "pypa", "github", "all"]),
    default="all",
    help="Advisory source to query.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Filter advisories by minimum severity.",
)
@click.option(
    "--patched-only",
    is_flag=True,
    default=False,
    help="Only show advisories with a known fix.",
)
@click.option(
    "--unpatched-only",
    is_flag=True,
    default=False,
    help="Only show advisories without a known fix.",
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
    source: str,
    severity: str | None,
    patched_only: bool,
    unpatched_only: bool,
    quiet: bool,
) -> None:
    """Check security advisories for project dependencies.

    Queries multiple advisory databases (OSV, PyPA, GitHub) for
    known vulnerabilities affecting your dependencies. Shows
    severity, affected versions, and available fixes.

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck advisories
    depcheck advisories --source osv
    depcheck advisories --severity high
    depcheck advisories --unpatched-only
    depcheck advisories --json
    """
    from depcheck.advisories import (
        AdvisorySource,
        render_advisories_json,
        render_advisories_table,
        run_advisories,
    )

    console = Console(quiet=quiet)

    source_map = {
        "osv": [AdvisorySource.OSV],
        "pypa": [AdvisorySource.PYPA],
        "github": [AdvisorySource.GITHUB],
        "all": [AdvisorySource.OSV, AdvisorySource.PYPA, AdvisorySource.GITHUB],
    }
    sources = source_map.get(source, source_map["all"])

    report = run_advisories(
        project_path=path,
        check_vulnerabilities=True,
        sources=sources,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Apply filters if specified
    if severity or patched_only or unpatched_only:
        for pkg_summary in report.packages:
            filtered = pkg_summary.advisories
            if severity:
                filtered = [a for a in filtered if a.severity.upper() >= severity.upper()]
            if patched_only:
                filtered = [a for a in filtered if a.is_patchable]
            if unpatched_only:
                filtered = [a for a in filtered if not a.is_patchable]
            pkg_summary.advisories = filtered
            pkg_summary.total_advisories = len(filtered)

    if output_json:
        render_advisories_json(report)
    elif not quiet:
        render_advisories_table(report, console=console)

    if report.total_critical > 0:
        if not quiet:
            console.print(f"[red]✗ {report.total_critical} critical advisories found[/red]")
        sys.exit(1)
