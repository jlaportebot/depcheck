"""Remediation plan generation for depcheck.

Builds an update plan, groups by priority, and optionally creates GitHub PRs.
Default path is offline (plan only) - no network calls.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.commands import _common
from depcheck.remediate import build_remediation_plan
from depcheck.update import build_update_plan, render_update_plan_table

__all__ = ["command"]


@click.command(name="remediate")
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
    help="Output results as JSON.",
)
@click.option(
    "--repo",
    "repository",
    default=None,
    help="GitHub repository in 'owner/name' format (required for --apply).",
)
@click.option(
    "--apply/--dry-run",
    "apply",
    default=False,
    help="Create GitHub PRs for the remediation plan (requires GITHUB_TOKEN and --repo). "
    "Defaults to --dry-run, which never touches the network.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking in the scan.",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Check license compliance in the scan.",
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
    repository: str | None,
    apply: bool,
    no_vuln_check: bool,
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Build a remediation plan from dependency scan results.

    By default (--dry-run), prints the plan as a table or JSON.
    With --apply --repo owner/name, creates GitHub PRs (requires GITHUB_TOKEN).

    PATH is the project directory to scan (defaults to current directory).
    """
    console = Console(quiet=quiet)

    if apply and not repository:
        console.print("[red]Error:[/red] --apply requires --repo owner/name")
        sys.exit(2)

    result = _common.scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        if output_json:
            jsonout.write_text(jsonout.to_json({"error": "scan failed", "details": result.errors}))
        sys.exit(2)

    update_plan = build_update_plan(result)
    remediation_plan = build_remediation_plan(update_plan, repository or "local/project")

    if apply:
        console.print(
            "[yellow]Warning:[/yellow] --apply creates GitHub PRs. Not implemented in offline mode."
        )
        console.print("Use --dry-run (default) to see the plan without network calls.")
        sys.exit(1)

    if output_json:
        jsonout.write_text(jsonout.to_json(remediation_plan.to_dict()))
    elif not quiet:
        render_update_plan_table(update_plan, console=console)
        console.print()
        console.print("[bold]Remediation Groups:[/bold]")
        for group in remediation_plan.groups:
            console.print(
                f"  {group.name}: {group.title} ({group.priority}) - {len(group.packages)} packages"
            )

    sys.exit(0)
