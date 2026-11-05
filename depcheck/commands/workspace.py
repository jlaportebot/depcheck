"""Workspace/monorepo scanning for depcheck.

Wraps depcheck.workspace.scan_workspace and depcheck.workspace_analysis.analyze_workspace_dependencies
with rendering via depcheck.workspace_report.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.workspace import scan_workspace
from depcheck.workspace_analysis import analyze_workspace_dependencies
from depcheck.workspace_report import render_workspace_json, render_workspace_table


@click.command(name="workspace")
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
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking.",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Check license compliance for each dependency.",
)
@click.option(
    "--allow-license",
    "allowed_licenses",
    multiple=True,
    type=click.Choice(
        ["permissive", "copyleft", "public_domain"],
        case_sensitive=False,
    ),
    help="Allowed license categories. Repeat for multiple.",
)
@click.option(
    "--deny-license",
    "denied_licenses",
    multiple=True,
    help="Specific SPDX license IDs to deny. Repeat for multiple.",
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
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    quiet: bool,
) -> None:
    """Scan a monorepo/workspace and aggregate results across all member projects.

    Detects uv, Poetry, Hatch, PDM, and setuptools workspace configurations.
    PATH is the workspace root directory (defaults to current directory).
    """
    console = Console(quiet=quiet)

    # Parse license policy options
    from depcheck.licenses import LicenseCategory

    allowed_categories: list[LicenseCategory] | None = None
    if allowed_licenses:
        category_map = {
            "permissive": LicenseCategory.PERMISSIVE,
            "copyleft": LicenseCategory.COPYLEFT,
            "public_domain": LicenseCategory.PUBLIC_DOMAIN,
        }
        allowed_categories = [
            category_map[cat.lower()] for cat in allowed_licenses if cat.lower() in category_map
        ]

    denied_list: list[str] | None = None
    if denied_licenses:
        denied_list = list(denied_licenses)

    should_check_licenses = check_licenses or bool(allowed_licenses) or bool(denied_licenses)

    # Run workspace scan
    workspace_result = scan_workspace(
        root=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=should_check_licenses,
        allowed_license_categories=allowed_categories,
        denied_licenses=denied_list,
    )

    if workspace_result.errors and not workspace_result.members:
        for error in workspace_result.errors:
            console.print(f"[red]Error:[/red] {error}")
        if output_json:
            jsonout.write_text(
                jsonout.to_json(
                    {
                        "workspace": {
                            "type": workspace_result.workspace_type.value,
                            "root": str(workspace_result.root),
                            "errors": workspace_result.errors,
                        },
                        "members": [],
                    }
                )
            )
        sys.exit(2)

    # Run cross-project analysis
    analysis = analyze_workspace_dependencies(workspace_result)

    # Render output
    if output_json:
        jsonout.write_text(render_workspace_json(workspace_result, analysis))
    elif not quiet:
        render_workspace_table(workspace_result, analysis, console=console)

    sys.exit(0)
