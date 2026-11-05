"""Scan a project for dependency health issues."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.commands import _common
from depcheck.formats import FORMAT_CHOICES, render_format
from depcheck.licenses import LicenseCategory
from depcheck.output import determine_exit_code, render_json, render_table


@click.command(name="scan")
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
    help="Output results as JSON (useful for CI/CD pipelines).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(
        ["table", "json", *FORMAT_CHOICES],
        case_sensitive=False,
    ),
    default="table",
    help="Output format: table (default), json, sarif, markdown or junit.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["vulnerable", "outdated", "unmaintained", "license", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if the specified condition is met.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
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
    help="Allowed license categories. Repeat for multiple. "
    "E.g., --allow-license permissive --allow-license public_domain",
)
@click.option(
    "--deny-license",
    "denied_licenses",
    multiple=True,
    help="Specific SPDX license IDs to deny. Repeat for multiple. "
    "E.g., --deny-license GPL-3.0 --deny-license AGPL-3.0",
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
    fmt: str,
    fail_on: str | None,
    no_vuln_check: bool,
    check_licenses: bool,
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    quiet: bool,
) -> None:
    """Scan a Python project for dependency health issues.

    PATH is the project directory to scan (defaults to current directory).
    depcheck looks for requirements.txt, pyproject.toml, or Pipfile.

    Use --format to pick the output format: table (default), json, sarif
    (for GitHub code scanning), markdown (for PR comments) or junit.
    """
    console = Console(quiet=quiet)

    # Parse license policy options
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

    # Enable license check if any license options are specified
    should_check_licenses = check_licenses or bool(allowed_licenses) or bool(denied_licenses)

    # Run the scan
    result = _common.scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=should_check_licenses,
        allowed_license_categories=allowed_categories,
        denied_licenses=denied_list,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        if output_json:
            jsonout.write_text(jsonout.to_json(result.to_dict()))
        sys.exit(2)

    # Render output
    _render_result(result, fmt=fmt, output_json=output_json, quiet=quiet)

    # Determine exit code
    exit_code = determine_exit_code(result, fail_on)

    if exit_code != 0 and not quiet:
        if fail_on:
            console.print(f"[red]✗ Scan failed: --fail-on {fail_on} condition met[/red]")

    sys.exit(exit_code)


def _render_result(result, *, fmt: str, output_json: bool, quiet: bool) -> None:
    """Render a scan result in the requested format.

    Args:
        result: The scan result to render.
        fmt: Format name: "table", "json", "sarif", "markdown" or "junit".
        output_json: Whether the legacy --json flag was given.
        quiet: Whether to suppress output entirely.
    """
    if output_json or fmt == "json":
        render_json(result, console=Console(quiet=False) if quiet else None)
        return
    if fmt != "table":
        jsonout.write_text(render_format(result, fmt))
        return
    if not quiet:
        render_table(result)
