"""Scan a project for dependency health issues."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.commands import _common
from depcheck.config import load_config
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
@click.pass_context
def command(
    ctx: click.Context,
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

    Configuration is loaded from ``pyproject.toml`` ([tool.depcheck]) or from
    the file given with the global ``--config`` flag. ``DEPCHECK_*``
    environment variables override file values, and explicit CLI flags win
    over both.
    """
    console = Console(quiet=quiet)

    # Load configuration (file + DEPCHECK_* environment overrides).
    config_path = ctx.obj.get("config_path") if ctx.obj else None
    config = load_config(project_path=path, config_path=config_path)
    scan_cfg = config.scan

    # Resolve each scan parameter: explicit CLI flag > config/env > default.
    param_source = ctx.get_parameter_source
    command_line = click.core.ParameterSource.COMMANDLINE

    if param_source("no_vuln_check") is command_line:
        check_vulnerabilities = not no_vuln_check
    else:
        check_vulnerabilities = scan_cfg.check_vulnerabilities

    effective_fail_on = fail_on if param_source("fail_on") is command_line else scan_cfg.fail_on

    if param_source("check_licenses") is command_line:
        effective_check_licenses = check_licenses
    else:
        effective_check_licenses = scan_cfg.check_licenses

    # License allow/deny lists: CLI flags win, otherwise fall back to config.
    if param_source("allow_license") is command_line and allowed_licenses:
        category_map = {
            "permissive": LicenseCategory.PERMISSIVE,
            "copyleft": LicenseCategory.COPYLEFT,
            "public_domain": LicenseCategory.PUBLIC_DOMAIN,
        }
        allowed_categories = [
            category_map[cat.lower()] for cat in allowed_licenses if cat.lower() in category_map
        ]
        effective_check_licenses = True
    elif scan_cfg.allowed_license_categories:
        try:
            allowed_categories = [
                LicenseCategory[cat.upper()] for cat in scan_cfg.allowed_license_categories
            ]
        except KeyError:
            allowed_categories = None
        effective_check_licenses = True
    else:
        allowed_categories = None

    if param_source("deny_license") is command_line and denied_licenses:
        denied_list = list(denied_licenses)
        effective_check_licenses = True
    elif scan_cfg.denied_licenses:
        denied_list = list(scan_cfg.denied_licenses)
        effective_check_licenses = True
    else:
        denied_list = None

    # Resolve quiet/output_json from config when not given on the CLI.
    if param_source("quiet") is not command_line:
        quiet = quiet or scan_cfg.quiet
    if param_source("json") is not command_line:
        output_json = output_json or scan_cfg.output_json

    # Run the scan
    result = _common.scan_project(
        project_path=path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=effective_check_licenses,
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
    exit_code = determine_exit_code(result, effective_fail_on)

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
