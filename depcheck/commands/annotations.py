"""GitHub Actions annotations output for depcheck scan results.

Emits workflow commands compatible with GitHub Actions annotations:
::error file=pyproject.toml,line=1::message
::warning file=requirements.txt,line=5::message
::notice file=setup.py,line=10::message
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.commands import _common
from depcheck.output import render_github_annotations

if TYPE_CHECKING:
    from depcheck.models import ScanResult


# Type annotation mappings for GitHub Actions
_SEVERITY_TO_TYPE = {
    "error": "error",
    "warning": "warning",
    "notice": "notice",
}


def _emit_annotations(annotations: list[dict], output_file: Path | None) -> None:
    """Emit GitHub Actions annotation workflow commands.

    Args:
        annotations: List of annotation dicts with keys type, file, line, message.
        output_file: Optional file path to write to instead of stdout.
    """
    lines: list[str] = []
    for ann in annotations:
        ann_type = ann.get("type", "notice")
        file_path = ann.get("file", "")
        line = ann.get("line", 0)
        message = ann.get("message", "")

        # GitHub Actions format: ::type file={file},line={line}::{message}
        if file_path and line:
            line_str = f"file={file_path},line={line}"
        elif file_path:
            line_str = f"file={file_path}"
        else:
            line_str = ""

        if line_str:
            workflow_cmd = f"::{ann_type} {line_str}::{message}"
        else:
            workflow_cmd = f"::{ann_type}::{message}"

        lines.append(workflow_cmd)

    output = "\n".join(lines) + ("\n" if lines else "")

    if output_file:
        output_file.write_text(output, encoding="utf-8")
    else:
        # Use jsonout.write_text to avoid Rich corruption
        jsonout.write_text(output)


def _check_fail_on(result: ScanResult, fail_on: str | None) -> int:
    """Determine exit code based on --fail-on condition.

    Args:
        result: The scan result.
        fail_on: One of 'vulnerable', 'outdated', 'unmaintained', 'license', 'any', or None.

    Returns:
        Exit code (0 or 1).
    """
    if not fail_on:
        return 0

    condition = fail_on.lower()
    if condition == "any":
        return 1 if result.packages else 0

    for pkg in result.packages:
        if condition == "vulnerable" and pkg.status.value == "vulnerable":
            return 1
        if condition == "outdated" and pkg.status.value == "outdated":
            return 1
        if condition == "unmaintained" and pkg.status.value == "unmaintained":
            return 1
        if condition == "license" and pkg.license_info and not pkg.license_info.is_compliant:
            return 1

    return 0


@click.command(name="annotations")
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
    help="Emit raw annotation list as JSON instead of GitHub Actions workflow commands.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write annotations to FILE instead of stdout.",
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
    output_file: str | None,
    fail_on: str | None,
    no_vuln_check: bool,
    check_licenses: bool,
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    quiet: bool,
) -> None:
    """Generate GitHub Actions annotations from a dependency scan.

    PATH is the project directory to scan (defaults to current directory).
    Emits workflow commands like ::error file=pyproject.toml,line=1::message

    Use --output to write to a file instead of stdout.
    Use --json to emit the raw annotation list as JSON.
    Use --fail-on to exit with code 1 when a condition is met.
    """
    console = Console(quiet=quiet)
    output_path = Path(output_file) if output_file else None

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

    # Generate annotations
    annotations = render_github_annotations(result)

    # Output
    if output_json:
        jsonout.write_text(jsonout.to_json(annotations))
    else:
        _emit_annotations(annotations, output_path)

    # Determine exit code
    exit_code = _check_fail_on(result, fail_on)

    if exit_code != 0 and not quiet:
        if fail_on:
            console.print(f"[red]✗ Annotations: --fail-on {fail_on} condition met[/red]")

    sys.exit(exit_code)
