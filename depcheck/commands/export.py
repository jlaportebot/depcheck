"""Export a Software Bill of Materials (SBOM)."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="export")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["cyclonedx", "spdx", "summary"], case_sensitive=False),
    default="cyclonedx",
    help="SBOM output format (default: cyclonedx).",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write SBOM to file instead of stdout.",
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
    help="Include license compliance information in the SBOM.",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output raw JSON even for summary format (instead of Rich table).",
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
    output_file: str | None,
    no_vuln_check: bool,
    check_licenses: bool,
    json_output: bool,
    quiet: bool,
) -> None:
    """Generate a Software Bill of Materials (SBOM) for a project.

    PATH is the project directory to scan (defaults to current directory).

    Supports CycloneDX (OWASP standard) and SPDX (Linux Foundation standard)
    formats for supply chain security compliance.

    Examples:

    \b
    depcheck export --format cyclonedx
    depcheck export --format spdx --output sbom.json
    depcheck export --format summary --json-output
    depcheck export --format cyclonedx --output bom.cdx.json
    """
    from depcheck.export import (
        generate_sbom,
        render_cyclonedx,
        render_spdx,
        render_summary_json,
        render_summary_table,
        write_sbom_to_file,
    )

    console = Console(quiet=quiet)

    fmt = fmt.lower()

    # Generate SBOM
    sbom = generate_sbom(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        include_licenses=check_licenses,
    )

    if sbom.errors and not sbom.components:
        for error in sbom.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Output to file
    if output_file:
        written = write_sbom_to_file(sbom, format=fmt, output_path=output_file)
        if not quiet:
            console.print(f"[green]SBOM written to {written}[/green]")
            console.print(f"[dim]{sbom.total} components exported in {fmt} format[/dim]")
        sys.exit(0)

    # Output to stdout
    if fmt == "cyclonedx":
        content = render_cyclonedx(sbom)
        jsonout.write_text(content)
    elif fmt == "spdx":
        content = render_spdx(sbom)
        jsonout.write_text(content)
    elif fmt == "summary":
        if json_output:
            content = render_summary_json(sbom)
            jsonout.write_text(content)
    elif not quiet:
        render_summary_table(sbom, console=console)
