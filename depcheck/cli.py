"""Command-line interface for depcheck."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import __version__
from depcheck.output import determine_exit_code, render_json, render_table
from depcheck.scanner import scan_project


@click.group()
@click.version_option(version=__version__, prog_name="depcheck")
def main() -> None:
    """depcheck — A dependency health checker for Python projects.

    Scan your project's dependencies for vulnerabilities, outdated packages,
    unmaintained libraries, and yanked or removed packages.
    """
    pass


@main.command()
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
    'E.g., --deny-license GPL-3.0 --deny-license AGPL-3.0',
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def scan(
    path: str,
    output_json: bool,
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
    """
    console = Console(quiet=quiet)

    # Parse license policy options
    allowed_categories: list | None = None
    if allowed_licenses:
        try:
            from depcheck.licenses import LicenseCategory

            category_map = {
                "permissive": LicenseCategory.PERMISSIVE,
                "copyleft": LicenseCategory.COPYLEFT,
                "public_domain": LicenseCategory.PUBLIC_DOMAIN,
            }
            allowed_categories = [
                category_map[cat.lower()]
                for cat in allowed_licenses
                if cat.lower() in category_map
            ]
        except ImportError:
            click.echo("License compliance requires the license-checking feature.", err=True)

    denied_list: list[str] | None = None
    if denied_licenses:
        denied_list = list(denied_licenses)

    # Enable license check if any license options are specified
    should_check_licenses = check_licenses or bool(allowed_licenses) or bool(denied_licenses)

    # Run the scan
    result = scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=should_check_licenses,
        allowed_license_categories=allowed_categories,
        denied_licenses=denied_list,
    )

    # Render output
    if output_json:
        render_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        render_table(result)

    # Determine exit code
    exit_code = determine_exit_code(result, fail_on)

    if exit_code != 0 and not quiet:
        if fail_on:
            console.print(f"[red]✗ Scan failed: --fail-on {fail_on} condition met[/red]")

    sys.exit(exit_code)


@main.command()
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
    help="Output the dependency tree as JSON.",
)
@click.option(
    "--max-depth",
    type=int,
    default=3,
    help="Maximum depth to resolve in the dependency tree (default: 3).",
)
@click.option(
    "--display-depth",
    type=int,
    default=None,
    help="Maximum depth to display (useful for large trees). Defaults to --max-depth.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster tree resolution).",
)
@click.option(
    "--no-highlight",
    is_flag=True,
    default=False,
    help="Disable color-coded health status highlighting in the tree.",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info in the tree (at top-level only).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def tree(
    path: str,
    output_json: bool,
    max_depth: int,
    display_depth: int | None,
    no_vuln_check: bool,
    no_highlight: bool,
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Display the dependency tree for a Python project.

    PATH is the project directory to scan (defaults to current directory).
    Resolves the full dependency tree by querying PyPI for each package's
    declared dependencies and displays it with health status indicators.

    Each package shows its version and health status:
      ✓ healthy  ↑ outdated  ! vulnerable  ⚠ unmaintained  ✗ yanked/removed

    Circular dependencies are detected and marked with ↻.
    """
    from depcheck.tree import render_tree, render_tree_json, resolve_dependency_tree

    console = Console(quiet=quiet)

    # Resolve the dependency tree
    result = resolve_dependency_tree(
        project_path=path,
        max_depth=max_depth,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    # Render output
    if output_json:
        render_tree_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        effective_display_depth = display_depth if display_depth is not None else max_depth
        render_tree(
            result,
            max_depth=effective_display_depth,
            highlight_issues=not no_highlight,
            console=console,
        )

    # Exit with error if there are circular deps or all packages failed
    if result.circular_deps:
        sys.exit(1)


if __name__ == "__main__":
    main()
