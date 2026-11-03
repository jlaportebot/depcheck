"""Bundle a project into a reproducible artifact set."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="bundle")
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
    help="Output bundle report as JSON.",
)
@click.option(
    "--with",
    "extra_commands",
    multiple=True,
    type=click.Choice(
        ["check", "audit", "outdated", "license", "size", "history"],
        case_sensitive=False,
    ),
    help="Commands to include in the bundle. Repeat for multiple. Default: check, audit, outdated.",
)
@click.option(
    "--all",
    "run_all",
    is_flag=True,
    default=False,
    help="Run all available commands (check, audit, outdated, license, size, history).",
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
    extra_commands: tuple[str, ...],
    run_all: bool,
    quiet: bool,
) -> None:
    """Run multiple depcheck commands in a single pass.

    Executes a configurable bundle of analyses (check, audit, outdated,
    license, size, history) and produces a combined report. Ideal for
    CI pipelines and nightly audits.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck bundle
    depcheck bundle --all
    depcheck bundle --with audit --with license --with size
    depcheck bundle --json
    depcheck bundle --all --json
    """
    from depcheck.bundle import BundleCommand, render_bundle_json, render_bundle_table, run_bundle

    console = Console(quiet=quiet)

    # Build command list
    if run_all:
        commands = list(BundleCommand)
    elif extra_commands:
        name_to_cmd = {cmd.value: cmd for cmd in BundleCommand}
        commands = [name_to_cmd[cmd] for cmd in extra_commands if cmd in name_to_cmd]
    else:
        commands = None  # Use default bundle

    report = run_bundle(project_path=path, commands=commands)

    if report.errors and not report.results:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_bundle_json(report)
    elif not quiet:
        render_bundle_table(report, console=console)

    if not report.overall_success:
        sys.exit(1)
