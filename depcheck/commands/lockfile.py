"""Inspect, diff and audit lockfiles."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="lockfile")
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
    help="Output lockfile analysis as JSON.",
)
@click.option(
    "--audit",
    "run_audit_flag",
    is_flag=True,
    default=False,
    help="Run pip-audit for vulnerability scanning (requires pip-audit installed).",
)
@click.option(
    "--diff",
    "diff_target",
    type=click.Path(exists=True),
    default=None,
    help="Compare lockfile against another lockfile to show diff.",
)
@click.option(
    "--freeze",
    is_flag=True,
    default=False,
    help="Generate a pip freeze output for the current environment.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write freeze output to file (use with --freeze).",
)
@click.option(
    "--fail-on-unpinned",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any unpinned dependencies are found.",
)
@click.option(
    "--fail-on-drift",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any version drift is detected.",
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
    run_audit_flag: bool,
    diff_target: str | None,
    freeze: bool,
    output_file: str | None,
    fail_on_unpinned: bool,
    fail_on_drift: bool,
    quiet: bool,
) -> None:
    """Analyze lockfiles for unpinned deps, drift, and hash issues.

    Finds and analyzes all lockfile types in your project: requirements.txt,
    Pipfile.lock, and poetry.lock. Detects unpinned dependencies, version
    drift from manifests, missing hashes, and (optionally) runs pip-audit.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck lockfile
    depcheck lockfile --json
    depcheck lockfile --audit
    depcheck lockfile --freeze
    depcheck lockfile --freeze --output requirements.lock
    depcheck lockfile --diff requirements.old.txt
    depcheck lockfile --fail-on-unpinned
    """
    from pathlib import Path

    from depcheck.lockfile import (
        analyze_project_lockfiles,
        diff_lockfiles,
        find_lockfiles,
        generate_freeze,
        render_lockfile_diff_table,
        render_lockfile_json,
        render_lockfile_table,
        render_pip_audit_table,
        run_pip_audit,
    )

    console = Console(quiet=quiet)

    # Freeze mode
    if freeze:
        content = generate_freeze(project_path=path, output_path=output_file)
        if not output_file and not quiet:
            console.print(content)
        if output_file and not quiet:
            console.print(f"[green]Freeze written to {output_file}[/green]")
        return

    # Diff mode
    if diff_target:
        project = Path(path).resolve()
        lockfiles = find_lockfiles(project)
        if not lockfiles:
            console.print("[red]No lockfiles found in project[/red]")
            sys.exit(1)

        target_path = Path(diff_target).resolve()
        # Use the first lockfile found as the "old" side
        old_path = lockfiles[0]
        result = diff_lockfiles(old_path, target_path)
        if output_json:
            jsonout.write_json(result.to_dict())
        elif not quiet:
            render_lockfile_diff_table(result, console=console)
        if result.has_changes and fail_on_drift:
            sys.exit(1)
        return

    # Normal analysis mode
    reports = analyze_project_lockfiles(project_path=path)

    if not reports:
        if not quiet:
            console.print("[yellow]No lockfiles found in project.[/yellow]")
            console.print(
                "[dim]Create a requirements.txt with pinned versions, or use --freeze to generate one.[/dim]"
            )
        sys.exit(0)

    if output_json:
        render_lockfile_json(reports)
    elif not quiet:
        render_lockfile_table(reports, console=console)

    # pip-audit integration
    if run_audit_flag:
        # Find the first requirements-style lockfile to audit
        req_path: Path | None = None
        for lf in find_lockfiles(Path(path).resolve()):
            if lf.name.endswith(".txt"):
                req_path = lf
                break

        audit_result = run_pip_audit(req_path)
        if not quiet:
            render_pip_audit_table(audit_result, console=console)

    # Exit codes
    for report in reports:
        if fail_on_unpinned and report.unpinned:
            if not quiet:
                console.print(f"[red]✗ Unpinned dependencies found in {report.path}[/red]")
            sys.exit(1)
        if fail_on_drift and report.drift:
            if not quiet:
                console.print(f"[red]✗ Version drift detected in {report.path}[/red]")
            sys.exit(1)
