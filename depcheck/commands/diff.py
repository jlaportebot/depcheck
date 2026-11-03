"""Compare dependency files or detect lockfile drift."""

from __future__ import annotations

import sys

import click
from rich.console import Console


@click.command(name="diff")
@click.argument(
    "old",
    type=click.Path(exists=True),
)
@click.argument(
    "new",
    type=click.Path(exists=True),
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output diff as JSON (useful for CI/CD pipelines).",
)
@click.option(
    "--unified",
    is_flag=True,
    default=False,
    help="Show unified diff (traditional diff format) instead of table.",
)
@click.option(
    "--drift",
    is_flag=True,
    default=False,
    help="Detect lockfile drift: OLD is the manifest, NEW is the lockfile.",
)
@click.option(
    "--fail-on-change",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any dependency changes are detected (useful in CI).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def command(
    old: str,
    new: str,
    output_json: bool,
    unified: bool,
    drift: bool,
    fail_on_change: bool,
    quiet: bool,
) -> None:
    """Compare two dependency files and show differences.

    OLD and NEW are paths to dependency files (requirements.txt, pyproject.toml,
    or Pipfile) or project directories to compare.

    Examples:

    \b
      depcheck diff requirements.old.txt requirements.new.txt
      depcheck diff pyproject.toml pyproject.new.toml
      depcheck diff old_project/ new_project/
      depcheck diff --drift requirements.txt requirements.lock
      depcheck diff --json requirements.old.txt requirements.new.txt
      depcheck diff --unified v1.txt v2.txt
      depcheck diff --fail-on-change requirements.old.txt requirements.new.txt
    """
    from pathlib import Path

    from depcheck.diff import (
        detect_lockfile_drift,
        diff_directories,
        diff_files,
        generate_unified_diff,
        render_diff_json,
        render_diff_table,
    )

    console = Console(quiet=quiet)

    old_path = Path(old)
    new_path = Path(new)

    # Determine mode: drift, directory, or file
    if drift:
        result = detect_lockfile_drift(old_path, new_path)
    elif old_path.is_dir() and new_path.is_dir():
        result = diff_directories(old_path, new_path)
    else:
        result = diff_files(old_path, new_path)

    # Render output
    if unified and not drift:
        if not quiet:
            unified_output = generate_unified_diff(old_path, new_path)
            if unified_output:
                console.print(unified_output, highlight=False)
            else:
                console.print("[green]No differences found.[/green]")
    elif output_json:
        render_diff_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        render_diff_table(result, console=console)

    # Exit code for CI
    if fail_on_change and (result.added_count or result.removed_count or result.changed_count):
        sys.exit(1)
