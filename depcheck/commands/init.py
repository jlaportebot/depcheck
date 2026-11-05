"""Scaffold a new depcheck project.

Wraps :mod:`depcheck.scaffolding` so a user can bootstrap a config file and a
GitHub Actions workflow in one command.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.scaffolding import render_scaffold_markdown, scaffold_project


@click.command(name="init")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--workflow/--no-workflow",
    default=True,
    help="Also create a GitHub Actions workflow.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing files instead of skipping them.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output the scaffold result as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def command(
    path: str,
    workflow: bool,
    force: bool,
    output_json: bool,
    quiet: bool,
) -> None:
    """Scaffold a depcheck configuration for a project.

    Creates ``depcheck.yaml`` in PATH and, unless --no-workflow is given,
    a ``.github/workflows/depcheck.yml`` that runs depcheck in CI.

    Existing files are left untouched unless --force is given.
    """
    console = Console(quiet=quiet)

    result = scaffold_project(path, workflow=workflow, force=force)

    if output_json:
        jsonout.write_text(jsonout.to_json(result.to_dict()))
    elif not quiet:
        console.print(render_scaffold_markdown(result), markup=False)

    if result.warnings and not quiet and not output_json:
        console.print()
        console.print(f"[yellow]{len(result.warnings)} file(s) already existed[/yellow]")

    sys.exit(0)
