"""Configuration management commands for depcheck.

Provides `depcheck config show|validate|generate` subcommands.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.config import generate_default_config, load_config, validate_config


@click.group(name="config")
def config_group() -> None:
    """Show, validate, or generate depcheck configuration."""
    pass


@config_group.command(name="show")
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
    help="Output configuration as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def show_command(
    path: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Show the effective configuration for a project.

    PATH is the project directory (defaults to current directory).
    Merges pyproject.toml [tool.depcheck] with defaults and CLI overrides.
    """
    console = Console(quiet=quiet)
    config = load_config(project_path=path)

    if output_json:
        jsonout.write_text(jsonout.to_json(config.to_dict()))
    elif not quiet:
        console.print(jsonout.to_json(config.to_dict()))


@config_group.command(name="validate")
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
    help="Output validation results as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def validate_command(
    path: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Validate the depcheck configuration for a project.

    Exits with code 1 if any validation errors are found.
    PATH is the project directory (defaults to current directory).
    """
    console = Console(quiet=quiet)
    config = load_config(project_path=path)
    issues = validate_config(config)

    if output_json:
        jsonout.write_text(jsonout.to_json({"valid": len(issues) == 0, "issues": issues}))
    elif not quiet:
        if issues:
            for issue in issues:
                console.print(f"[yellow]⚠[/yellow] {issue}")
        else:
            console.print("[green]✓ Configuration is valid[/green]")
    sys.exit(1 if issues else 0)


@config_group.command(name="generate")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--write",
    "write_file",
    is_flag=True,
    default=False,
    help="Write to <PATH>/depcheck.yaml instead of printing.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON instead of YAML/TOML.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def generate_command(
    path: str,
    write_file: bool,
    output_json: bool,
    quiet: bool,
) -> None:
    """Generate a default depcheck configuration.

    Prints the default configuration as TOML (suitable for pyproject.toml).
    Use --write to write to <PATH>/depcheck.yaml instead.
    PATH is the project directory (defaults to current directory).
    """
    console = Console(quiet=quiet)
    config_str = generate_default_config(project_path=path)

    if write_file:
        out_path = Path(path) / "depcheck.yaml"
        out_path.write_text(config_str, encoding="utf-8")
        if not quiet:
            console.print(f"[green]✓[/green] Written to {out_path}")
    elif output_json:
        jsonout.write_text(jsonout.to_json({"config": config_str}))
    elif not quiet:
        console.print(config_str.rstrip(), markup=False)


# The click group IS the command object that gets registered
command = config_group
