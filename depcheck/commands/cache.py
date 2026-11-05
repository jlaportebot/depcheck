"""Manage the on-disk response cache.

Exposes the SQLite cache that :mod:`depcheck.cache` maintains so users can
inspect it, clear it when it goes stale, or locate the database file.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.cache import ResponseCache, cache_database_path

__all__ = ["command"]


def _cache_dir_option() -> Callable[[Any], Any]:
    """Build the ``--cache-dir`` option shared by every subcommand.

    Returns:
        The Click decorator that adds ``--cache-dir`` to a command.
    """
    return click.option(
        "--cache-dir",
        "cache_dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
        default=None,
        help="Directory that holds the cache database (defaults to the platform cache dir).",
    )


def _json_option() -> Callable[[Any], Any]:
    """Build the ``--json`` option shared by every subcommand.

    Returns:
        The Click decorator that adds ``--json`` to a command.
    """
    return click.option(
        "--json",
        "output_json",
        is_flag=True,
        default=False,
        help="Output the result as JSON.",
    )


@click.group(name="cache")
def cache_group() -> None:
    """Inspect and manage the depcheck response cache."""


@cache_group.command(name="stats")
@_cache_dir_option()
@_json_option()
def stats_command(cache_dir: Path | None, output_json: bool) -> None:
    """Show how many responses are cached and where the cache lives."""
    cache = _open_cache(cache_dir)
    stats = cache.stats()

    if output_json:
        jsonout.write_text(jsonout.to_json(stats.to_dict()))
    else:
        console = Console()
        console.print(f"Cache path: [bold]{stats.path}[/bold]")
        console.print(f"Entries: [bold]{stats.entries}[/bold]")
        console.print(f"Expired entries: [bold]{stats.expired_entries}[/bold]")
        console.print(f"Size: [bold]{stats.size_bytes}[/bold] bytes")

    sys.exit(0)


@cache_group.command(name="clear")
@_cache_dir_option()
@_json_option()
def clear_command(cache_dir: Path | None, output_json: bool) -> None:
    """Remove every entry from the cache."""
    cache = _open_cache(cache_dir)
    removed = cache.clear()

    if output_json:
        jsonout.write_text(jsonout.to_json({"removed": removed, "path": str(cache.path)}))
    else:
        console = Console()
        console.print(f"Removed [bold]{removed}[/bold] cache entr(y/ies)")

    sys.exit(0)


@cache_group.command(name="path")
@_cache_dir_option()
@_json_option()
def path_command(cache_dir: Path | None, output_json: bool) -> None:
    """Print the path of the cache database."""
    path = cache_database_path() if cache_dir is None else cache_dir / "cache.sqlite3"

    if output_json:
        jsonout.write_text(jsonout.to_json({"path": str(path)}))
    else:
        click.echo(str(path))

    sys.exit(0)


def _open_cache(cache_dir: Path | None) -> ResponseCache:
    """Open the cache in the given directory.

    Args:
        cache_dir: Directory that holds the database, or None for the default.

    Returns:
        A cache handle pointing at the requested directory.
    """
    return ResponseCache(cache_dir, enabled=True)


# The click group IS the command object that gets registered.
command = cache_group
