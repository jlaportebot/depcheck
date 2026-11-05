"""Command-line interface for depcheck.

This module is a thin registrar: it defines the ``depcheck`` command group and
registers one command object per module in :mod:`depcheck.commands`. The
individual commands live in their own modules so that neither the group nor any
single command grows into an unmaintainable file.

``scan_project`` is re-exported here on purpose: it is the binding every
command resolves the scanner through, and tests patch it at this path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from depcheck import __version__
from depcheck.cache import configure_cache
from depcheck.commands import (
    advisories,
    annotations,
    audit,
    badge,
    budget,
    bundle,
    cache,
    check,
    ci,
    compat,
    completions,
    config,
    depdrift,
    diff,
    doctor,
    explain,
    export,
    graph,
    history,
    init,
    isolate,
    license,
    lockfile,
    outdated,
    policy,
    predict,
    remediate,
    risks,
    scan,
    search,
    size,
    sizescore,
    stack,
    suggest,
    summary,
    tree,
    unused,
    update,
    watch,
    why,
    workspace,
)
from depcheck.scanner import scan_project

__all__ = ["main", "scan_project"]


@click.group()
@click.version_option(version=__version__, prog_name="depcheck")
@click.option(
    "--no-cache",
    "no_cache",
    is_flag=True,
    default=False,
    help="Disable the on-disk response cache for this run.",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Never touch the network: serve every response from the local cache.",
)
@click.option(
    "--cache-ttl",
    type=int,
    default=None,
    help="Override the cache TTL in seconds (0 disables caching).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an explicit depcheck config file (defaults to pyproject.toml). "
    "DEPCHECK_* environment variables override values loaded from the file.",
)
@click.pass_context
def main(
    ctx: click.Context,
    no_cache: bool,
    offline: bool,
    cache_ttl: int | None,
    config_path: Path | None,
) -> None:
    """depcheck — A dependency health checker for Python projects.

    Scan your project's dependencies for vulnerabilities, outdated packages,
    unmaintained libraries, yanked or removed packages, and license compliance.
    """
    ttl_overrides = None
    if cache_ttl is not None:
        ttl_overrides = {"pypi": cache_ttl, "osv": cache_ttl}
    configure_cache(
        enabled=not no_cache and cache_ttl != 0,
        offline=offline,
        ttl_overrides=ttl_overrides,
    )
    ctx.ensure_object(dict)
    ctx.obj["offline"] = offline
    ctx.obj["cache_ttl"] = cache_ttl
    ctx.obj["config_path"] = config_path


#: Every command module, in the order they are listed by ``depcheck --help``.
_COMMAND_MODULES = (
    advisories,
    annotations,
    audit,
    badge,
    budget,
    bundle,
    cache,
    check,
    ci,
    compat,
    completions,
    config,
    depdrift,
    diff,
    doctor,
    explain,
    export,
    graph,
    history,
    init,
    isolate,
    license,
    lockfile,
    outdated,
    policy,
    predict,
    remediate,
    risks,
    scan,
    search,
    size,
    sizescore,
    stack,
    suggest,
    summary,
    tree,
    unused,
    update,
    watch,
    why,
    workspace,
)


def _register_commands(group: click.Group, modules: tuple[Any, ...]) -> None:
    """Register every command object exposed by the given modules.

    Args:
        group: The Click group the commands are attached to.
        modules: The command modules to register.
    """
    for module in modules:
        group.add_command(module.command)


_register_commands(main, _COMMAND_MODULES)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()
