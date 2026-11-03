"""Detect unused dependencies via AST analysis."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from depcheck import jsonout


@click.command(name="unused")
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
    help="Output unused-dependency analysis as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
@click.option(
    "--include-undeclared",
    is_flag=True,
    default=False,
    help="Also report packages imported in source but missing from the manifest.",
)
@click.option(
    "--exclude",
    "exclude_patterns",
    multiple=True,
    type=str,
    help="Glob patterns to exclude from source scanning. Repeat for multiple. "
    "E.g., --exclude 'vendor/**' --exclude 'stubs/*'",
)
@click.option(
    "--confidence",
    "confidence_threshold",
    type=click.Choice(["high", "medium", "low"], case_sensitive=False),
    default="low",
    help="Minimum confidence level to report (default: low = report all).",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["high", "medium", "low", "any"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if any finding meets the threshold. "
    "Use 'any' to fail on any unused or undeclared dependency.",
)
def command(
    path: str,
    output_json: bool,
    quiet: bool,
    include_undeclared: bool,
    exclude_patterns: tuple[str, ...],
    confidence_threshold: str,
    fail_on: str | None,
) -> None:
    """Detect declared dependencies that are never imported in source code.

    Uses AST-based import extraction (not fragile regex) with a comprehensive
    import-name to distribution-name mapping to catch ``import yaml`` →
    ``pyyaml`` mismatches. Each finding carries a confidence score
    (HIGH / MEDIUM / LOW) to reduce false positives.

    PATH is the project directory (defaults to current directory).

    Examples:\n
    \\b
    depcheck unused
    depcheck unused --include-undeclared
    depcheck unused --confidence high --fail-on high
    depcheck unused /path/to/project --json
    """
    from depcheck.unused import (
        Confidence,
        UnusedAnalyzer,
        UnusedConfig,
        determine_unused_exit_code,
        render_unused_table,
    )

    console = Console(quiet=quiet)

    threshold_map = {
        "high": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "low": Confidence.LOW,
    }
    threshold = threshold_map.get(confidence_threshold.lower(), Confidence.LOW)

    config = UnusedConfig(
        exclude_patterns=list(exclude_patterns),
        include_undeclared=include_undeclared,
        confidence_threshold=threshold,
    )

    analyzer = UnusedAnalyzer(config=config)
    result = analyzer.analyze(project_path=Path(path))

    if result.errors and not result.unused and not result.undeclared:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        jsonout.write_json(result.to_dict())
    elif not quiet:
        render_unused_table(result, console=console)

    if fail_on is not None:
        sys.exit(determine_unused_exit_code(result, fail_on=fail_on))
