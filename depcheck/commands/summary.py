"""Quick health summary with letter grade and badge for depcheck.

Wraps depcheck.scorecard.build_scorecard and provides CLI access.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.scorecard import (
    build_scorecard,
    generate_badge_url,
    render_scorecard,
)


@click.command(name="summary")
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
    help="Output results as JSON.",
)
@click.option(
    "--badge",
    is_flag=True,
    default=False,
    help="Print only the shields.io badge URL.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking.",
)
@click.option(
    "--no-license-check",
    is_flag=True,
    default=False,
    help="Skip license compliance checking.",
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
    badge: bool,
    no_vuln_check: bool,
    no_license_check: bool,
    quiet: bool,
) -> None:
    """Generate a quick health summary with letter grade and badge.

    PATH is the project directory to scan (defaults to current directory).
    """
    console = Console(quiet=quiet)

    # Build scorecard
    scorecard = build_scorecard(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=not no_license_check,
    )

    # Output
    if badge:
        badge_url = generate_badge_url(scorecard)
        console.print(badge_url, markup=False, highlight=False)
    elif output_json:
        jsonout.write_text(jsonout.to_json(scorecard.to_dict()))
    elif not quiet:
        render_scorecard(scorecard, console=console)

    sys.exit(0)
