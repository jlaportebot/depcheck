"""Shields.io badge URL for the depcheck health score.

Wraps :func:`depcheck.scorecard.generate_badge_url` so a README can embed a
live health badge with a single command.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck import jsonout
from depcheck.scorecard import build_scorecard, generate_badge_url


@click.command(name="badge")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
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
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output the badge metadata as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def command(
    path: str,
    no_vuln_check: bool,
    no_license_check: bool,
    output_json: bool,
    quiet: bool,
) -> None:
    """Print a shields.io badge URL for the project's dependency health score.

    The URL can be embedded directly in a README:

    \b
    ![depcheck](https://img.shields.io/badge/depcheck-A+(92)-brightgreen)
    """
    console = Console(quiet=quiet)

    scorecard = build_scorecard(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=not no_license_check,
    )
    badge_url = generate_badge_url(scorecard)

    if output_json:
        jsonout.write_text(
            jsonout.to_json(
                {
                    "badge_url": badge_url,
                    "grade": scorecard.grade.value,
                    "score": scorecard.overall_score,
                }
            )
        )
    elif not quiet:
        console.print(badge_url, markup=False, highlight=False)

    sys.exit(0)
