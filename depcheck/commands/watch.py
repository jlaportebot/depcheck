"""Watch dependency files and re-scan on change."""

from __future__ import annotations

import click
from rich.console import Console


@click.command(name="watch")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--debounce",
    type=float,
    default=2.0,
    help="Seconds to wait after a file change before re-scanning (default: 2.0).",
)
@click.option(
    "--poll-interval",
    type=float,
    default=1.0,
    help="Seconds between file change polls (default: 1.0).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster scanning).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Check license compliance for each dependency.",
)
@click.option(
    "--allow-license",
    "allowed_licenses",
    multiple=True,
    type=click.Choice(
        ["permissive", "copyleft", "public_domain"],
        case_sensitive=False,
    ),
    help="Allowed license categories. Repeat for multiple.",
)
@click.option(
    "--deny-license",
    "denied_licenses",
    multiple=True,
    help="Specific SPDX license IDs to deny. Repeat for multiple.",
)
@click.option(
    "--exit-on-issue",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any dependency issues are found (CI guard mode).",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["vulnerable", "outdated", "unmaintained", "license", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Issue type that triggers exit (with --exit-on-issue). Default: any.",
)
@click.option(
    "--no-history",
    is_flag=True,
    default=False,
    help="Don't show scan history in the dashboard.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress dashboard output; only print on changes.",
)
def command(
    path: str,
    debounce: float,
    poll_interval: float,
    no_vuln_check: bool,
    check_licenses: bool,
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    exit_on_issue: bool,
    fail_on: str | None,
    no_history: bool,
    quiet: bool,
) -> None:
    """Watch a project for dependency changes and re-scan automatically.

    Monitors dependency files (requirements.txt, pyproject.toml, Pipfile, etc.)
    and automatically re-scans when changes are detected. Shows a live dashboard
    with health status, change detection, and historical scan results.

    Perfect for long-running development sessions or as a CI guard that
    continuously monitors your project's dependency health.

    Examples:

    \b
    depcheck watch
    depcheck watch /path/to/project
    depcheck watch --no-vuln-check --debounce 5
    depcheck watch --exit-on-issue --fail-on vulnerable
    depcheck watch --check-licenses --deny-license GPL-3.0
    depcheck watch --no-history
    """
    from depcheck.licenses import LicenseCategory
    from depcheck.watch import WatchConfig, watch_loop

    console = Console(quiet=quiet)

    # Parse license policy options
    allowed_categories: list[LicenseCategory] | None = None
    if allowed_licenses:
        category_map = {
            "permissive": LicenseCategory.PERMISSIVE,
            "copyleft": LicenseCategory.COPYLEFT,
            "public_domain": LicenseCategory.PUBLIC_DOMAIN,
        }
        allowed_categories = [
            category_map[cat.lower()] for cat in allowed_licenses if cat.lower() in category_map
        ]

    denied_list: list[str] | None = None
    if denied_licenses:
        denied_list = list(denied_licenses)

    # Enable license check if any license options are specified
    should_check_licenses = check_licenses or bool(allowed_licenses) or bool(denied_licenses)

    config = WatchConfig(
        project_path=path,
        debounce_seconds=debounce,
        poll_interval=poll_interval,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=should_check_licenses,
        allowed_license_categories=allowed_categories,
        denied_licenses=denied_list,
        exit_on_issue=exit_on_issue,
        fail_on=fail_on,
        show_history=not no_history,
    )

    try:
        watch_loop(config, console=console)
    except KeyboardInterrupt:
        pass
